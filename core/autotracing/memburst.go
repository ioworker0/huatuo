// Copyright 2025 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package autotracing

// 本文件功能概述:
// 监控匿名内存 (Active(anon)+Inactive(anon)) 突增的“内存冲击 / burst”场景，并在满足条件时记录当下系统内存占用最高的若干进程。
// 主要流程:
//   1. 初始化：读取 MemTotal，建立长度为 HistoryWindowLength 的环形缓冲 history，用于保存最近 N 次采样的匿名内存量 (KiB)。
//   2. 周期采样：每 SampleInterval 秒读取 /proc/meminfo 的 Active(anon) 与 Inactive(anon)，求和 currentSum。
//   3. 写入环形缓冲：history[currentIndex] = currentSum，currentIndex 前进一格 (取模)。当缓冲写满一次后 isHistoryFull = true。
//   4. 检测突增：缓冲写满后，用“最旧值” oldestSum 与当前 currentSum 比较；条件：
//        currentSum >= burstRatio * oldestSum  AND  currentSum >= (anonThreshold% * MemTotal)
//      满足则认为发生了一次匿名内存突增。
//   5. 获取进程 TOP：读取所有进程 RSS，按内存排序，截取 TopNProcesses 条，保存到存储层。
//   6. 静默期 (SilencePeriod)：两次上报之间必须间隔 >= SilencePeriod 秒，避免频繁重复记录。
// 关键配置 (conf.Get().Tracing.MemoryBurst.*):
//   HistoryWindowLength    环形历史窗口大小，影响“最久前”对比点的时间跨度。
//   SampleInterval         采样间隔秒。
//   SilencePeriod          两次成功上报之间的最短间隔秒。
//   TopNProcesses          上报时抓取内存占用前 N 名进程。
//   BurstRatio             突增比例阈值；例如 1.5 表示当前值 >= 1.5 * 最旧值。
//   AnonThreshold          匿名内存占 MemTotal 的百分比阈值 (整数)；用于过滤只发生在低内存绝对值上的微小波动。
// 注意点:
//   - 仅对匿名内存做突增检测，忽略文件缓存等；适合捕捉用户态分配 (malloc/brk/mmap 匿名) 激增场景。
//   - 采用“当前 vs 最旧”策略而不是“滑动平均 vs 当前”，可能对缓冲边界较敏感，可后续改进为对比平均或中位数。
//   - getTopMemoryProcesses 使用 RSS (常驻集合)；对于容器场景可补充 cgroup 维度信息。
//   - readMemInfo 逐行解析 /proc/meminfo，简单高效，但没有做单位健壮性校验 (默认 kB)。
//   - 初始写入阶段未写满窗口不做突增检测 (isHistoryFull=false)。
// 潜在改进:
//   1. 增加对 OOM killer 事件或内核回收指标的关联，提供更丰富上下文。
//   2. 报告时加入时间序列 (完整 history) 以便前端绘制趋势。
//   3. 采用指数平滑/移动平均降低抖动与“单点爆发”误判。
//   4. 支持排除白名单进程 (如系统守护进程)。
//   5. 支持 cgroup/container 维度的 top 统计。
// 拼写提示: tracing.RegisterEventTracing("membust", ...) 里 "membust" 可能是 "memburst" 的拼写错误，保留以兼容现有调用。

import (
	"bufio"
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"huatuo-bamai/internal/conf"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/storage"
	"huatuo-bamai/pkg/tracing"

	"github.com/shirou/gopsutil/process"
)

func init() {
	tracing.RegisterEventTracing("membust", newMemBurst)
}

func newMemBurst() (*tracing.EventTracingAttr, error) {
	return &tracing.EventTracingAttr{
		TracingData: &memBurstTracing{},
		Internal:    10,
		Flag:        tracing.FlagTracing,
	}, nil
}

// memBurstTracing: 空结构，仅实现 Start 方法，无内部字段状态。
type memBurstTracing struct{}

// MemoryTracingData: 持久化数据结构，当前仅保存一次突增触发时的 Top 进程快照。
// 可扩展字段: 触发时匿名内存值、最旧值、窗口长度、配置参数等。
type MemoryTracingData struct {
	TopMemoryUsage []ProcessMemoryInfo `json:"top_memory_usage"`
}

// ProcessMemoryInfo: 进程 PID/名称/RSS 用于排序与输出。
// 注意: RSS 可能不完全反映匿名内存；更精细可用 smaps 或 pss，但开销更大。
// ByMemory: 降序排序 (MemorySize 大的优先) 实现 sort.Interface。
type ProcessMemoryInfo struct {
	PID         int32  `json:"pid"`
	ProcessName string `json:"process_name"`
	MemorySize  uint64 `json:"memory_size"`
}

type ByMemory []ProcessMemoryInfo

func (a ByMemory) Len() int           { return len(a) }
func (a ByMemory) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByMemory) Less(i, j int) bool { return a[i].MemorySize > a[j].MemorySize }

// getTopMemoryProcesses: 遍历系统所有进程，读取 RSS 与名字，过滤出可访问的，排序取前 N。
// 错误与边界:
//   - 单个进程读取失败直接跳过 (可能权限/瞬时退出)。
//   - 若总进程数 < N 则返回全部。
//
// 性能: 对大量进程场景每次突增触发都要全量扫描，可考虑缓存或限制频率。
// pass required keys and readMemInfo will return their values according to /proc/meminfo
func getTopMemoryProcesses(topN int) ([]ProcessMemoryInfo, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var pmInfos []ProcessMemoryInfo
	for _, p := range processes {
		memInfo, err := p.MemoryInfo()
		if err != nil {
			continue
		}
		name, err := p.Name()
		if err != nil {
			continue
		}
		pmInfos = append(pmInfos, ProcessMemoryInfo{
			PID:         p.Pid,
			ProcessName: name,
			MemorySize:  memInfo.RSS,
		})
	}

	// Sort the processes by memory usage
	sort.Sort(ByMemory(pmInfos))

	if len(pmInfos) < topN {
		return pmInfos, nil
	}
	return pmInfos[:topN], nil
}

// readMemInfo: 给定一组 key (如 Active(anon), Inactive(anon), MemTotal)，解析 /proc/meminfo 返回对应数值(kB)。
// 终止条件: 所有必需 key 已解析或文件结束。
// 注意: 简单字符串处理，没有校验单位“kB”大小写；若未来内核格式变化需增强健壮性。
// checkAndRecordMemoryUsage: 环形缓冲写入与突增检测主逻辑。
// 参数:
//
//	currentIndex      *int   当前写入位置索引 (指向即将写入的槽)；写完后递增取模。
//	isHistoryFull     *bool  标记缓冲是否写满至少一轮；未写满前不检测突增。
//	memTotal          int    总内存 KiB (用于 anon 阈值换算)。
//	history           []int  环形缓冲 (长度 = HistoryWindowLength)，保存过去的匿名内存值。
//	historyWindowLength int  缓冲长度，便于计算写满条件。
//	topNProcesses     int    需要返回的进程数。
//	burstRatio        float64 突增比例阈值。
//	anonThreshold     int    匿名内存占比阈值 (百分比)。
//
// 返回:
//
//	[]ProcessMemoryInfo: 若触发突增返回 Top 进程列表，否则空切片。
//
// 检测逻辑:
//
//	oldestSum = history[currentIndex] (此时 currentIndex 指向下一次要写入的位置，因此它存的值是最旧的)
//	条件: currentSum >= burstRatio * oldestSum  && currentSum >= (anonThreshold * memTotal / 100)
//
// 日志: 输出当前 Active/Inactive 匿名内存值辅助调试。
// 错误处理: 读取 /proc/meminfo 出错仅记录日志并返回空列表，不直接终止整体流程。
func readMemInfo(requiredKeys map[string]bool) (map[string]int, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	results := make(map[string]int)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.Trim(fields[0], ":")
		if _, ok := requiredKeys[key]; ok {
			value, err := strconv.Atoi(strings.Trim(fields[1], " kB"))
			if err != nil {
				return nil, err
			}
			results[key] = value

			if len(results) == len(requiredKeys) {
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// Core function
func (c *memBurstTracing) Start(ctx context.Context) error {
	var err error

	historyWindowLength := conf.Get().Tracing.MemoryBurst.HistoryWindowLength
	sampleInterval := conf.Get().Tracing.MemoryBurst.SampleInterval
	silencePeriod := conf.Get().Tracing.MemoryBurst.SilencePeriod
	topNProcesses := conf.Get().Tracing.MemoryBurst.TopNProcesses
	burstRatio := conf.Get().Tracing.MemoryBurst.BurstRatio
	anonThreshold := conf.Get().Tracing.MemoryBurst.AnonThreshold

	memInfo, err := readMemInfo(map[string]bool{"MemTotal": true})
	if err != nil {
		log.Infof("Error reading MemTotal from memory info: %v\n", err)
		return err
	}
	memTotal := memInfo["MemTotal"]
	history := make([]int, historyWindowLength) // circular buffer
	var currentIndex int
	var isHistoryFull bool // don't check memory burst until we have enough data
	var topProcesses []ProcessMemoryInfo
	lastReportTime := time.Now().Add(-24 * time.Hour)

	_, err = checkAndRecordMemoryUsage(&currentIndex, &isHistoryFull, memTotal, history, historyWindowLength, topNProcesses, burstRatio, anonThreshold)
	if err != nil {
		log.Errorf("Fail to checkAndRecordMemoryUsage")
		return err
	}

	for {
		ticker := time.NewTicker(time.Duration(sampleInterval) * time.Second)
		stoppedByUser := false

		for range ticker.C {
			topProcesses, err = checkAndRecordMemoryUsage(&currentIndex, &isHistoryFull, memTotal, history, historyWindowLength, topNProcesses, burstRatio, anonThreshold)
			if err != nil {
				log.Errorf("Fail to checkAndRecordMemoryUsage")
				return err
			}

			select {
			case <-ctx.Done():
				log.Info("Caller request to stop")
				stoppedByUser = true
			default:
			}

			if len(topProcesses) > 0 || stoppedByUser {
				break
			}
		}

		ticker.Stop()

		if stoppedByUser {
			break
		}

		currentTime := time.Now()
		diff := currentTime.Sub(lastReportTime).Seconds()
		if diff < float64(silencePeriod) {
			continue
		}

		lastReportTime = currentTime

		storage.Save("memburst", "", time.Now(), &MemoryTracingData{TopMemoryUsage: topProcesses})
	}

	return nil
}
