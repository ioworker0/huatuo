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
// 针对容器 (cgroup) 的 CPU 使用情况进行“主动/自适应”追踪：
// 1. 周期性枚举正常容器 (pod.GetNormalContainers)，维护一个 containersCPUIdle 映射，保存每个容器最近一次的 CPU 使用原始值与换算后的百分比。
// 2. 利用 cgroup cpu.stat (通过 cgroupMgr.CpuUsage) 与 cpu.cfs_quota_us/period_us (cgroupMgr.CpuQuotaAndPeriod) 计算该容器在本周期的 user/sys/total 百分比。
//    百分比公式: 百分比 = (delta_ticks / elapsed_microseconds / cpu_cores) * 100。
//    其中 delta_ticks 为本轮与上一轮的差值，elapsed_microseconds 为两次采样的时间间隔，cpu_cores = quota/period (近似有效核数)。
// 3. 当同时满足“当前百分比超过阈值”与“该百分比的增量超过阈值” (user/sys/total 任意一组) 且与上次 perf 距离超过 intervalContinuousPerf 秒时，触发一次 perf BPF 采样。
// 4. 使用 perf 工具加载 cpuidle.o BPF 对象执行系统/容器范围采样，拿到火焰图 JSON (flamedata)，持久化到 storage (Save)。
// 5. 避免持续触发：traceTime 用于节流连续 perf；每次触发后重置 prevUsage 让下一轮重新积累增量。
// 关键结构:
//   cpuStats: 描述某次或某段增量的 user/sys/total ticks 或百分比。
//   containerCPUInfo: 保存原始 ticks/百分比/增量/路径/存活标记/上次 trace 时间等。
//   cpuIdleThreshold: 配置的阈值 (usage 与 delta) 以及连续触发间隔。
// 边界与注意事项:
//   - 首次采样容器 prevUsage 为空，updateContainerCpuUsage 返回 "cpu usage first update" 用于跳过触发逻辑。
//   - 若 delta.total == 0 (ticks 未增加) 视为无变化，跳过。
//   - 计算 cpuCores 时如果 quota==math.MaxUint64 (即无限制) 直接报错“cpu too large”避免错误放大；如果算出的核心数=0 (极小限额) 返回错误。
//   - 采用 Microseconds 作为间隔单位，存在整除截断；可后续改为浮点或更精细的时间单位提升精度。
//   - 更新 alive 标记策略：每轮枚举先标记所有在列表里的 alive=true，下一轮 detect 时若未刷新则删除该容器。
// 扩展建议:
//   - 增加平滑处理 (滑动窗口均值/指数平滑) 避免瞬时抖动触发 perf。
//   - 引入最大触发次数限制，在高压场景防止大量 perf 开销。
//   - 支持将火焰图与原始 cgroup CPU 限额配对存储 (当前只保存百分比)。
//   - 对于无限制 CPU 的容器 (quota=MaxUint64) 可按 /proc/stat 或 /sys/fs/cgroup/cpu.stat usage per CPU 进行归一化。

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"path"
	"strconv"
	"time"

	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/stats"
	"huatuo-bamai/internal/conf"
	"huatuo-bamai/internal/flamegraph"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/internal/storage"
	"huatuo-bamai/pkg/tracing"
	"huatuo-bamai/pkg/types"
)

func init() {
	tracing.RegisterEventTracing("cpuidle", newCPUIdle)
}

var cgroupMgr cgroups.Cgroup

func newCPUIdle() (*tracing.EventTracingAttr, error) {
	cgroupMgr, _ = cgroups.NewCgroupManager()

	return &tracing.EventTracingAttr{
		TracingData: &cpuIdleTracing{},
		Internal:    20,
		Flag:        tracing.FlagTracing,
	}, nil
}

// cpuIdleTracing: 空结构用于实现 Start 接口，实例本身不保存状态，状态存储在全局 map。
type cpuIdleTracing struct{}

// cpuStats: 通用结构，既用于保存原始 ticks，也用于保存换算后的百分比；含 user/sys/total 三类字段。
type cpuStats struct {
	user  int64
	sys   int64
	total int64
}

// containerCPUInfo:
//
//	prevUsage: 上一次的原始 ticks 累积值 (user/sys/total)
//	prevUsagePercentage: 上一次换算后的百分比快照
//	nowUsagePercentage: 当前百分比
//	deltaUsagePercentage: 当前与上一次百分比差值 (用于突增检测)
//	path: cgroup 路径后缀 (用于读取 cgroup 文件)
//	alive: 在本轮枚举中是否仍存在 (心跳标记)
//	id: 容器 ID (用于持久化、perf 指定)
//	traceTime: 上次触发 perf 的时间戳 (用于节流)
//	updateTime: 上次更新 ticks 的时间戳 (用于计算 elapsed)
type containerCPUInfo struct {
	prevUsagePercentage  cpuStats
	nowUsagePercentage   cpuStats
	deltaUsagePercentage cpuStats
	prevUsage            cpuStats
	path                 string
	alive                bool
	id                   string
	traceTime            time.Time
	updateTime           time.Time
}

// cpuIdleThreshold: 定义使用率与增量的触发阈值，以及连续 perf 的最小间隔 (秒)。
// usageX > threshold.usageX 与 deltaX > threshold.deltaX 必须同时满足 (逐类 AND，再整体 OR)。
type cpuIdleThreshold struct {
	deltaUser              int64
	deltaSys               int64
	deltaTotal             int64
	usageUser              int64
	usageSys               int64
	usageTotal             int64
	intervalContinuousPerf int64
}

// containersCPUIdleMap: 以容器 ID 为 key 存储容器 CPU 信息，遍历过程中可能删除失活容器。
// containersCPUIdle 是容器信息的映射
type containersCPUIdleMap map[string]*containerCPUInfo

var containersCPUIdle = make(containersCPUIdleMap)

// updateContainersCPUIdle 定期更新容器 CPU 使用信息:
// 1. 调用 pod.GetNormalContainers() 获取当前所有正常容器。
// 2. 遍历容器列表，更新 containersCPUIdle 映射。
//   - 已存在的容器：更新 path、alive、id 字段。
//   - 新容器：初始化所有字段。
func updateContainersCPUIdle() error {
	containers, err := pod.GetNormalContainers()
	if err != nil {
		return err
	}

	for _, container := range containers {
		if _, ok := containersCPUIdle[container.ID]; ok {
			containersCPUIdle[container.ID].path = container.CgroupSuffix
			containersCPUIdle[container.ID].alive = true
			containersCPUIdle[container.ID].id = container.ID
			continue
		}

		containersCPUIdle[container.ID] = &containerCPUInfo{
			path:  container.CgroupSuffix,
			alive: true,
			id:    container.ID,
		}
	}

	return nil
}

// detectCPUIdleContainer:
//
//	遍历所有容器 -> 删除失活 -> 更新使用率 -> 根据阈值判定是否触发。
//	返回首个满足条件的容器；没有则返回错误避免中断主循环 (上层直接 continue)。
func detectCPUIdleContainer(threshold *cpuIdleThreshold) (*containerCPUInfo, error) {
	for id, container := range containersCPUIdle {
		if !container.alive {
			delete(containersCPUIdle, id)
		} else {
			container.alive = false

			if err := updateContainerCpuUsage(container); err != nil {
				log.Debugf("cpuidle update container [%s]: %v", container.path, err)
				continue
			}

			log.Debugf("container [%s], usage: %v", container.path, container.nowUsagePercentage)

			if shouldCareThisEvent(container, threshold) {
				return container, nil
			}
		}
	}

	return nil, fmt.Errorf("no cpuidle containers")
}

// containerCpuUsage: 将 cgroupMgr.CpuUsage 返回的 stats.CpuUsage 转换成本地 cpuStats 结构。
func containerCpuUsage(usage *stats.CpuUsage) cpuStats {
	return cpuStats{
		user:  int64(usage.User),
		sys:   int64(usage.System),
		total: int64(usage.Usage),
	}
}

// containerCpuUsageDelta: 两个 cpuStats 的简单差值，适用于 ticks 或百分比 (保持字段意义)。
func containerCpuUsageDelta(cpu1, cpu2 *cpuStats) cpuStats {
	return cpuStats{
		user:  cpu1.user - cpu2.user,
		sys:   cpu1.sys - cpu2.sys,
		total: cpu1.total - cpu2.total,
	}
}

// updateContainerCpuUsage 更新容器的 CPU 使用信息:
// 步骤:
// 1. 读取配额与周期，计算可用核心数 cpuCores = quota/period。
// 2. 读取当前 ticks；若首次则只初始化 prevUsage 与 updateTime 并返回特殊错误用于上层跳过。
// 3. 计算 delta ticks；若 delta.total==0 直接更新 updateTime 并返回特殊错误 (无变化)。
// 4. 根据 elapsed(微秒) 和 cpuCores 计算 user/sys/total 百分比 (整除形式)。
// 5. 初始化 prevUsagePercentage (若首次)；计算 deltaUsagePercentage；刷新 prevUsagePercentage 与 prevUsage。
// 6. 更新时间戳，用于下一轮计算 elapsed。
// 注意: 整数截断会造成误差，压力高/间隔小场景可考虑改为浮点或纳秒 granularity。
func updateContainerCpuUsage(container *containerCPUInfo) error {
	cpuQuotaPeriod, err := cgroupMgr.CpuQuotaAndPeriod(container.path)
	if err != nil {
		return err
	}

	if cpuQuotaPeriod.Quota == math.MaxUint64 {
		return fmt.Errorf("cpu too large")
	}

	cpuCores := int64(cpuQuotaPeriod.Quota / cpuQuotaPeriod.Period)
	if cpuCores == 0 {
		return fmt.Errorf("cpu too small")
	}

	usage, err := cgroupMgr.CpuUsage(container.path)
	if err != nil {
		return err
	}

	if container.prevUsage == (cpuStats{}) {
		container.prevUsage = containerCpuUsage(usage)
		container.updateTime = time.Now()
		return fmt.Errorf("cpu usage first update")
	}

	delta := containerCpuUsageDelta(
		&cpuStats{
			user:  int64(usage.User),
			sys:   int64(usage.System),
			total: int64(usage.Usage),
		}, &container.prevUsage)
	if delta.total == 0 {
		container.updateTime = time.Now()
		return fmt.Errorf("cpu usage no changed")
	}

	updateElasped := time.Since(container.updateTime).Microseconds()

	container.nowUsagePercentage.user = 100 * delta.user / updateElasped / cpuCores
	container.nowUsagePercentage.sys = 100 * delta.sys / updateElasped / cpuCores
	container.nowUsagePercentage.total = 100 * delta.total / updateElasped / cpuCores

	if container.prevUsagePercentage == (cpuStats{}) {
		container.prevUsagePercentage = container.nowUsagePercentage
	}

	container.deltaUsagePercentage = containerCpuUsageDelta(
		&container.nowUsagePercentage,
		&container.prevUsagePercentage)
	container.prevUsagePercentage = container.nowUsagePercentage
	container.prevUsage = containerCpuUsage(usage)
	container.updateTime = time.Now()
	return nil
}

// shouldCareThisEvent 判定是否需要关注该事件:
// 1. 与上次 perf 的时间间隔必须 > intervalContinuousPerf，避免极短间隔重复触发。
// 2. 对 user/sys/total 三类分别检查 (当前百分比 > usageThreshold) AND (百分比增量 > deltaThreshold)。
// 3. 任意一类满足则触发 (整体 OR)。
// 4. 触发后重置 prevUsage 为空，用于下一轮重新聚合增量，避免延续过往的 delta。
func shouldCareThisEvent(container *containerCPUInfo, threshold *cpuIdleThreshold) bool {
	nowtime := time.Now()
	intervalContinuousPerf := nowtime.Sub(container.traceTime)

	if int64(intervalContinuousPerf.Seconds()) > threshold.intervalContinuousPerf {
		if (container.nowUsagePercentage.user > threshold.usageUser &&
			container.deltaUsagePercentage.user > threshold.deltaUser) ||
			(container.nowUsagePercentage.sys > threshold.usageSys &&
				container.deltaUsagePercentage.sys > threshold.deltaSys) ||
			(container.nowUsagePercentage.total > threshold.usageTotal &&
				container.deltaUsagePercentage.total > threshold.deltaTotal) {
			container.traceTime = nowtime
			container.prevUsage = cpuStats{}
			return true
		}
	}

	return false
}

// runPerf 执行 perf 命令:
//
//	--bpf-obj cpuidle.o : 预编译好的 BPF 程序对象文件；
//	--container-id: 指定目标容器 (perf 内部应做 cgroup 匹配或 PID 过滤)；
//	--duration: 采样时长秒数；附加 +30 秒超时冗余防止 perf 自身延迟退出导致阻塞。
//
// 返回 combinedOutput：包含标准输出与错误输出，失败时用于调试。
func runPerf(parent context.Context, containerId string, timeOut int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeOut+30)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path.Join(tracing.TaskBinDir, "perf"),
		"--bpf-obj", "cpuidle.o",
		"--container-id", containerId,
		"--duration", strconv.FormatInt(timeOut, 10))

	return cmd.CombinedOutput()
}

// buildAndSaveCPUIdleContainer 构建保存数据:
//   - 使用当前百分比与增量与阈值对比，携带火焰图栈信息。
//   - 火焰图 JSON -> FrameData 列表。
//   - storage.Save(key="cpuidle", container.id, traceTime=container.traceTime)。
func buildAndSaveCPUIdleContainer(container *containerCPUInfo, threshold *cpuIdleThreshold, flamedata []byte) error {
	tracerData := CPUIdleTracingData{
		NowUser:             container.nowUsagePercentage.user,
		DeltaUser:           container.deltaUsagePercentage.user,
		UserThreshold:       threshold.usageUser,
		DeltaUserThreshold:  threshold.deltaUser,
		NowSys:              container.nowUsagePercentage.sys,
		DeltaSys:            container.deltaUsagePercentage.sys,
		SysThreshold:        threshold.usageSys,
		DeltaSysThreshold:   threshold.deltaSys,
		NowUsage:            container.nowUsagePercentage.total,
		DeltaUsage:          container.deltaUsagePercentage.total,
		UsageThreshold:      threshold.usageTotal,
		DeltaUsageThreshold: threshold.deltaTotal,
	}

	if err := json.Unmarshal(flamedata, &tracerData.FlameData); err != nil {
		return err
	}

	log.Debugf("cpuidle flamedata %v", tracerData.FlameData)
	storage.Save("cpuidle", container.id, container.traceTime, &tracerData)
	return nil
}

type CPUIdleTracingData struct {
	NowUser             int64                  `json:"user"`
	UserThreshold       int64                  `json:"user_threshold"`
	DeltaUser           int64                  `json:"deltauser"`
	DeltaUserThreshold  int64                  `json:"deltauser_threshold"`
	NowSys              int64                  `json:"sys"`
	SysThreshold        int64                  `json:"sys_threshold"`
	DeltaSys            int64                  `json:"deltasys"`
	DeltaSysThreshold   int64                  `json:"deltasys_threshold"`
	NowUsage            int64                  `json:"usage"`
	UsageThreshold      int64                  `json:"usage_threshold"`
	DeltaUsage          int64                  `json:"deltausage"`
	DeltaUsageThreshold int64                  `json:"deltausage_threshold"`
	FlameData           []flamegraph.FrameData `json:"flamedata"`
}

func (c *cpuIdleTracing) Start(ctx context.Context) error {
	interval := conf.Get().Tracing.CPUIdle.Interval
	perfRunTimeOut := conf.Get().Tracing.CPUIdle.PerfRunTimeOut

	threshold := &cpuIdleThreshold{
		deltaUser:              conf.Get().Tracing.CPUIdle.DeltaUserThreshold,
		deltaSys:               conf.Get().Tracing.CPUIdle.DeltaSysThreshold,
		deltaTotal:             conf.Get().Tracing.CPUIdle.DeltaUsageThreshold,
		usageUser:              conf.Get().Tracing.CPUIdle.UserThreshold,
		usageSys:               conf.Get().Tracing.CPUIdle.SysThreshold,
		usageTotal:             conf.Get().Tracing.CPUIdle.UsageThreshold,
		intervalContinuousPerf: conf.Get().Tracing.CPUIdle.IntervalContinuousPerf,
	}

	for {
		select {
		case <-ctx.Done():
			return types.ErrExitByCancelCtx
		case <-time.After(time.Duration(interval) * time.Second):
			if err := updateContainersCPUIdle(); err != nil {
				return err
			}

			container, err := detectCPUIdleContainer(threshold)
			if err != nil {
				continue
			}

			log.Infof("start perf container [%s], id [%s] with usage: %v, perf_run_timeout: %d",
				container.path, container.id,
				container.nowUsagePercentage,
				perfRunTimeOut)
			flamedata, err := runPerf(ctx, container.id, perfRunTimeOut)
			if err != nil {
				log.Debugf("perf err: %v, output: %v", err, string(flamedata))
				return err
			}

			if len(flamedata) == 0 {
				log.Infof("perf output is null for container id [%s]", container.id)
				continue
			}

			_ = buildAndSaveCPUIdleContainer(container, threshold, flamedata)
		}
	}
}
