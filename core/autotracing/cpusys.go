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
// 自动追踪系统级 CPU system 使用率 (即 /proc/stat 第一个 cpu 行中第三个字段 "system" 所占比例)。
// 周期性读取 /proc/stat, 计算本周期的 system 百分比 (sysPercent) 及相对上一周期的变化量 (sysPercentDelta)。
// 当 system 百分比或变化量超过配置阈值 (SysThreshold / DeltaSysThreshold) 时，触发一次系统范围 perf 采样，
// 使用 BPF 对象 cpuidle.o (可能内含采样点或辅助逻辑) 生成火焰图数据 (JSON)，并持久化保存。
// 关键点:
//   1. /proc/stat 第一行字段顺序: user nice system idle iowait irq softirq ... -> 下标 0,1,2,...; 这里取 i==2 作为 system。
//   2. 百分比计算: (Δsystem_ticks / Δtotal_ticks)*100 (整型计算, 可能有截断)。
//   3. sysPercentDelta = 本次 system 百分比 - 上一次 system 百分比, 用于捕捉“突增”场景。
//   4. runPerfSystemWide 增加 30s 容错 (timeOut+30) 防止超时中断，避免频繁失败。
//   5. flamegraph 数据 JSON 反序列化到 CpuSysTracingData.FlameData 后入库 storage.Save。
//   6. EventTracingAttr.Internal=20 表示内部调度间隔单位 (结合外层框架)，FlagTracing 标记为 tracing 类事件。
//   7. 仅在 shouldCareThisEvent 返回 true 时才执行高成本 perf，降低性能开销。
//   8. 可能的边界情况: 初次读取无历史数据 -> 只初始化不触发; /proc/stat 读取失败 -> 返回错误终止; perf 输出为空 -> 跳过保存。
// 可扩展: 支持 user/irq/softirq 等字段; 增加平滑算法 (滑动平均) 减少抖动; 增加最大连续触发次数限制; 增加采样标签 (机器/实例)。

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"huatuo-bamai/internal/conf"
	"huatuo-bamai/internal/flamegraph"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/storage"
	"huatuo-bamai/pkg/tracing"
	"huatuo-bamai/pkg/types"
)

// init: 注册 "cpusys" 自动追踪事件，框架后续按配置周期调用其 Start。
func init() {
	tracing.RegisterEventTracing("cpusys", newCpuSys)
}

// newCpuSys: 构造追踪属性，Internal=20 (框架使用)，FlagTracing 表示是 tracing 事件。
func newCpuSys() (*tracing.EventTracingAttr, error) {
	return &tracing.EventTracingAttr{
		TracingData: &cpuSysTracing{},
		Internal:    20,
		Flag:        tracing.FlagTracing,
	}, nil
}

// cpuUsage: 保存一次 /proc/stat 读取后的总 tick 与 system tick 累积值 (都是自启动以来递增)。
type cpuUsage struct {
	system uint64 // /proc/stat 第一行第三个字段 (system) 累积 tick 数
	total  uint64 // 当前行所有字段求和 (总体 tick 累积)
}

// cpuSysTracing: 维护当前状态与计算出的百分比及增量
// usage 保存上一周期采样的累积数; sysPercent=本周期 system 百分比; sysPercentDelta=与上一周期差值。
type cpuSysTracing struct {
	usage           *cpuUsage
	sysPercent      int64 // 本周期 system 百分比 (0-100)
	sysPercentDelta int64 // 与上一周期比较的变化量 (可能为负)
}

// CpuSysTracingData: 持久化时的结构，包含当前值、阈值、增量及火焰图数据。
type CpuSysTracingData struct {
	NowSys            int64                  `json:"now_sys"`
	SysThreshold      int64                  `json:"sys_threshold"`
	DeltaSys          int64                  `json:"deltasys"`
	DeltaSysThreshold int64                  `json:"deltasys_threshold"`
	FlameData         []flamegraph.FrameData `json:"flamedata"`
}

// cpuSysThreshold: 封装两个触发阈值：
// usage: 当前 system 百分比阈值
// delta: system 百分比变化量阈值 (突增告警)
type cpuSysThreshold struct {
	delta int64
	usage int64
}

// cpuSysUsage: 读取 /proc/stat 第一行，解析系统/总 tick。只读一次，不含锁。
// 返回: 累积 system 与累积 total tick；错误时返回 error。
func cpuSysUsage() (*cpuUsage, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan()
	fields := strings.Fields(scanner.Text())[1:]

	var total, sys uint64
	for i, field := range fields {
		val, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return nil, err
		}

		total += val
		if i == 2 {
			sys = val
		}
	}

	return &cpuUsage{system: sys, total: total}, nil
}

// updateCpuSysUsage: 基于最新 /proc/stat 数据计算系统百分比与变化量。
// 计算公式:
//
//	sysUsageDelta = new.system - old.system
//	sysTotalDelta = new.total  - old.total
//	sysPercentage = (sysUsageDelta * 100) / sysTotalDelta (整除)
//
// 若首次调用 (c.usage == nil) 则仅初始化不计算 sysPercentDelta。
func (c *cpuSysTracing) updateCpuSysUsage() error {
	usage, err := cpuSysUsage()
	if err != nil {
		return err
	}

	if c.usage == nil {
		c.usage = usage
		return nil
	}

	sysUsageDelta := usage.system - c.usage.system
	sysTotalDelta := usage.total - c.usage.total
	sysPercentage := int64(100 * sysUsageDelta / sysTotalDelta)

	c.sysPercentDelta = sysPercentage - c.sysPercent
	c.sysPercent = sysPercentage
	c.usage = usage
	return nil
}

// shouldCareThisEvent: 判断是否超过阈值，需要触发 perf 采样。
// 触发条件: 当前 system 百分比 > usage 阈值 或 百分比变化量 > delta 阈值。
// 返回 true 表示关心，false 表示继续下一轮等待。
func (c *cpuSysTracing) shouldCareThisEvent(threshold *cpuSysThreshold) bool {
	log.Debugf("sys %d, sys delta: %d", c.sysPercent, c.sysPercentDelta)

	if c.sysPercent > threshold.usage || c.sysPercentDelta > threshold.delta {
		return true
	}

	return false
}

// runPerfSystemWide: 执行系统范围 perf 采样，超时时间 = timeOut + 30 秒冗余。
// 使用 cpuidle.o BPF 对象 (需预放置在 tracing.TaskBinDir)。
// 返回: perf 标准输出与错误（CombinedOutput）。失败时输出可用于调试。
func runPerfSystemWide(parent context.Context, timeOut int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeOut+30)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path.Join(tracing.TaskBinDir, "perf"),
		"--bpf-obj", "cpuidle.o",
		"--duration", strconv.FormatInt(timeOut, 10))

	return cmd.CombinedOutput()
}

// buildAndSaveCPUSystem: 构建最终追踪数据结构并写入存储层。
// 步骤: 组装 CpuSysTracingData -> 解析 flamedata JSON -> 调用 storage.Save。
func (c *cpuSysTracing) buildAndSaveCPUSystem(traceTime time.Time, threshold *cpuSysThreshold, flamedata []byte) error {
	tracerData := CpuSysTracingData{
		NowSys:            c.sysPercent,
		SysThreshold:      threshold.usage,
		DeltaSys:          c.sysPercentDelta,
		DeltaSysThreshold: threshold.delta,
	}

	if err := json.Unmarshal(flamedata, &tracerData.FlameData); err != nil {
		return err
	}

	log.Debugf("cpuidle flamedata %v", tracerData.FlameData)
	storage.Save("cpusys", "", traceTime, &tracerData)
	return nil
}

// Start: 主循环。
// 周期: interval 秒 (从配置读取)。每轮:
//  1. 更新 CPU system 使用率数据。
//  2. 判断是否超过阈值 (shouldCareThisEvent)。
//  3. 若超过 -> 记录当前时间 traceTime，执行 runPerfSystemWide，并解析+保存结果。
//
// 结束条件: ctx.Done() (外部取消)。
// 异常处理: 任一步骤 err 直接返回终止追踪；perf 输出为空则跳过保存继续下一轮。
func (c *cpuSysTracing) Start(ctx context.Context) error {
	interval := conf.Get().Tracing.CPUSys.Interval
	perfRunTimeOut := conf.Get().Tracing.CPUSys.PerfRunTimeOut

	threshold := &cpuSysThreshold{
		delta: conf.Get().Tracing.CPUSys.DeltaSysThreshold,
		usage: conf.Get().Tracing.CPUSys.SysThreshold,
	}

	for {
		select {
		case <-ctx.Done():
			return types.ErrExitByCancelCtx
		case <-time.After(time.Duration(interval) * time.Second):
			if err := c.updateCpuSysUsage(); err != nil {
				return err
			}

			if ok := c.shouldCareThisEvent(threshold); !ok {
				continue
			}

			traceTime := time.Now()

			log.Infof("start perf system wide, cpu sys: %d, delta: %d, perf_run_timeout: %d",
				c.sysPercent, c.sysPercentDelta, perfRunTimeOut)
			flamedata, err := runPerfSystemWide(ctx, perfRunTimeOut)
			if err != nil {
				log.Debugf("perf err: %v, output: %v", err, string(flamedata))
				return err
			}

			if len(flamedata) == 0 {
				log.Infof("perf output is null for system usage")
				continue
			}

			if err := c.buildAndSaveCPUSystem(traceTime, threshold, flamedata); err != nil {
				return err
			}
		}
	}
}
