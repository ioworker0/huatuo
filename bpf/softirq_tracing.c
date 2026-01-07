#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"
#include "bpf_ratelimit.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// 目的概述:
// 监控 CPU tick 期间的 softirq / 调度 tick 处理延迟，定位潜在的 "长时间未运行 softirq" 或 "tick 被延后" 场景。
// 通过在 account_process_tick(kprobe) 中计算当前时间与上次记录时间 soft_ts 的差值 delta，
// 若超过阈值 (softirq_thresh = 5ms) 则输出事件 (perf event) 给用户态，附带当前内核栈、进程信息、卡顿持续时间等。
// 结合 NOHZ (tick stop/restart) 相关 tracepoint/kprobe，控制开始/停止统计，避免在停 tick 期间误报。
// 核心时序:
//   tick_nohz_restart_sched_tick(kprobe) -> 标记 tick 重启 (start_trace=1, restarting_tick=1, soft_ts=now)
//   account_process_tick(kprobe)         -> 若首次(restarting_tick=1)则重置 soft_ts；否则计算 delta 并可能上报；更新 soft_ts
//   tick_stop(tracepoint)                -> 成功停 tick 时 start_trace=0，停止后续统计。

#define NR_STACK_TRACE_MAX 0x4000
#define MSEC_PER_NSEC 1000000UL
#define TICK_DEP_MASK_NONE 0
#define SOFTIRQ_THRESH 5000000UL // 默认阈值: 5,000,000 ns = 5 ms

// 可调阈值: 用户态可通过 BTF/偏移重写 (volatile + const)，编译期默认为 5ms
volatile const u64 softirq_thresh = SOFTIRQ_THRESH;

#define TICK 1000 // ratelimit: interval = 1 秒，burst = CPU_NUM * 1000 * 1000 (放大后减少丢事件)
// BPF_RATELIMIT(rate, interval_seconds, burst)
// 防止在大量 CPU 上短时间内高频触发造成 perf 事件风暴；超出速率后静默丢弃。
BPF_RATELIMIT(rate, 1, COMPAT_CPU_NUM *TICK * 1000);

// 每 CPU 的 tick 状态记录
// start_trace: 是否处于统计窗口 (NOHZ 重启后置 1，tick 停止置 0)
// restarting_tick: 标记刚从 nohz 停止状态恢复，第一轮 account_process_tick 只重置 soft_ts 不做检测
// soft_ts: 上一次记录的时间戳 (ns)，用于计算 delta
struct timer_softirq_run_ts {
	u32 start_trace;
	u32 restarting_tick;
	u64 soft_ts;
};

// 上报事件结构：包含当前内核栈、发生时间、滞后时长、任务信息、CPU
struct report_event {
	u64 stack[PERF_MAX_STACK_DEPTH];
	s64 stack_size; // 实际采集栈条目数 (可能为负表示错误，如 -EFAULT/-EINVAL)
	u64 now;        // 当前时间戳 ns
	u64 stall_time; // delta = now - soft_ts
	char comm[COMPAT_TASK_COMM_LEN];
	u32 pid;
	u32 cpu;
};

// timerts_map: 每 CPU 一个 slot (PERCPU_ARRAY + max_entries=1)，通过 key=0 获取当前 CPU 的结构体副本
// 这样避免哈希查找及锁竞争，访问 O(1)；BPF 框架自动根据 CPU 提供独立存储。
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct timer_softirq_run_ts));
	__uint(max_entries, 1);
} timerts_map SEC(".maps");

// report_map: 为每 CPU 提供一个临时缓冲区用于构造 perf 输出的数据，避免使用栈导致扩展性/栈深限制
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32)); // 固定 key=0
	__uint(value_size, sizeof(struct report_event));
	__uint(max_entries, 1);
} report_map SEC(".maps");

// irqoff_event_map: PERF_EVENT_ARRAY 用于把捕获的 stall 事件发送到用户态 (perf buffer / ringbuf consumer)
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} irqoff_event_map SEC(".maps");

// kprobe: account_process_tick
// 触发: 每次内核为当前进程记账 CPU 时间 (调度 tick) 时调用
// 流程:
//   1. 速率限制检查 (bpf_ratelimited)
//   2. 读取当前 CPU 的 timer_softirq_run_ts 结构
//   3. 若未开始跟踪 (start_trace=0) 直接返回
//   4. 若 soft_ts 尚未初始化则记录当前时间并返回
//   5. 若处于 restarting_tick 首次迭代: 清除标记并重置 soft_ts (不判定 stall)
//   6. 计算 delta = now - soft_ts；若 >= softirq_thresh (5ms) 则构造并上报事件
//   7. 更新 soft_ts = now，用于下一次比较
SEC("kprobe/account_process_tick")
void probe_account_process_tick(struct pt_regs *ctx)
{
	// 速率限制: 超过速率则直接丢弃此次检查
	if (bpf_ratelimited(&rate))
		return;

	int key = 0;
	struct timer_softirq_run_ts *ts;
	struct report_event *event;
	u64 now;
	u64 delta;

	ts = bpf_map_lookup_elem(&timerts_map, &key);
	if (!ts)
		return; // 理论上不会发生

	if (!ts->start_trace)
		return; // 未处于跟踪窗口 (tick 已停)

	// 第一次初始化 soft_ts
	if (!ts->soft_ts) {
		ts->soft_ts = bpf_ktime_get_ns();
		return;
	}

	event = bpf_map_lookup_elem(&report_map, &key);
	if (!event)
		return; // 理论上不会发生

	// 刚重启 tick: 只做一次 soft_ts 刷新，避免把停 tick 期间累计的时间视为 stall
	if (ts->restarting_tick) {
		ts->restarting_tick = 0;
		ts->soft_ts	    = bpf_ktime_get_ns();
		return;
	}

	now   = bpf_ktime_get_ns();
	delta = now - ts->soft_ts;

	// 超过阈值: 采集当前任务信息与内核栈 (bpf_get_stack flags=0 -> 采集内核栈)
	if (delta >= softirq_thresh) {
		event->now       = now;
		event->stall_time = delta;
		__builtin_memset(event->comm, 0, sizeof(event->comm));
		bpf_get_current_comm(&event->comm, sizeof(event->comm));
		event->pid = (u32)bpf_get_current_pid_tgid();
		event->cpu = bpf_get_smp_processor_id();
		event->stack_size =
		    bpf_get_stack(ctx, event->stack, sizeof(event->stack), 0);

		// 输出到 perf event buffer，用户态消费解析 stall 栈根因
		bpf_perf_event_output(ctx, &irqoff_event_map,
				      COMPAT_BPF_F_CURRENT_CPU, event,
				      sizeof(struct report_event));
	}

	// 更新基准时间戳
	ts->soft_ts = now;
}

// tracepoint: timer/tick_stop
// 触发: NOHZ 机制停掉周期性 tick 后
// 若成功并且 dependency=NONE，标记 stop 跟踪，避免在停止期间累积的时间被误判为 stall
SEC("tracepoint/timer/tick_stop")
void probe_tick_stop(struct trace_event_raw_tick_stop *ctx)
{
	struct timer_softirq_run_ts *ts;
	int key = 0;

	ts = bpf_map_lookup_elem(&timerts_map, &key);
	if (!ts)
		return;

	if (ctx->success == 1 && ctx->dependency == TICK_DEP_MASK_NONE) {
		ts->start_trace = 0;
	}
}

// kprobe: tick_nohz_restart_sched_tick
// 触发: CPU 退出 NOHZ 停 tick 状态，恢复调度 tick
// 动作: 重新开启跟踪窗口 (start_trace=1)，标记 restarting_tick=1 (下一次 account_process_tick 只重置 soft_ts)
SEC("kprobe/tick_nohz_restart_sched_tick")
void probe_tick_nohz_restart_sched_tick(struct pt_regs *ctx)
{
	struct timer_softirq_run_ts *ts;
	int key = 0;
	u64 now;

	ts = bpf_map_lookup_elem(&timerts_map, &key);
	if (!ts)
		return;

	now = bpf_ktime_get_ns();

	ts->soft_ts	    = now;
	ts->start_trace    = 1;
	ts->restarting_tick = 1;
}
