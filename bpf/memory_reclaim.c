#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"
#include "vmlinux_sched.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// 记录每个 memcg 发生 direct reclaim（通常发生在内存分配/charge 失败时，
// 任务主动进入内存回收路径）的计数。当前仅有一个指标，可后续扩展。
struct mem_cgroup_metric {
	/* direct reclaim 次数（前台/应用线程触发，而不是 kswapd 后台线程） */
	unsigned long directstall_count;
};

// 用哈希表记录：key = cgroup_subsys_state 指针(转成 unsigned long)，value = 该 memcg 的统计结构。
// 说明：这里 key 声明为 unsigned long，因此在查找/更新时应该使用“指针值”而不是“局部变量地址”。
// 下面 tracepoint 里保持现有写法，只增加注释，如需更严谨可改成：
//   unsigned long css = (unsigned long)mm_subsys;
//   valp = bpf_map_lookup_elem(&mem_cgroup_map, &css);
// 避免误把 &mm_subsys（局部变量地址）当作 key；若确认现网无问题可按需调整。
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, unsigned long);          // memcg 对应的 cgroup_subsys_state * 强转后的值
	__type(value, struct mem_cgroup_metric);
	__uint(max_entries, 10240);           // 支持的 memcg 数量上限
} mem_cgroup_map SEC(".maps");

// 关于 task->cgroups->subsys 与 memory_cgrp_id：
// 1) task->cgroups 指向 struct css_set，其中包含数组 subsys[]。
// 2) subsys[] 的每个元素是一个 struct cgroup_subsys_state * (css)，代表该任务在对应控制器上的 cgroup 状态。
// 3) memory_cgrp_id 是内核枚举 enum cgroup_subsys_id 中 memory 控制器的索引（在当前生成的 vmlinux_* 头文件里值为 4），
//    通过 BTF 导出，CO-RE 稳定访问，不需要硬编码数字。
// 4) subsys[memory_cgrp_id] 实际指向 struct mem_cgroup（其头部嵌入了 struct cgroup_subsys_state），可唯一标识一个 memcg。
// 5) 因此将该指针值（css 指针）当作 key，可以区分不同的 memory cgroup；释放事件里同样用此指针删除。
// 6) 注意当前实现用局部变量地址 &mm_subsys 作为哈希 key：若需更语义清晰，可改成 unsigned long css = (unsigned long)mm_subsys; 再用 &css。
SEC("tracepoint/vmscan/mm_vmscan_memcg_reclaim_begin")
int tracepoint_vmscan_mm_vmscan_memcg_reclaim_begin(struct pt_regs *ctx)
{
	struct cgroup_subsys_state *mm_subsys;  // 当前任务对应的 memory 子系统 css
	struct mem_cgroup_metric *valp;         // 指向已有统计项
	struct task_struct *task;

	// 获取当前任务 (current)
	task = (struct task_struct *)bpf_get_current_task();
	// 过滤掉 kswapd：kswapd 属于后台回收线程，不计入 direct reclaim
	if (BPF_CORE_READ(task, flags) & PF_KSWAPD)
		return 0;

	// 获取当前 task 所属 memcg 的 cgroup_subsys_state 指针
	mm_subsys = BPF_CORE_READ(task, cgroups, subsys[memory_cgrp_id]);
	// 注意：这里使用 &mm_subsys 作为 key（即局部变量地址）——通常期望 key 为指针值本身。
	// 如果发现统计不命中，可考虑改为：unsigned long css = (unsigned long)mm_subsys; 再传 &css。
	valp = bpf_map_lookup_elem(&mem_cgroup_map, &mm_subsys);
	if (!valp) {
		// 首次出现该 memcg：初始化 directstall_count=1
		struct mem_cgroup_metric new_metrics = {
			.directstall_count = 1,
		};
		bpf_map_update_elem(&mem_cgroup_map, &mm_subsys, &new_metrics,
				    COMPAT_BPF_ANY);
		return 0;
	}

	// 已存在则原子加 1；__sync_fetch_and_add 在 BPF 中被 clang 降级成内核 helper/原子指令
	__sync_fetch_and_add(&valp->directstall_count, 1);
	return 0;
}

// kprobe: mem_cgroup_css_released
// 当 memcg 的 css 生命周期结束（释放）时触发，及时删除 map 中的对应 key，避免泄漏/脏数据。
SEC("kprobe/mem_cgroup_css_released")
int kprobe_mem_cgroup_css_released(struct pt_regs *ctx)
{
	u64 css = PT_REGS_PARM1(ctx); // 参数 1: 被释放的 cgroup_subsys_state 指针
	bpf_map_delete_elem(&mem_cgroup_map, &css); // 清理统计数据
	return 0;
}
