#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/*
 * 程序目的 (Overview):
 * 在读取 sysfs 属性 carrier_down_count_show 时（该 show 函数被调用表示查询网卡 carrier down 相关统计），
 * 采样当前 net_device 的 rx_dropped 计数并存入 BPF 哈希表，供用户态后续聚合/展示。
 *
 * 说明:
 * 1. hook 点为 kprobe/carrier_down_count_show —— 这是一个内核中 sysfs 入口的 show 回调，调用频率由用户空间读该文件决定；
 *    因此此采样是“被动”的，适合作为低频、按需的刷新方式。
 * 2. netdev->rx_dropped (atomic64_t 类型内部的 counter 字段) 统计的是驱动或协议栈丢弃的接收包数量（内存不足、非法报文等）。
 * 3. 当前只保存 rx_dropped，可以扩展存储 tx_dropped、rx_errors、tx_errors 等。
 * 4. 哈希表大小设为 64，假设活跃网卡数量较少；若需要支持更多逻辑设备/虚拟设备，可增大或改用 LRU_HASH。
 * 5. 使用 BPF_CORE_READ + CO-RE 保持对不同内核版本的字段偏移兼容。
 * 6. container_of(dev, struct net_device, dev) 从 struct device 指针还原 struct net_device 指针；内核中 net_device 嵌入了 dev 成员。
 * 7. 读 rx_dropped.counter 并非原子获取（只是当前瞬间值），但用于统计面板通常足够；若需强一致可考虑附加时间戳或多次采样。
 */

/*
 * Hash map for tracking network device packet drop statistics
 * Key:   Network interface index (ifindex)
 * Value: Received drop count (rx_dropped)
 *
 * 扩展建议:
 * - 若要对时间维度做增量分析，可改成存结构 {last, now, ts}。
 * - 若担心并发/内存占用，可限制只采集指定 ifindex（在用户态侧过滤）。
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);   // 预估网卡数量上限；根据实际部署环境适当调整
	__type(key, u32);           // ifindex 唯一标识网卡
	__type(value, u64);         // 当前采样的 rx_dropped 计数（snapshot）
} rx_sw_dropped_stats SEC(".maps");

/*
 * kprobe/carrier_down_count_show - Track packet drop statistics when
 *                                  network device carrier state changes
 * @dev: Pointer to device structure (sysfs show 回调的参数)
 *
 * 触发流程:
 *   用户态读取对应 sysfs 节点 -> 内核调用 carrier_down_count_show -> 本 eBPF 函数执行 -> 更新哈希表快照。
 */
SEC("kprobe/carrier_down_count_show")
int BPF_KPROBE(carrier_down_count_show, struct device *dev)
{
	// 从 struct device 反推回 struct net_device：net_device 内嵌 dev 成员
	struct net_device *netdev = container_of(dev, struct net_device, dev);
	// 通过 CO-RE 读取 ifindex（网卡标识）
	u32 key = BPF_CORE_READ(netdev, ifindex);
	// 读取 rx_dropped 的内部 counter 字段 (atomic64_t)，这里只是获取当前瞬时值
	u64 value = BPF_CORE_READ(netdev, rx_dropped.counter);

	// 更新/插入快照；COMPAT_BPF_ANY 允许覆盖旧值
	bpf_map_update_elem(&rx_sw_dropped_stats, &key, &value, COMPAT_BPF_ANY);
	return 0;
}
