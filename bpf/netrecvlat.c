// Measure RX latency of TCP IPv4 packets at several receive path stages
// using skb->tstamp (software timestamp) and output via perf events.
// Stages: netif_receive_skb (netif), tcp_v4_rcv (TCP stack), skb_copy_datagram_iovec (copy to user).

// go:build ignore
// https://mp.weixin.qq.com/s/W20R4pAJauZ0MW9r4cQ9pg

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"
#include "bpf_ratelimit.h"
#include "vmlinux_net.h"

// TODO
// 例以 ARRAY map 为例
// 不再通过 const rewrite 传 mono_wall_offset（仍可对 to_netif 等保持原写法，或一起改为 map）。
// 加载后写入初始偏移: id := b.MapIDByName("mono_wall_offset_map") key := uint32(0) val := estMonoWallOffset()
// 通过 WriteMapItems 写 (key=0,value=val)
volatile const long long mono_wall_offset = 0;
// Latency thresholds (ns); only report events exceeding each stage's limit.
//         ToNetIf = 5 # ms, from driver to a core recv
//         ToTCPV4 = 10 # ms, from driver to TCP recv, contains ToNetIf
//         ToUserCopy = 115 # ms, from driver to user recv, contains ToNetIf + ToUserCopy
volatile const long long to_netif	  = 5 * 1000 * 1000;   // 5ms: time from NIC to netif_receive_skb
volatile const long long to_tcpv4	  = 10 * 1000 * 1000;  // 10ms: time until tcp_v4_rcv
volatile const long long to_user_copy	  = 115 * 1000 * 1000; // 115ms: time until userspace copy

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

BPF_RATELIMIT(rate, 1, 100);

struct perf_event_t {
	// Basic task / connection & latency metadata exported to user space.
	char comm[COMPAT_TASK_COMM_LEN];
	u64 latency;
	u64 tgid_pid;
	u64 pkt_len;
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u32 seq;
	u32 ack_seq;
	u8 state;
	u8 where;
};

enum skb_rcv_where {
	TO_NETIF_RCV,
	TO_TCPV4_RCV,
	TO_USER_COPY,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} net_recv_lat_event_map SEC(".maps");

struct mix {
	// Bundles minimal data passed to fill_and_output_event.
	struct iphdr *ip_hdr;
	u64 lat;   // computed latency
	u8 state;  // TCP state (if available)
	u8 where;  // stage identifier
};

static inline u64 delta_now_skb_tstamp(struct sk_buff *skb)
{
	// Return delta between now (mono + offset) and skb timestamp; 0 means unusable (skip).
	u64 tstamp = BPF_CORE_READ(skb, tstamp);
	// although the skb->tstamp record is opened in user space by
	// SOF_TIMESTAMPING_RX_SOFTWARE, it is still 0 in the following cases:
	// unix recv, netlink recv, few virtual dev(e.g. tun dev, napi dsabled)
	if (!tstamp)
		return 0;

	return bpf_ktime_get_ns() + mono_wall_offset - tstamp;
}

static inline u8 get_state(struct sk_buff *skb)
{
	return BPF_CORE_READ(skb, sk, __sk_common.skc_state);
}

static inline void
fill_and_output_event(void *ctx, struct sk_buff *skb, struct mix *_mix)
{
	// Build perf_event_t and emit if ratelimit allows.
	struct perf_event_t event = {};
	struct tcphdr tcp_hdr;

	// ratelimit
	if (bpf_ratelimited(&rate))
		return;

	if (likely(_mix->where == TO_USER_COPY)) {
		event.tgid_pid = bpf_get_current_pid_tgid();
		bpf_get_current_comm(&event.comm, sizeof(event.comm));
	}

	bpf_probe_read(&tcp_hdr, sizeof(tcp_hdr), skb_transport_header(skb));
	event.latency = _mix->lat;
	event.saddr   = _mix->ip_hdr->saddr;
	event.daddr   = _mix->ip_hdr->daddr;
	event.sport   = tcp_hdr.source;
	event.dport   = tcp_hdr.dest;
	event.seq     = tcp_hdr.seq;
	event.ack_seq = tcp_hdr.ack_seq;
	event.pkt_len = BPF_CORE_READ(skb, len);
	event.state   = _mix->state;
	event.where   = _mix->where;

	bpf_perf_event_output(ctx, &net_recv_lat_event_map,
			      COMPAT_BPF_F_CURRENT_CPU, &event,
			      sizeof(struct perf_event_t));
}

SEC("tracepoint/net/netif_receive_skb")
int netif_receive_skb_prog(struct trace_event_raw_net_dev_template *args)
{
	// Stage 1: packet just entered netif_receive_skb (earliest softirq context).
	// 近似计算驱动、软中断的延迟: ts1 - ts0
	struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
	struct iphdr ip_hdr;
	u64 delta;

	if (unlikely(BPF_CORE_READ(skb, protocol) !=
		     bpf_ntohs(ETH_P_IP))) // IPv4
		return 0;

	bpf_probe_read(&ip_hdr, sizeof(ip_hdr), skb_network_header(skb));
	if (ip_hdr.protocol != IPPROTO_TCP)
		return 0;

	delta = delta_now_skb_tstamp(skb);
	if (delta < to_netif)
		return 0;

	fill_and_output_event(args, skb,
			      &(struct mix){&ip_hdr, delta, 0, TO_NETIF_RCV});

	return 0;
}

SEC("kprobe/tcp_v4_rcv")
int tcp_v4_rcv_prog(struct pt_regs *ctx)
{
	// Stage 2: TCP layer processing (kprobe on tcp_v4_rcv).
	// 协议栈延迟：ts2 - ts0
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1_CORE(ctx);
	struct iphdr ip_hdr;
	u64 delta;

	delta = delta_now_skb_tstamp(skb);
	if (delta < to_tcpv4)
		return 0;

	bpf_probe_read(&ip_hdr, sizeof(ip_hdr), skb_network_header(skb));
	fill_and_output_event(
	    ctx, skb,
	    &(struct mix){&ip_hdr, delta, get_state(skb), TO_TCPV4_RCV});

	return 0;
}

SEC("tracepoint/skb/skb_copy_datagram_iovec")
int skb_copy_datagram_iovec_prog(
    struct trace_event_raw_skb_copy_datagram_iovec *args)
{
	// Stage 3: Data copied to userspace (recv path) when iovec copy happens.
	// 用户主动取包延迟：ts3 - ts0
	struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
	struct iphdr ip_hdr;
	u64 delta;

	if (unlikely(BPF_CORE_READ(skb, protocol) != bpf_ntohs(ETH_P_IP)))
		return 0;

	bpf_probe_read(&ip_hdr, sizeof(ip_hdr), skb_network_header(skb));
	if (ip_hdr.protocol != IPPROTO_TCP)
		return 0;

	delta = delta_now_skb_tstamp(skb);
	if (delta < to_user_copy)
		return 0;

	fill_and_output_event(
	    args, skb,
	    &(struct mix){&ip_hdr, delta, get_state(skb), TO_USER_COPY});

	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
