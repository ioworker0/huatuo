#include "vmlinux.h"
#include "bpf_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define DNAME_INLINE_LEN 64
#define PAGE_SIZE 4096

// 设备过滤器配置，用于只监控指定的块设备
volatile const u32 FILTER_DEVS[16] = {};
volatile const u32 FILTER_DEV_COUNT = 0;
// IO 调度延迟阈值（纳秒），超过此值才上报
volatile const u64 FILTER_EVENT_TIMEOUT = 100000000;

// 检查设备是否应该被处理
// 返回 1 表示处理，返回 0 表示过滤
/*
 * Check if device should be filtered
 * Returns 1 if device should be processed, 0 if should be filtered out
 */
static __always_inline int should_process_device(u32 dev)
{
	if (FILTER_DEV_COUNT == 0)
		return 1;

	for (int i = 0; i < FILTER_DEV_COUNT && i < 16; i++)
		if (FILTER_DEVS[i] == dev)
			return 1;

	return 0;
}

// 延迟统计信息
struct latency_info {
	u64 cnt;       // IO 计数
	u64 max_d2c;   // 最大设备到完成延迟
	u64 sum_d2c;   // 累计设备到完成延迟
	u64 max_q2c;   // 最大队列到完成延迟
	u64 sum_q2c;   // 累计队列到完成延迟
};

// IO 源 Map 的 key：用于聚合同一进程/文件/设备的 IO
struct io_key {
	u32 pid;      // 进程 PID
	u32 dev;      // 设备号
	u64 inode;    // 文件 inode
};

// IO 起始信息 Map 的 key：用于匹配 issue 和 done
struct hash_key {
	dev_t dev;       // 设备号
	u32 _pad;
	sector_t sector; // 扇区号
};

// IO 起始信息：issue 阶段记录的临时信息
struct io_start_info {
	u64 inode;                  // 文件 inode
	u32 pid;                    // 进程 PID
	u32 dev;                    // 设备号
	u64 data_len;               // IO 数据长度
	struct blkcg_gq *bi_blkg;   // block cgroup 指针
	char comm[COMPAT_TASK_COMM_LEN]; // 进程名
};

// IO 数据统计：聚合后的完整 IO 信息
struct io_data {
	u32 tgid;                   // 线程组 ID（进程组）
	u32 pid;                    // 进程 PID
	u32 dev;                    // 设备号
	u32 flag;                   // IOCB 标志（如直接 IO）
	u64 fs_write_bytes;         // 文件系统写入字节数
	u64 fs_read_bytes;          // 文件系统读取字节数
	u64 block_write_bytes;      // 块设备写入字节数
	u64 block_read_bytes;       // 块设备读取字节数
	u64 inode;                  // 文件 inode
	u64 blkcg_gq;               // block cgroup
	struct latency_info latency;// 延迟统计
	char comm[COMPAT_TASK_COMM_LEN]; // 进程名
	char filename[DNAME_INLINE_LEN]; // 文件名
	char d1name[DNAME_INLINE_LEN];   // 父目录名
	char d2name[DNAME_INLINE_LEN];   // 爷目录名
	char d3name[DNAME_INLINE_LEN];   // 曾祖目录名
};

// IO 源统计 Map：按 (pid, dev, inode) 聚合 IO 数据
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__uint(key_size, sizeof(struct io_key));
	__uint(value_size, sizeof(struct io_data));
} io_source_map SEC(".maps");

// IO 起始信息 Map：临时存储 issue 阶段的信息，等待 done 时匹配
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__uint(key_size, sizeof(struct hash_key));
	__uint(value_size, sizeof(struct io_start_info));
} start_info_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u64));
} request_struct_map SEC(".maps");


#define REQ_OP_BITS	8
#define REQ_OP_MASK	((1 << REQ_OP_BITS) - 1)
#define REQ_META	(1ULL << __REQ_META)

// 判断是否为写请求
static __always_inline int is_write_request(u32 cmd_flags)
{
	return (cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE;
}

// 兼容不同内核版本的 request_queue 结构
struct request_queue___new {
	struct gendisk *disk;
};

// 兼容不同内核版本的 block_device 结构
struct block_device___new {
	dev_t bd_dev;
};

// 兼容不同内核版本的磁盘设备获取
/*
 * compatible with different kernel versions of disk device acquisition
 */
static __always_inline struct gendisk *get_request_disk(struct request *req)
{
	if (bpf_core_field_exists(req->rq_disk)) {
		return BPF_CORE_READ(req, rq_disk);
	} else {
		struct request_queue___new *q;

		q = (struct request_queue___new *)BPF_CORE_READ(req, q);
		return BPF_CORE_READ(q, disk);
	}
}

// 兼容不同内核版本的分区号获取
/*
 * compatible with different kernel versions of partition number acquisition
 */
static __always_inline int get_partition_number(struct request *req)
{
	void *part = BPF_CORE_READ(req, part);

	if (bpf_core_field_exists(((struct hd_struct *)part)->partno)) {
		return BPF_CORE_READ((struct hd_struct *)part, partno);
	} else {
		struct block_device___new *new_part;
		int partno;

		new_part = (struct block_device___new *)part;
		partno = BPF_CORE_READ(new_part, bd_dev);
		return partno & 0xff;
	}
}

// 块层 QoS issue 钩子：IO 请求提交到块设备队列时触发
// 用于记录 IO 请求的起始信息（设备、inode、进程等）
SEC("kprobe/rq_qos_issue")
int bpf_rq_qos_issue(struct pt_regs *ctx)
{
	struct request *req = (struct request *)PT_REGS_PARM2(ctx);
	struct hash_key key = {};
	struct io_start_info info = {};
    struct bio *bio;
	struct inode *inode;
	struct gendisk *disk;
	u32 cmd_flags;
    int partno;
	int devn[2];

	bio = BPF_CORE_READ(req, bio);

	// 过滤元数据请求，只关注数据 IO
	cmd_flags = BPF_CORE_READ(req, cmd_flags);
	if (cmd_flags & REQ_META)
		return 0;

	// 获取磁盘设备号和分区号
	disk = get_request_disk(req);
	/* gendisk.major, gendisk.first_minor */
	if (bpf_probe_read(devn, sizeof(devn), disk))
		return -1;

	// 构造设备号：格式为 (major & 0xfff) << 20 | (minor + partno)
	partno = get_partition_number(req);
	key.dev = (devn[0] & 0xfff) << 20 | (devn[1] & 0xff) + partno;
	key.sector = BPF_CORE_READ(req, __sector);

	// 检查是否需要过滤该设备
	if (!should_process_device(key.dev))
		return 0;

	// 提取 inode 信息，用于识别文件
	inode = BPF_CORE_READ(bio, bi_io_vec, bv_page, mapping, host);
	info.inode = BPF_CORE_READ(inode, i_ino);
	if (info.inode == 0)
		info.dev = key.dev;  // 直接 IO，使用块设备号
	else
		info.dev = BPF_CORE_READ(inode, i_sb, s_dev);  // 文件 IO，使用文件系统设备号

	// 记录进程和 IO 信息
	info.pid = bpf_get_current_pid_tgid() >> 32;
	info.bi_blkg = BPF_CORE_READ(bio, bi_blkg);
	info.data_len = BPF_CORE_READ(req, __data_len);
	bpf_get_current_comm(info.comm, COMPAT_TASK_COMM_LEN);

	// 保存到 start_info_map，等待 done 时匹配
	bpf_map_update_elem(&start_info_map, &key, &info, COMPAT_BPF_ANY);

	return 0;
}

// 块层 QoS done 钩子：IO 请求完成时触发
// 用于计算延迟和统计 IO 读写字节数
SEC("kprobe/rq_qos_done")
int bpf_rq_qos_done(struct pt_regs *ctx)
{
	struct request *req = (struct request *)PT_REGS_PARM2(ctx);
	struct io_start_info *info = NULL;
	struct hash_key info_key = {};
	struct io_key io_key = {};
	struct io_data data = {};
	struct io_data *entry;
    struct gendisk *disk;
    u32 cmd_flags;
    int partno;
	int devn[2];
	u64 now;

	// 获取设备号，用于查找 start_info_map 中的对应记录
	disk = get_request_disk(req);
	/* gendisk.major, gendisk.first_minor */
	if (bpf_probe_read(devn, sizeof(devn), disk))
		return -1;

	partno = get_partition_number(req);
	info_key.dev = (devn[0] & 0xfff) << 20 | (devn[1] & 0xff) + partno;
	info_key.sector = BPF_CORE_READ(req, __sector);

	if (!should_process_device(info_key.dev))
		return 0;

	// 查找 issue 阶段保存的起始信息
	info = bpf_map_lookup_elem(&start_info_map, &info_key);
	if (!info)
		return 0;

	// 构造 io_source_map 的 key
	io_key.dev = info->dev;
	io_key.inode = info->inode;
	/* for direct IO, set pid value in key */
	if (io_key.inode == 0)
		io_key.pid = info->pid;

	// 查找或创建 io_source_map 条目
	entry = bpf_map_lookup_elem(&io_source_map, &io_key);
	if (!entry)
		entry = &data;

	// 根据 REQ_OP 判断读写方向，累加字节数
	cmd_flags = BPF_CORE_READ(req, cmd_flags);
	if (is_write_request(cmd_flags)) {
		entry->block_write_bytes += info->data_len;
	} else if ((cmd_flags & REQ_OP_MASK) == REQ_OP_READ) {
		entry->block_read_bytes += info->data_len;
	} else {
		bpf_map_delete_elem(&start_info_map, &info_key);
		return 0;
	}

	// 计算并累加延迟：q2c (queue to complete) 和 d2c (device to complete)
	now = bpf_ktime_get_ns();
	entry->latency.sum_q2c += now - BPF_CORE_READ(req, start_time_ns);
	entry->latency.sum_d2c += now - BPF_CORE_READ(req, io_start_time_ns);
	entry->latency.cnt++;

	// 如果是新条目，初始化其他字段并保存到 map
	if (entry == &data) {
		entry->blkcg_gq = (u64)info->bi_blkg;
		entry->pid = info->pid;
		entry->dev = info->dev;
		entry->inode = info->inode;
		bpf_probe_read_str(entry->comm, COMPAT_TASK_COMM_LEN,
				   info->comm);
		bpf_map_update_elem(&io_source_map, &io_key, &data,
				    COMPAT_BPF_ANY);
	}
	// 删除 start_info_map 中的临时记录
	bpf_map_delete_elem(&start_info_map, &info_key);

	return 0;
}


// 初始化 io_data 的进程和文件路径信息
// 提取文件名和父目录名（最多3级）
static __always_inline  void init_io_data(struct io_data *entry, struct dentry *root_dentry,
			  struct dentry *dentry, struct inode *inode)
{
	u64 t = bpf_get_current_pid_tgid();

	// 提取进程 PID 和 TGID
	entry->pid = t >> 32;
	entry->tgid = t & 0xffffffff;

	// 读取进程名
	bpf_get_current_comm(entry->comm, COMPAT_TASK_COMM_LEN);

	// 提取文件名和3级父目录名，用于构建文件路径
	bpf_probe_read_str(entry->filename, DNAME_INLINE_LEN,
			   BPF_CORE_READ(dentry, d_name.name));

	dentry = BPF_CORE_READ(dentry, d_parent);
	bpf_probe_read_str(entry->d1name, DNAME_INLINE_LEN,
			   BPF_CORE_READ(dentry, d_name.name));

	dentry = BPF_CORE_READ(dentry, d_parent);
	bpf_probe_read_str(entry->d2name, DNAME_INLINE_LEN,
			   BPF_CORE_READ(dentry, d_name.name));

	dentry = BPF_CORE_READ(dentry, d_parent);
	bpf_probe_read_str(entry->d3name, DNAME_INLINE_LEN,
			   BPF_CORE_READ(dentry, d_name.name));
}

struct iov_iter___new {
	bool data_source;
} __attribute__((preserve_access_index));

// 文件系统读写通用处理函数
// 追踪文件的读写操作，统计文件系统层面的 IO
static __always_inline  int bpf_file_read_write(struct pt_regs *ctx)
{
	struct kiocb *iocb = (struct kiocb *)PT_REGS_PARM1(ctx);
	struct io_data data = {};
	struct io_data *entry = NULL;
	struct dentry *dentry;
	struct dentry *root_dentry;
	struct inode *inode;
	struct io_key key = {};
	struct iov_iter *from;
	size_t count;
	unsigned int type;

	// 从 kiocb 中提取 inode 和设备号
	inode = BPF_CORE_READ(iocb, ki_filp, f_inode);
	key.inode = BPF_CORE_READ(inode, i_ino);
	key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

	if (!should_process_device(key.dev))
		return 0;

	entry = bpf_map_lookup_elem(&io_source_map, &key);
	if (!entry)
		entry = &data;

	// 首次访问时，初始化文件路径信息
	dentry = BPF_CORE_READ(iocb, ki_filp, f_path.dentry);
	root_dentry = BPF_CORE_READ(iocb, ki_filp, f_path.mnt, mnt_root);
	if (entry->tgid == 0) {
		init_io_data(entry, root_dentry, dentry, inode);
		entry->dev = key.dev;
		entry->inode = key.inode;
	}

	// 获取读写字节数
	from = (struct iov_iter *)PT_REGS_PARM2(ctx);
	count = BPF_CORE_READ(from, count);

	// 兼容不同内核版本的 iov_iter 结构
	if (bpf_core_field_exists(from->type)) {
		type = BPF_CORE_READ(from, type);
	} else {
		struct iov_iter___new *from_new;

		from_new = (struct iov_iter___new *)from;
		type = BPF_CORE_READ(from_new, data_source);
	}

	// 判断读写方向并累加字节数
	type = type & 0x1;
	if (type) /* 0: read, 1: write */
		entry->fs_write_bytes += count;
	else
		entry->fs_read_bytes += count;

	// 保存 IOCB 标志（如是否为直接 IO）
	entry->flag = BPF_CORE_READ(iocb, ki_flags);
	if (entry == &data)
		bpf_map_update_elem(&io_source_map, &key, &data, COMPAT_BPF_ANY);

	return 0;
}

// 文件读迭代器钩子（ext4/xfs）
SEC("kprobe/anyfs_file_read_iter")
int bpf_anyfs_file_read_iter(struct pt_regs *ctx)
{
	return bpf_file_read_write(ctx);
}

// 文件写迭代器钩子（ext4/xfs）
SEC("kprobe/anyfs_file_write_iter")
int bpf_anyfs_file_write_iter(struct pt_regs *ctx)
{
	return bpf_file_read_write(ctx);
}

// 页面写回处理（mmap 写入触发）
static __always_inline int bpf_filemap_page_mkwrite(struct pt_regs *ctx)
{
	struct vm_fault *vm = (struct vm_fault *)PT_REGS_PARM1(ctx);
	struct vm_area_struct *vma = BPF_CORE_READ(vm, vma);
    struct io_data *entry = NULL;
    struct io_data data = {};
	struct io_key key = {};
	struct inode *inode;

	inode = BPF_CORE_READ(vma, vm_file, f_inode);
	key.inode = BPF_CORE_READ(inode, i_ino);
	key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

	if (!should_process_device(key.dev))
		return 0;

	entry = bpf_map_lookup_elem(&io_source_map, &key);
	if (!entry)
		entry = &data;

	if (entry->tgid == 0) {
		struct dentry *dentry;
		struct dentry *root_dentry;

		dentry = BPF_CORE_READ(vma, vm_file, f_path.dentry);
		root_dentry = BPF_CORE_READ(vma, vm_file, f_path.mnt, mnt_root);
		init_io_data(entry, root_dentry, dentry, inode);
		entry->dev = key.dev;
		entry->inode = key.inode;
	}

	// mmap 写入按页计算，每次增加 PAGE_SIZE
	entry->fs_write_bytes += PAGE_SIZE;
	if (entry == &data)
		bpf_map_update_elem(&io_source_map, &key, &data, COMPAT_BPF_ANY);

	return 0;
}

// 页面写回钩子（ext4/xfs）
SEC("kprobe/anyfs_filemap_page_mkwrite")
int bpf_anyfs_filemap_page_mkwrite(struct pt_regs *ctx)
{
	return bpf_filemap_page_mkwrite(ctx);
}

// 页面错误处理（mmap 读取触发）
SEC("kprobe/filemap_fault")
int bpf_filemap_fault(struct pt_regs *ctx)
{
	struct vm_fault *vm = (struct vm_fault *)PT_REGS_PARM1(ctx);
	struct vm_area_struct *vma = BPF_CORE_READ(vm, vma);
    struct io_data *entry = NULL;
    struct io_data data = {};
	struct io_key key = {};
	struct inode *inode;

	inode = BPF_CORE_READ(vma, vm_file, f_inode);
	key.inode = BPF_CORE_READ(inode, i_ino);
	key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

	if (!should_process_device(key.dev))
		return 0;

	entry = bpf_map_lookup_elem(&io_source_map, &key);
	if (!entry)
		entry = &data;

	if (entry->tgid == 0) {
		struct dentry *dentry;
		struct dentry *root_dentry;

		dentry = BPF_CORE_READ(vma, vm_file, f_path.dentry);
		root_dentry = BPF_CORE_READ(vma, vm_file, f_path.mnt, mnt_root);
		init_io_data(entry, root_dentry, dentry, inode);
		entry->dev = key.dev;
		entry->inode = key.inode;
	}
	// mmap 读取按页计算，每次增加 PAGE_SIZE
	entry->fs_read_bytes += PAGE_SIZE;

	if (entry == &data)
		bpf_map_update_elem(&io_source_map, &key, &data, COMPAT_BPF_ANY);

	return 0;
}

struct iodelay_entry {
	u64 stack[PERF_MIN_STACK_DEPTH];
	u64 ts;
	u64 cost;
	int stack_size;
	u32 pid;
	u32 tid;
	u32 cpu;
	char comm[COMPAT_TASK_COMM_LEN];
};

// IO 调度堆栈 Map：存储 io_schedule 的堆栈和时间戳信息
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct iodelay_entry));
	__uint(max_entries, 128);
} io_schedule_stack SEC(".maps");

// IO 延迟事件 perf buffer：将超过阈值的延迟事件发送到用户空间
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} iodelay_perf_events SEC(".maps");

// IO 调度延迟事件结构
struct iodelay_entry {
	u64 stack[PERF_MIN_STACK_DEPTH];  // 内核堆栈
	u64 ts;                            // 开始时间戳
	u64 cost;                          // 延迟时间（纳秒）
	int stack_size;                    // 堆栈深度
	u32 pid;                           // 进程 PID
	u32 tid;                           // 线程 TID
	u32 cpu;                           // CPU 编号
	char comm[COMPAT_TASK_COMM_LEN];   // 进程名
};

// 检测 io_schedule 开始
// 记录时间戳和堆栈信息，等待返回时计算延迟
static __always_inline  int detect_io_schedule(struct pt_regs *ctx)
{
    struct iodelay_entry entry = {};
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id & 0xffffffff;

	// 记录开始时间和进程信息
	entry.ts = bpf_ktime_get_ns();
	bpf_get_current_comm(entry.comm, COMPAT_TASK_COMM_LEN);

	// 捕获内核堆栈，用于延迟分析
	entry.stack_size = bpf_get_stack(ctx, entry.stack,
					 sizeof(entry.stack), 0);
	bpf_map_update_elem(&io_schedule_stack, &pid, &entry, COMPAT_BPF_ANY);

	return 0;
}

SEC("kprobe/io_schedule")
int bpf_io_schedule(struct pt_regs *ctx)
{
	return detect_io_schedule(ctx);
}

SEC("kprobe/io_schedule_timeout")
int bpf_io_schedule_timeout(struct pt_regs *ctx)
{
	return detect_io_schedule(ctx);
}

// 检测 io_schedule 返回
// 计算延迟，如果超过阈值则发送到用户空间
static __always_inline  int detect_io_schedule_return(struct pt_regs *ctx)
{
	struct iodelay_entry *entry;
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id & 0xffffffff;
	u64 now = bpf_ktime_get_ns();

	// 查找对应的开始记录
	entry = bpf_map_lookup_elem(&io_schedule_stack, &pid);
	if (!entry)
		return 0;

	// 如果延迟超过阈值，发送到用户空间
	if (now - entry->ts > FILTER_EVENT_TIMEOUT) {
		entry->pid = (id >> 32) & 0xffffffff;
		entry->tid = pid;
		entry->cost = now - entry->ts;
		bpf_perf_event_output(ctx, &iodelay_perf_events,
				      COMPAT_BPF_F_CURRENT_CPU, entry,
				      sizeof(struct iodelay_entry));
	}
	// 清理临时记录
	bpf_map_delete_elem(&io_schedule_stack, &pid);

	return 0;
}

SEC("kretprobe/io_schedule")
int bpf_return_io_schedule(struct pt_regs *ctx)
{
	return detect_io_schedule_return(ctx);
}

SEC("kretprobe/io_schedule_timeout")
int bpf_return_io_schedule_timeout(struct pt_regs *ctx)
{
	return detect_io_schedule_return(ctx);
}
