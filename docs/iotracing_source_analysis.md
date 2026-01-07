# HUATUO iotracing：Linux 内核 IO 全栈观测深度解析

https://mp.weixin.qq.com/s/Kps4DamL6kG6zNqibUv6PQ

## 目录
- [产品概述](#产品概述)
- [用户痛点](#用户痛点)
- [解决方案](#解决方案)
- [基础用法](#基础用法)
- [高级用法](#高级用法)
- [生产环境案例](#生产环境案例)
- [技术原理与源码分析](#技术原理与源码分析)
- [总结](#总结)

---

## 产品概述

**iotracing** 是 HUATUO（华佗）项目推出的一款基于 eBPF 技术的 IO 全栈观测工具，专为解决 Linux 系统中 IO 性能问题定位困难而设计。它能够在不修改内核代码、不重启系统的情况下，实现对 IO 路径的全方位追踪。

### 核心能力

✅ **全栈追踪**：从文件系统层 → 块层 → 设备层，完整追踪 IO 生命周期
✅ **精准定位**：精确到进程、容器、文件、设备的 IO 归属
✅ **延迟分析**：提供 q2c（队列到完成）、d2c（设备到完成）等多维度延迟指标
✅ **自动触发**：结合 autotracing 框架，自动识别异常并启动追踪

---

## 用户痛点

### 典型故障场景

**场景描述**：深夜监控系统突然报警 - 磁盘 IOPS 爆表，磁盘利用率达到 100%！

业务影响：
- 数据库查询超时
- 用户请求失败率飙升
- 服务响应缓慢

### 传统工具的局限性

使用传统的 IO 工具（如 iotop、iostat、pidstat 等）排查时，常常遇到以下困境：

| 问题 | 传统工具 | 影响 |
|------|---------|------|
| **进程-文件关联缺失** | 能看到某个进程在触发 IO，却不知道具体读写哪个文件 | 无法精确定位数据源 |
| **磁盘-进程关联缺失** | 能看到磁盘疯狂写入，却不知道 IO 来自哪个业务进程 | 找不到元凶进程 |
| **回写归属不明** | 能看到内核线程刷脏页，却无法追踪到原始业务进程 | 责任归属不清 |
| **延迟信息缺失** | 能看到 IO 吞吐量，却不知道延迟情况 | 无法定位性能瓶颈 |
| **事后无法追溯** | 问题已恢复，现场已丢失，无法复现 | 根因分析困难 |

### 核心痛点

**不能全景分析"是谁在写"、"写到哪里"、"为什么慢"**

---

## 解决方案

### iotracing 的完整信息视图

iotracing 通过 eBPF 技术在内核关键路径上插桩，一步到位获取高 IO 的所有信息：

```
┌─────────────────────────────────────────────────────────────┐
│                    iotracing 追踪信息                        │
├─────────────────────────────────────────────────────────────┤
│  • 进程信息：PID、进程名、容器 hostname                      │
│  • 设备信息：设备号（major:minor）、磁盘名称                  │
│  • 文件信息：完整文件路径、inode 号                           │
│  • 延迟信息：q2c、d2c 延迟（微秒）                           │
│  • IO 类型：文件系统读写、块设备读写、mmap 读写              │
│  • 回写追踪：内核线程回写 → 原始业务进程                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 基础用法

### 1. 快速上手

运行 iotracing 工具（默认 8 秒采样周期）：

```bash
sudo ./iotracing --duration 8
```

**输出示例**：

```
PID      COMMAND              FS_READ FS_WRITE DISK_READ DISK_WRITE FILES
=======  ==================== ======= ======== ========= ========== ======
1234     mysql                5.2GB   1.8GB    5.1GB     1.7GB      156
5678     java_app             120MB   5.6GB    115MB     5.5GB      23
```

**解读**：
- `mysql` 进程是最大的 IO 消耗者
- 每秒读取 5.2GB、写入 1.8GB
- 操作了 156 个文件

### 2. 深入分析

工具还会输出每个进程的详细文件操作信息：

```
===========================================================================
PID: 1234     TOTAL_IO: R=5.2GB W=1.8GB     FILES: 156
COMMAND: mysql
-----------------------------------
DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE/INODE
8:0     3.2GB   800MB    3.1GB     780MB       q2c=450   d2c=380  /var/lib/mysql/ibdata1 (3456789)
8:0     1.5GB   600MB    1.4GB     590MB       q2c=520   d2c=410  /var/lib/mysql/ib_logfile0 (3456790)
8:0     500MB   400MB    480MB     390MB       q2c=380   d2c=320  /var/lib/mysql/table1.ibd (3456791)
```

**关键指标说明**：
- `DEVICE`：设备号（8:0 表示 /dev/sda）
- `FS_READ/WRITE`：文件系统层面的读写量
- `DISK_READ/WRITE`：块设备层面的实际读写量
- `q2c`：queue to complete，从进入队列到完成的延迟
- `d2c`：device to complete，从设备开始到完成的延迟

### 3. 容器环境支持

在容器化环境中，iotracing 能够识别 IO 所属容器：

```
PID      COMMAND              CONTAINER_HOSTNAME      FS_READ ...
=======  ==================== ==================== ======== ...
12345    nginx                web-server-001         50MB
12346    php-fpm              app-backend-002       120MB
```

**实现原理**：通过读取 `/proc/<pid>/cpuset` 和 `/proc/<pid>/mountinfo` 推断容器 ID 和名称。

### 4. 回写 IO 追踪

这是 iotracing 的核心能力之一！

**问题**：普通工具只能看到内核线程（如 `kworker/u8:0`）在刷脏页，无法定位到业务进程。

**iotracing 解决方案**：

```
PID      COMMAND              FS_WRITE DISK_WRITE FILES
=======  ==================== ======== ========== ======
12890    kworker/u8:0         0       2.5GB      45

===========================================================================
SOURCE PROCESS OF DIRTY PAGE WRITEBACK:
PID: 5678  COMMAND: mysqld  FILES: 45
---------------------------------------------------------------
DEVICE  FS_WRITE DISK_WRITE   LATENCY(μs)      FILE
8:0     1.5GB    1.4GB        q2c=420         /var/lib/mysql/temp.MYD
```

**解读**：虽然是由 `kworker` 执行的实际写入，但脏页是由 `mysqld` 进程产生的。

---

## 高级用法

### 自动触发机制

**问题场景**：
- 凌晨监控告警：磁盘 IO 突然飙升到 100%，持续 30 秒后恢复
- 业务影响：数据库查询超时，用户请求失败
- 排查困境：等你登录服务器，现场已消失

**autotracing + iotracing 自动化方案**：

在 `core/autotracing/iotracing.go` 中配置阈值：

```go
type IoThresholds struct {
    RbpsThreshold  uint64  // 读吞吐阈值（MB/s）
    WbpsThreshold  uint64  // 写吞吐阈值（MB/s）
    UtilThreshold  uint64  // 利用率阈值（%）
    AwaitThreshold uint64  // 延迟阈值（毫秒）
}
```

**工作流程**：

1. **监控阶段**：autotracing 持续监控 `/proc/diskstats`
2. **阈值检测**：检测到 IO 异常（如利用率 > 80%）
3. **自动触发**：启动 iotracing 采样 40 秒
4. **数据保存**：自动保存到存储后端，供事后分析

**触发条件示例**：

```go
// 检测到 IO 利用率持续高且吞吐量大
if (prev.IOutil > 80 && curr.IOutil > 80) &&
   (prev.ReadBps > 100*1024*1024 && curr.ReadBps > 100*1024*1024) {
    // 触发 iotracing
}
```

---

## 生产环境案例

### 真实故障：突增读请求导致性能下降

**背景**：
- 某在线服务服务器在 17:50 左右发生大量读磁盘请求
- 持续约 40 秒后恢复正常
- 期间数据库查询超时率飙升

**使用 iotracing 分析**：

```
17:50:23 触发条件：ioutil=87%, read_bps=350MB/s
启动 iotracing 采样 40 秒...

采样结果：
PID  COMMAND          DISK_READ  AWAIT    TOP FILES
823  python_app       320MB      45ms     /data/cache/*.idx (23 files)
```

**根因分析**：
- Python 应用的缓存预热脚本被误触发
- 大量读取索引文件导致磁盘利用率飙升
- `await` 延迟达到 45ms（平时 < 5ms）

**解决措施**：
- 调整缓存预热策略，改为限流模式
- 设置 IO 优先级，避免影响业务查询

---

## 技术原理与源码分析

### 输出数据来源与计算方式

iotracing 的输出包含多个字段，每个字段都来自特定的 BPF hook。理解数据来源对准确分析问题至关重要。

#### 输出示例与字段映射

##### 示例 1：进程级汇总输出

```
PID      COMMAND              FS_READ FS_WRITE DISK_READ DISK_WRITE FILES
=======  ==================== ======= ======== ========= ========== ======
1234     mysql                5.2GB   1.8GB    5.1GB     1.7GB      156
```

| 字段 | 数据来源 Hook | BPF 字段 | 计算方式 | 源码位置 |
|------|--------------|---------|---------|---------|
| **PID** | 所有 hooks | `info.pid` / `entry.pid` | `bpf_get_current_pid_tgid() >> 32` | 所有 BPF 程序 |
| **COMMAND** | 所有 hooks | `entry.comm[]` | `bpf_get_current_comm()` | 所有 BPF 程序 |
| **FS_READ** | `ext4/xfs_file_read_iter`<br>`filemap_fault` | `entry.fs_read_bytes` | **累加**每次读取的字节数 | `bpf/iotracing.c:377`<br>`bpf/iotracing.c:488` |
| **FS_WRITE** | `ext4/xfs_file_write_iter`<br>`ext4/xfs_page_mkwrite`<br>`xfs_filemap_page_mkwrite` | `entry.fs_write_bytes` | **累加**每次写入的字节数 | `bpf/iotracing.c:375`<br>`bpf/iotracing.c:441` |
| **DISK_READ** | `rq_qos_done` | `entry.block_read_bytes` | **累加**每次 IO 请求的 data_len | `bpf/iotracing.c:263` |
| **DISK_WRITE** | `rq_qos_done` | `entry.block_write_bytes` | **累加**每次 IO 请求的 data_len | `bpf/iotracing.c:261` |
| **FILES** | 文件系统 hooks | - | 统计不同的 inode 数量 | 用户空间计算 |

**关键计算**（用户空间）：
```go
// cmd/iotracing/iotracing.go:209-217
// 将字节转换为每秒速率（B/s）
rbps = data.FsReadBytes / durationSecond
wbps = data.FsWriteBytes / durationSecond
drbps = data.BlockReadBytes / durationSecond
dwbps = data.BlockWriteBytes / durationSecond
```

##### 示例 2：文件级详细输出

```
===========================================================================
PID: 1234     TOTAL_IO: R=5.2GB W=1.8GB     FILES: 156
COMMAND: mysql
-----------------------------------
DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE/INODE
8:0     3.2GB   800MB    3.1GB     780MB       q2c=450   d2c=380  /var/lib/mysql/ibdata1 (3456789)
```

**原始数据格式**（从 BPF map 导出）：
```
[8:0], fs_read=3200000000b/s, fs_write=800000000b/s,
 disk_read=3100000000b/s, disk_write=780000000b/s,
 q2c=450us, d2c=380us, inode=3456789, /var/lib/mysql/ibdata1
```

| 字段 | 数据来源 Hook | BPF 字段 | 计算方式 | 源码位置 |
|------|--------------|---------|---------|---------|
| **DEVICE** | `rq_qos_issue` | `key.dev` / `info.dev` | `(major & 0xfff) << 20 \| (minor + partno)` | `bpf/iotracing.c:183` |
| **FS_READ** | `ext4/xfs_file_read_iter`<br>`filemap_fault` | `entry.fs_read_bytes` | **累加** iov_iter count 或 PAGE_SIZE | `bpf/iotracing.c:377` |
| **FS_WRITE** | `ext4/xfs_file_write_iter`<br>`*_page_mkwrite` | `entry.fs_write_bytes` | **累加** iov_iter count 或 PAGE_SIZE | `bpf/iotracing.c:375` |
| **DISK_READ** | `rq_qos_done` | `entry.block_read_bytes` | **累加** `info->data_len` | `bpf/iotracing.c:263` |
| **DISK_WRITE** | `rq_qos_done` | `entry.block_write_bytes` | **累加** `info->data_len` | `bpf/iotracing.c:261` |
| **q2c** | `rq_qos_done` | `entry.latency.sum_q2c` | `(now - req->start_time_ns) / count / 1000` | `bpf/iotracing.c:271`<br>`cmd/iotracing/iotracing.go:225` |
| **d2c** | `rq_qos_done` | `entry.latency.sum_d2c` | `(now - req->io_start_time_ns) / count / 1000` | `bpf/iotracing.c:272`<br>`cmd/iotracing/iotracing.go:226` |
| **inode** | `rq_qos_issue` | `info.inode` | `BPF_CORE_READ(inode, i_ino)` | `bpf/iotracing.c:193` |
| **FILE** | `ext4/xfs_file_*_iter`<br>`filemap_fault`<br>`*_page_mkwrite` | `entry.filename/d1name/d2name/d3name` | 提取 dentry（最多 3 级目录） | `bpf/iotracing.c:308-321` |

**延迟计算详解**：

```c
// BPF 程序中累加纳秒级延迟（bpf/iotracing.c:269-273）
now = bpf_ktime_get_ns();
entry->latency.sum_q2c += now - BPF_CORE_READ(req, start_time_ns);
entry->latency.sum_d2c += now - BPF_CORE_READ(req, io_start_time_ns);
entry->latency.cnt++;
```

```go
// 用户空间转换为微秒并计算平均值（cmd/iotracing/iotracing.go:224-227）
if data.Latency.Count > 0 {
    q2c = data.Latency.SumQ2C / (data.Latency.Count * 1000)  // 纳秒 → 微秒
    d2c = data.Latency.SumD2C / (data.Latency.Count * 1000)
}
```

**示例计算**：
```
假设有 1000 次 IO 请求：
  SumQ2C = 450,000,000 纳秒
  SumD2C = 380,000,000 纳秒
  Count = 1000

计算：
  q2c = 450,000,000 / (1000 * 1000) = 450μs
  d2c = 380,000,000 / (1000 * 1000) = 380μs
```

##### 示例 3：回写 IO 追踪输出

**问题**：普通工具只能看到内核线程刷盘

```
PID      COMMAND              FS_WRITE DISK_WRITE FILES
=======  ==================== ======== ========== ======
12890    kworker/u8:0         0       2.5GB      45
```

**iotracing 的解决方案**：追溯到原始业务进程

```
===========================================================================
SOURCE PROCESS OF DIRTY PAGE WRITEBACK:
PID: 5678  COMMAND: mysqld  FILES: 45
---------------------------------------------------------------
DEVICE  FS_WRITE DISK_WRITE   LATENCY(μs)      FILE
8:0     1.5GB    1.4GB        q2c=420         /var/lib/mysql/temp.MYD
```

**工作原理**：

```
时间线：
  t0: mysqld 进程写文件
      └─ ext4_file_write_iter hook 触发
          ├─ 捕获：pid=5678, comm="mysqld"
          ├─ 捕获：文件="/var/lib/mysql/temp.MYD"
          ├─ 累加：fs_write_bytes += 1.5GB
          └─ 保存到 io_source_map[pid=5678, inode=...]

  t1: 数据写入页面缓存，标记为脏页

  t2: 内核线程 kworker 触发回写
      └─ rq_qos_issue/done hooks 触发
          ├─ 捕获：pid=12890 (kworker)
          ├─ 累加：block_write_bytes += 2.5GB
          └─ 关键：**通过 inode 找到原始进程**

  t3: 用户空间聚合
      └─ 从 io_source_map 读取
          ├─ 发现：inode=12345 关联两个进程
          ├─ kworker：只有 block_write_bytes（无 fs_write_bytes）
          ├─ mysqld：有 fs_write_bytes
          └─ 输出：SOURCE PROCESS = mysqld
```

**关键源码逻辑**：

```c
// bpf/iotracing.c:247-251
// 构造 io_source_map 的 key
io_key.dev = info->dev;
io_key.inode = info->inode;
if (io_key.inode == 0)
    io_key.pid = info->pid;  // 直接 IO，使用 block 层的 pid
// 否则不设置 pid，通过 inode 聚合所有进程
```

```go
// cmd/iotracing/iotracing.go:232-233
// 判断是否只有块层 IO（无文件系统层）
if data.Tgid == 0 {
    // 这说明只抓到了块层 IO，可能是 kworker
    // 需要显示实际产生 IO 的进程
}
```

**识别回写的标志**：
- `FS_WRITE = 0` 且 `DISK_WRITE > 0`：说明是回写 IO
- 显示 `SOURCE PROCESS`：通过 inode 关联找到原始进程

#### 块层 IO 如何关联到进程 PID？

**问题**：`rq_qos_done` hook 在 IO 完成时触发，此时可能是由 kworker 内核线程执行，如何知道是哪个进程发起的 IO？

**解决方案**：issue/done 配对机制

```
┌─────────────────────────────────────────────────────────────┐
│ issue/done 配对流程                                          │
└─────────────────────────────────────────────────────────────┘

步骤 1: rq_qos_issue（IO 提交时）
  ├─ 触发进程：业务进程（如 mysqld, pid=1234）
  ├─ 捕获信息：
  │   ├─ pid = 1234
  │   ├─ dev = 8:0
  │   ├─ sector = 12345
  │   ├─ inode = 3456789
  │   └─ data_len = 16384
  └─ 保存到 start_info_map[key=(dev=8:0, sector=12345)]
      └─ value = {pid=1234, inode=3456789, data_len=16384, ...}

步骤 2: [磁盘处理 IO...]

步骤 3: rq_qos_done（IO 完成时）
  ├─ 触发进程：可能是 kworker（不重要）
  ├─ 捕获信息：
  │   ├─ dev = 8:0
  │   └─ sector = 12345
  ├─ 从 start_info_map 查找：key=(dev=8:0, sector=12345)
  │   └─ 找到 issue 阶段保存的信息！
  │       ├─ pid = 1234  ← 关键：这是发起 IO 的进程
  │       ├─ inode = 3456789
  │       └─ data_len = 16384
  ├─ 计算：q2c = now - start_time_ns
  ├─ 更新到 io_source_map[key=(pid=1234, inode=3456789, dev=8:0)]
  │   └─ block_read_bytes += 16384
  │   └─ latency.sum_q2c += q2c
  └─ 删除 start_info_map 中的临时记录
```

**关键源码**：

```c
// bpf/iotracing.c:241-243
// rq_qos_done 中查找 issue 阶段保存的信息
info = bpf_map_lookup_elem(&start_info_map, &info_key);
if (!info)
    return 0;  // 没找到对应的 issue 记录，放弃

// 现在 info->pid 就是发起 IO 的进程 PID
// 即使当前执行的是 kworker，也能追溯到原始进程
```

**为什么能成功配对？**
- **唯一性**：(dev, sector) 唯一标识一个 IO 请求
- **持久性**：从 issue 到 done，(dev, sector) 不变
- **时间窗口**：IO 请求的生命周期内，start_info_map 中的记录不会过期

**实际场景示例**：

```
时刻 t0: mysqld (pid=1234) 调用 write(fd, buf, 16384)
  └─ ext4_file_write_iter hook
      └─ 保存：io_source_map[pid=1234, inode=...] = {fs_write_bytes += 16384}

时刻 t1: IO 请求进入块层
  └─ rq_qos_issue hook
      ├─ 捕获：pid=1234, dev=8:0, sector=50000
      └─ 保存：start_info_map[dev=8:0, sector=50000] = {pid=1234, ...}

时刻 t2: 数据写入页面缓存，标记为脏页

时刻 t3: kworker (pid=12890) 触发回写
  └─ rq_qos_issue hook (新的 IO 请求)
      ├─ 捕获：pid=12890, dev=8:0, sector=50001
      └─ 保存：start_info_map[dev=8:0, sector=50001] = {pid=12890, ...}

时刻 t4: kworker 执行实际的磁盘写入
  └─ rq_qos_done hook (对应 t1 的请求)
      ├─ 查找：start_info_map[dev=8:0, sector=50000]
      ├─ 找到：pid=1234 (mysqld)
      ├─ 更新：io_source_map[pid=1234, inode=...] = {block_write_bytes += 16384}
      └─ 删除：start_info_map[dev=8:0, sector=50000]

  └─ rq_qos_done hook (对应 t3 的请求)
      ├─ 查找：start_info_map[dev=8:0, sector=50001]
      ├─ 找到：pid=12890 (kworker)
      ├─ 发现：没有对应的 fs_write_bytes
      └─ 判断：这是回写 IO，需要追溯原始进程
```

**数据结构设计**：

```c
// bpf/iotracing.c:50-55
// start_info_map 的 key：用于 issue/done 配对
struct hash_key {
    dev_t dev;       // 设备号
    u32 _pad;
    sector_t sector; // 扇区号（唯一标识 IO 请求）
};

// bpf/iotracing.c:57-65
// start_info_map 的 value：issue 阶段捕获的信息
struct io_start_info {
    u64 inode;      // 文件 inode（用于关联文件系统 hook）
    u32 pid;        // 发起 IO 的进程 PID（关键！）
    u32 dev;        // 设备号
    u64 data_len;   // IO 大小
    ...
};
```

**为什么需要两阶段设计？**

```
单阶段设计（假设只使用 rq_qos_done）：
  ❌ 问题：rq_qos_done 触发时，可能是 kworker 执行
  ❌ 无法知道是谁发起的 IO

两阶段设计（issue + done）：
  ✅ rq_qos_issue：捕获发起进程的 PID
  ✅ rq_qos_done：通过 (dev, sector) 找到 issue 记录
  ✅ 结果：即使 kworker 执行，也能追溯到原始进程
```

**完整的数据流**：

```
进程级汇总（PID 维度）：
  io_source_map 的 key 包含 pid
  └─ key = {pid=1234, dev=8:0, inode=3456789}
  └─ 所有相同 (pid, dev, inode) 的 IO 都聚合到这个条目

文件级详情（inode 维度）：
  同一个 pid 可能操作多个文件
  └─ 条目 1: {pid=1234, dev=8:0, inode=3456789} → ibdata1
  └─ 条目 2: {pid=1234, dev=8:0, inode=3456790} → ib_logfile0
  └─ 用户空间按 pid 分组输出
```

#### 数据关联机制

**核心：通过 inode 号关联不同 hooks 的数据**

```
┌─────────────────────────────────────────────────────────────┐
│ io_source_map 的 Key 结构                                   │
├─────────────────────────────────────────────────────────────┤
│ struct io_key {                                             │
│     u32 pid;      // 进程 PID（直接 IO 时使用）              │
│     u32 dev;      // 设备号                                  │
│     u64 inode;    // 文件 inode                             │
│ };                                                          │
└─────────────────────────────────────────────────────────────┘
```

**关联流程**：

```
1. 文件系统层 Hook (ext4_file_read_iter)
   ├─ 捕获：inode=3456789, dev=8:0, pid=1234
   ├─ 捕获：文件路径="var/lib/mysql/ibdata1"
   ├─ 累加：fs_read_bytes += 16KB
   └─ 保存到 io_source_map[pid=1234, inode=3456789, dev=8:0]

2. 块层 Hook (rq_qos_done)
   ├─ 捕获：inode=3456789, dev=8:0
   ├─ 累加：block_read_bytes += 16KB
   ├─ 计算：q2c = 450μs, d2c = 380μs
   └─ 更新到 io_source_map[pid=1234, inode=3456789, dev=8:0]
      (注意：如果 inode!=0，通过 inode 匹配，忽略 pid)

3. 用户空间聚合
   ├─ 从 io_source_map 导出所有条目
   ├─ 通过 (pid, inode, dev) 作为唯一键聚合
   └─ 输出：
       PID: 1234
       FILE: /var/lib/mysql/ibdata1 (来自文件系统 hook)
       FS_READ: 16KB (来自文件系统 hook)
       DISK_READ: 16KB (来自块层 hook)
       q2c: 450μs, d2c: 380μs (来自块层 hook)
```

#### FS_* vs BLOCK_* 的差异分析

**为什么 FS_READ 和 DISK_READ 可能不一样？**

| 场景 | FS_READ | DISK_READ | 原因 | Hook 捕获时机 |
|------|---------|-----------|------|--------------|
| **缓存命中** | 16KB | 0 | 数据在页面缓存中，不需要读磁盘 | `ext4_file_read_iter` 触发<br>`rq_qos_done` 不触发 |
| **预读** | 16KB | 32KB | 内核预读了相邻数据 | 文件系统请求 16KB<br>块层实际读 32KB |
| **直接 IO** | 16KB | 16KB | 绕过缓存，两者相等 | 两个 hook 捕获相同大小 |
| **压缩文件** | 50KB | 10KB | 文件系统压缩后实际存储更少 | 读取解压后 50KB<br>磁盘实际 10KB |
| **写回** | 100KB | 0 | 写入缓存，尚未刷盘 | `ext4_file_write_iter` 捕获<br>刷盘时才触发块层 |
| **mmap 读** | 4KB | 4KB | 按页（PAGE_SIZE）计算 | `filemap_fault` 捕获 4KB |

**分析技巧**：

```
情况 1: FS_READ ≈ DISK_READ
  └─ 结论：缓存未命中，直接读磁盘
  └─ 示例：FS_READ=16MB, DISK_READ=16MB

情况 2: FS_READ > DISK_READ
  └─ 结论：压缩文件或预读
  └─ 示例：FS_READ=100MB, DISK_READ=20MB (压缩文件)

情况 3: FS_READ < DISK_READ
  └─ 结论：可能有元数据 IO
  └─ 示例：FS_READ=10MB, DISK_READ=12MB (2MB 元数据)

情况 4: DISK_READ = 0
  └─ 结论：完全缓存命中
  └─ 示例：FS_READ=50MB, DISK_READ=0 (全部从缓存读取)

情况 5: FS_WRITE = 0, DISK_WRITE > 0
  └─ 结论：回写 IO（kworker 刷脏页）
  └─ 需要查看 SOURCE PROCESS
```

### 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         用户空间                                │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ iotracing    │    │ autotracing  │    │   Storage    │      │
│  │ CLI 工具     │───▶│  框架        │───▶│   后端       │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ bpf() syscall
                              │
┌─────────────────────────────────────────────────────────────────┐
│                         内核空间                                │
│  ┌───────────────────────────────────────────────────────┐     │
│  │                   iotracing.bpf                       │     │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │     │
│  │  │ 块层钩子     │  │ 文件系统钩子 │  │ 延迟检测    │  │     │
│  │  │ rq_qos_*    │  │ *_iter      │  │ io_schedule │  │     │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │     │
│  └───────────────────────────────────────────────────────┘     │
│                           │                                    │
│  ┌───────────────────────────────────────────────────────┐     │
│  │                    BPF Maps                          │     │
│  │  • io_source_map      - IO 统计数据                   │     │
│  │  • start_info_map     - IO 起始信息（issue/done 匹配）│     │
│  │  • io_schedule_stack  - 调度延迟堆栈                 │     │
│  └───────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      硬件层                                     │
│                    块设备 / NVMe                                │
└─────────────────────────────────────────────────────────────────┘
```

### BPF 程序核心逻辑

#### 1. 块层追踪：rq_qos_issue/done

**源码位置**：`bpf/iotracing.c:154-290`

**原理**：在块层 QoS（Quality of Service）钩子上插桩，追踪每个 IO 请求的完整生命周期。

**Issue 阶段（请求提交）**：

```c
// bpf/iotracing.c:157
SEC("kprobe/rq_qos_issue")
int bpf_rq_qos_issue(struct pt_regs *ctx)
{
    struct request *req = (struct request *)PT_REGS_PARM2(ctx);
    struct hash_key key = {};
    struct io_start_info info = {};

    // 1. 过滤元数据请求，只关注数据 IO
    cmd_flags = BPF_CORE_READ(req, cmd_flags);
    if (cmd_flags & REQ_META)
        return 0;

    // 2. 获取设备号和扇区号
    key.dev = (devn[0] & 0xfff) << 20 | (devn[1] & 0xff) + partno;
    key.sector = BPF_CORE_READ(req, __sector);

    // 3. 提取 inode 信息（区分文件 IO 和直接 IO）
    info.inode = BPF_CORE_READ(inode, i_ino);
    if (info.inode == 0)
        info.dev = key.dev;  // 直接 IO
    else
        info.dev = BPF_CORE_READ(inode, i_sb, s_dev);  // 文件 IO

    // 4. 记录进程信息和时间戳
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(info.comm, COMPAT_TASK_COMM_LEN);

    // 5. 保存到 start_info_map，等待 done 时匹配
    bpf_map_update_elem(&start_info_map, &key, &info, COMPAT_BPF_ANY);

    return 0;
}
```

**Done 阶段（请求完成）**：

```c
// bpf/iotracing.c:213
SEC("kprobe/rq_qos_done")
int bpf_rq_qos_done(struct pt_regs *ctx)
{
    // 1. 根据（设备号、扇区号）查找 issue 阶段的信息
    info = bpf_map_lookup_elem(&start_info_map, &info_key);

    // 2. 判断读写方向，累加字节数
    if (is_write_request(cmd_flags)) {
        entry->block_write_bytes += info->data_len;
    } else {
        entry->block_read_bytes += info->data_len;
    }

    // 3. 计算延迟：q2c 和 d2c
    now = bpf_ktime_get_ns();
    entry->latency.sum_q2c += now - BPF_CORE_READ(req, start_time_ns);
    entry->latency.sum_d2c += now - BPF_CORE_READ(req, io_start_time_ns);
    entry->latency.cnt++;

    // 4. 保存到 io_source_map
    bpf_map_update_elem(&io_source_map, &io_key, &data, COMPAT_BPF_ANY);

    // 5. 清理临时记录
    bpf_map_delete_elem(&start_info_map, &info_key);

    return 0;
}
```

**关键设计**：
- **issue/done 配对**：通过 `(dev, sector)` 唯一标识一个 IO 请求
- **延迟计算**：`q2c = 完成时间 - 入队时间`，`d2c = 完成时间 - 设备开始时间`
- **数据聚合**：按 `(pid, dev, inode)` 聚合，避免用户空间处理大量事件

#### 2. 文件系统追踪：*_iter 钩子

**源码位置**：`bpf/iotracing.c:324-405`

**支持的文件系统**：
- ext4：`ext4_file_read_iter`、`ext4_file_write_iter`
- xfs：`xfs_file_read_iter`、`xfs_file_write_iter`

**实现逻辑**：

```c
// bpf/iotracing.c:324
static __always_inline int bpf_file_read_write(struct pt_regs *ctx)
{
    // 1. 从 kiocb 中提取 inode 和设备号
    inode = BPF_CORE_READ(iocb, ki_filp, f_inode);
    key.inode = BPF_CORE_READ(inode, i_ino);
    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

    // 2. 首次访问时，初始化文件路径信息
    if (entry->tgid == 0) {
        init_io_data(entry, root_dentry, dentry, inode);
        // 提取文件名和 3 级父目录名
    }

    // 3. 获取读写字节数
    from = (struct iov_iter *)PT_REGS_PARM2(ctx);
    count = BPF_CORE_READ(from, count);

    // 4. 兼容不同内核版本的 iov_iter 结构
    if (bpf_core_field_exists(from->type)) {
        type = BPF_CORE_READ(from, type);
    } else {
        struct iov_iter___new *from_new;
        from_new = (struct iov_iter___new *)from;
        type = BPF_CORE_READ(from_new, data_source);
    }

    // 5. 判断读写方向并累加字节数
    type = type & 0x1;
    if (type)  // 1: write
        entry->fs_write_bytes += count;
    else      // 0: read
        entry->fs_read_bytes += count;

    return 0;
}
```

**文件路径提取**：

```c
// bpf/iotracing.c:295
static __always_inline void init_io_data(...)
{
    // 提取文件名和 3 级父目录名，用于构建完整路径
    bpf_probe_read_str(entry->filename, DNAME_INLINE_LEN,
                       BPF_CORE_READ(dentry, d_name.name));

    dentry = BPF_CORE_READ(dentry, d_parent);
    bpf_probe_read_str(entry->d1name, DNAME_INLINE_LEN, ...);

    dentry = BPF_CORE_READ(dentry, d_parent);
    bpf_probe_read_str(entry->d2name, DNAME_INLINE_LEN, ...);

    dentry = BPF_CORE_READ(dentry, d_parent);
    bpf_probe_read_str(entry->d3name, DNAME_INLINE_LEN, ...);
}
```

**为什么只追踪 3 级目录？**
- BPF 栈空间有限，不能无限递归
- 3 级目录通常足够识别文件（如 `/var/lib/mysql/ibdata1`）

#### 3. 页面缓存追踪：filemap_fault/page_mkwrite

**应用场景**：追踪 mmap 读写（不经过 `read()`/`write()` 系统调用）

**页面写回（mmap 写入触发）**：

```c
// bpf/iotracing.c:408
static __always_inline int bpf_filemap_page_mkwrite(struct pt_regs *ctx)
{
    struct vm_fault *vm = (struct vm_fault *)PT_REGS_PARM1(ctx);
    struct vm_area_struct *vma = BPF_CORE_READ(vm, vma);

    inode = BPF_CORE_READ(vma, vm_file, f_inode);
    key.inode = BPF_CORE_READ(inode, i_ino);

    // mmap 写入按页计算，每次增加 PAGE_SIZE（4KB）
    entry->fs_write_bytes += PAGE_SIZE;

    return 0;
}
```

**页面错误（mmap 读取触发）**：

```c
// bpf/iotracing.c:456
SEC("kprobe/filemap_fault")
int bpf_filemap_fault(struct pt_regs *ctx)
{
    // mmap 读取按页计算，每次增加 PAGE_SIZE
    entry->fs_read_bytes += PAGE_SIZE;
    return 0;
}
```

#### 4. IO 调度延迟追踪：io_schedule

**源码位置**：`bpf/iotracing.c:526-576`

**问题**：进程等待 IO 完成的时间（`io_schedule()`）过长，导致性能下降。

**检测逻辑**：

```c
// bpf/iotracing.c:538
// 检测 io_schedule 返回
static __always_inline int detect_io_schedule_return(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();

    // 查找对应的开始记录
    entry = bpf_map_lookup_elem(&io_schedule_stack, &pid);

    // 如果延迟超过阈值（默认 100ms），发送到用户空间
    if (now - entry->ts > FILTER_EVENT_TIMEOUT) {
        entry->cost = now - entry->ts;
        bpf_perf_event_output(ctx, &iodelay_perf_events,
                              COMPAT_BPF_F_CURRENT_CPU, entry,
                              sizeof(struct iodelay_entry));
    }

    return 0;
}
```

**堆栈捕获**：

```c
// bpf/iotracing.c:526
SEC("kprobe/io_schedule")
int bpf_io_schedule(struct pt_regs *ctx)
{
    // 记录开始时间和进程信息
    entry.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(entry.comm, COMPAT_TASK_COMM_LEN);

    // 捕获内核堆栈，用于延迟分析
    entry.stack_size = bpf_get_stack(ctx, entry.stack,
                                     sizeof(entry.stack), 0);
    bpf_map_update_elem(&io_schedule_stack, &pid, &entry, COMPAT_BPF_ANY);

    return 0;
}
```

**堆栈解析**：用户空间通过 `symbol.DumpKernelBackTrace()` 将地址解析为符号名。

### 数据结构设计

#### 核心数据结构

```c
// bpf/iotracing.c:68
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
    char comm[16];              // 进程名
    char filename[64];          // 文件名
    char d1name[64];            // 父目录名
    char d2name[64];            // 爷目录名
    char d3name[64];            // 曾祖目录名
};
```

**设计亮点**：
- **多层级统计**：同时记录文件系统层（`fs_*`）和块层（`block_*`）的 IO
- **延迟聚合**：`sum_q2c`、`sum_d2c`、`cnt` 用于计算平均延迟
- **路径重构**：通过 4 级目录名拼接完整路径

#### BPF Maps 设计

```c
// bpf/iotracing.c:82
// IO 源统计 Map：按 (pid, dev, inode) 聚合 IO 数据
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __uint(key_size, sizeof(struct io_key));
    __uint(value_size, sizeof(struct io_data));
} io_source_map SEC(".maps");

// IO 起始信息 Map：临时存储 issue 阶段的信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(struct hash_key));
    __uint(value_size, sizeof(struct io_start_info));
} start_info_map SEC(".maps");

// IO 调度堆栈 Map：存储 io_schedule 的堆栈和时间戳
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct iodelay_entry));
} io_schedule_stack SEC(".maps");
```

**Map 大小考虑**：
- `io_source_map`: 512 条目，假设追踪 Top 100 进程，每进程 5 个文件
- `start_info_map`: 4096 条目，支持高并发 IO 场景
- `io_schedule_stack`: 128 条目，同时追踪的线程数

### 用户空间实现

#### 工具入口

**源码位置**：`cmd/iotracing/iotracing.go:468`

```go
func mainAction(ctx *cli.Context) error {
    // 1. 解析命令行参数
    parseCmdConfig(ctx)

    // 2. 初始化 BPF 管理器
    bpf.InitBpfManager(&bpf.Option{
        KeepaliveTimeout: int(tracingCmd.config.durationSecond),
    })

    // 3. 加载 BPF 程序
    b, err := bpf.LoadBpfFromBytes("iotracing.o", iotracing, tracingCmd.filters)

    // 4. 动态挂载 BPF 程序
    reader, err := attachAndEventPipe(signalCtx, b)

    // 5. 读取 perf event 事件
    for {
        reader.ReadInto(&event)  // IO 调度延迟事件
        tracingCmd.ioData.IOStack = append(...)
    }

    // 6. 导出 io_source_map 数据
    iodata, _ := b.DumpMapByName("io_source_map")

    // 7. 排序并格式化输出
    printIOTracingData(tracingCmd.ioData)

    return nil
}
```

#### 动态挂载策略

**源码位置**：`cmd/iotracing/iotracing.go:338`

**支持多种挂载方式**：

```go
// 1. 块层钩子（内核版本兼容）
var requestQosIssue, requestQosDone string
if checkKprobeFunctionExists("rq_qos_issue") {
    requestQosIssue = "rq_qos_issue"
    requestQosDone = "rq_qos_done"
} else {
    requestQosIssue = "__rq_qos_issue"  // 5.0+ 内核
    requestQosDone = "__rq_qos_done"
}

// 2. 文件系统钩子（动态检测）
opts = append(opts, []bpf.AttachOption{
    {
        ProgramName: "bpf_anyfs_file_read_iter",
        Symbol:      "ext4_file_read_iter",  // ext4
    },
    {
        ProgramName: "bpf_anyfs_file_read_iter",
        Symbol:      "xfs_file_read_iter",   // xfs
    },
}...)
```

**关键函数**：`attachAndEventPipe()` 负责挂载所有 BPF 程序并创建 perf event reader。

#### 数据处理流程

```go
// cmd/iotracing/iotracing.go:530
// 1. 从 BPF Map 导出数据
iodata, _ := b.DumpMapByName("io_source_map")

// 2. 构建优先队列（按 IO 量排序）
sortTable := NewSortTable()
fileTable := NewFileTable()

for _, dataRaw := range iodata {
    var data IOData
    binary.Read(buf, binary.LittleEndian, &data)

    blkSize := data.BlockWriteBytes + data.BlockReadBytes
    sortTable.Update(data.Pid, blkSize)
    fileTable.Update(data.Pid, &IODataStat{&data, blkSize})
}

// 3. 提取 Top N 进程
pids := sortTable.TopKeyN(int(tracingCmd.config.maxProcess))

// 4. 解析文件路径
for _, pid := range pids {
    files := fileTable.QueueByKey(pid)
    procFileData := parseProcFileTable(pid, files)
    // data.FilePathName() -> "d3name/d2name/d1name/filename"
}
```

#### 容器信息推断

**源码位置**：`internal/utils/procfsutil/`

```go
func HostnameByPid(pid uint32) (string, error) {
    // 1. 读取 /proc/<pid>/cpuset
    cpuset, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cpuset", pid))

    // 2. 从 cpuset 提取容器 ID
    // 例如：/kubepods/pod1234/5678 -> pod1234

    // 3. 查询容器名称（通过 Docker API 或 CRI）
    containerName := queryContainerName(containerID)

    return containerName, nil
}
```

### Autotracing 框架集成

**源码位置**：`core/autotracing/iotracing.go:256`

```go
func (c *ioTracing) Start(ctx context.Context) error {
    // 1. 配置阈值
    thresholds := IoThresholds{
        RbpsThreshold:  conf.Get().AutoTracing.IOTracing.RbpsThreshold,
        WbpsThreshold:  conf.Get().AutoTracing.IOTracing.WbpsThreshold,
        UtilThreshold:  conf.Get().AutoTracing.IOTracing.UtilThreshold,
        AwaitThreshold: conf.Get().AutoTracing.IOTracing.AwaitThreshold,
    }

    // 2. 等待磁盘事件（监控 /proc/diskstats）
    reasonSnapshot, err := waittingDiskEvents(ctx, 5, thresholds)

    // 3. 创建 iotracing 任务
    taskID := tracing.NewTask("iotracing", 40*time.Second,
                              tracing.TaskStorageStdout, []string{"--json"})

    // 4. 等待任务完成
    result := tracing.Result(taskID)

    // 5. 保存数据
    storage.Save("iotracing", "", time.Now(), &ioStatusData)

    return nil
}
```

**监控逻辑**：

```go
// core/autotracing/iotracing.go:203
func waittingDiskEvents(ctx context.Context, intervalSeconds uint64, thresholds IoThresholds) (*ReasonSnapshot, error) {
    ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)

    for {
        currentRawStats, _ := ReadDiskStats()

        for i := range currentRawStats {
            curr := &currentRawStats[i]

            // 计算指标
            metric := buildDiskMetric(prev, curr, intervalSeconds)

            // 检查阈值
            reasonType := shouldIoThreshold(lastMetrics[curr.DeviceName], metric, thresholds)

            if reasonType != ioReasonNone {
                return &ReasonSnapshot{
                    Type:     reasonType.String(),  // "ioutil", "read_bps"...
                    Device:   curr.DeviceName,
                    Iostatus: metric,
                }, nil
            }

            lastMetrics[curr.DeviceName] = metric
        }
    }
}
```

**阈值判断逻辑**：

```go
// core/autotracing/iotracing.go:138
func shouldIoThreshold(prev, curr DiskStatus, thresholds IoThresholds) thresholdReason {
    // 1. 检查 IO 利用率
    if prev.IOutil > thresholds.UtilThreshold &&
       curr.IOutil > thresholds.UtilThreshold {

        // NVMe 设备：检查吞吐量
        if thresholds.nvme {
            if prev.ReadBps > thresholds.RbpsThreshold*1024*1024 &&
               curr.ReadBps > thresholds.RbpsThreshold*1024*1024 {
                return ioReasonReadBps
            }
        } else {
            // SATA/SAS 设备：直接报告利用率高
            return ioReasonUtil
        }
    }

    // 2. 检查 await 延迟
    if prev.ReadAwait > thresholds.AwaitThreshold &&
       curr.ReadAwait > thresholds.AwaitThreshold {
        return ioReasonReadAwait
    }

    return ioReasonNone
}
```

---

## 总结

### iotracing 的核心优势

| 特性 | 传统工具 | iotracing |
|------|---------|-----------|
| **进程-文件关联** | ❌ | ✅ 精确到文件路径 |
| **回写归属** | ❌ | ✅ 追溯到原始进程 |
| **延迟分析** | 部分支持 | ✅ q2c/d2c + 调用栈 |
| **容器支持** | ❌ | ✅ 识别容器 ID |
| **自动触发** | ❌ | ✅ autotracing 框架 |
| **事后追溯** | ❌ | ✅ 自动保存现场 |

### 技术亮点

1. **全栈追踪**：从文件系统到块设备，无死角覆盖
2. **智能聚合**：内核空间聚合，减少用户空间开销
3. **动态挂载**：支持多内核版本、多文件系统
4. **延迟分析**：多维度延迟指标 + 调用栈
5. **自动化**：autotracing 框架实现无人值守

### 适用场景

✅ 突发 IO 问题定位
✅ 数据库性能优化
✅ 容器环境 IO 排查
✅ 存储系统性能调优
✅ 定期性能审计

---

## 参考资料

- **项目地址**：
  - GitHub: https://github.com/ccfos/huatuo
  - GitLink: https://gitlink.org.cn/ccfos/huatuo
- **官方网站**：https://huatuo.tech
- **核心源码**：
  - BPF 程序：`bpf/iotracing.c`
  - CLI 工具：`cmd/iotracing/iotracing.go`
  - Autotracing：`core/autotracing/iotracing.go`

---

**文档版本**：v1.0
**最后更新**：2025-01-07
**维护者**：HUATUO 开源社区
