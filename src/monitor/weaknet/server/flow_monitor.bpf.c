#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// 定义IPv4地址族标识（若系统头文件未定义则补充）
#ifndef AF_INET
#define AF_INET 2
#endif

char LICENSE[] SEC("license") = "GPL";

/**
 * 连接标识结构体：用于唯一标识一个网络连接
 * 包含源地址、目的地址、源端口、目的端口和协议，构成唯一键
 */
struct conn_key {
    __u32 saddr;       // 源IPv4地址（网络序）
    __u32 daddr;       // 目的IPv4地址（网络序）
    __u16 sport;       // 源端口（网络序）
    __u16 dport;       // 目的端口（网络序）
    __u8  protocol;    // 协议类型（6=TCP，17=UDP）
}__attribute__((packed)); 

/**
 * 流量统计数据结构体：记录连接的流量信息
 */
struct flow_data {
    __u64 bytes;       // 累计发送字节数
    __u64 packets;     // 累计发送包数
    __u32 pid;         // 发送进程的PID（最新发送的进程）
};

// ring buffer 中传输的流量事件结构（包含连接标识和统计数据）
struct flow_event {
    struct conn_key key;    // 连接唯一标识
    struct flow_data data;  // 流量统计数据
};

// ring buffer 映射（内核态 -> 用户态传输数据）
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB 缓冲区（根据需求调整）
} events SEC(".maps");

// 触发标志映射（用户态通过此映射触发数据推送）
// 键为 0，值为 1 时触发内核态推送 current_sec 中的所有数据
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} trigger SEC(".maps");

/**
 * 当前窗口流量统计映射（哈希表）
 * 类型：LRU_HASH（最近最少使用淘汰机制，自动清理不活跃连接）
 * 最大条目：65536（限制内存占用，可根据需求调整）
 * 键：conn_key（连接唯一标识）
 * 值：flow_data（该连接的流量统计）
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key);
    __type(value, struct flow_data);
} current_sec SEC(".maps");

/**
 * 网卡过滤配置映射（哈希表）
 * 用于指定只统计特定网卡的流量（可选配置）
 * 键：网卡索引（ifindex）
 * 值：0表示不过滤， 1表示过滤
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} cfg_iface SEC(".maps");

/**
 * 检查当前数据包的网卡是否允许被统计
 * @param skb_ifindex：数据包所在的网卡索引
 * @return：true表示允许统计，false表示过滤
 */
static __always_inline bool iface_allowed(__u32 skb_ifindex)
{
    // 查找配置的网卡索引
    __u32 *want = bpf_map_lookup_elem(&cfg_iface, &skb_ifindex);
    
    // 未配置网卡过滤（映射中无数据），默认放行
    if (!want) return true;
    
    return *want == 0;
}

/**
 * 从sock结构体中提取信息，填充连接标识（conn_key）
 * @param sk：内核sock结构体指针（表示一个网络连接）
 * @param proto：协议类型（6=TCP，17=UDP）
 * @param k：输出参数，待填充的连接标识
 * @return：0表示成功，-1表示失败（如非IPv4协议）
 */
static __always_inline int fill_key_from_sock(struct sock *sk, __u8 proto, struct conn_key *k)
{
    // 获取地址族（仅处理IPv4）
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return -1;  // 过滤非IPv4连接

    // 从sock结构体中读取源地址和目的地址（网络序）
    k->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);  // 源地址（本地接收地址）
    k->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);      // 目的地址

    // 源端口：内核中存储为本地序，需转换为网络序（与目的端口统一格式）
    __u16 sport_host = BPF_CORE_READ(sk, __sk_common.skc_num);  // 源端口（本地序）
    k->sport = bpf_htons(sport_host);  // 转换为网络序

    // 目的端口：内核中已为网络序（直接读取）
    k->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    // 记录协议类型
    k->protocol = proto;
    return 0;
}

// 遍历 current_sec 时的回调函数：将每个会话数据推送到 ring buffer
static int send_flow_to_ringbuf(struct conn_key *key, struct flow_data *value, void *ctx)
{
    // 从 ring buffer 申请空间（非阻塞，失败则跳过）
    struct flow_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;  // 空间不足，继续下一个条目

    // 复制连接标识和统计数据到事件结构
    e->key = *key;
    e->data = *value;

    // 提交数据到 ring buffer（用户态可见）
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 触发推送：将 current_sec 中的所有会话数据推送到 ring buffer
static  __always_inline int send_flow_to_ringbuf_all(void)
{
    __u32 trigger_key = 0;
    __u32 *trigger_flag = bpf_map_lookup_elem(&trigger, &trigger_key);

    // 检查触发标志：用户态设置为 1 时触发推送
    if (!trigger_flag || *trigger_flag != 1)
        return 0;

    // 遍历 current_sec 哈希表，将所有会话数据推送到 ring buffer
    bpf_for_each_map_elem(&current_sec, send_flow_to_ringbuf, NULL, 0);

    // 重置触发标志（避免重复推送）
    *trigger_flag = 0;
    return 0;
}

/**
 * 更新流量统计数据（累加字节数和包数）
 * @param k：连接标识（键）
 * @param add_bytes：本次需累加的字节数
 */
static __always_inline void account_flow(struct conn_key *k, __u64 add_bytes)
{
    // 查找该连接是否已在映射中
    struct flow_data *v = bpf_map_lookup_elem(&current_sec, k);

    if (!v) {
        // 连接首次出现：初始化统计数据
        struct flow_data init = {0};
        init.bytes = add_bytes;       // 初始字节数
        init.packets = 1;             // 初始包数（1个包）
        // 获取当前进程PID（bpf_get_current_pid_tgid返回PID<<32 | TID，取低32位）
        init.pid = (__u32)(bpf_get_current_pid_tgid() & 0xffffffff);
        // 将新连接加入映射
        bpf_map_update_elem(&current_sec, k, &init, 0);
    } else {
        // 连接已存在：原子累加（避免并发修改冲突）
        __sync_fetch_and_add(&v->bytes, add_bytes);  // 累加字节数
        __sync_fetch_and_add(&v->packets, 1);        // 累加包数
        // 更新为最新发送进程的PID
        v->pid = (__u32)(bpf_get_current_pid_tgid() & 0xffffffff);
    }
}

/**
 * TCP发送流量统计：挂钩内核函数ip_queue_xmit（TCP数据包发送入口）
 * kprobe：动态跟踪点，在函数入口处执行
 * 函数原型：ip_queue_xmit(struct sock *sk, struct sk_buff *skb, ...)
 */
SEC("kprobe/ip_queue_xmit")
int tcp_transmit_entry(struct pt_regs *ctx)
{
    // 从函数参数获取sock结构体（第一个参数）和skb（第二个参数）
    // PT_REGS_PARMx(ctx)用于从寄存器中提取函数参数（x86架构）
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    // 校验参数有效性（避免空指针访问）
    if (!sk || !skb) return 0;

    // 网卡过滤：获取数据包所在的网卡索引
    struct net_device *dev = BPF_CORE_READ(skb, dev);  // skb关联的网络设备
    __u32 ifindex = dev ? BPF_CORE_READ(dev, ifindex) : 0;  // 网卡索引
    if (!iface_allowed(ifindex))  // 不允许的网卡则跳过统计
        return 0;

    // 填充TCP连接的标识信息
    struct conn_key k = {};
    if (fill_key_from_sock(sk, 6 /*TCP协议*/, &k) < 0)
        return 0;  // 非IPv4连接则跳过

    // 获取数据包长度（skb->len为整个数据包的字节数）
    __u32 len = BPF_CORE_READ(skb, len);
    // 更新TCP流量统计
    account_flow(&k, len);
    return 0;
}

/**
 * UDP发送流量统计：挂钩内核函数udp_sendmsg（UDP消息发送入口）
 * kprobe：动态跟踪点，在函数入口处执行
 * 函数原型：udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
 */
SEC("kprobe/udp_sendmsg")
int udp_send_entry(struct pt_regs *ctx)
{
    // 从函数参数获取sock结构体（第一个参数）和消息长度（第三个参数）
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    unsigned long len = (unsigned long)PT_REGS_PARM3(ctx);  // 发送的字节数

    // 校验sock有效性
    if (!sk) return 0;

    // UDP无skb结构体（或旧内核中skb字段兼容性差），此处不做网卡过滤
    // 仅统计所有网卡的UDP流量

    // 填充UDP连接的标识信息
    struct conn_key k = {};
    if (fill_key_from_sock(sk, 17 /*UDP协议*/, &k) < 0)
        return 0;  // 非IPv4连接则跳过

    // 更新UDP流量统计（len为本次发送的字节数）
    account_flow(&k, (__u64)len);
    return 0;
}