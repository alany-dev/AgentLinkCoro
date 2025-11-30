#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include "base/singleton.h"
#include "base/net/socket.h"
#include "net_info.hpp"

namespace monitor::weaknet
{
/**
 * @brief TCP统计数据结构体
 *
 * 用于存储TCP连接的关键统计信息，包括接收段数、发送段数和重传段数，
 * 这些数据主要从系统的TCP协议栈中获取，用于后续丢包率计算。
 */
struct TcpStats {
    uint64_t inSegs = 0;      // TCP接收的总段数（Tcp: InSegs）
    uint64_t outSegs = 0;     // TCP发送的总段数（Tcp: OutSegs）
    uint64_t retransSegs = 0; // TCP重传的总段数（Tcp: RetransSegs）
    bool valid = false;       // 数据有效性标记，true表示统计数据有效
};

/**
 * @brief TCP丢包率计算结果结构体
 *
 * 存储基于两次TCP统计采样计算得出的丢包相关信息，包括丢包率百分比、
 * 发送段和重传段的增量，以及根据丢包率划分的网络质量等级。
 */
struct TcpLossResult {
    double ratePercent = 0.0; // 丢包率百分比，计算公式：(deltaRetrans / deltaOut) * 100
    uint64_t sentDelta = 0;   // 两次采样间发送段数的增量（delta OutSegs）
    uint64_t retransDelta = 0; // 两次采样间重传段数的增量（delta RetransSegs）
    TcpLossLevel level = TcpLossLevel::Unknown; // 网络质量等级：good（良好）/degraded（轻度丢包）/poor（严重丢包）/insufficient（数据不足）
};

/**
 * @brief TCP丢包监控器类
 *
 * 用于监控系统或特定网络接口的TCP丢包情况。
 * 通过Netlink协议获取TCP统计数据，计算丢包率并评估网络质量等级。
 */
class TcpLossMonitor
{
public:
    /**
     * @brief 采样系统级TCP统计数据
     *
     * 收集系统所有网络接口的TCP统计信息，主要通过Netlink SOCK_DIAG协议获取。
     *
     * @param outStats 输出参数，用于存储采样到的TCP统计数据
     * @return bool 采样成功返回true，失败返回false
     */
    static bool sample(TcpStats &outStats);

    /**
     * @brief 采样指定网络接口的TCP统计数据
     *
     * 收集特定网卡接口的TCP统计信息，优先通过Netlink聚合该接口的tcp_info数据，
     * 在必要情况下会使用备选方法获取统计数据。
     *
     * @param ifaceName 目标网络接口名称（如"eth0"、"wlan0"）
     * @param outStats 输出参数，用于存储采样到的TCP统计数据
     * @return bool 采样成功返回true，失败返回false（如接口不存在）
     */
    static bool sampleForInterface(const std::string &ifaceName, TcpStats &outStats);

    /**
     * @brief 计算TCP丢包率及网络质量等级
     *
     * 基于两次采样的TCP统计数据（前一次和当前），计算丢包率并根据预定义阈值
     * 确定网络质量等级。支持自定义最小发送段数阈值和质量等级阈值。
     *
     * @param prev 前一次采样的TCP统计数据
     * @param curr 当前采样的TCP统计数据
     * @param minSent 计算丢包率的最小发送段数增量阈值（默认10）
     * @param degradedThresholdPct 判定为"degraded"的丢包率阈值（默认1.0%）
     * @param poorThresholdPct 判定为"poor"的丢包率阈值（默认5.0%）
     * @return TcpLossResult 包含丢包率、增量和质量等级的计算结果
     */
    static TcpLossResult compute(const TcpStats &prev, const TcpStats &curr, uint64_t minSent = 10,
                                 double degradedThresholdPct = 1.0, double poorThresholdPct = 5.0);

private:
    /**
     * @brief 通过Netlink SOCK_DIAG协议获取TCP socket统计数据
     *
     * 这是一个内部辅助函数，负责通过Netlink协议与Linux内核通信，获取指定协议族（IPv4或IPv6）
     * 和指定网卡接口的所有TCP socket详细统计信息。该函数采用SOCK_DIAG_BY_FAMILY消息类型，
     * 向内核请求TCP socket诊断数据，并从中提取重传次数和近似发送段数等关键指标。
     *
     * 函数工作流程：
     * 1. 构造Netlink请求消息，指定协议族和诊断参数
     * 2. 通过sendmsg发送请求到内核
     * 3. 循环接收内核返回的响应消息
     * 4. 解析每个socket的诊断信息，提取tcp_info结构体中的统计数据
     * 5. 根据需要按网卡接口过滤数据，并累加统计指标
     *
     * @param nlSock Netlink socket文件描述符（已初始化的NETLINK_SOCK_DIAG类型socket）
     * @param family 协议族（AF_INET=IPv4，AF_INET6=IPv6）
     * @param filterIfindex 目标网卡的索引（<=0表示不过滤网卡，收集所有网卡数据）
     * @param segsOutApprox 输出参数，近似发送段数（通过tcpi_unacked/tcpi_retrans/tcpi_sacked估算）
     * @param segsInApprox 输出参数，近似接收段数（当前未实际赋值，预留字段）
     * @param totalRetrans 输出参数，总重传段数（所有符合条件socket的重传次数之和）
     * @return bool 操作成功返回true，失败返回false（如发送/接收Netlink消息失败）
     */
    /**
     * @brief 通过Netlink SOCK_DIAG协议获取TCP socket统计数据
     *
     * 这是一个内部辅助函数，负责通过Netlink协议与Linux内核通信，获取指定协议族（IPv4或IPv6）
     * 和指定网卡接口的所有TCP socket详细统计信息。该函数采用SOCK_DIAG_BY_FAMILY消息类型，
     * 向内核请求TCP socket诊断数据，并从中提取重传次数和近似发送段数等关键指标。
     *
     * @param nlSock Netlink socket文件描述符（已初始化的NETLINK_SOCK_DIAG类型socket）
     * @param family 协议族（AF_INET=IPv4，AF_INET6=IPv6）
     * @param filterIfindex 目标网卡的索引（<=0表示不过滤网卡，收集所有网卡数据）
     * @param segsOutApprox 输出参数，近似发送段数（通过tcpi_unacked/tcpi_retrans/tcpi_sacked估算）
     * @param segsInApprox 输出参数，近似接收段数（当前未实际赋值，预留字段）
     * @param totalRetrans 输出参数，总重传段数（所有符合条件socket的重传次数之和）
     * @return bool 操作成功返回true，失败返回false（如发送/接收Netlink消息失败）
     */
    static bool dumpTcpStatsByFamilyAndInterface(base::Socket::ptr nlSock, int family,
                                                 int filterIfindex, uint64_t &segsOutApprox,
                                                 uint64_t &segsInApprox, uint64_t &totalRetrans);

    /**
     * @brief 汇总指定网卡的IPv4和IPv6 TCP统计数据
     *
     * 内部辅助函数，整合ifnameToIndex、dumpTcpStatsByFamilyAndInterface、getInterfaceTxPackets的功能：
     * 1. 将网卡名转换为索引；
     * 2. 获取该网卡的IPv4和IPv6 TCP socket统计；
     * 3. 若TCP发送段数估算值为0，用L2层发送数据包数补充（避免分母为0）。
     *
     * @param iface 目标网卡名
     * @param segsOutApprox 输出参数，汇总的TCP近似发送段数
     * @param segsInApprox 输出参数，汇总的TCP近似接收段数（预留，当前为0）
     * @param totalRetrans 输出参数，汇总的TCP总重传段数
     * @return bool 操作成功返回true，失败返回false（如网卡不存在、Netlink操作失败）
     */
    static bool sampleTcpStatsForInterface(const std::string &iface, uint64_t &segsOutApprox,
                                           uint64_t &segsInApprox, uint64_t &totalRetrans);

    /**
     * @brief 通过Netlink RTM_GETLINK请求，获取指定网卡的L2层发送数据包统计
     *
     * 内部辅助函数，通过路由Netlink协议（RTM_GETLINK）获取网卡的传输统计，支持32位（IFLA_STATS）和64位（IFLA_STATS64）统计结构，
     * 优先使用64位结构避免数据溢出，最终返回网卡的总发送数据包数（L2层，包含所有协议，不仅TCP）。
     *
     * @param ifindex 目标网卡的索引
     * @param txPackets 输出参数，网卡的总发送数据包数
     * @return bool 操作成功返回true，失败返回false（如socket创建失败、消息发送/接收失败）
     */
    static bool getInterfaceTxPackets(int ifindex, uint64_t &txPackets);
};
} // namespace monitor::weaknet