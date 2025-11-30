/**
 * @file net_info.hpp
 * @brief 网络信息类定义
 *
 * 该文件定义了网络接口的信息存储类 NetInfo，用于保存和管理网络接口的各种属性，
 * 包括接口类型、状态、质量评估、RTT延迟、RSSI信号强度、TCP丢包率以及流量统计等信息。
 * 这个类在整个网络诊断系统中作为网络接口信息的核心数据结构使用。
 */

#pragma once

#include <net/if.h>
#include <string>
#include <iostream>
#include <net/if_arp.h>

namespace monitor::weaknet
{

/**
 * @enum NetType
 * @brief 网络类型枚举
 *
 * 定义了系统支持的不同类型的网络接口。
 */
enum class NetType {
    Unknown = 0, // 未知网络类型
    Ethernet,    // 以太网接口
    WiFi,        // Wi-Fi无线网络接口
};

// string -> NetType 方法
static NetType NetTypefromString(unsigned short arphrd)
{
    switch (arphrd) {
        case ARPHRD_ETHER:
            return NetType::Ethernet;
        case ARPHRD_IEEE80211:
            return NetType::WiFi;
        default:
            return NetType::Unknown;
    }
}

inline std::ostream &operator<<(std::ostream &os, NetType type)
{
    switch (type) {
        case NetType::Unknown:
            os << "Unknown";
            break;
        case NetType::Ethernet:
            os << "Ethernet";
            break;
        case NetType::WiFi:
            os << "WiFi";
            break;
        default:
            os << "Invalid";
            break;
    }
    return os;
}

/**
 * @enum NetState
 * @brief 网络接口状态枚举
 *
 * 定义了网络接口的两种基本状态：启用和禁用。
 */
enum class NetState {
    Down = 0, // 接口关闭或不可用
    Up        // 接口启用并可用
};

inline std::ostream &operator<<(std::ostream &os, NetState state)
{
    switch (state) {
        case NetState::Down:
            os << "Down";
            break;
        case NetState::Up:
            os << "Up";
            break;
        default:
            os << "Invalid";
            break;
    }
    return os;
}

/**
 * @enum LinkQuality
 * @brief 链路质量评估枚举
 *
 * 定义了对网络链路质量的五级评估。
 */
enum class LinkQuality {
    Unknown = 0, // 未知质量
    Good,        // 质量良好
    Fair,        // 质量一般
    Poor,        // 质量较差
    Bad          // 质量很差
};

inline std::ostream &operator<<(std::ostream &os, LinkQuality quality)
{
    switch (quality) {
        case LinkQuality::Unknown:
            os << "Unknown";
            break;
        case LinkQuality::Good:
            os << "Good";
            break;
        case LinkQuality::Fair:
            os << "Fair";
            break;
        case LinkQuality::Poor:
            os << "Poor";
            break;
        case LinkQuality::Bad:
            os << "Bad";
            break;
        default:
            os << "Invalid";
            break;
    }
    return os;
}

/**
 * @enum TcpLossLevel
 * @brief TCP丢包等级枚举
 *
 * 定义了根据TCP丢包率评估的三级等级。
 */
enum class TcpLossLevel {
    Unknown = 0,  // 未知丢包等级
    Insufficient, // 数据不足
    Good,         // 丢包率低
    Degraded,     // 丢包率中等
    Poor          // 丢包率高
};

// 重载输出运算符，作为全局函数
inline std::ostream &operator<<(std::ostream &os, TcpLossLevel level)
{
    switch (level) {
        case TcpLossLevel::Unknown:
            os << "Unknown";
            break;
        case TcpLossLevel::Insufficient:
            os << "Insufficient";
            break;
        case TcpLossLevel::Good:
            os << "Good";
            break;
        case TcpLossLevel::Degraded:
            os << "Degraded";
            break;
        case TcpLossLevel::Poor:
            os << "Poor";
            break;
        default:
            os << "Invalid";
            break;
    }
    return os;
}

/**
 * @class NetInfo
 * @brief 网络接口信息类
 *
 * 该类用于存储和管理网络接口的详细信息，包括基本属性、质量评估、性能指标等。
 * 提供了属性的设置和获取方法，以及用于比较接口的辅助方法。
 */
class NetInfo
{
public:
    /**
     * @brief 默认构造函数
     *
     * 创建一个空的网络接口信息对象，所有属性使用默认值。
     */
    NetInfo() = default;

    /**
     * @brief 带接口名的构造函数
     *
     * 创建一个指定接口名的网络接口信息对象。
     *
     * @param name 网络接口名称
     */
    explicit NetInfo(std::string name, uint32_t index) : ifname_(std::move(name)), index_(index) {}

    void setIfName(const std::string &n) { ifname_ = n; }
    const std::string &ifName() const { return ifname_; }

    void setIndex(uint32_t i) { index_ = i; }
    uint32_t index() const { return index_; }

    void setDefaultRoute(bool v) { is_default_ = v; }
    bool isDefaultRoute() const { return is_default_; }

    void setType(NetType t) { type_ = t; }
    NetType type() const { return type_; }

    void setRttMs(int rtt) { rtt_ms_ = rtt; }
    int rttMs() const { return rtt_ms_; }

    void setPrevRttMs(int rtt) { prev_rtt_ms_ = rtt; }
    int prevRttMs() const { return prev_rtt_ms_; }

    void setState(NetState s) { state_ = s; }
    NetState state() const { return state_; }

    void setQuality(LinkQuality q) { quality_ = q; }
    LinkQuality quality() const { return quality_; }

    void setRssiDbm(int rssi) { rssi_dbm_ = rssi; }
    int rssiDbm() const { return rssi_dbm_; }

    void setUsingNow(bool v) { using_now_ = v; }
    bool usingNow() const { return using_now_; }

    void setTcpLossRate(double rate) { tcp_loss_rate_ = rate; }
    double tcpLossRate() const { return tcp_loss_rate_; }

    void setTcpLossLevel(TcpLossLevel level) { tcp_loss_level_ = level; }
    TcpLossLevel tcpLossLevel() const { return tcp_loss_level_; }

    void setTrafficStats(uint64_t totalBps, uint64_t totalPps, uint32_t activeFlows)
    {
        traffic_total_bps_ = totalBps;
        traffic_total_pps_ = totalPps;
        traffic_active_flows_ = activeFlows;
    }

    uint64_t trafficTotalBps() const { return traffic_total_bps_; }

    uint64_t trafficTotalPps() const { return traffic_total_pps_; }

    uint32_t trafficActiveFlows() const { return traffic_active_flows_; }

    bool sameKey(const NetInfo &other) const { return ifname_ == other.ifname_; }

    bool operator==(const NetInfo &other) const
    {
        return ifname_ == other.ifname_ && is_default_ == other.is_default_ && type_ == other.type_
               && rtt_ms_ == other.rtt_ms_ && state_ == other.state_;
    }

private:
    std::string ifname_;                         // 网络接口名
    uint32_t index_ = 0;                         // 网络接口索引
    bool is_default_ = false;                    // 是否为默认路由接口
    NetType type_ = NetType::Unknown;            // 网络接口类型
    int rtt_ms_ = -1;                            // 当前RTT延迟值（毫秒）
    int prev_rtt_ms_ = -1;                       // 上一次RTT延迟值（毫秒）
    NetState state_ = NetState::Down;            // 网络接口状态
    bool using_now_ = false;                     // 是否当前被判定为"正在上网"的接口
    LinkQuality quality_ = LinkQuality::Unknown; // 链路质量评估
    int rssi_dbm_ = -1000;        // Wi-Fi RSSI信号强度（dBm），非Wi-Fi接口保持默认值
    double tcp_loss_rate_ = -1.0; // TCP丢包率（百分比）
    TcpLossLevel tcp_loss_level_; // TCP丢包率等级（good/degraded/poor/insufficient）

    // 流量统计信息
    uint64_t traffic_total_bps_ = 0;    // 总带宽（bytes per second）
    uint64_t traffic_total_pps_ = 0;    // 总包速率（packets per second）
    uint32_t traffic_active_flows_ = 0; // 活跃连接数
};

} // namespace monitor::weaknet
