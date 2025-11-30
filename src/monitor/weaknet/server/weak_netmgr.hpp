/**
 * @file weak_netmgr.hpp
 * @brief 网络接口管理器头文件
 *
 * 该文件定义了 WeakNetMgr 类，负责管理系统中的网络接口信息、
 * 收集网络接口质量指标，并提供线程安全的接口信息访问和更新机制。
 * WeakNetMgr 是整个网络诊断系统的核心组件之一，负责协调各个网络监控模块。
 */

#pragma once

#include <vector>
#include <string>
#include <memory>
#include "base/coro/iomanager.h"
#include "net_iface.hpp"
#include "net_info.hpp"
#include "traffic_analyzer.hpp"
#include "net_wifirssi.hpp"
#include "base/mutex.h"

namespace monitor::weaknet
{

/**
 * @class WeakNetMgr
 * @brief 网络接口管理器
 *
 * 该类负责管理网络接口信息列表，收集和更新网络质量指标，
 * 并提供线程安全的接口信息访问机制。它整合了多种网络监控功能，
 * 包括RTT延迟测量、Wi-Fi信号强度监控、TCP丢包率跟踪和流量分析。
 */
class WeakNetMgr
{
public:
    using ptr = std::shared_ptr<WeakNetMgr>;
    using RWMutexType = base::RWSpinlock;

    WeakNetMgr(base::IOManager *io_mgr);
    ~WeakNetMgr();

    /**
     * @brief 初始化WeakNetMgr
     *
     * 执行WeakNetMgr的初始化过程，包括收集当前系统中的网络接口信息并标记
     * 当前正在使用的网络接口。这是WeakNetMgr开始正常工作前的必要步骤。
     */
    void init();

    /**
     * @brief 更新当前网络接口列表
     *
     * 将收集到的当前系统网络接口信息更新到 WeakNetMgr 内部的存储中。
     * 这是在初始化后或接口状态变化时调用的方法，确保管理器中的接口列表
     * 与实际系统状态保持同步。
     *
     * @param interfaces 包含当前系统网络接口信息的 NetInfo 列表
     */
    void updateInterfaces(std::vector<NetInfo> &&interfaces, const std::string &new_using_iface);

    /**
     * @brief 获取当前网络接口列表
     *
     * 返回 WeakNetMgr 内部存储的当前系统网络接口信息列表。
     * 这个列表包含了所有具备上网能力的网络接口，每个接口都有详细的属性信息。
     *
     * @return 当前系统网络接口信息列表
     */
    std::pair<std::vector<NetInfo>, std::string> getCurrentInterfaces() const;

    /**
     * @brief 获取当前正在使用的网络接口名
     *
     * 返回 WeakNetMgr 内部记录的当前正在使用的网络接口名。
     * 这个接口名在初始化时被设置，后续可以通过 updateInterfaces 方法更新。
     *
     * @return 当前正在使用的网络接口名
     */
    std::string getUsingIface() const { return current_using_iface_; }

    /**
     * @brief 收集当前系统中具备上网能力的网络接口
     *
     * 从底层查询或外部模块同步当前系统中可用的网络接口，
     * 创建并返回包含基本信息的 NetInfo 列表。默认通过 NetInterfaceManager
     * 获取接口名，再填充基本字段，包括默认路由状态、接口类型和状态等。
     *
     * @return 包含当前系统中所有网络接口基本信息的 NetInfo 列表
     */
    std::pair<std::vector<NetInfo>, std::string> collectCurrentInterfaces();

    /**
     * @brief 将 NetInfo 列表转换为接口名数组
     *
     * 从网络接口信息列表中提取所有接口的名称，形成字符串数组返回。
     * 这个方法主要用于向 D-Bus 客户端返回接口列表。
     *
     * @return 包含所有接口名称的字符串数组
     */
    static std::vector<std::string> namesOf(const std::vector<NetInfo> &interfaces);

    static std::vector<uint32_t> indicesOf(const std::vector<NetInfo> &interfaces);
    /**
     * @brief 更新网络接口的 RTT 延迟和链路质量
     *
     * 通过对指定主机执行 ping 测试，更新网络接口列表中每个接口的 RTT 延迟值，
     * 并根据延迟值评估链路质量。
     *
     * @param host 用于 ping 测试的目标主机地址（域名或 IP）
     * @param timeoutMs ping 操作的超时时间（毫秒），默认值为 800ms
     * @return 如果任一接口的 RTT 或链路质量发生变化则返回 true，否则返回 false
     */
    bool updateRttAndState(const std::string &host, int timeoutMs = 800);

    /**
     * @brief 更新 Wi-Fi 接口的 RSSI 信号强度
     *
     * 仅对列表中类型为 WiFi 的网络接口，通过 wpa_supplicant 控制接口获取并更新 RSSI 信号强度。
     *
     * @param ctrlDir wpa_supplicant 控制目录路径，可留空以自动探测
     * @return 如果任一 WiFi 接口的 RSSI 值发生变化则返回 true，否则返回 false
     */
    bool updateWifiRssi(const std::string &ctrlDir = "");

    /**
     * @brief 更新指定接口的 TCP 丢包率
     *
     * 根据接口名查找并更新指定网络接口的 TCP 丢包率和丢包等级。
     *
     * @param iface_name 要更新的接口名称
     * @param loss_rate TCP 丢包率（百分比）
     * @param loss_level TCP 丢包率等级描述（如 good、degraded、poor、insufficient）
     * @return 如果丢包率或丢包等级发生变化则返回 true，否则返回 false
     */
    bool updateTcpLossRate(const std::string &iface_name, double loss_rate,
                           TcpLossLevel loss_level);

    /**
     * @brief 流量分析相关函数
     *
     * 启动流量分析器，对指定网络接口进行流量监控和分析。
     *
     * @param interval_seconds 流量统计的采样间隔（秒），默认值为 10 秒
     */
    void startTrafficAnalysis(int interval_seconds = 10);

    /**
     * @brief 更新当前上网网卡的流量分析数据
     *
     * 从流量分析器获取最新的流量统计数据，并更新到当前正在使用的网络接口信息中。
     *
     * @return 如果流量数据发生变化则返回 true，否则返回 false
     */
    bool updateTrafficAnalysis();

private:
    base::IOManager *io_mgr_;                              // IO管理器指针
    mutable RWMutexType iface_mutex_;                      // 保护接口列表的互斥锁
    std::shared_ptr<TrafficAnalyzer> traffic_analyzer_;    // 流量分析器指针
    NetInterfaceManager::ptr net_iface_mgr_;               // 网络接口管理器指针
    std::vector<NetInfo> current_interfaces_;              // 当前接口列表
    std::string current_using_iface_;                      // 当前正在使用的网络接口名
    std::map<std::string, WiFiRssiClient *> rssi_clients_; // wifi接口名到WiFiRssiClient的映射
};

} // namespace monitor::weaknet
