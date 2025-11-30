/**
 * @file weak_netmgr.cpp
 * @brief 网络接口管理器实现文件
 *
 * 该文件实现了 WeakNetMgr 类的所有功能，负责管理系统中的网络接口信息、
 * 收集和更新网络质量指标（如RTT延迟、WiFi信号强度、TCP丢包率等），
 * 并提供线程安全的接口信息访问机制。作为网络诊断系统的核心组件，
 * 它协调各个网络监控模块的数据收集、分析和状态更新。
 */
#include "net_info.hpp"
#include "traffic_analyzer.hpp"
#include "weak_netmgr.hpp"
#include "net_iface.hpp"
#include "base/macro.h"
#include "net_ping.hpp"
#include "logger.hpp"
#include <algorithm>

/**
 * @namespace weaknet_dbus
 * @brief 网络诊断系统的D-Bus服务命名空间
 *
 * 该命名空间包含了网络诊断系统中与D-Bus服务相关的所有类和功能，
 * 负责实现系统网络状态监控、诊断和报告功能。
 */
namespace monitor::weaknet
{

WeakNetMgr::WeakNetMgr(base::IOManager *io_mgr) : io_mgr_(io_mgr)
{
    traffic_analyzer_ = std::make_shared<TrafficAnalyzer>(io_mgr_);
    if (_UNLIKELY(!traffic_analyzer_)) {
        LOG_ERROR(LogModule::WEAK_MGR, "Failed to create TrafficAnalyzer");
    }

    net_iface_mgr_ = std::make_shared<NetInterfaceManager>();
    if (_UNLIKELY(!net_iface_mgr_)) {
        LOG_ERROR(LogModule::WEAK_MGR, "Failed to create NetInterfaceManager");
    }
}

WeakNetMgr::~WeakNetMgr()
{
    traffic_analyzer_.reset();
    rssi_clients_.clear();
}

void WeakNetMgr::updateInterfaces(std::vector<NetInfo> &&interfaces,
                                  const std::string &new_using_iface)
{
    RWMutexType::WriteLock lock(iface_mutex_);
    current_interfaces_ = std::move(interfaces);
    current_using_iface_ = new_using_iface;
}

std::pair<std::vector<NetInfo>, std::string> WeakNetMgr::getCurrentInterfaces() const
{
    RWMutexType::WriteLock lock(iface_mutex_);
    return std::make_pair(current_interfaces_, current_using_iface_);
}

void WeakNetMgr::init()
{
    auto [current_interfaces, current_using_iface] = collectCurrentInterfaces();
    updateInterfaces(std::move(current_interfaces), current_using_iface);
}

/**
 * @brief 收集当前系统中具备上网能力的网络接口，无锁
 *
 * 从底层系统中获取所有具备上网能力的网络接口，并为每个接口创建基本的 NetInfo 对象，
 * 设置初始属性值，并标记当前正在使用的接口。这是获取系统网络接口基本信息的核心方法。
 *
 * @return 包含当前系统中所有可用网络接口基本信息的 NetInfo 列表
 */
std::pair<std::vector<NetInfo>, std::string> WeakNetMgr::collectCurrentInterfaces()
{
    std::vector<NetInfo> result;
    std::string current_using_iface;
    // 获取当前系统中所有具备上网能力的网络接口名称
    auto names = net_iface_mgr_->collect();
    std::string usingIf = net_iface_mgr_->getCurrentIfName();

    result.reserve(names.size());
    // 为每个网络接口创建 NetInfo 对象并设置基本属性
    for (const auto &n : names) {
        NetInfo info(n, if_nametoindex(n.c_str()));
        
        // 设置初始属性值：
        // - 默认路由设置为 false（后续可扩展）
        // - 接口类型初始化为未知
        // - 接口状态初始化为 Up（假设接口处于活跃状态）
        // - RTT值初始化为-1（表示尚未测量）
        info.setDefaultRoute(false);
        info.setType(net_iface_mgr_->getIfaceType(n));
        info.setState(NetState::Up);
        info.setRttMs(-1);

        if (!usingIf.empty() && n == usingIf) {
            info.setUsingNow(true);
        }

        result.push_back(info);
    }
    return std::make_pair(result, usingIf);
}

/**
 * @brief 根据RTT值分类网络链路质量
 *
 * 静态辅助函数，根据网络接口的往返延迟时间（RTT）值，将网络质量分类为不同等级。
 * RTT值越小，表示网络延迟越低，质量越好。
 *
 * @param rttMs 当前测量的RTT值（毫秒），负值表示测量失败或网络不可达
 * @param prevMs 上一次测量的RTT值（毫秒），当前版本未使用此参数
 * @return 网络链路质量等级（Good、Fair、Poor或Bad）
 */
static LinkQuality classifyQualityFromRtt(int rttMs, int prevMs)
{
    if (rttMs < 0)
        return LinkQuality::Bad;
    else if (rttMs <= 50)
        return LinkQuality::Good;
    else if (rttMs <= 100)
        return LinkQuality::Fair;
    else if (rttMs <= 200)
        return LinkQuality::Poor;
    return LinkQuality::Bad;
}

/**
 * @brief 更新网络接口列表的RTT（往返时间）和网络状态，并检测是否有状态变化
 *
 * 该方法通过对指定主机执行ping操作，获取每个网络接口的最新RTT值，
 * 并根据RTT值更新接口的链路质量和网络状态（上线/下线），同时记录是否有任何状态发生变更。
 *
 * @param[in] host 用于ping测试的目标主机地址（域名或IP）
 * @param[in] timeoutMs ping操作的超时时间（毫秒）
 * @return bool 若列表中任一接口的链路质量或网络状态发生变化，则返回true；否则返回false
 */
bool WeakNetMgr::updateRttAndState(const std::string &host, int timeoutMs)
{
    RWMutexType::WriteLock lock(iface_mutex_);
    bool anyChanged = false;

    for (auto &x : current_interfaces_) {
        LOG_INFO(LogModule::WEAK_MGR, "updateRttAndState: processing interface " << x.ifName());

        // 保存当前RTT值作为"上一次RTT"，用于后续链路质量判断
        int prev = x.rttMs();

        // 对目标主机执行ping操作，指定网络接口和超时时间，获取最新RTT值
        // 返回值r：若ping成功则为RTT（毫秒），若失败则为负数（如-1表示超时或不可达）
        int r = NetPing::ping(host, x.ifName(), timeoutMs);

        // 更新接口的"上一次RTT"和"当前RTT"
        x.setPrevRttMs(prev);
        x.setRttMs(r);

        // 根据新RTT（r）和旧RTT（prev）分类链路质量（如优、良、中、差）
        LinkQuality q = classifyQualityFromRtt(r, prev);

        if (x.quality() != q) {
            x.setQuality(q);
            anyChanged = true;
        }

        // 根据RTT值粗略判断网络状态：RTT有效（>=0）则为上线（Up），否则为下线（Down）
        // 注：此处逻辑可扩展，例如结合信号强度、丢包率等更多指标判断状态
        NetState ns = (r >= 0) ? NetState::Up : NetState::Down;

        // 若网络状态发生变化，更新状态并标记状态变更
        if (x.state() != ns) {
            x.setState(ns);
            anyChanged = true;
        }

        // 记录当前接口的更新结果：接口名、RTT、链路质量（枚举值）、网络状态（枚举值）
        LOG_INFO(LogModule::WEAK_MGR, "iface=" << x.ifName() << " rtt=" << r
                                               << "ms quality=" << static_cast<int>(x.quality())
                                               << " state=" << static_cast<int>(x.state()));
    }
    return anyChanged;
}

/**
 * @brief 更新网络接口列表中所有WiFi类型接口的RSSI（接收信号强度指示）值
 *
 * 该函数仅处理列表中的WiFi类型网络接口，通过WiFiRssiClient工具类连接接口的控制套接字，
 * 获取最新RSSI值并更新到NetInfo对象中。若任一接口的RSSI值发生变化，返回true；仅处理WiFi接口，非WiFi接口会被跳过。
 *
 * @param[in] ctrlDir
 * WiFi接口控制目录路径（用于WiFiRssiClient连接接口的控制套接字，具体路径依赖底层驱动/硬件实现）
 * @return bool 若列表中任一WiFi接口的RSSI值发生更新，则返回true；无变化或无有效WiFi接口时返回false
 */
bool WeakNetMgr::updateWifiRssi(const std::string &ctrlDir)
{
    RWMutexType::WriteLock lock(iface_mutex_);
    bool anyChanged = false;
    for (auto &x : current_interfaces_) {
        if (x.type() != NetType::WiFi) {
            LOG_INFO(LogModule::WEAK_MGR,
                     "updateWifiRssi: skipping non-WiFi interface " << x.type());
            continue;
        }

        // 为每个WiFi接口获取或创建对应的WiFiRssiClient实例
        WiFiRssiClient *client = nullptr;
        {
            auto it = rssi_clients_.find(x.ifName());
            if (it == rssi_clients_.end()) {
                client = new WiFiRssiClient();

                if (!client->connect(x.ifName(), ctrlDir)) {
                    continue;
                }
                rssi_clients_[x.ifName()] = client;
            } else {
                client = it->second;
            }
        }

        // 连接成功，获取当前WiFi接口的最新RSSI值（单位：dBm，数值越小信号越弱）
        int rssi = client->getRssi();

        // 检查获取RSSI是否成功（-1000表示失败）
        if (rssi == -1000) {
            LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: failed to get RSSI for " << x.ifName());
            rssi_clients_.erase(x.ifName());
            continue;
        }

        LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: got RSSI " << rssi << " for " << x.ifName());

        // 对比新RSSI值与旧值，若不一致则更新，并标记状态变化
        if (x.rssiDbm() != rssi) {
            x.setRssiDbm(rssi);
            anyChanged = true;

            if (x.usingNow()) {
                LOG_INFO(LogModule::RSSI,
                         "using iface " << x.ifName() << " RSSI=" << rssi << " dBm");
            }

            LOG_INFO(LogModule::WEAK_MGR, "iface=" << x.ifName() << " rssi=" << rssi);
        }
    }
    return anyChanged;
}

// static
std::vector<std::string> WeakNetMgr::namesOf(const std::vector<NetInfo> &interfaces)
{
    std::vector<std::string> names;
    names.reserve(interfaces.size());
    for (const auto &x : interfaces) {
        names.push_back(x.ifName());
    }
    return names;
}

std::vector<uint32_t> WeakNetMgr::indicesOf(const std::vector<NetInfo> &interfaces)
{
    std::vector<uint32_t> indices;
    indices.reserve(interfaces.size());
    for (const auto &x : interfaces) {
        indices.push_back(x.index());
    }
    return indices;
}

bool WeakNetMgr::updateTcpLossRate(const std::string &iface_name, double loss_rate,
                                   TcpLossLevel loss_level)
{
    RWMutexType::WriteLock lock(iface_mutex_);
    // 标记是否有丢包率或丢包等级发生变化
    bool changed = false;

    // 遍历接口列表查找目标接口
    for (auto &x : current_interfaces_) {
        // 找到匹配的接口名称
        if (x.ifName() == iface_name) {
            // 标记丢包率和丢包等级是否发生变化
            bool rateChanged = false, levelChanged = false;

            // 检查丢包率是否发生变化
            if (x.tcpLossRate() != loss_rate) {
                x.setTcpLossRate(loss_rate);
                rateChanged = true;
            }

            // 检查丢包等级是否发生变化
            if (x.tcpLossLevel() != loss_level) {
                x.setTcpLossLevel(loss_level);
                levelChanged = true;
            }

            // 如果有任何变化，更新标志并记录日志
            if (rateChanged || levelChanged) {
                changed = true;

                // 如果该接口是当前正在使用的接口，记录在TCP丢包模块日志中
                if (x.usingNow()) {
                    LOG_INFO(LogModule::TCP_LOSS,
                             "using iface " << iface_name << " TCP loss rate updated: " << loss_rate
                                            << "% (" << loss_level << ")");
                }

                // 记录接口丢包率和等级的更新结果
                LOG_INFO(LogModule::WEAK_MGR, "iface=" << x.ifName()
                                                       << " tcp_loss_rate=" << x.tcpLossRate()
                                                       << " tcp_loss_level=" << x.tcpLossLevel());
            }

            // 找到目标接口后，跳出循环
            break;
        }
    }

    return changed;
}

/**
 * @brief 启动网络流量分析
 *
 * 初始化并启动流量分析器，开始对指定网络接口进行流量监控和分析。
 * 如果流量分析器尚未创建，则创建一个新实例。
 *
 * @param interface 要监控的网络接口名称
 * @param interval_seconds 流量统计的采样间隔（秒），默认值为 10 秒
 */
void WeakNetMgr::startTrafficAnalysis(int interval_seconds)
{
    // 如果流量分析器尚未创建，创建一个新实例
    if (_UNLIKELY(!traffic_analyzer_)) {
        traffic_analyzer_ = std::make_shared<TrafficAnalyzer>(io_mgr_);
    }
    RWMutexType::ReadLock lock(iface_mutex_);
    // 启动流量分析器，开始监控指定接口
    traffic_analyzer_->start(WeakNetMgr::indicesOf(current_interfaces_), interval_seconds);
}

bool WeakNetMgr::updateTrafficAnalysis()
{
    RWMutexType::WriteLock lock(iface_mutex_);
    if (!traffic_analyzer_ || !traffic_analyzer_->isRunning()) {
        return false;
    }

    bool changed = false;

    try {
        auto stats = traffic_analyzer_->getCurrentStats();

        // 获取流量最大的连接（Top 5，最小流量10字节）
        auto topFlows = traffic_analyzer_->getTopFlows(5, 10);

        // 检测异常流量（阈值为5%）
        auto anomalies = traffic_analyzer_->detectAnomalies(5);

        // 更新当前上网网卡的流量信息
        for (auto &net : current_interfaces_) {
            // 只更新当前正在使用的接口
            if (net.usingNow()) {
                // 更新流量统计信息（总带宽、包速率、活跃连接数）
                net.setTrafficStats(stats.totalBps, stats.totalPps, stats.activeFlows);

                // 如果检测到异常流量，记录日志
                if (!anomalies.empty()) {
                    LOG_INFO(LogModule::WEAK_MGR, "Traffic anomalies detected on "
                                                      << net.ifName() << ": " << anomalies.size()
                                                      << " anomalies");
                    for (const auto &anomaly : anomalies) {
                        LOG_INFO(LogModule::WEAK_MGR,
                                 "Anomaly: " << anomaly.anomalyType
                                             << " severity: " << (anomaly.severity * 100) << "%");
                    }
                }

                // 记录更新的流量统计信息
                LOG_INFO(LogModule::WEAK_MGR, "Updated traffic stats for "
                                                  << net.ifName() << ": "
                                                  << (stats.totalBps / (1024 * 1024)) << " MB/s, "
                                                  << stats.activeFlows << " flows, "
                                                  << stats.totalPps << " pps");

                // 标记有数据更新
                changed = true;
                // 找到正在使用的接口后跳出循环
                break;
            }
        }

    } catch (const std::exception &e) {
        // 捕获并记录可能发生的异常
        LOG_ERROR(LogModule::WEAK_MGR, "Traffic analysis update error: " << e.what());
    }

    return changed;
}

} // namespace monitor::weaknet
