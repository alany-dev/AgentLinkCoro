#include "server.hpp"
#include "base/coro/iomanager.h"
#include "logger.hpp"
#include "common.hpp"
#include "event_manager.hpp"
#include "network_quality_assessor.hpp"
#include "net_tcp.hpp"
#include "base/macro.h"
#include <chrono>

namespace monitor::weaknet
{
static bool diffInterfaces(const std::vector<NetInfo> &old_list,
                           const std::vector<NetInfo> &new_list, std::vector<std::string> &added,
                           std::vector<std::string> &removed, std::string &old_using_iface,
                           std::string &new_using_iface)
{
    added.clear();
    removed.clear();

    for (const auto &it : new_list) {
        if (it.usingNow()) {
            new_using_iface = it.ifName();
        }
        if (std::find(old_list.begin(), old_list.end(), it) == old_list.end())
            added.push_back(it.ifName());
    }
    for (const auto &it : old_list) {
        if (it.usingNow()) {
            old_using_iface = it.ifName();
        }
        if (std::find(new_list.begin(), new_list.end(), it) == new_list.end())
            removed.push_back(it.ifName());
    }
    return added.size() > 0 || removed.size() > 0;
}

WeakNetServer::WeakNetServer(base::IOManager *io_mgr) : m_io_mgr(io_mgr)
{
}

WeakNetServer::~WeakNetServer()
{
    // 设置运行标志为false，确保所有循环终止
    running.store(false);

    // 取消DBus定时器
    if (m_dbus_timer) {
        m_dbus_timer->cancel();
        m_dbus_timer = nullptr;
    }

    // 清理资源
    if (service) {
        delete service;
        service = nullptr;
    }

    if (weak_mgr) {
        weak_mgr.reset();
    }

    if (connection) {
        dbus_connection_close(connection);
        dbus_connection_unref(connection);
        connection = nullptr;
    }

    google::ShutdownGoogleLogging();
}

int WeakNetServer::start()
{
    if (_UNLIKELY(!Logger::init("server", "./logs/server", LogLevel::INFO, true))) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }

    if (_UNLIKELY(!init_dbus()))
        return 1;

    EventManager::GetInstance()->startEventMonitoring(this);

    if (_LIKELY(!weak_mgr))
        weak_mgr = std::make_shared<WeakNetMgr>(m_io_mgr);

    weak_mgr->init();

    // 启动接口使用监控  ⭐
    // 该函数创建一个独立 ，负责周期性监控系统中的网络接口状态变化，以及 当前正在使用网络接口的变化
    // 并在检测到变化时通过DBus发送信号通知客户端
    start_iface_monitor();

    // 启动 RTT 监控 ：使用阿里云 DNS 223.5.5.5 作为目标
    LOG_INFO(LogModule::RTT, "starting monitor thread (target=223.5.5.5, interval=10s)");

    // RTT ⭐
    // 周期性地更新指定主机的RTT值和网络接口状态，当检测到RTT或网络质量发生变化时，通过DBus发送信号通知
    m_io_mgr->schedule(std::bind(&WeakNetServer::start_rtt_monitor, this, "223.5.5.5", 10000, 800));

    // 启动 Wi-Fi RSSI 监控 （wpa_supplicant ctrl 目录自动探测）⭐
    LOG_INFO(LogModule::RSSI, "starting RSSI monitor thread (interval=10s)");
    m_io_mgr->schedule(std::bind(&WeakNetServer::start_rssi_monitor, this, ""));

    // 启动 TCP 丢包率监控  ⭐
    LOG_INFO(LogModule::TCP_LOSS, "starting TCP loss rate monitor thread (interval=10s)");
    m_io_mgr->schedule(std::bind(&WeakNetServer::start_tcp_loss_monitor, this));

    // 启动流量分析  ⭐
    LOG_INFO(LogModule::WEAK_MGR, "starting traffic analysis thread (interval=10s)");
    m_io_mgr->schedule(std::bind(&WeakNetServer::start_traffic_analysis, this));

    // 启动网络质量监控  ⭐
    LOG_INFO(LogModule::WEAK_MGR, "starting network quality monitor thread (interval=15s)");
    m_io_mgr->schedule(std::bind(&WeakNetServer::start_network_quality, this));

    int timeout_ms = 100;
    m_dbus_timer = m_io_mgr->addTimer(
        timeout_ms,
        [this, timeout_ms]() {
            if (!running.load())
                return;
            int ret = dbus_connection_read_write_dispatch(connection, timeout_ms);
            if (ret == -1)
                return;
        },
        true);

    return 0;
}

::DBusConnection *WeakNetServer::init_dbus()
{
    LOG_INFO(LogModule::DBUS, "init_dbus: start connecting to session bus...");
    // 初始化 系统
    dbus_threads_init_default();

    DBusError err;
    // 初始化错误对象
    dbus_error_init(&err);

    // 连接会话总线
    DBusConnection *connection = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (dbus_error_is_set(&err)) {
        LOG_ERROR(LogModule::DBUS, "连接会话总线失败: " << err.message);
        dbus_error_free(&err);
        return nullptr;
    }
    if (!connection)
        return nullptr;
    LOG_INFO(LogModule::DBUS, "connected to session bus");

    LOG_INFO(LogModule::DBUS, "requesting bus name: " << kBusName);
    // 请求服务名（替换已存在）
    int ret = dbus_bus_request_name(connection, kBusName, DBUS_NAME_FLAG_REPLACE_EXISTING, &err);
    if (dbus_error_is_set(&err)) {
        LOG_ERROR(LogModule::DBUS, "请求服务名失败: " << err.message);
        dbus_error_free(&err);
    }
    if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        LOG_ERROR(LogModule::DBUS, "未能成为主拥有者，ret=" << ret);
        return nullptr;
    }

    // 使用服务类进行对象注册（保存到上下文，统一管理生命周期）
    LOG_INFO(LogModule::DBUS,
             "registering object path: " << kObjectPath << " (interface=" << kInterface << ")");
    service = new DbusService(this);
    if (!service->register_on_connection(connection)) {
        LOG_ERROR(LogModule::DBUS, "注册对象路径失败");
        delete service;
        service = nullptr;
        return nullptr;
    }
    LOG_INFO(LogModule::DBUS, "DBus 服务端已启动，接口 " << kInterface << "，方法 " << kMethodGet
                                                         << "，信号 " << kSignalChanged);
    return connection;
}

void WeakNetServer::start_iface_monitor()
{

    LOG_INFO(LogModule::INTERFACE, "monitor thread started");

    if (_UNLIKELY(!weak_mgr))
        weak_mgr = std::make_shared<WeakNetMgr>(m_io_mgr);

    std::vector<NetInfo> current;
    int32_t change_counter = 0;

    while (_LIKELY(running.load())) {
        LOG_INFO(LogModule::INTERFACE, "tick: collecting interfaces");
        auto [latest, last_using_iface] = weak_mgr->collectCurrentInterfaces();

        for (const auto &net : latest) {
            if (net.usingNow()) {
                LOG_INFO(LogModule::INTERFACE,
                         "ACTIVE: " << net.ifName() << " | RTT: " << net.rttMs()
                                    << "ms"                            // 往返时延（毫秒）
                                    << " | Quality: " << net.quality() // 网络质量评分
                                    << " | RSSI: " << net.rssiDbm()
                                    << "dBm" // 接收信号强度（分贝毫瓦）
                                    << " | TCP Loss: " << net.tcpLossRate() << "% ("
                                    << net.tcpLossLevel() << ")" // TCP丢包率及等级
                                    << " | Traffic: " << (net.trafficTotalBps() / (1024 * 1024))
                                    << "MB/s, "                               // 总流量（MB/s）
                                    << net.trafficActiveFlows() << " flows, " // 活跃流数量
                                    << net.trafficTotalPps() << " pps"); // 总数据包速率（包/秒）
            } else {
                LOG_INFO(LogModule::INTERFACE, "INACTIVE: " << net.ifName()
                                                            << " | RTT: " << net.rttMs() << "ms"
                                                            << " | Quality: " << net.quality()
                                                            << " | RSSI: " << net.rssiDbm() << "dBm"
                                                            << " | TCP Loss: " << net.tcpLossRate()
                                                            << "% (" << net.tcpLossLevel() << ")");
            }
        }
        std::vector<std::string> added, removed;
        std::string new_using_iface;
        std::string old_using_iface;
        // 对比接口变化：若存在新增或移除的接口
        if (diffInterfaces(current, latest, added, removed, old_using_iface, new_using_iface)) {
            current = latest;

            weak_mgr->updateInterfaces(std::move(latest), new_using_iface);

            std::string msg = "Interfaces changed (using flags in log): +";
            for (size_t i = 0; i < added.size(); ++i) {
                msg += (i == 0 ? "" : ",");
                msg += added[i];
            }
            msg += " -";
            for (size_t i = 0; i < removed.size(); ++i) {
                msg += (i == 0 ? "" : ",");
                msg += removed[i];
            }

            LOG_INFO(LogModule::INTERFACE, msg);

            for (const auto &x : latest) {
                if (x.usingNow()) {
                    LOG_INFO(LogModule::INTERFACE,
                             "[using] " << x.ifName() << " is current uplink");
                }
            }

            if (_LIKELY(service)) {
                // 当整体的接口变化时，触发信号
                base::IOManager::GetThis()->schedule([this, msg, change_counter]() {
                    service->emitChanged(msg, change_counter);
                    EventManager::GetInstance()->emitInterfaceChanged(msg, "network_manager");
                });

                // 当正在使用的接口发生变化时，触发信号
                if (new_using_iface != old_using_iface) {
                    msg = std::string("Using iface updated: ") + new_using_iface;
                    base::IOManager::GetThis()->schedule([this, msg, new_using_iface]() {
                        service->emitChanged(msg, 0);
                        EventManager::GetInstance()->emitConnectionModeChanged(msg,
                                                                               new_using_iface);
                    });
                }
            }
            change_counter++;
        } else {
            LOG_INFO(LogModule::INTERFACE, "no changes detected");
        }

        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void WeakNetServer::start_rtt_monitor(const std::string &host, int intervalMs, int timeoutMs)
{

    LOG_INFO(LogModule::RTT, "RTT monitor thread started");

    if (_UNLIKELY(!weak_mgr))
        weak_mgr = std::make_shared<WeakNetMgr>(m_io_mgr);

    int loop_count = 0;

    while (_LIKELY(running.load())) {
        loop_count++;

        LOG_INFO(LogModule::RTT, "RTT monitor thread running, loop=" << loop_count << ", running="
                                                                     << running.load());

        try {
            LOG_INFO(LogModule::RTT, "RTT monitor: calling updateRttAndStateSafe");

            // 调用线程安全的方法更新RTT和网络状态
            // 该方法会向目标主机发送检测包（如ICMP），计算RTT，并更新网络接口的质量状态
            // 返回值changed表示本次更新是否导致了RTT或质量状态的变化
            bool changed = weak_mgr->updateRttAndState(host, timeoutMs);

            // 若检测到状态变化，且服务实例存在，则发送信号通知
            if (changed && _LIKELY(service)) {
                LOG_INFO(LogModule::RTT, "RTT/Quality updated - emitting signal");
                m_io_mgr->schedule(
                    [this]() { service->emitChanged("RTT/Quality updated", /*counter*/ 0); });
            } else {
                LOG_INFO(LogModule::RTT, "RTT_MONITOR: no changes detected");
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        } catch (const std::exception &e) {
            LOG_ERROR(LogModule::RTT, "RTT monitor exception: " << e.what());
        } catch (...) {
            LOG_ERROR(LogModule::RTT, "RTT monitor unknown exception");
        }
    }
}

void WeakNetServer::start_rssi_monitor(const std::string &ctrlDir)
{

    LOG_INFO(LogModule::RSSI, "RSSI monitor thread started");
    if (_UNLIKELY(!weak_mgr)) {
        weak_mgr = std::make_shared<WeakNetMgr>(m_io_mgr);
    }

    int loop_count = 0;

    while (_LIKELY(running.load())) {
        loop_count++;
        LOG_INFO(LogModule::RSSI, "RSSI monitor: calling updateWifiRssiSafe");

        // ⭐ RSSI更新接口：更新所有WiFi接口的RSSI值
        bool changed = weak_mgr->updateWifiRssi(ctrlDir);

        if (changed && _LIKELY(service)) {
            LOG_INFO(LogModule::RSSI, "WiFi RSSI updated - emitting signal");
            m_io_mgr->schedule([this]() { service->emitChanged("WiFi RSSI updated", 0); });
        } else {
            LOG_INFO(LogModule::RSSI, "RSSI_MONITOR: no changes detected");
        }
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
    std::printf("[WIFI RSSI] monitor terminated.\n");
}

void WeakNetServer::start_tcp_loss_monitor()
{

    LOG_INFO(LogModule::TCP_LOSS, "TCP loss monitor thread started");
    if (_UNLIKELY(!weak_mgr)) {
        weak_mgr = std::make_shared<WeakNetMgr>(m_io_mgr);
    }
    TcpStats prevStats, currStats;
    bool hasPrevStats = false;

    int loop_count = 0;
    while (_LIKELY(running.load())) {
        loop_count++;

        LOG_INFO(LogModule::TCP_LOSS,
                 "tick: monitoring TCP loss rate... (loop=" << loop_count << ")");

        auto currentIface = weak_mgr->getUsingIface();

        // 若未找到活跃网络接口
        if (currentIface.empty()) {
            LOG_INFO(LogModule::TCP_LOSS, "TCP_LOSS_MONITOR: no active interface found (checking "
                                              << currentIface.size() << " interfaces)");
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        LOG_INFO(LogModule::TCP_LOSS, "monitoring interface: " << currentIface);

        // 采样当前活跃接口的TCP统计数据（如发送包数、重传包数等） ⭐
        if (!TcpLossMonitor::sampleForInterface(currentIface, currStats)) {
            LOG_ERROR(LogModule::TCP_LOSS,
                      "failed to sample TCP stats for interface: " << currentIface);
            std::this_thread::sleep_for(std::chrono::seconds(10));
            continue;
        }

        // 若存在前一次的统计数据，则计算丢包率（首次循环无历史数据，不执行）
        if (hasPrevStats) {
            // 调用监控器计算两次采样的丢包结果（基于前次和当前统计数据）
            TcpLossResult result = TcpLossMonitor::compute(prevStats, currStats);

            // 仅当发送的数据包增量超过10时才处理（避免数据量过小导致的计算误差）
            if (result.sentDelta >= 10) {
                // 打印丢包率详情日志：接口名、丢包率（百分比）、发送增量、重传增量、丢包等级
                LOG_INFO(LogModule::TCP_LOSS,
                         "TCP_LOSS_MONITOR: interface=" << currentIface
                                                        << " rate=" << result.ratePercent << "%"
                                                        << " delta_sent=" << result.sentDelta
                                                        << " delta_retrans=" << result.retransDelta
                                                        << " level=" << result.level);

                // 安全更新弱网管理模块中该接口的TCP丢包率和等级
                bool updated =
                    weak_mgr->updateTcpLossRate(currentIface, result.ratePercent, result.level);
                // 若更新成功且存在服务实例，则发送DBus信号通知丢包率变化
                if (updated && _LIKELY(service)) {
                    // 构造通知消息，包含接口名、丢包率和等级
                    std::stringstream ss;
                    ss << "TCP loss rate updated for " << currentIface << ": " << result.ratePercent
                       << "% (" << result.level << ")";
                    std::string msg = ss.str();
                    LOG_INFO(LogModule::TCP_LOSS,
                             "TCP loss rate updated - emitting signal: " << msg);
                    m_io_mgr->schedule([this, msg]() { service->emitChanged(msg, 0); });
                }
            }
        }
        prevStats = currStats;
        hasPrevStats = true;

        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
    std::printf("[tcp_loss] monitor terminated.\n");
}
void WeakNetServer::start_traffic_analysis()
{

    LOG_INFO(LogModule::WEAK_MGR, "traffic analysis thread started");

    if (_UNLIKELY(!weak_mgr))
        weak_mgr = std::make_shared<WeakNetMgr>(m_io_mgr);

    // 启动流量分析器
    weak_mgr->startTrafficAnalysis(10);

    int loop_count = 0;
    while (_LIKELY(running.load())) {
        loop_count++;
        LOG_INFO(LogModule::WEAK_MGR, "traffic analysis thread running, loop=" << loop_count);

        try {
            bool changed = weak_mgr->updateTrafficAnalysis();

            if (changed && _LIKELY(service)) {
                LOG_INFO(LogModule::WEAK_MGR, "Traffic analysis updated - emitting signal");
                m_io_mgr->schedule(
                    [this]() { service->emitChanged("Traffic analysis updated", 0); });
            } else {
                LOG_INFO(LogModule::WEAK_MGR, "TRAFFIC_ANALYSIS: no changes detected");
            }
        } catch (const std::exception &e) {
            LOG_ERROR(LogModule::WEAK_MGR, "Traffic analysis error: " << e.what());
        }

        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
    LOG_INFO(LogModule::WEAK_MGR, "traffic analysis thread stopped");
}

void WeakNetServer::start_network_quality()
{
    LOG_INFO(LogModule::WEAK_MGR, "network quality monitor thread started");

    NetworkQualityAssessor assessor;
    NetworkQualityResult lastQuality;
    lastQuality.level = NetworkQualityLevel::UNKNOWN;

    int loop_count = 0;
    while (_LIKELY(running.load())) {
        loop_count++;
        LOG_INFO(LogModule::WEAK_MGR, "network quality thread running, loop=" << loop_count);
        try {
            auto [currentInterfaces, currentIface] = weak_mgr->getCurrentInterfaces();
            LOG_INFO(LogModule::WEAK_MGR,
                     "network quality: current interfaces count=" << currentInterfaces.size());

            // 评估网络质量
            NetworkQualityResult currentQuality = assessor.assessQuality(currentInterfaces);

            // 检查质量是否发生变化
            if (currentQuality.level != lastQuality.level
                || std::abs(currentQuality.score - lastQuality.score) > 15.0) {

                LOG_INFO(LogModule::WEAK_MGR,
                         "网络质量变化: " << currentQuality.levelName << " (分数: " << std::fixed
                                          << std::setprecision(1) << currentQuality.score << ")");

                // 发送网络质量变化事件
                EventManager::GetInstance()->emitNetworkQualityChanged(
                    currentQuality.levelName, currentQuality.details, "network_quality_assessor");

                lastQuality = currentQuality;
            } else {
                LOG_INFO(LogModule::WEAK_MGR,
                         "网络质量稳定: " << currentQuality.levelName << " (分数: " << std::fixed
                                          << std::setprecision(1) << currentQuality.score << ")");
            }

        } catch (const std::exception &e) {
            LOG_ERROR(LogModule::WEAK_MGR, "网络质量监控错误: " << e.what());
        }

        std::this_thread::sleep_for(std::chrono::seconds(15)); // 15秒检查一次
    }
    std::printf("[network_quality] monitor terminated.\n");
}

} // namespace monitor::weaknet