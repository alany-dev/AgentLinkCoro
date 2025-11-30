#pragma once
#include "base/coro/iomanager.h"
#include <dbus/dbus.h>
#include "dbus_service.hpp"
#include "event_manager.hpp"
#include "weak_netmgr.hpp"
#include "net_info.hpp"
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>

namespace monitor::weaknet
{

class WeakNetServer
{
public:
    WeakNetServer(base::IOManager *io_mgr = base::IOManager::GetThis());
    ~WeakNetServer();

    int start();

    ::DBusConnection *getDbusConnection() { return connection; }
    DbusService *getDbusService() { return service; }

    // 获取所有的网卡
    std::vector<std::string> getIfaceNames()
    {
        std::lock_guard<std::mutex> lk(iface_mutex);
        return WeakNetMgr::namesOf(iface_list);
    }

    // 获取当前正在使用的网卡名称
    std::string getCurrentIface()
    {
        std::string currentIface;
        std::lock_guard<std::mutex> lk(iface_mutex);
        // 遍历网卡列表，寻找当前活跃的网卡（usingNow()返回true表示正在使用）
        for (const auto &net : iface_list) {
            if (net.usingNow()) {
                currentIface = net.ifName(); // 获取活跃网卡的名称（如"eth0"）
                break;
            }
        }
        return currentIface;
    }

private:
    ::DBusConnection *init_dbus();
    void start_iface_monitor();
    void start_rtt_monitor(const std::string &host, int intervalMs = 2000, int timeoutMs = 800);
    void start_rssi_monitor(const std::string &ctrlDir = "");
    void start_tcp_loss_monitor();
    void start_traffic_analysis();
    void start_network_quality();

private:
    base::IOManager *m_io_mgr = nullptr;

    // DBus 连接
    ::DBusConnection *connection = nullptr;

    // 运行标志
    std::atomic<bool> running{true};

    // 共享的可上网网卡列表（NetInfo）
    std::mutex iface_mutex;
    std::vector<NetInfo> iface_list;

    // 服务对象（方法处理与信号发送）
    DbusService *service = nullptr;

    // 弱网管理器
    WeakNetMgr::ptr weak_mgr = nullptr;
    
    // DBus事件处理定时器
    base::Timer::ptr m_dbus_timer = nullptr;
};
} // namespace monitor::weaknet