#include "base/macro.h"
#include "logger.hpp"
#include "net_ping.hpp"
#include "base/coro/iomanager.h"
#include "weak_netmgr.hpp"
#include <signal.h>

using namespace monitor::weaknet;
bool running = true;

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

void handle_signal(int signum)
{
    running = false;
    LOG_INFO_F(LogModule::TEST, "Signal %d received, setting running to false", signum);
}

int main()
{
    std::cout << "test_ping begin" << std::endl;
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    if (!Logger::init("server", "./logs/server", LogLevel::INFO, true)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }

    LOG_INFO(LogModule::TEST, "test_ping begin");
    base::IOManager iom(1, true);
    int intervalMs = 10000;
    WeakNetMgr::ptr weak_mgr = std::make_shared<WeakNetMgr>(&iom);
    weak_mgr->init();
    iom.schedule([weak_mgr, intervalMs] {
        LOG_INFO(LogModule::TEST, "monitor thread started");

        std::vector<NetInfo> current;
        int32_t change_counter = 0;

        while (running) {
            LOG_INFO(LogModule::TEST, "tick: collecting interfaces");
            auto [latest, last_using_iface] = weak_mgr->collectCurrentInterfaces();

            for (const auto &net : latest) {
                if (net.usingNow()) {
                    LOG_INFO(LogModule::TEST,
                             "ACTIVE: " << net.ifName() << " | RTT: " << net.rttMs()
                                        << "ms" // 往返时延（毫秒）
                                        << " | Quality: " << net.quality() // 网络质量评分
                                        << " | RSSI: " << net.rssiDbm()
                                        << "dBm" // 接收信号强度（分贝毫瓦）
                                        << " | TCP Loss: " << net.tcpLossRate() << "% ("
                                        << net.tcpLossLevel() << ")" // TCP丢包率及等级
                                        << " | Traffic: " << (net.trafficTotalBps() / (1024 * 1024))
                                        << "MB/s, " // 总流量（MB/s）
                                        << net.trafficActiveFlows() << " flows, " // 活跃流数量
                                        << net.trafficTotalPps()
                                        << " pps"); // 总数据包速率（包/秒）
                } else {
                    LOG_INFO(LogModule::TEST, "INACTIVE: " << net.ifName()
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

                LOG_INFO(LogModule::TEST, msg);

                for (const auto &x : latest) {
                    if (x.usingNow()) {
                        LOG_INFO(LogModule::TEST,
                                 "[using] " << x.ifName() << " is current uplink");
                    }
                }
                change_counter++;
            } else {
                LOG_INFO(LogModule::TEST, "no changes detected");
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
    });

    return 0;
}