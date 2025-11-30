#include "logger.hpp"
#include "net_ping.hpp"
#include "base/coro/iomanager.h"
#include "weak_netmgr.hpp"
#include <signal.h>

using namespace monitor::weaknet;
bool running = true;

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
    if (!Logger::init("server", "./logs/server.log", LogLevel::INFO, true)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }

    LOG_INFO(LogModule::TEST, "test_ping begin");
    base::IOManager iom(1, true);
    std::string host = "223.5.5.5";
    int intervalMs = 1000;
    WeakNetMgr::ptr weak_mgr = std::make_shared<WeakNetMgr>(&iom);
    weak_mgr->init();
    std::string ctrlDir = "";
    iom.schedule([weak_mgr, host, intervalMs, ctrlDir] {
        LOG_INFO(LogModule::RTT, "RTT monitor thread started");

        while (running) {
            try {
                bool changed = weak_mgr->updateWifiRssi(ctrlDir);

                // 若检测到状态变化，且服务实例存在，则发送信号通知
                if (changed) {
                    LOG_INFO(LogModule::RSSI, "WiFi RSSI updated - emitting signal");
                } else {
                    LOG_INFO(LogModule::RSSI, "RSSI_MONITOR: no changes detected");
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
            } catch (const std::exception &e) {
                LOG_ERROR(LogModule::RTT, "RTT monitor exception: " << e.what());
            } catch (...) {
                LOG_ERROR(LogModule::RTT, "RTT monitor unknown exception");
            }
        }
    });

    return 0;
}