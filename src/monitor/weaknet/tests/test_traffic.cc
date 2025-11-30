#include "base/macro.h"
#include "logger.hpp"
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
        LOG_INFO(LogModule::WEAK_MGR, "traffic analysis thread started");

        auto [latest, currentIface] = weak_mgr->collectCurrentInterfaces();
        // 启动流量分析器
        weak_mgr->startTrafficAnalysis(10);

        while (_LIKELY(running)) {
            try {
                bool changed = weak_mgr->updateTrafficAnalysis();

                if (changed) {
                    LOG_INFO(LogModule::WEAK_MGR, "Traffic analysis updated - emitting signal");

                } else {
                    LOG_INFO(LogModule::WEAK_MGR, "TRAFFIC_ANALYSIS: no changes detected");
                }
            } catch (const std::exception &e) {
                LOG_ERROR(LogModule::WEAK_MGR, "Traffic analysis error: " << e.what());
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        LOG_INFO(LogModule::WEAK_MGR, "traffic analysis thread stopped");
    });

    return 0;
}