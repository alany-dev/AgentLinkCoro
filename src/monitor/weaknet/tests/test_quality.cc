#include "base/macro.h"
#include "logger.hpp"
#include "net_ping.hpp"
#include "base/coro/iomanager.h"
#include "network_quality_assessor.hpp"
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
    if (!Logger::init("server", "./logs/server", LogLevel::INFO, true)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }

    LOG_INFO(LogModule::TEST, "test_ping begin");
    base::IOManager iom(1, true);
    std::string host = "223.5.5.5";
    int intervalMs = 15 * 1000;
    WeakNetMgr::ptr weak_mgr = std::make_shared<WeakNetMgr>(&iom);
    weak_mgr->init();
    iom.schedule([weak_mgr, host, intervalMs] {
        LOG_INFO(LogModule::WEAK_MGR, "network quality monitor thread started");

        NetworkQualityAssessor assessor;
        NetworkQualityResult lastQuality;
        lastQuality.level = NetworkQualityLevel::UNKNOWN;

        int loop_count = 0;
        while (_LIKELY(running)) {
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

                    LOG_INFO(LogModule::WEAK_MGR, "网络质量变化: " << currentQuality.levelName
                                                                   << " (分数: " << std::fixed
                                                                   << std::setprecision(1)
                                                                   << currentQuality.score << ")");

                    lastQuality = currentQuality;
                } else {
                    LOG_INFO(LogModule::WEAK_MGR, "网络质量稳定: " << currentQuality.levelName
                                                                   << " (分数: " << std::fixed
                                                                   << std::setprecision(1)
                                                                   << currentQuality.score << ")");
                }

            } catch (const std::exception &e) {
                LOG_ERROR(LogModule::WEAK_MGR, "网络质量监控错误: " << e.what());
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs)); // 15秒检查一次
        }
        std::printf("[network_quality] monitor terminated.\n");
    });

    return 0;
}