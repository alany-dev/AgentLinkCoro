#include "base/macro.h"
#include "logger.hpp"
#include "net_ping.hpp"
#include "base/coro/iomanager.h"
#include "net_tcp.hpp"
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
    int intervalMs = 1000;
    WeakNetMgr::ptr weak_mgr = std::make_shared<WeakNetMgr>(&iom);
    weak_mgr->init();
    iom.schedule([weak_mgr, intervalMs] {
        LOG_INFO(LogModule::TCP_LOSS, "TCP loss monitor thread started");
        TcpStats prevStats, currStats;
        bool hasPrevStats = false;

        while (_LIKELY(running)) {

            auto currentIface = weak_mgr->getUsingIface();

            // 若未找到活跃网络接口
            if (currentIface.empty()) {
                LOG_INFO(LogModule::TCP_LOSS,
                         "TCP_LOSS_MONITOR: no active interface found (checking "
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
                             "TCP_LOSS_MONITOR: interface="
                                 << currentIface << " rate=" << result.ratePercent << "%"
                                 << " delta_sent=" << result.sentDelta << " delta_retrans="
                                 << result.retransDelta << " level=" << result.level);

                    // 安全更新弱网管理模块中该接口的TCP丢包率和等级
                    bool updated =
                        weak_mgr->updateTcpLossRate(currentIface, result.ratePercent, result.level);
                    // 若更新成功且存在服务实例，则发送DBus信号通知丢包率变化
                    if (updated) {
                        // 构造通知消息，包含接口名、丢包率和等级
                        std::stringstream ss;
                        ss << "TCP loss rate updated for " << currentIface << ": "
                           << result.ratePercent << "% (" << result.level << ")";
                        std::string msg = ss.str();
                        LOG_INFO(LogModule::TCP_LOSS,
                                 "TCP loss rate updated - emitting signal: " << msg);
                    }
                }
            }
            prevStats = currStats;
            hasPrevStats = true;

            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        std::printf("[tcp_loss] monitor terminated.\n");
    });

    return 0;
}