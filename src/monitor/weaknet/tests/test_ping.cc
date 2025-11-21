#include "base/macro.h"
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
    LOG_INFO(LogModule::TEST, "Signal received, setting running to false");
}

int main(int argc, char **argv)
{
    base::IOManager iom(1, true);
    std::string host = "www.baidu.com";
    int intervalMs = 1000;
    int timeoutMs = 500;
    WeakNetMgr::ptr weak_mgr = std::make_shared<WeakNetMgr>(&iom);
    weak_mgr->init();
    iom.schedule([weak_mgr, host, intervalMs, timeoutMs] {
        LOG_INFO(LogModule::RTT, "RTT monitor thread started");

        while (_LIKELY(running)) {    
            try {
                // 调用线程安全的方法更新RTT和网络状态
                // 该方法会向目标主机发送检测包（如ICMP），计算RTT，并更新网络接口的质量状态
                // 返回值changed表示本次更新是否导致了RTT或质量状态的变化
                bool changed = weak_mgr->updateRttAndState(host, timeoutMs);

                // 若检测到状态变化，且服务实例存在，则发送信号通知
                if (changed) {
                    LOG_INFO(LogModule::RTT, "RTT/Quality updated - emitting signal");
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
    });

    return 0;
}