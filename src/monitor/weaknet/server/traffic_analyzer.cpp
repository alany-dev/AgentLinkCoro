/**
 * @file traffic_analyzer.cpp
 * @brief 流量分析线程实现文件
 *
 * 实现TrafficAnalyzer类的核心功能，包括线程管理、流量监控、异常检测等。
 * 支持动态添加和移除监控的网络接口，实现多网卡同时监控。
 * 该文件包含了所有方法的具体实现代码。
 */
#include "traffic_analyzer.hpp"
#include "logger.hpp"
#include "traffic_analyzer.hpp"
#include "base/macro.h"
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <algorithm>
#include <sstream>

namespace monitor::weaknet
{

namespace
{
    std::string vec_to_str(std::vector<uint32_t> vec)
    {
        std::ostringstream oss;
        for (const auto &idx : vec) {
            oss << idx << " ";
        }
        return oss.str();
    }
} // namespace

/**
 * @brief TrafficAnalyzer构造函数实现
 *
 * 初始化TrafficAnalyzer对象的成员变量，包括：
 * 1. 将running_状态设置为false
 * 2. 设置默认分析间隔为10秒
 * 3. 获取NetTrafficAnalyzer的单例实例
 */
TrafficAnalyzer::TrafficAnalyzer(base::IOManager *io_mgr)
    : m_io_mgr(io_mgr), running_(false), interval_seconds_(10)
{
}

/**
 * @brief TrafficAnalyzer析构函数实现
 *
 * 确保在对象销毁前调用stop()方法停止所有正在运行的分析线程，
 * 防止资源泄漏和线程未正确终止的问题。
 */
TrafficAnalyzer::~TrafficAnalyzer()
{
    if (!running_.load()) {
        return;
    }
    running_.store(false);

    // 等待分析线程安全退出
    if (analyzer_thread_ && analyzer_thread_->joinable()) {
        analyzer_thread_->join();
        analyzer_thread_.reset();
    }

    analyzer_->clearHistory();
    LOG_INFO(LogModule::WEAK_MGR, "Traffic analyzer stopped");
}

/**
 * @brief 启动流量分析线程的实现
 *
 * 主要执行以下操作：
 * 1. 检查分析器是否已在运行，如果是则直接返回
 * 2. 保存网络接口名称和分析间隔参数
 * 3. 配置eBPF相关参数
 * 4. 初始化网络接口，支持降级运行模式
 * 5. 创建并启动分析线程
 *
 * @param interface 要监控的网络接口名称
 * @param interval_seconds 分析周期（秒）
 */
void TrafficAnalyzer::start(const std::vector<uint32_t> &interfaces, int interval_seconds)
{
    // 检查分析器是否已经在运行
    if (_LIKELY(running_.load())) {
        LOG_INFO(LogModule::WEAK_MGR, "Traffic analyzer already running");
        return;
    }

    analyzer_ = std::make_shared<NetTrafficAnalyzer>();
    // 设置流量异常检测参数
    analyzer_->setAnomalyDetectionParams(
        5 * 1024 * 1024,  // 突发阈值: 5MB/s，超过此值被视为流量突增
        20 * 1024 * 1024, // 可疑阈值: 20MB/s，超过此值被视为可疑流量
        2.5               // 突发倍数: 2.5倍，与历史均值比较的倍数
    );
    analyzer_->init();

    interval_seconds_ = interval_seconds;
    analyzer_->updateInterface(interfaces);

    running_.store(true);

    m_io_mgr->schedule(std::bind(&TrafficAnalyzer::analyzeLoop, this));
}

bool TrafficAnalyzer::addInterface(const uint32_t &interface)
{
    return analyzer_->updateInterface({interface});
}

bool TrafficAnalyzer::removeInterface(const uint32_t &interface)
{
    return analyzer_->updateInterface({}, {interface});
}

/**
 * @brief 流量分析主循环的实现
 *
 * 在线程中运行的核心分析逻辑，周期性执行以下任务：
 * 1. 获取实时流量统计数据并更新缓存
 * 2. 检测异常流量模式
 * 3. 记录流量统计信息
 * 4. 识别并记录Top流量连接
 * 5. 在指定的分析间隔内休眠
 *
 * 该方法采用多层异常处理机制，确保即使在部分功能不可用时仍能继续运行。
 */
void TrafficAnalyzer::analyzeLoop()
{
    LOG_INFO(LogModule::WEAK_MGR, "Traffic analysis loop started");

    while (running_.load()) {
        try {
            // 获取实时统计（如果eBPF可用）
            NetTrafficAnalyzer::RealTimeStats stats;
            bool hasStats = false;

            try {
                stats = analyzer_->getRealTimeStats();
                hasStats = true;

                // 更新缓存
                {
                    MutexType::Lock lock(stats_mutex_);
                    cached_stats_ = stats;
                }
            } catch (const std::exception &e) {
                LOG_INFO(LogModule::WEAK_MGR,
                         "Traffic stats unavailable (eBPF not working): " << e.what());
            }

            // 检测异常流量（如果eBPF可用）
            if (hasStats) {
                try {
                    auto anomalies = analyzer_->detectAnomalies(5);
                    if (!anomalies.empty()) {
                        LOG_INFO(LogModule::WEAK_MGR,
                                 "Detected " << anomalies.size() << " traffic anomalies");
                        for (const auto &anomaly : anomalies) {
                            LOG_INFO(LogModule::WEAK_MGR,
                                     "Anomaly: " << anomaly.anomalyType << " on " << anomaly.flowKey
                                                 << " (severity: " << (anomaly.severity * 100)
                                                 << "%)");
                        }
                    }
                } catch (const std::exception &e) {
                    LOG_INFO(LogModule::WEAK_MGR, "Anomaly detection unavailable: " << e.what());
                }
            }

            // 记录详细流量统计
            if (hasStats) {

                LOG_INFO(LogModule::WEAK_MGR,
                         "TRAFFIC_MONITOR: Total=" << (stats.totalBps / (1024 * 1024))
                                                   << "MB/s, Flows=" << stats.activeFlows
                                                   << ", PPS=" << stats.totalPps);

                // 获取Top流量连接并记录
                try {
                    auto topFlows = analyzer_->sampleTopFlows(5, 5);
                    if (!topFlows.empty()) {
                        LOG_INFO(LogModule::WEAK_MGR, "TOP_FLOWS: ");
                        for (size_t i = 0; i < std::min(topFlows.size(), size_t(3)); ++i) {
                            const auto &flow = topFlows[i];

                            LOG_INFO(LogModule::WEAK_MGR,
                                     "  " << (i + 1) << ". " << flow.proto << " " << flow.src << ":"
                                          << flow.sport << " -> " << flow.dst << ":" << flow.dport
                                          << " | " << (flow.bps / 1024) << "KB/s, " << flow.pps
                                          << "pps");
                        }
                    }
                } catch (const std::exception &e) {
                    LOG_INFO(LogModule::WEAK_MGR, "Top flows unavailable: " << e.what());
                }
            } else {
                LOG_INFO(LogModule::WEAK_MGR, "TRAFFIC_MONITOR: Running in degraded "
                                              "mode (no eBPF data available)");
            }

        } catch (const std::exception &e) {
            LOG_ERROR(LogModule::WEAK_MGR, "Traffic analysis error: " << e.what());
        }
        std::this_thread::sleep_for(std::chrono::seconds(interval_seconds_));
    }

    LOG_INFO(LogModule::WEAK_MGR, "Traffic analysis loop stopped");
}

NetTrafficAnalyzer::RealTimeStats TrafficAnalyzer::getCurrentStats()
{
    MutexType::Lock lock(stats_mutex_);
    return cached_stats_;
}

std::vector<FlowRate> TrafficAnalyzer::getTopFlows(int sample_seconds, int top_count) const
{
    return analyzer_->sampleTopFlows(sample_seconds, top_count);
}

std::vector<TrafficAnomaly> TrafficAnalyzer::detectAnomalies(int detection_seconds) const
{
    return analyzer_->detectAnomalies(detection_seconds);
}

std::map<std::string, TrafficHistory> TrafficAnalyzer::getTrafficHistory() const
{
    return analyzer_->getTrafficHistory();
}

} // namespace monitor::weaknet
