#pragma once

#include <thread>
#include <atomic>
#include <string>
#include <memory>
#include <vector>
#include <map>
#include "base/coro/iomanager.h"
#include "base/mutex.h"
#include "net_traffic.hpp"

namespace monitor::weaknet
{

/**
 * @class TrafficAnalyzer
 * @brief 流量分析线程管理器，负责周期性监控网络流量并进行异常检测
 *
 * 该类封装了网络流量分析的核心功能，通过周期性地收集和分析网络接口的流量数据，
 * 支持实时流量监控、异常检测、Top流量连接统计以及流量历史记录管理。
 * 采用线程安全设计，确保在多线程环境下的数据一致性。
 * 支持动态添加和移除监控的网络接口。
 */
class TrafficAnalyzer
{
public:
    using MutexType = base::Spinlock;
    TrafficAnalyzer(base::IOManager *io_mgr);

    ~TrafficAnalyzer();

    bool isRunning() const { return running_.load(); }

    /**
     * @brief 启动流量分析线程
     *
     * 初始化网络接口并创建新线程执行周期性流量分析任务。
     * 如果分析器已经在运行，则不执行任何操作。
     *
     * @param interfaces 要监控的网络接口索引向量（如{0, 1}等）
     * @param interval_seconds 分析周期，单位为秒，默认为10秒
     */
    void start(const std::vector<uint32_t> &interfaces, int interval_seconds = 10);

    /**
     * @brief 添加要监控的网络接口
     *
     * 动态添加新的网络接口到监控列表。如果分析器正在运行，将立即开始监控新接口。
     *
     * @param interface 要添加的网络接口索引
     * @return 是否成功添加
     */
    bool addInterface(const uint32_t &interface);

    /**
     * @brief 移除要监控的网络接口
     *
     * 从监控列表中移除指定的网络接口。
     *
     * @param interface 要移除的网络接口索引
     * @return 是否成功移除
     */
    bool removeInterface(const uint32_t &interface);

    /**
     * @brief 获取当前流量统计数据
     *
     * 以线程安全的方式返回最新的流量统计信息。
     */
    NetTrafficAnalyzer::RealTimeStats getCurrentStats();

    /**
     * @brief 获取流量消耗最高的连接列表
     *
     * 采样指定时间内的网络流量，返回流量消耗最大的前N个连接。
     *
     * @param sample_seconds 采样持续时间，单位为秒，默认为5秒
     * @param top_count 返回的连接数量，默认为10个
     * @return 按流量降序排列的FlowRate对象向量
     */
    std::vector<FlowRate> getTopFlows(int sample_seconds = 5, int top_count = 10) const;

    /**
     * @brief 检测网络流量异常
     *
     * 分析指定时间窗口内的流量模式，识别潜在的异常流量行为。
     *
     * @param detection_seconds 检测持续时间，单位为秒，默认为5秒
     * @return 检测到的流量异常列表
     */
    std::vector<TrafficAnomaly> detectAnomalies(int detection_seconds = 5) const;

    /**
     * @brief 获取流量历史记录
     *
     * 返回按照不同键值（如协议类型、IP地址等）分类的流量历史统计数据。
     *
     * @return 键为分类标识，值为对应TrafficHistory对象的映射
     */
    std::map<std::string, TrafficHistory> getTrafficHistory() const;

private:
    void analyzeLoop();
    void updateMonitoredInterfaces();

    base::IOManager *m_io_mgr;

    NetTrafficAnalyzer::ptr analyzer_;

    std::atomic<bool> running_;

    int interval_seconds_;

    MutexType stats_mutex_;                          // 保护stats缓存的互斥锁
    NetTrafficAnalyzer::RealTimeStats cached_stats_; // 按接口缓存统计数据

    std::unique_ptr<std::thread> analyzer_thread_; // 分析线程的智能指针
};

} // namespace monitor::weaknet
