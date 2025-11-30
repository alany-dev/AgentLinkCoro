#include "net_traffic.hpp"
#include "flow_monitor.bpf.skel.h"
#include "logger.hpp"
#include "net_iface.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <string>
#include <thread>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <net/if.h>
#include <unordered_map>
#include <sstream>
#include <errno.h>
#include <cmath>
#include <numeric>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <vector>

namespace monitor::weaknet
{

NetTrafficAnalyzer::NetTrafficAnalyzer()
{
}

NetTrafficAnalyzer::~NetTrafficAnalyzer()
{
    // 1. 若已挂载eBPF程序，先取消挂载
    if (attached_ && skel_) {
        flow_monitor_bpf__detach(skel_); // 取消eBPF程序与内核探针的绑定
        LOG_INFO(LogModule::WEAK_MGR, "eBPF程序已自动取消挂载");
    }

    // 2. 销毁eBPF skeleton，释放内核资源（程序、映射、ring buffer等）
    if (skel_) {
        flow_monitor_bpf__destroy(skel_); // 释放skeleton占用的所有资源
        skel_ = nullptr;
        LOG_INFO(LogModule::WEAK_MGR, "eBPF skeleton已销毁");
    }
    attached_ = false; // 重置挂载状态
}

/**
 * @brief 为指定网络接口初始化流量分析器（加载并附加eBPF程序）
 * @return 初始化成功返回true，失败返回false
 */
bool NetTrafficAnalyzer::init()
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print([](enum libbpf_print_level level, const char *fmt, va_list args) -> int {
        (void)level;
        return vfprintf(stderr, fmt, args);
    });

    if (attached_)
        return true;

    skel_ = flow_monitor_bpf__open_and_load();
    if (!skel_) {
        fprintf(stderr, "加载 eBPF 程序失败\n");
        return false;
    }

    int err = flow_monitor_bpf__attach(skel_);
    if (err) {
        fprintf(stderr, "附加探针失败: %d\n", err);
        flow_monitor_bpf__destroy(skel_);
        return false;
    }

    attached_ = true;
    return true;
}

bool NetTrafficAnalyzer::updateInterface(const std::vector<uint32_t> &addIfaces,
                                         const std::vector<uint32_t> &removeIfaces)
{
    if (attached_ || !skel_)
        return false;
    MutexType::Lock lock(boundIfaceIndexMutex_);
    // 移除已删除的接口
    for (const auto &ifaceIndex : removeIfaces) {
        auto it = std::find(boundIfaceIndex_.begin(), boundIfaceIndex_.end(), ifaceIndex);
        if (it != boundIfaceIndex_.end()) {
            boundIfaceIndex_.erase(it);
            if (ifaceIndex > 0) {
                __u32 cfg_iface = 0;
                bpf_map_update_elem(bpf_map__fd(skel_->maps.cfg_iface), &ifaceIndex, &cfg_iface,
                                    BPF_ANY);
            }
        }
    }
    // 添加新接口
    for (const auto &ifaceIndex : addIfaces) {
        if (std::find(boundIfaceIndex_.begin(), boundIfaceIndex_.end(), ifaceIndex)
            != boundIfaceIndex_.end()) {
            LOG_INFO_F(LogModule::WEAK_MGR, "Interface already monitored: %d", ifaceIndex);
            continue;
        }
        boundIfaceIndex_.push_back(ifaceIndex);
        if (ifaceIndex > 0) {
            __u32 cfg_iface = 1;
            bpf_map_update_elem(bpf_map__fd(skel_->maps.cfg_iface), &ifaceIndex, &cfg_iface,
                                BPF_ANY);
        }
    }
    return true;
}

/**
 * @brief 采样指定时间间隔内的顶级流量流（按bps排序）
 * @param intervalSec 采样间隔（秒）
 * @param topN 返回的顶级流数量
 * @return 包含顶级流信息的FlowRate向量
 */
std::vector<FlowRate> NetTrafficAnalyzer::sampleTopFlows(int intervalSec, int topN)
{
    std::vector<FlowRate> out;
    if (!attached_ || !skel_)
        return out;

    std::unordered_map<std::string, flow_data> snapBaseline; // 基线数据（t0）
    std::unordered_map<std::string, flow_data> snapCurrent;

    // 辅助函数：触发内核推送数据并通过 Ring Buffer 收集快照
    auto collectSnapshot = [this](std::unordered_map<std::string, flow_data> &snap) -> bool {
        snap.clear(); // 清空快照，避免残留数据

        // 1. 设置触发标志，通知内核推送数据
        __u32 trigger_key = 0, trigger_flag = 1;
        int err = bpf_map_update_elem(bpf_map__fd(skel_->maps.trigger), &trigger_key, &trigger_flag,
                                      BPF_ANY);
        if (err) {
            LOG_ERROR_F(LogModule::WEAK_MGR, "触发内核数据推送失败 errno: %d", errno);
            return false;
        }

        // 2. 创建 Ring Buffer，绑定回调和快照容器（ctx 传递快照指针）
        struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel_->maps.events),
                                                  handleEvent, // 静态回调函数
                                                  &snap, // 上下文：当前要填充的快照
                                                  nullptr);
        if (!rb) {
            LOG_ERROR(LogModule::WEAK_MGR, "创建 Ring Buffer 失败");
            return false;
        }

        // 3. Poll Ring Buffer 接收数据（超时 2 秒，确保数据接收完毕）
        const int POLL_TIMEOUT_MS = 2000;
        err = ring_buffer__poll(rb, POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            LOG_ERROR_F(LogModule::WEAK_MGR, "Ring Buffer 接收数据失败: %d", err);
            ring_buffer__free(rb);
            return false;
        }

        // 4. 释放 Ring Buffer（避免内存泄漏）
        ring_buffer__free(rb);
        LOG_INFO_F(LogModule::WEAK_MGR, "快照采集完成，有效流数量: %d", snap.size());
        return true;
    };

    // -------------------------- 第一次采集：基线数据 --------------------------
    if (!collectSnapshot(snapBaseline)) {
        return out;
    }

    // -------------------------- 等待采样间隔 --------------------------
    LOG_INFO_F(LogModule::WEAK_MGR, "等待 %d 秒采样间隔...", intervalSec);
    std::this_thread::sleep_for(std::chrono::seconds(intervalSec));

    // -------------------------- 第二次采集：当前数据 --------------------------
    if (!collectSnapshot(snapCurrent)) {
        return out;
    }

    // -------------------------- 计算两次采集的差值 --------------------------
    for (const auto &[flowKey, currData] : snapCurrent) {
        // 查找基线数据中的对应流
        auto baselineIt = snapBaseline.find(flowKey);
        __u64 prevBytes = 0, prevPkts = 0;
        __u32 prevPid = 0;

        if (baselineIt != snapBaseline.end()) {
            prevBytes = baselineIt->second.bytes;
            prevPkts = baselineIt->second.packets;
            prevPid = baselineIt->second.pid;
        }

        // 计算增量（确保非负，避免内核 LRU 淘汰导致的数值回滚）
        __u64 deltaBytes = currData.bytes >= prevBytes ? (currData.bytes - prevBytes) : 0;
        __u64 deltaPkts = currData.packets >= prevPkts ? (currData.packets - prevPkts) : 0;

        // 无增量则跳过
        if (deltaBytes == 0 && deltaPkts == 0) {
            continue;
        }

        struct conn_key key {
        };
        sscanf(flowKey.c_str(), "%u:%hu-%u:%hu/%hhu", &key.saddr, &key.sport, &key.daddr,
               &key.dport, &key.protocol);

        FlowRate fr;
        fr.src = ip_str(key.saddr);
        fr.dst = ip_str(key.daddr);
        fr.sport = ntohs(key.sport);
        fr.dport = ntohs(key.dport);
        fr.proto = (key.protocol == 6)
                       ? "TCP"
                       : (key.protocol == 17 ? "UDP" : std::to_string(key.protocol));

        fr.bps =
            deltaBytes
            / static_cast<uint64_t>(intervalSec); // 字节/秒（bps 此处为字节速率，如需比特需×8）
        fr.pps = deltaPkts / static_cast<uint64_t>(intervalSec);
        fr.pid = currData.pid != 0 ? currData.pid : prevPid;

        out.push_back(fr);
    }

    // -------------------------- 按 bps 降序排序，取前 topN --------------------------
    std::sort(out.begin(), out.end(),
              [](const FlowRate &a, const FlowRate &b) { return a.bps > b.bps; });

    if (static_cast<int>(out.size()) > topN) {
        out.resize(topN);
    }

    LOG_INFO_F(LogModule::WEAK_MGR, "采样完成，返回前 %d 条顶级流", topN);
    return out;
}

std::string NetTrafficAnalyzer::generateFlowKey(const FlowRate &flow)
{
    std::ostringstream oss;
    oss << flow.src << ":" << flow.sport << "-" << flow.dst << ":" << flow.dport << "/"
        << flow.proto;
    return oss.str();
}

/**
 * @brief 判断当前流量是否为突发流量（基于历史平均值）
 * @param history 该流的历史流量记录
 * @param currentBps 当前流量速率（bps）
 * @return 是突发流量返回true，否则返回false
 */
bool NetTrafficAnalyzer::isBurstTraffic(const TrafficHistory &history, uint64_t currentBps)
{
    // 历史数据不足3个点时，无法判断突发
    if (history.bpsHistory.size() < 3)
        return false;

    // 计算历史bps平均值
    uint64_t avgBps = std::accumulate(history.bpsHistory.begin(), history.bpsHistory.end(),
                                      0ULL // 初始值（无符号长整型0）
                                      )
                      / history.bpsHistory.size();

    // 若当前流量超过平均值的burstMultiplier_倍，则判定为突发
    return currentBps > (avgBps * burstMultiplier_);
}

/**
 * @brief 判断当前流量是否为可疑流量（基于阈值和进程信息）
 * @param currentBps 当前流量速率（bps）
 * @param pid 流量关联的进程ID
 * @return 是可疑流量返回true，否则返回false
 */
bool NetTrafficAnalyzer::isSuspiciousTraffic(uint64_t currentBps, uint32_t pid)
{
    // 首先检查是否超过可疑流量阈值
    if (currentBps < suspiciousThresholdBps_)
        return false;

    // 可扩展：添加基于PID的异常检测（如特定进程的异常流量）
    // 示例：if (pid == known_malicious_pid) return true;
    return true;
}

/**
 * @brief 计算异常的严重程度（0.0~1.0）
 * @param currentBps 当前流量速率
 * @param threshold 阈值速率
 * @param multiplier 阈值倍数（超过此倍数则严重程度为1.0）
 * @return 严重程度（0.0表示无异常，1.0表示最严重）
 */
double NetTrafficAnalyzer::calculateSeverity(uint64_t currentBps, uint64_t threshold,
                                             double multiplier)
{
    if (currentBps <= threshold)
        return 0.0; // 未超过阈值，无严重度

    // 计算当前值与阈值的比率
    double ratio = (double)currentBps / threshold;
    // 严重度映射：(threshold, threshold*multiplier] → (0,1]
    double severity = std::min(1.0, (ratio - 1.0) / (multiplier - 1.0));
    return severity;
}

/**
 * @brief 检测流量异常（突发、可疑、高流量）
 * @param intervalSec 检测间隔（秒）
 * @param burstThresholdBps 突发流量绝对阈值
 * @param suspiciousThresholdBps 可疑流量阈值
 * @param burstMultiplier 突发流量相对倍数阈值
 * @return 检测到的异常列表
 */
std::vector<TrafficAnomaly> NetTrafficAnalyzer::detectAnomalies(int intervalSec,
                                                                uint64_t burstThresholdBps,
                                                                uint64_t suspiciousThresholdBps,
                                                                double burstMultiplier)
{
    std::vector<TrafficAnomaly> anomalies;
    if (!attached_)
        return anomalies; // 未初始化则返回空

    // 获取当前流量数据（采样更多流以全面检测异常）
    auto flows = sampleTopFlows(intervalSec, 1000);

    // 加锁保护历史记录（多线程安全）
    MutexType::Lock lock(historyMutex_);
    auto now = std::chrono::system_clock::now(); // 当前时间戳

    // 遍历每个流，更新历史并检测异常
    for (const auto &flow : flows) {
        std::string flowKey = generateFlowKey(flow);
        // 更新该流的历史记录
        auto &history = trafficHistory_[flowKey];       // 若不存在则自动创建
        history.bpsHistory.push_back(flow.bps);         // 记录当前bps
        history.ppsHistory.push_back(flow.pps);         // 记录当前pps
        history.totalBytes += flow.bps * intervalSec;   // 累计总字节数
        history.totalPackets += flow.pps * intervalSec; // 累计总包数
        history.lastUpdate = now;                       // 更新最后活动时间

        // 限制历史记录大小（避免内存溢出）
        if (history.bpsHistory.size() > MAX_HISTORY_SIZE) {
            history.bpsHistory.pop_front(); // 移除最旧的记录
            history.ppsHistory.pop_front();
        }

        // 检测1：突发流量（同时满足绝对阈值和相对倍数）
        if (flow.bps > burstThresholdBps && isBurstTraffic(history, flow.bps)) {
            TrafficAnomaly anomaly;
            anomaly.flowKey = flowKey;
            anomaly.anomalyType = "burst"; // 异常类型：突发
            anomaly.currentBps = flow.bps;
            anomaly.thresholdBps = burstThresholdBps;
            anomaly.severity = calculateSeverity(flow.bps, burstThresholdBps, burstMultiplier);
            anomaly.timestamp = now;
            anomaly.description =
                "检测到突发流量: " + std::to_string(flow.bps / (1024 * 1024)) + " MB/s";
            anomalies.push_back(anomaly);
        }

        // 检测2：可疑流量（超过可疑阈值）
        if (isSuspiciousTraffic(flow.bps, flow.pid)) {
            TrafficAnomaly anomaly;
            anomaly.flowKey = flowKey;
            anomaly.anomalyType = "suspicious"; // 异常类型：可疑
            anomaly.currentBps = flow.bps;
            anomaly.thresholdBps = suspiciousThresholdBps;
            anomaly.severity =
                calculateSeverity(flow.bps, suspiciousThresholdBps, 2.0); // 2倍阈值为严重
            anomaly.timestamp = now;
            anomaly.description = "检测到可疑流量: " + std::to_string(flow.bps / (1024 * 1024))
                                  + " MB/s, PID: " + std::to_string(flow.pid);
            anomalies.push_back(anomaly);
        }

        // 检测3：高流量（超过阈值但未达可疑标准）
        if (flow.bps > suspiciousThresholdBps) {
            TrafficAnomaly anomaly;
            anomaly.flowKey = flowKey;
            anomaly.anomalyType = "high_volume"; // 异常类型：高流量
            anomaly.currentBps = flow.bps;
            anomaly.thresholdBps = suspiciousThresholdBps;
            anomaly.severity =
                calculateSeverity(flow.bps, suspiciousThresholdBps, 1.5); // 1.5倍阈值为严重
            anomaly.timestamp = now;
            anomaly.description =
                "检测到高流量: " + std::to_string(flow.bps / (1024 * 1024)) + " MB/s";
            anomalies.push_back(anomaly);
        }
    }

    return anomalies;
}

/**
 * @brief 获取所有流的历史流量记录
 * @return 流标识到历史记录的映射（线程安全）
 */
std::map<std::string, TrafficHistory> NetTrafficAnalyzer::getTrafficHistory()
{
    MutexType::Lock lock(historyMutex_);
    return trafficHistory_;
}

/**
 * @brief 设置异常检测的参数（线程安全）
 * @param burstThreshold 突发流量绝对阈值（bps）
 * @param suspiciousThreshold 可疑流量阈值（bps）
 * @param burstMultiplier 突发流量相对倍数
 */
void NetTrafficAnalyzer::setAnomalyDetectionParams(uint64_t burstThreshold,
                                                   uint64_t suspiciousThreshold,
                                                   double burstMultiplier)
{
    MutexType::Lock lock(historyMutex_);
    burstThresholdBps_ = burstThreshold;
    suspiciousThresholdBps_ = suspiciousThreshold;
    burstMultiplier_ = burstMultiplier;
}

/**
 * @brief 获取实时流量统计信息
 * @return 包含总bps、总pps、活跃流数和时间戳的统计结构
 */
NetTrafficAnalyzer::RealTimeStats NetTrafficAnalyzer::getRealTimeStats()
{
    RealTimeStats stats;
    if (!attached_)
        return stats; // 未初始化则返回空

    // 1秒采样获取当前流量（更多流以确保统计准确）
    auto flows = sampleTopFlows(1, 1000);

    stats.timestamp = std::chrono::system_clock::now(); // 记录采样时间
    stats.activeFlows = flows.size();                   // 活跃流数量

    // 累加总流量
    for (const auto &flow : flows) {
        stats.totalBps += flow.bps; // 总每秒字节数
        stats.totalPps += flow.pps; // 总每秒包数
    }

    return stats;
}

/**
 * @brief 清除所有流量历史记录（线程安全）
 */
void NetTrafficAnalyzer::clearHistory()
{
    MutexType::Lock lock(historyMutex_);
    trafficHistory_.clear();
}
} // namespace monitor::weaknet