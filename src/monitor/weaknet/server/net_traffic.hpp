#pragma once

#include "base/coro/iomanager.h"
#include "base/mutex.h"
#include "base/singleton.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <chrono>
#include <deque>
#include <map>
#include <sstream>
#include "flow_monitor.bpf.skel.h"

namespace monitor::weaknet
{

// 定义eBPF映射中的键值结构（与内核态eBPF程序定义一致）
// 键：流的唯一标识（源IP、目的IP、源端口、目的端口、协议）
struct conn_key {
    __u32 saddr;   // 源IP（网络字节序）
    __u32 daddr;   // 目的IP（网络字节序）
    __u16 sport;   // 源端口（网络字节序）
    __u16 dport;   // 目的端口（网络字节序）
    __u8 protocol; // 协议（6=TCP，17=UDP）
};

// 值：流的统计数据（字节数、包数、进程ID）
struct flow_data {
    __u64 bytes;   // 总字节数
    __u64 packets; // 总包数
    __u32 pid;     // 关联的进程ID
};

struct flow_event {
    struct conn_key key;
    struct flow_data data;
};

struct FlowRate {
    std::string src;
    std::string dst;
    int sport = 0;
    int dport = 0;
    std::string proto; // TCP/UDP
    uint64_t bps = 0;  // bytes per second
    uint64_t pps = 0;  // packets per second
    uint32_t pid = 0;
};

// 流量异常检测结果
struct TrafficAnomaly {
    std::string flowKey;     // 连接标识
    std::string anomalyType; // 异常类型: "burst", "suspicious", "high_volume"
    uint64_t currentBps;     // 当前速率
    uint64_t thresholdBps;   // 阈值
    double severity;         // 严重程度 0.0-1.0
    std::chrono::system_clock::time_point timestamp;
    std::string description; // 异常描述
};

// 流量历史记录
struct TrafficHistory {
    std::deque<uint64_t> bpsHistory; // 历史速率记录
    std::deque<uint64_t> ppsHistory; // 历史包速率记录
    std::chrono::system_clock::time_point lastUpdate;
    uint64_t totalBytes = 0;
    uint64_t totalPackets = 0;
};

class NetTrafficAnalyzer
{
public:
    using MutexType = base::Spinlock;
    using ptr = std::shared_ptr<NetTrafficAnalyzer>;

    NetTrafficAnalyzer();
    ~NetTrafficAnalyzer();

    // 初始化并附加到内核（按接口过滤），成功返回 true
    bool init();

    bool updateInterface(const std::vector<uint32_t> &addIfaces = {},
                         const std::vector<uint32_t> &removeIfaces = {});

    // 采样 intervalSec 秒窗口，返回 TopN 流信息
    std::vector<FlowRate> sampleTopFlows(int intervalSec, int topN);

    // 异常流量检测功能
    std::vector<TrafficAnomaly>
    detectAnomalies(int intervalSec,
                    uint64_t burstThresholdBps = 10 * 1024 * 1024,      // 10MB/s
                    uint64_t suspiciousThresholdBps = 50 * 1024 * 1024, // 50MB/s
                    double burstMultiplier = 3.0);                      // 突发倍数阈值

    // 获取流量历史统计
    std::map<std::string, TrafficHistory> getTrafficHistory();

    // 设置异常检测参数
    void setAnomalyDetectionParams(uint64_t burstThreshold, uint64_t suspiciousThreshold,
                                   double burstMultiplier);

    // 获取实时流量统计
    struct RealTimeStats {
        uint64_t totalBps = 0;
        uint64_t totalPps = 0;
        size_t activeFlows = 0;
        std::chrono::system_clock::time_point timestamp;
    };
    RealTimeStats getRealTimeStats();

    // 清理历史数据
    void clearHistory();

    std::vector<uint32_t> getBoundIfaceIndex() const { return boundIfaceIndex_; }

private:
    MutexType boundIfaceIndexMutex_;
    std::vector<uint32_t> boundIfaceIndex_; // 绑定的网卡索引列表

    bool attached_ = false;
    struct flow_monitor_bpf *skel_ = nullptr;

    // 异常检测相关
    MutexType historyMutex_;
    std::map<std::string, TrafficHistory> trafficHistory_;
    uint64_t burstThresholdBps_ = 10 * 1024 * 1024;      // 10MB/s
    uint64_t suspiciousThresholdBps_ = 50 * 1024 * 1024; // 50MB/s
    double burstMultiplier_ = 3.0;                       // 突发倍数阈值
    static constexpr size_t MAX_HISTORY_SIZE = 60;       // 保留60个历史记录

    // 内部方法
    std::string generateFlowKey(const FlowRate &flow);
    bool isBurstTraffic(const TrafficHistory &history, uint64_t currentBps);
    bool isSuspiciousTraffic(uint64_t currentBps, uint32_t pid);
    double calculateSeverity(uint64_t currentBps, uint64_t threshold, double multiplier);

    static std::string keyStr(const conn_key &k)
    {
        std::ostringstream oss;
        oss << k.saddr << ":" << k.sport << "-" << k.daddr << ":" << k.dport << "/"
            << static_cast<int>(k.protocol);
        return oss.str();
    }

    static std::string ip_str(__u32 net_ip)
    {
        struct in_addr addr;
        addr.s_addr = net_ip;
        char buf[INET_ADDRSTRLEN] = {0};
        return inet_ntop(AF_INET, &addr, buf, sizeof(buf)) ? buf : "unknown";
    }

    static int handleEvent(void *ctx, void *data, size_t data_sz)
    {
        // ctx 传递的是存储快照的 unordered_map 指针
        auto *snap = reinterpret_cast<std::unordered_map<std::string, flow_data> *>(ctx);
        const auto *e = reinterpret_cast<const flow_event *>(data);

        // 生成流唯一标识，存入快照
        std::string key = keyStr(e->key);
        snap->emplace(key, e->data);
        return 0;
    }
};
} // namespace monitor::weaknet