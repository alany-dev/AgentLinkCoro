// network_quality_assessor.hpp
// 网络质量评估器：基于多个指标评估网络质量
// 该组件用于对网络接口的整体质量进行量化评估，并输出质量等级、分数以及可序列化的详细指标。
// 评估指标包含：RTT、TCP丢包、RSSI（无线强度）以及基于流量特征的得分，且支持阈值可配置。
// 用法概览：
// 1) 构造 NetworkQualityAssessor；
// 2) 调用 assessQuality(interfaces) 或 assessInterfaceQuality(interface) 获取
// NetworkQualityResult； 3) 可通过 hasQualityChanged 检测显著质量波动； 4) 可通过 updateThresholds
// 调整各项阈值（单位见注释）。

#ifndef NETWORK_QUALITY_ASSESSOR_HPP
#define NETWORK_QUALITY_ASSESSOR_HPP

#include <string>
#include <map>
#include <vector>
#include "net_info.hpp"

namespace monitor::weaknet
{

// 网络质量等级
// 语义定义：
// - EXCELLENT(4): 各项指标处于优异水平，用户体验接近最优；
// - GOOD(3): 指标整体良好，偶有轻微抖动但不影响主要体验；
// - FAIR(2): 一般水平，可能存在延迟/丢包/信号弱导致的可感知影响；
// - POOR(1): 质量较差，明显影响交互（高延迟/高丢包/弱信号/异常流量等）；
// - UNKNOWN(0): 无有效数据支撑评估（无接口或指标缺失）。
enum class NetworkQualityLevel {
    EXCELLENT = 4, // 优秀
    GOOD = 3,      // 良好
    FAIR = 2,      // 一般
    POOR = 1,      // 差
    UNKNOWN = 0    // 未知
};

// 网络质量评估结果
// 说明：
// - level/levelName：质量等级及其字符串表示；
// - score：0-100 归一化质量分数（越高越好）；
// - details：JSON 字符串，包含各项指标与元信息，便于日志与上层展示；
// - issues：检测到的潜在问题列表（英文短句，便于跨系统消费）。
struct NetworkQualityResult {
    NetworkQualityLevel level;
    std::string levelName;
    std::string details;             // JSON格式的详细指标
    double score;                    // 0-100的质量分数
    std::vector<std::string> issues; // 发现的问题列表
};

class NetworkQualityAssessor
{
private:
    // 质量评估阈值配置
    // 单位说明：
    // - RTT：毫秒(ms)
    // - TCP 丢包率：百分比(%)，例如 0.5 表示 0.5%
    // - RSSI：dBm（越接近 0 越强；-50 优于 -70）
    // - 流量分析：基于活跃流和平均包长的启发式打分
    struct QualityThresholds {
        // RTT阈值（毫秒）
        int rtt_excellent = 50;
        int rtt_good = 100;
        int rtt_fair = 200;

        // TCP丢包率阈值（百分比）
        double tcp_loss_excellent = 0.1;
        double tcp_loss_good = 0.5;
        double tcp_loss_fair = 2.0;

        // RSSI阈值（dBm）
        int rssi_excellent = -50;
        int rssi_good = -60;
        int rssi_fair = -70;

        // 流量异常阈值
        double traffic_anomaly_threshold = 0.8; // 异常流量比例阈值
        uint32_t min_flows_for_analysis = 5;         // 最小流数量用于分析
    };

    QualityThresholds thresholds_;
    NetworkQualityResult lastResult_;
    int32_t qualityChangeCounter_;

public:
    NetworkQualityAssessor();

    // 评估网络质量
    // 从多个网络接口中选择当前活跃接口（若无显式活跃则回退到首个接口）进行质量评估。
    // 参数：
    // - interfaces：可用网络接口的快照列表
    // 返回：
    // - NetworkQualityResult：含质量等级、分数、问题列表与 JSON 详情
    NetworkQualityResult assessQuality(const std::vector<NetInfo> &interfaces);

    // 评估单个接口质量
    // 对给定 NetInfo（单个接口）计算各子指标得分并加权合成总分，随后映射为等级。
    // 同时会执行问题检测与详细 JSON 结构生成，并记录质量变化计数。
    NetworkQualityResult assessInterfaceQuality(const NetInfo &interface);

    // 获取质量等级名称
    // 返回值例如："EXCELLENT" / "GOOD" / ...
    static std::string getQualityLevelName(NetworkQualityLevel level);

    // 生成详细质量信息（JSON格式）
    // 将指标与问题列表序列化为 JSON，便于持久化与上层展示。
    std::string generateQualityDetails(const NetInfo &interface, double score,
                                       const std::vector<std::string> &issues);

    // 检查是否有质量变化
    // 定义：等级变化或分数变化绝对值 > 10 视为“有变化”。
    bool hasQualityChanged(const NetworkQualityResult &current);

    // 获取质量变化计数器
    int32_t getQualityChangeCounter() const { return qualityChangeCounter_; }

    // 更新阈值配置
    // 注意：更新阈值不会追溯影响历史结果，仅影响后续评估。
    void updateThresholds(const QualityThresholds &newThresholds);

private:
    // 计算RTT质量分数
    // 逻辑：阈值分段 + 超阈线性扣分（保底 20 分；无数据给中等 50 分）
    double calculateRttScore(int rttMs);

    // 计算TCP丢包质量分数
    // 逻辑：阈值分段 + 超阈线性扣分（保底 10 分；无数据给中等 50 分）
    double calculateTcpLossScore(double lossRate);

    // 计算RSSI质量分数
    // 逻辑：阈值分段 + 低于阈值线性扣分（保底 10 分；无数据给中等 50 分）
    double calculateRssiScore(int rssiDbm);

    // 计算流量质量分数
    // 逻辑：以 70 为基础分；根据平均包长、活跃流数量进行加/减分；无流量给 50 分。
    double calculateTrafficScore(const NetInfo &interface);

    // 检测网络问题
    // 输出可读的英文问题描述，包含高延迟/高丢包/弱信号/异常包长/整体质量差等。
    std::vector<std::string> detectNetworkIssues(const NetInfo &interface, double score);

    // 生成JSON格式的详细指标
    // 输出字段：interface, quality_score, rtt_ms, tcp_loss_rate, rssi_dbm, traffic_bps,
    // traffic_pps, active_flows, quality_level(原接口质量字段数值), using_now, issues[]
    std::string generateMetricsJson(const NetInfo &interface, double score,
                                    const std::vector<std::string> &issues);
};

} // namespace monitor::weaknet

#endif // NETWORK_QUALITY_ASSESSOR_HPP
