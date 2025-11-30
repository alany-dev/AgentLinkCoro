// network_quality_assessor.cpp
// 网络质量评估器实现
// 实现要点：
// - 将多个子指标（RTT/TCP丢包/RSSI/流量特征）转换为 0-100 的子分；
// - 通过可调整权重的加权平均得到总分，并映射到离散质量等级；
// - 伴随问题检测，输出结构化 JSON 详情，便于记录与上层消费；
// - 提供质量变化检测，辅助触发事件/告警等上层逻辑。

#include "network_quality_assessor.hpp"
#include "logger.hpp"
#include <sstream>
#include <algorithm>
#include <cmath>
#include <iomanip>

namespace monitor::weaknet {

NetworkQualityAssessor::NetworkQualityAssessor() 
    : qualityChangeCounter_(0) {
    lastResult_.level = NetworkQualityLevel::UNKNOWN;
    lastResult_.score = 0.0;
}

NetworkQualityResult NetworkQualityAssessor::assessQuality(const std::vector<NetInfo>& interfaces) {
    // 无可用接口：返回 UNKNOWN 并附带错误详情
    if (interfaces.empty()) {
        NetworkQualityResult result;
        result.level = NetworkQualityLevel::UNKNOWN;
        result.levelName = "UNKNOWN";
        result.score = 0.0;
        result.details = "{\"error\":\"No interfaces available\"}";
        result.issues.push_back("No network interfaces detected");
        return result;
    }

    // 找到当前使用的接口
    // 优先使用 usingNow() 为 true 的接口；若不存在，回退为第一个接口
    const NetInfo* activeInterface = nullptr;
    for (const auto& iface : interfaces) {
        if (iface.usingNow()) {
            activeInterface = &iface;
            break;
        }
    }

    // 如果没有找到活跃接口，使用第一个接口
    if (!activeInterface) {
        activeInterface = &interfaces[0];
    }

    return assessInterfaceQuality(*activeInterface);
}

NetworkQualityResult NetworkQualityAssessor::assessInterfaceQuality(const NetInfo& interface) {
    NetworkQualityResult result;
    
    // 计算各项指标分数
    // 注意：各项子分在 0-100 区间内，越高代表越好
    double rttScore = calculateRttScore(interface.rttMs());
    double tcpLossScore = calculateTcpLossScore(interface.tcpLossRate());
    double rssiScore = calculateRssiScore(interface.rssiDbm());
    double trafficScore = calculateTrafficScore(interface);
    
    // 加权平均计算总分（权重可调整）
    // 默认权重：RTT 0.3、TCP丢包 0.3、RSSI 0.2、流量 0.2
    double totalScore = (rttScore * 0.3 + tcpLossScore * 0.3 + rssiScore * 0.2 + trafficScore * 0.2);
    
    // 根据分数确定质量等级
    // 阈值设计：>=90 优秀；>=75 良好；>=50 一般；其余为差
    if (totalScore >= 90) {
        result.level = NetworkQualityLevel::EXCELLENT;
    } else if (totalScore >= 75) {
        result.level = NetworkQualityLevel::GOOD;
    } else if (totalScore >= 50) {
        result.level = NetworkQualityLevel::FAIR;
    } else {
        result.level = NetworkQualityLevel::POOR;
    }
    
    result.levelName = getQualityLevelName(result.level);
    result.score = totalScore;
    
    // 检测网络问题
    // 输出英文短语便于统一消费，如日志/告警/前端展示
    result.issues = detectNetworkIssues(interface, totalScore);
    
    // 生成详细质量信息
    // details 为 JSON 字符串，包含原始指标、派生信息与问题数组
    result.details = generateQualityDetails(interface, totalScore, result.issues);
    
    // 检查质量是否发生变化
    // 定义：等级改变或分数差绝对值 > 10 视为显著变化
    if (hasQualityChanged(result)) {
        qualityChangeCounter_++;
        LOG_INFO(LogModule::WEAK_MGR, "网络质量变化: " << result.levelName 
            << " (分数: " << std::fixed << std::setprecision(1) << result.score 
            << ", 接口: " << interface.ifName() << ")");
    }
    
    lastResult_ = result;
    return result;
}

std::string NetworkQualityAssessor::getQualityLevelName(NetworkQualityLevel level) {
    switch (level) {
        case NetworkQualityLevel::EXCELLENT: return "EXCELLENT";
        case NetworkQualityLevel::GOOD: return "GOOD";
        case NetworkQualityLevel::FAIR: return "FAIR";
        case NetworkQualityLevel::POOR: return "POOR";
        case NetworkQualityLevel::UNKNOWN: 
        default: return "UNKNOWN";
    }
}

std::string NetworkQualityAssessor::generateQualityDetails(const NetInfo& interface, double score, const std::vector<std::string>& issues) {
    // 目前 details 与 generateMetricsJson 等价；保留该封装以便未来扩展（例如添加更多格式）
    return generateMetricsJson(interface, score, issues);
}

bool NetworkQualityAssessor::hasQualityChanged(const NetworkQualityResult& current) {
    // 分数波动阈值（10 分）用于避免频繁抖动导致的误报
    return (current.level != lastResult_.level) || 
           (std::abs(current.score - lastResult_.score) > 10.0);  // 分数变化超过10分认为有变化
}

void NetworkQualityAssessor::updateThresholds(const QualityThresholds& newThresholds) {
    thresholds_ = newThresholds;
    LOG_INFO(LogModule::WEAK_MGR, "网络质量评估阈值已更新");
}

double NetworkQualityAssessor::calculateRttScore(int rttMs) {
    // 无法测量：给中等分，避免直接判差导致误报
    if (rttMs <= 0) return 50.0;  // 无法测量RTT时给中等分数
    
    // 分段：优秀/良好/一般，超过一般后线性扣分（最多扣 40 分，保底 20）
    if (rttMs <= thresholds_.rtt_excellent) return 100.0;
    if (rttMs <= thresholds_.rtt_good) return 80.0;
    if (rttMs <= thresholds_.rtt_fair) return 60.0;
    
    // 超过fair阈值，按比例递减
    double excess = rttMs - thresholds_.rtt_fair;
    double penalty = std::min(excess * 0.5, 40.0);  // 最多扣40分
    return std::max(20.0, 60.0 - penalty);
}

double NetworkQualityAssessor::calculateTcpLossScore(double lossRate) {
    // 无法测量：给中等分
    if (lossRate < 0) return 50.0;  // 无法测量丢包率时给中等分数
    
    // 分段：优秀/良好/一般，超过一般后线性扣分（最多扣 50 分，保底 10）
    if (lossRate <= thresholds_.tcp_loss_excellent) return 100.0;
    if (lossRate <= thresholds_.tcp_loss_good) return 80.0;
    if (lossRate <= thresholds_.tcp_loss_fair) return 60.0;
    
    // 超过fair阈值，按比例递减
    double excess = lossRate - thresholds_.tcp_loss_fair;
    double penalty = std::min(excess * 20.0, 50.0);  // 最多扣50分
    return std::max(10.0, 60.0 - penalty);
}

double NetworkQualityAssessor::calculateRssiScore(int rssiDbm) {
    // 无法测量：给中等分
    if (rssiDbm == 0) return 50.0;  // 无法测量RSSI时给中等分数
    
    // RSSI 越大越好（-50 优于 -70），因此使用“>=”比较
    if (rssiDbm >= thresholds_.rssi_excellent) return 100.0;
    if (rssiDbm >= thresholds_.rssi_good) return 80.0;
    if (rssiDbm >= thresholds_.rssi_fair) return 60.0;
    
    // 低于fair阈值，按比例递减
    double deficit = thresholds_.rssi_fair - rssiDbm;
    double penalty = std::min(deficit * 2.0, 50.0);  // 最多扣50分
    return std::max(10.0, 60.0 - penalty);
}

double NetworkQualityAssessor::calculateTrafficScore(const NetInfo& interface) {
    // 基于流量分析计算质量分数
    // 初始基准为 70 分，体现“有正常流量时的常见可用状态”
    double score = 70.0;  // 基础分数
    
    // 检查流量异常
    if (interface.trafficActiveFlows() > 0) {
        // 有活跃流量，根据流量特征评分
        double bps = interface.trafficTotalBps();
        double pps = interface.trafficTotalPps();
        
        if (bps > 0 && pps > 0) {
            double avgPacketSize = bps / pps;
            // 较大的平均包（>1KB）通常意味着稳定的大流吞吐，正向加分；
            // 很小的平均包（<200B）可能暗示握手/重传/心跳过多等问题，负向减分。
            if (avgPacketSize > 1000) {  // 平均包大小大于1KB，网络质量较好
                score += 20.0;
            } else if (avgPacketSize < 200) {  // 平均包大小很小，可能有网络问题
                score -= 20.0;
            }
        }
        
        // 检查流数量
        if (interface.trafficActiveFlows() >= thresholds_.min_flows_for_analysis) {
            score += 10.0;  // 有足够的流进行质量分析
        }
    } else {
        score = 50.0;  // 没有活跃流量，给中等分数（避免无流量时过度悲观）
    }
    
    return std::max(0.0, std::min(100.0, score));
}

std::vector<std::string> NetworkQualityAssessor::detectNetworkIssues(const NetInfo& interface, double score) {
    std::vector<std::string> issues;
    
    // RTT问题检测
    if (interface.rttMs() > thresholds_.rtt_fair) {
        issues.push_back("High latency: " + std::to_string(interface.rttMs()) + "ms");
    }
    
    // TCP丢包问题检测
    if (interface.tcpLossRate() > thresholds_.tcp_loss_fair) {
        issues.push_back("High packet loss: " + std::to_string(interface.tcpLossRate()) + "%");
    }
    
    // RSSI问题检测
    if (interface.rssiDbm() != 0 && interface.rssiDbm() < thresholds_.rssi_fair) {
        issues.push_back("Weak signal: " + std::to_string(interface.rssiDbm()) + "dBm");
    }
    
    // 流量问题检测
    if (interface.trafficActiveFlows() > 0) {
        double bps = interface.trafficTotalBps();
        double pps = interface.trafficTotalPps();
        if (bps > 0 && pps > 0) {
            double avgPacketSize = bps / pps;
            if (avgPacketSize < 200) {
                issues.push_back("Small packet size: " + std::to_string(avgPacketSize) + " bytes");
            }
        }
    }
    
    // 总体质量评估
    // 对整体得分过低的情况追加高层级问题概述
    if (score < 30) {
        issues.push_back("Poor overall network quality");
    } else if (score < 50) {
        issues.push_back("Below average network quality");
    }
    
    return issues;
}

std::string NetworkQualityAssessor::generateMetricsJson(const NetInfo& interface, double score, const std::vector<std::string>& issues) {
    std::ostringstream json;
    json << "{";
    json << "\"interface\":\"" << interface.ifName() << "\",";
    json << "\"quality_score\":" << std::fixed << std::setprecision(1) << score << ",";
    json << "\"rtt_ms\":" << interface.rttMs() << ",";
    json << "\"tcp_loss_rate\":" << std::fixed << std::setprecision(2) << interface.tcpLossRate() << ",";
    json << "\"rssi_dbm\":" << interface.rssiDbm() << ",";
    json << "\"traffic_bps\":" << interface.trafficTotalBps() << ",";
    json << "\"traffic_pps\":" << interface.trafficTotalPps() << ",";
    json << "\"active_flows\":" << interface.trafficActiveFlows() << ",";
    // 注意：quality_level 这里沿用 NetInfo::quality() 的数值（可能与本评估等级不同来源）
    json << "\"quality_level\":" << static_cast<int>(interface.quality()) << ",";
    json << "\"using_now\":" << (interface.usingNow() ? "true" : "false") << ",";
    json << "\"issues\":[";
    
    for (size_t i = 0; i < issues.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << issues[i] << "\"";
    }
    
    json << "]}";
    return json.str();
}

} // namespace weaknet_dbus
