#ifndef __QUIC_PACKET_SORTER_HH__
#define __QUIC_PACKET_SORTER_HH__

#include <map>
#include <unordered_map>
#include <vector>
#include <memory>
#include <functional>

#include "quic_frame.h"
#include "quic_packet.h"
#include "quic_utils.h"
#include "quic_congestion.h"

namespace base
{
namespace quic
{
    // 最大数据包编号，使用2^31-1作为上限
    static constexpr uint32_t MAX_PACKET_NUMBER = 0X7FFFFFFF;
    // 最大ACK范围数量，限制内存使用和处理效率
    static constexpr uint32_t MAX_NUMBER_ACK_RANGES = 64;

    class QuicPacket;

    /**
     * @brief 表示一个连续的数据包编号区间
     * 用于高效地跟踪接收到的数据包范围，通过区间合并减少内存使用
     */
    struct PacketInterval {
    public:
        typedef std::shared_ptr<PacketInterval> ptr;

        /**
         * @brief 构造函数
         * @param start 区间起始数据包编号
         * @param end 区间结束数据包编号
         */
        PacketInterval(QuicPacketNumber start, QuicPacketNumber end) : m_start(start), m_end(end) {}

        // 设置区间起始值
        void set_start(QuicPacketNumber start) { m_start = start; }
        // 设置区间结束值
        void set_end(QuicPacketNumber end) { m_end = end; }
        // 获取区间起始值
        QuicPacketNumber start() const { return m_start; }
        // 获取区间结束值
        QuicPacketNumber end() const { return m_end; }

        // 区间起始数据包编号
        QuicPacketNumber m_start = 0;
        // 区间结束数据包编号
        QuicPacketNumber m_end = MAX_PACKET_NUMBER;
    };

    /**
     * @brief 接收数据包历史记录管理
     * 负责跟踪已接收到的数据包编号范围，用于生成ACK帧和检测重复数据包
     */
    class ReceivedPacketHistory
    {
    public:
        typedef std::shared_ptr<ReceivedPacketHistory> ptr;

        /**
         * @brief 记录接收到的数据包
         * @param pn 数据包编号
         * @return 是否为新接收到的数据包（非重复）
         */
        bool receivedPacket(QuicPacketNumber pn);

        /**
         * @brief 将数据包编号添加到接收范围中，并尝试合并相邻区间
         * @param pn 数据包编号
         * @return 是否为新添加的编号
         */
        bool addToRanges(QuicPacketNumber pn);

        /**
         * @brief 清理超出最大范围数量的旧区间，保持内存使用在合理范围
         */
        void maybeDeleteOldRanges();

        /**
         * @brief 删除所有小于指定编号的数据包记录
         * @param pn 数据包编号阈值
         */
        void deleteBelow(QuicPacketNumber pn);

        /**
         * @brief 获取所有ACK范围，用于构造ACK帧
         * @return ACK范围列表
         */
        std::vector<AckRange::ptr> getAckRanges();

        /**
         * @brief 获取最高的ACK范围（最新接收到的连续数据包）
         * @return 最高ACK范围指针，若无数据则返回nullptr
         */
        AckRange::ptr getHighestAckRange();

        /**
         * @brief 检查数据包是否可能是重复的
         * @param pn 数据包编号
         * @return 是否可能重复
         */
        bool isPotentiallyDuplicate(QuicPacketNumber pn);

        /**
         * @brief 将当前状态转换为字符串表示，用于调试
         * @return 状态描述字符串
         */
        std::string toString();

    private:
        // 存储已接收数据包的区间列表，按数据包编号升序排列
        std::list<PacketInterval::ptr> m_ranges;
        // 已删除的最小数据包编号阈值
        uint64_t m_deleted_below;
    };

    /**
     * @brief 接收数据包跟踪器
     * 负责管理接收到的数据包，触发ACK生成，并处理ACK延迟策略
     */
    class ReceivedPacketTracker
    {
    public:
        typedef std::shared_ptr<ReceivedPacketTracker> ptr;
        typedef Mutex MutexType;

        /**
         * @brief 构造函数，初始化接收跟踪器
         */
        ReceivedPacketTracker();

        /**
         * @brief 获取已观察到的最大数据包接收时间
         * @return 接收时间戳（微秒）
         */
        uint64_t largestObservedReceivedTime() const { return m_largest_observed_received_time; }

        /**
         * @brief 获取自上次ACK发送以来收到的需要触发ACK的数据包数量
         * @return 数据包数量
         */
        int ackElicitingPacketsReceivedSinceLastAck() const
        {
            return m_ack_eliciting_packets_received_since_last_ack;
        }

        /**
         * @brief 获取ACK定时器时间
         * @return 定时器时间戳（微秒）
         */
        uint64_t ackAlarm() const { return m_ack_alarm; }

        /**
         * @brief 设置忽略低于指定编号的数据包
         * @param pn 数据包编号阈值
         */
        void ignoreBelow(QuicPacketNumber pn);

        /**
         * @brief 检查数据包是否应该已收到但缺失
         * @param pn 数据包编号
         * @return 是否缺失
         */
        bool isMissing(QuicPacketNumber pn);

        /**
         * @brief 检查是否有新的缺失数据包需要报告
         * @return 是否有新缺失包
         */
        bool hasNewMissingPackets();

        /**
         * @brief 可能将ACK加入队列，根据ACK触发条件
         * @param pn 数据包编号
         * @param recv_time 接收时间
         * @param was_missing 数据包是否之前缺失
         */
        void maybeQueueAck(QuicPacketNumber pn, uint64_t recv_time, bool was_missing);

        /**
         * @brief 处理接收到的数据包
         * @param pn 数据包编号
         * @param recv_time 接收时间
         * @param should_instigate_ack 是否应该触发ACK处理
         */
        void receivedPacket(QuicPacketNumber pn, uint64_t recv_time, bool should_instigate_ack);

        /**
         * @brief 获取ACK帧，可能根据条件决定是否生成
         * @param only_if_queued 是否仅在ACK已排队时生成
         * @return ACK帧指针，若不满足条件则返回nullptr
         */
        QuicAckFrame::ptr getAckFrame(bool only_if_queued);

        // 互斥锁，保护多线程访问
        MutexType m_mutex;
        // 接收数据包历史记录
        ReceivedPacketHistory::ptr m_packet_history;
        // 已观察到的最大数据包编号
        QuicPacketNumber m_largest_observed = 0;
        // 忽略以下编号的数据包阈值
        QuicPacketNumber m_ignore_below = 0;
        // 最大观察到的数据包接收时间
        uint64_t m_largest_observed_received_time = 0;
        // 是否有新的ACK需要发送
        bool m_has_new_ack = false;
        // ACK是否已排队等待发送
        bool m_ack_queued = false;
        // 自上次ACK以来收到的需要触发ACK的数据包数量
        int m_ack_eliciting_packets_received_since_last_ack = 0;
        // ACK定时器时间戳
        uint64_t m_ack_alarm = 0;
        // 上次发送的ACK帧
        QuicAckFrame::ptr m_last_ack = nullptr;
        // QUIC协议版本
        QuicVersion m_version;
    };

    /**
     * @brief 已发送数据包历史记录管理
     * 负责跟踪已发送的数据包，支持查找、迭代和删除操作
     */
    class SentPacketHistory
    {
    public:
        typedef std::shared_ptr<SentPacketHistory> ptr;
        typedef Mutex MutexType;

        /**
         * @brief 构造函数
         * @param rtt_stats RTT统计信息指针，用于计算超时时间
         */
        SentPacketHistory(RTTStats::ptr rtt_stats);

        /**
         * @brief 获取当前跟踪的数据包数量
         * @return 数据包数量
         */
        size_t len() const { return m_packet_map.size(); }

        /**
         * @brief 检查是否有未确认的数据包
         * @return 是否有未确认包
         */
        bool hasOutstandingPackets() { return (firstOutstanding() != nullptr); }

        /**
         * @brief 检查是否包含指定编号的数据包
         * @param pn 数据包编号
         * @return 是否存在
         */
        bool hasPacket(QuicPacketNumber pn) { return m_packet_map.count(pn) > 0; }

        /**
         * @brief 获取指定编号的数据包
         * @param pn 数据包编号
         * @return 数据包指针，不存在则返回nullptr
         */
        QuicPacket::ptr getPacket(QuicPacketNumber pn)
        {
            if (!hasPacket(pn))
                return nullptr;
            return *(m_packet_map[pn]);
        }

        /**
         * @brief 记录已发送的数据包
         * @param packet 数据包指针
         * @param is_ack_eliciting 是否需要ACK响应
         * @param now 当前时间
         */
        void sentPacket(QuicPacket::ptr packet, bool is_ack_eliciting, uint64_t now);

        /**
         * @brief 遍历所有数据包
         * @param cb 回调函数，返回false时停止遍历
         */
        void Iterate(std::function<bool(QuicPacket::ptr)> cb);

        /**
         * @brief 获取第一个未确认的数据包
         * @return 数据包指针，若没有则返回nullptr
         */
        QuicPacket::ptr firstOutstanding();

        /**
         * @brief 移除指定编号的数据包
         * @param pn 数据包编号
         * @return 是否成功移除
         */
        bool remove(QuicPacketNumber pn);

        /**
         * @brief 删除过期的数据包记录，释放内存
         * @param now 当前时间
         */
        void deleteOldPackets(uint64_t now);

    private:
        // 互斥锁，保护多线程访问
        MutexType m_mutex;
        // RTT统计信息，用于计算超时
        RTTStats::ptr m_rtt_stats = nullptr;
        // 数据包列表，按发送顺序存储
        std::list<QuicPacket::ptr> m_packet_list = {};
        // 数据包编号到列表迭代器的映射，用于快速查找
        std::unordered_map<QuicPacketNumber, std::list<QuicPacket::ptr>::iterator> m_packet_map;
        // 已发送的最高数据包编号
        QuicPacketNumber m_highest_sent = 0;
    };

    /**
     * @brief 发送数据包处理器
     * 管理数据包发送、重传、ACK处理、拥塞控制等核心功能
     */
    class SentPacketHandler
    {
    public:
        typedef std::shared_ptr<SentPacketHandler> ptr;
        // 放大限制因子，防止流量放大攻击
        static constexpr int amplicationFactor = 3;
        // 时间阈值系数，用于检测丢包
        static constexpr float timeThreshold = 9.0 / 8;
        // 数据包阈值，用于检测丢包（比最大确认包大此值的包视为丢失）
        static constexpr int packetThreshold = 3;

        /**
         * @brief 数据包编号空间
         * 存储特定类型数据包（如数据、控制等）的状态信息
         */
        struct PacketNumberSpace {
            // 数据包历史记录
            SentPacketHistory::ptr m_history = nullptr;
            // 最早可能丢包的时间
            uint64_t m_loss_time = 0;
            // 最后发送的需要ACK响应的数据包时间
            uint64_t m_last_ack_eliciting_packet_time = 0;
            // 已确认的最大数据包编号
            QuicPacketNumber m_largest_acked = 0;
            // 已发送的最大数据包编号
            QuicPacketNumber m_largest_sent = ~0ull;
        };

        /**
         * @brief 构造函数
         * @param rtt RTT统计信息指针
         */
        SentPacketHandler(const RTTStats::ptr &rtt);

        /**
         * @brief 获取数据数据包空间
         * @return 数据包空间常量引用
         */
        const PacketNumberSpace &dataPackets() const { return m_data_packets; }

        /**
         * @brief 获取已接收的字节数
         * @return 字节数
         */
        uint64_t bytesReceived() const { return m_bytes_received; }

        /**
         * @brief 获取已发送的字节数
         * @return 字节数
         */
        uint64_t bytesSent() const { return m_bytes_sent; }

        /**
         * @brief 获取当前在途的字节数
         * @return 字节数
         */
        uint64_t bytesInflight() const { return m_bytes_inflight; }

        /**
         * @brief 获取RTT统计信息
         * @return RTT统计指针
         */
        const RTTStats::ptr getRTTStats() const { return m_rtt_stats; }

        /**
         * @brief 从在途字节数中移除数据包大小
         * @param packet 数据包指针
         */
        void removeFromBytesInflight(QuicPacket::ptr packet);

        /**
         * @brief 丢弃数据包（预留接口）
         */
        void dropPackets();

        /**
         * @brief 记录收到的字节数
         * @param n 字节数
         */
        void receivedBytes(uint64_t n) { m_bytes_received += n; }

        /**
         * @brief 获取当前在途的数据包数量
         * @return 数据包数量
         */
        int packetsInflight() { return m_data_packets.m_history->len(); }

        /**
         * @brief 获取丢包时间和空间信息（预留接口）
         * @return 丢包时间
         */
        uint64_t getLossTimeAndSpace();

        /**
         * @brief 获取最低未确认的数据包编号
         * @return 数据包编号
         */
        QuicPacketNumber getLowestPacketNotConfirmedAcked() const
        {
            return m_lowest_not_confirmed_acked;
        }

        /**
         * @brief 检查是否有未确认的数据包
         * @return 是否有未确认包
         */
        bool hasOutstandingPackets();

        /**
         * @brief 检查是否受到流量放大限制
         * @return 是否受限制
         */
        bool isAmplificationLimited();

        /**
         * @brief 设置丢包检测定时器
         * @param phase 定时器阶段（0:初始, 1:ACK后, 2:超时后）
         */
        void setLossDetectionTimer(int phase);

        /**
         * @brief 发送数据包的内部实现
         * @param packet 数据包指针
         * @return 是否为需要ACK响应的数据包
         */
        bool sentPacketImpl(QuicPacket::ptr packet);

        /**
         * @brief 处理数据包发送
         * @param packet 数据包指针
         * @param now 当前时间
         */
        void sentPacket(QuicPacket::ptr packet, uint64_t now);

        /**
         * @brief 排队探测包进行重传
         * @return 是否成功排队
         */
        bool queueProbePacket();

        /**
         * @brief 为数据包中的帧排队进行重传
         * @param packet 数据包指针
         */
        void queueFramesForRetransmission(QuicPacket::ptr packet);

        /**
         * @brief 检测丢失的数据包
         * @param now 当前时间
         * @param lost_packets 丢失的数据包列表
         * @return 是否成功检测
         */
        bool detectLostPackets(uint64_t now, std::vector<QuicPacket::ptr> &lost_packets);

        /**
         * @brief 检测并移除已确认的数据包
         * @param frame ACK帧
         * @return 已确认的数据包列表
         */
        std::vector<QuicPacket::ptr> detectAndRemoveAckedPackets(QuicAckFrame::ptr frame);

        /**
         * @brief 处理收到的ACK
         * @param frame ACK帧
         * @param recv_time 接收时间
         * @return 是否成功处理
         */
        bool receivedAck(QuicAckFrame::ptr frame, uint64_t recv_time);

        /**
         * @brief 处理丢包检测超时
         * @return 是否需要发送探测包
         */
        bool onLossDetectionTimeout();

        /**
         * @brief 获取丢包检测超时时间
         * @return 超时时间戳
         */
        uint64_t getLossDetectionTimeout() const { return m_alarm; }

        /**
         * @brief 获取当前的数据包发送模式
         * @return 发送模式
         */
        PacketSendMode sendMode();

        /**
         * @brief 检查是否有 pacing预算
         * @return 是否有预算
         */
        bool hasPacingBudget() { return m_congestion->hasPacingBudget(); }

        /**
         * @brief 获取距离下一次发送的时间
         * @return 时间（微秒）
         */
        uint64_t timeUntilSend() const { return m_congestion->timeUntilSend(); }

        /**
         * @brief 设置最大数据报文大小
         * @param s 大小（字节）
         */
        void setMaxDatagramSize(uint64_t s) { m_congestion->setMaxDatagramSize(s); }

    private:
        // 数据包发送间隔
        uint64_t m_send_interval = 0;
        // 数据数据包空间
        PacketNumberSpace m_data_packets;
        // 已接收字节数
        uint64_t m_bytes_received = 0;
        // 已发送字节数
        uint64_t m_bytes_sent = 0;
        // 最低未确认的数据包编号
        QuicPacketNumber m_lowest_not_confirmed_acked = 0;
        // 已确认的数据包列表
        std::vector<QuicPacket::ptr> m_acked_packets = {};
        // 在途字节数
        uint64_t m_bytes_inflight = 0;
        // 拥塞控制算法实例
        SendAlgorithm::ptr m_congestion = nullptr;
        uint64_t m_is_bbr = 0;
        // RTT统计信息
        RTTStats::ptr m_rtt_stats;
        // PTO计数器
        uint32_t m_PTO_count = 0;
        // 需要发送的探测包数量
        int m_num_probes_to_send = 0;
        // 超时定时器时间戳
        uint64_t m_alarm = 0;
        // QUIC角色（客户端/服务器）
        QuicRole m_role;
    };

} // namespace quic
} // namespace base

#endif
