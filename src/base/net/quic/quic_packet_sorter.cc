#include "quic_packet_sorter.h"
#include "base/log/log.h"
#include "base/conf/config.h"
#include "base/macro.h"
#include "./bbr/bbr_sender.h"
#include <sstream>

namespace base
{
namespace quic
{
    // 系统日志记录器
    static base::Logger::ptr g_logger = _LOG_NAME("system");
    // 触发ACK前需要接收的数据包数量阈值
    _DEFINE_CONFIG(int, PacketsBeforeAck, "packets_before_ack", 2, "Number of packets before ack")
    // 最大ACK延迟时间（微秒），遵循QUIC协议规范
    _DEFINE_CONFIG(uint64_t, MAX_ACK_DELAY, "max_ack_delay", 25 * 1000, "Max ack delay in ms")

    /**
     * @class ReceivedPacketHistory
     * @brief 管理已接收数据包的历史记录，使用区间合并算法高效跟踪数据包接收状态
     */

    /**
     * @brief 记录接收到的数据包
     * @param pn 数据包编号
     * @return 是否为新接收到的数据包（非重复）
     *
     * 处理流程：
     * 1. 检查数据包是否已被删除（编号过小）
     * 2. 将数据包添加到接收范围
     * 3. 清理过旧的区间记录
     */
    bool ReceivedPacketHistory::receivedPacket(QuicPacketNumber pn)
    {
        // 忽略已删除的旧数据包
        if (pn < m_deleted_below) {
            return false;
        }
        // 尝试添加到接收范围并检查是否为新包
        auto is_new = addToRanges(pn);
        // 维护区间数量，防止内存溢出
        maybeDeleteOldRanges();
        return is_new;
    }

    /**
     * @brief 将数据包编号添加到接收范围中，并尝试合并相邻区间
     * @param pn 数据包编号
     * @return 是否为新添加的编号
     *
     * 核心算法：区间合并优化
     * - 从最大的区间开始反向遍历（从后往前）
     * - 检查多种合并情况：完全包含、相邻（前一个区间的结束+1=当前pn）、后一个区间开始-1=当前pn
     * - 对于无法合并的情况，在适当位置插入新区间
     *
     * 时间复杂度：O(n)，其中n为区间数量
     */
    bool ReceivedPacketHistory::addToRanges(QuicPacketNumber pn)
    {
        // 首次添加数据包
        if (m_ranges.size() == 0) {
            m_ranges.push_back(std::make_shared<PacketInterval>(pn, pn));
            return true;
        }

        // 反向遍历区间列表（从最大的区间开始）
        for (auto it = m_ranges.rbegin(); it != m_ranges.rend();) {
            // 情况1：数据包已在现有区间内，视为重复
            if (pn >= (*it)->m_start && pn <= (*it)->m_end) {
                return false;
            }

            // 情况2：数据包与区间相邻（区间结束值+1=数据包编号），扩展区间结束
            if ((*it)->m_end == pn - 1) {
                (*it)->m_end = pn;
                return true;
            }

            // 情况3：数据包与区间相邻（数据包编号+1=区间起始值），扩展区间起始
            if ((*it)->m_start == pn + 1) {
                (*it)->m_start = pn;

                // 检查是否可以进一步与前一个区间合并
                auto prev_it = it;
                prev_it++;
                if (prev_it != m_ranges.rend() && (*prev_it)->m_end + 1 == (*it)->m_start) {
                    // 合并两个区间
                    (*prev_it)->m_end = (*it)->m_end;
                    // 删除已合并的区间
                    it = std::list<PacketInterval::ptr>::reverse_iterator(
                        m_ranges.erase((++it).base()));
                }
                return true;
            }

            // 情况4：数据包大于当前区间的结束值，插入新的区间
            if (pn > (*it)->m_end) {
                m_ranges.insert((it++).base(), std::make_shared<PacketInterval>(pn, pn));
                return true;
            }

            ++it;
        }

        // 情况5：数据包小于所有区间，插入到列表开头
        m_ranges.push_front(std::make_shared<PacketInterval>(pn, pn));
        return true;
    }

    /**
     * @brief 清理超出最大范围数量的旧区间，保持内存使用在合理范围
     *
     * 移除最旧的区间（列表头部的区间，编号最小）直到区间数量不超过最大值
     */
    void ReceivedPacketHistory::maybeDeleteOldRanges()
    {
        while (m_ranges.size() > MAX_NUMBER_ACK_RANGES) {
            m_ranges.pop_front();
        }
    }

    /**
     * @brief 删除所有小于指定编号的数据包记录
     * @param pn 数据包编号阈值
     *
     * 清理逻辑：
     * 1. 跳过已经处理过的情况（当前阈值小于等于已删除阈值）
     * 2. 更新已删除阈值
     * 3. 遍历区间列表删除完全小于阈值的区间
     * 4. 处理部分重叠的区间（截断区间起始值）
     */
    void ReceivedPacketHistory::deleteBelow(QuicPacketNumber pn)
    {
        if (pn < m_deleted_below) { // 已经删除过更小的值，无需操作
            return;
        }

        m_deleted_below = pn;

        // 遍历删除完全小于阈值的区间
        for (auto it = m_ranges.begin(); it != m_ranges.end();) {
            if ((*it)->m_end < pn) {
                _LOG_INFO(g_logger) << "deleteBelow: " << (*it)->m_end;
                m_ranges.erase(it++);
                _LOG_INFO(g_logger) << "after deleteBelow: " << m_ranges.size();
            } else if (pn > (*it)->m_start && pn <= (*it)->m_end) {
                // 截断区间，只保留大于等于阈值的部分
                (*it)->m_start = pn;
                return;
            } else {
                ++it;
            }
        }
    }

    /**
     * @brief 获取所有ACK范围，用于构造ACK帧
     * @return ACK范围列表，按编号降序排列（符合QUIC协议要求）
     *
     * 注意：QUIC协议要求ACK范围按编号降序排列，因此从列表末尾（最大的区间）开始遍历
     */
    std::vector<AckRange::ptr> ReceivedPacketHistory::getAckRanges()
    {
        std::vector<AckRange::ptr> ack_ranges;
        if (m_ranges.size() == 0) {
            return ack_ranges;
        }

        // 反向遍历（从最大的区间开始），确保ACK范围按降序排列
        for (auto it = m_ranges.rbegin(); it != m_ranges.rend();) {
            ack_ranges.push_back(std::make_shared<AckRange>((*it)->m_start, (*it)->m_end));
            ++it;
        }
        return ack_ranges;
    }

    /**
     * @brief 获取最高的ACK范围（最新接收到的连续数据包）
     * @return 最高ACK范围指针，若无数据则返回nullptr
     */
    AckRange::ptr ReceivedPacketHistory::getHighestAckRange()
    {
        AckRange::ptr ack_range = nullptr;
        if (m_ranges.size() > 0) {
            // 列表末尾是最大的区间
            auto packet_interval = m_ranges.back();
            ack_range =
                std::make_shared<AckRange>(packet_interval->m_start, packet_interval->m_end);
        }
        return ack_range;
    }

    /**
     * @brief 检查数据包是否可能是重复的
     * @param pn 数据包编号
     * @return 是否可能重复
     *
     * 检测逻辑：
     * 1. 小于已删除阈值的数据包视为重复
     * 2. 检查数据包是否在任何已记录的区间内
     * 3. 优化：从最大的区间开始检查，因为最近的数据包更可能重复
     */
    bool ReceivedPacketHistory::isPotentiallyDuplicate(QuicPacketNumber pn)
    {
        // 已删除的数据包视为重复
        if (pn < m_deleted_below) {
            return true;
        }

        // 反向遍历，从最大的区间开始检查
        for (auto it = m_ranges.rbegin(); it != m_ranges.rend();) {
            // 数据包大于当前区间的最大值，不可能重复
            if (pn > (*it)->m_end) {
                return false;
            }
            // 数据包在当前区间内，可能重复
            if (pn <= (*it)->m_end && pn >= (*it)->m_start) {
                return true;
            }
            ++it;
        }
        return false;
    }

    /**
     * @brief 将当前状态转换为字符串表示，用于调试
     * @return 状态描述字符串
     */
    std::string ReceivedPacketHistory::toString()
    {
        std::stringstream ss;
        ss << "deleted below: " << m_deleted_below << ", size: " << m_ranges.size() << ", ";
        for (auto &it : m_ranges) {
            ss << "[" << it->start() << ", " << it->end() << "] ";
        }
        return ss.str();
    }

    /**
     * @class ReceivedPacketTracker
     * @brief 跟踪接收到的数据包并管理ACK生成和丢包检测所需的状态信息
     *
     * 主要功能：
     * 1. 记录和跟踪接收到的数据包
     * 2. 决定何时发送ACK帧
     * 3. 实现ACK延迟策略
     * 4. 检测和报告丢失的数据包
     */

    /**
     * @brief 构造函数，初始化数据包历史记录器
     */
    ReceivedPacketTracker::ReceivedPacketTracker()
    {
        m_packet_history = std::make_shared<ReceivedPacketHistory>();
    }

    /**
     * @brief 忽略所有编号小于指定值的数据包
     * @param pn 数据包编号阈值
     *
     * 当确认某范围的数据包不会再到达时调用此方法，以优化内存使用
     */
    void ReceivedPacketTracker::ignoreBelow(QuicPacketNumber pn)
    {
        if (pn <= m_ignore_below) {
            return;
        }
        m_ignore_below = pn;
        m_packet_history->deleteBelow(pn);
        _LOG_INFO(g_logger) << "Ignoring all packets below " << pn;
    }

    /**
     * @brief 检查数据包是否应该被视为丢失
     * @param pn 数据包编号
     * @return 如果数据包被认为丢失则返回true
     *
     * 判断逻辑：
     * 1. 如果尚未发送ACK帧或数据包编号小于忽略阈值，则不视为丢失
     * 2. 数据包编号小于最大已确认编号且未在ACK范围中，则视为丢失
     */
    bool ReceivedPacketTracker::isMissing(QuicPacketNumber pn)
    {
        if (m_last_ack == nullptr || pn < m_ignore_below) {
            return false;
        }
        return (pn < m_last_ack->largestAcked()) && (!m_last_ack->acksPacket(pn));
    }

    /**
     * @brief 检查是否有新的丢失数据包需要报告
     * @return 如果存在新的丢失数据包则返回true
     *
     * 判断条件：
     * 最高ACK范围的起始值大于上一次最大确认值+1，且该范围长度为1
     * 表明收到了一个跳过中间编号的单数据包，暗示中间数据包可能丢失
     */
    bool ReceivedPacketTracker::hasNewMissingPackets()
    {
        if (m_last_ack == nullptr) {
            return false;
        }
        auto highest_range = m_packet_history->getHighestAckRange();
        return (highest_range->m_smallest > m_last_ack->largestAcked() + 1)
               && (highest_range->len() == 1);
    }

    /**
     * @brief 决定是否应该将ACK帧加入发送队列
     * @param pn 数据包编号
     * @param recv_time 接收时间戳
     * @param was_missing 数据包是否之前被标记为丢失
     *
     * ACK触发策略：
     * 1. 首次接收到数据包时立即触发ACK
     * 2. 接收到之前丢失的数据包时立即触发ACK
     * 3. 接收到足够数量(>=PacketsBeforeAck)的需要ACK的数据包时触发ACK
     * 4. 检测到新的丢失数据包时触发ACK
     * 5. 若未触发ACK，则设置ACK延迟定时器
     */
    void ReceivedPacketTracker::maybeQueueAck(QuicPacketNumber pn, uint64_t recv_time,
                                              bool was_missing)
    {
        // 首次接收到数据包，需要立即确认
        if (m_last_ack == nullptr) {
            if (!m_ack_queued) {
                _LOG_DEBUG(g_logger) << "Queuing ACK because the first packet should be acked";
            }
            m_ack_queued = true;
            return;
        }

        // ACK已在队列中，无需重复处理
        if (m_ack_queued) {
            return;
        }

        // 增加需要ACK的数据包计数
        m_ack_eliciting_packets_received_since_last_ack++;

        // 收到之前被认为丢失的数据包，需要立即确认
        if (was_missing) {
            _LOG_DEBUG(g_logger) << "Queuing ACK because packet" << pn << " was missing before";
            m_ack_queued = true;
        }

        // 累积了足够数量的需要ACK的数据包
        if (m_ack_eliciting_packets_received_since_last_ack >= PacketsBeforeAck->getValue()) {
            _LOG_DEBUG(g_logger)
                << "Queueing ACK because packet " << m_ack_eliciting_packets_received_since_last_ack
                << " packets were received after the last ACK (using initial threshold: "
                << PacketsBeforeAck->getValue() << ")";
            m_ack_queued = true;
        } else if (m_ack_alarm == 0) {
            // 未达到触发阈值，设置ACK延迟定时器
            _LOG_DEBUG(g_logger) << "Setting ACK timer to max ack delay: "
                                 << MAX_ACK_DELAY->getValue();
            m_ack_alarm = recv_time + MAX_ACK_DELAY->getValue();
        }

        // 检测到新的丢失数据包需要报告
        if (hasNewMissingPackets()) {
            _LOG_DEBUG(g_logger) << "Queuing ACK because there's a new missing packet to report";
            m_ack_queued = true;
        }

        // 清除ACK延迟定时器
        if (m_ack_queued) {
            m_ack_alarm = 0;
        }
    }

    /**
     * @brief 处理接收到的数据包
     * @param pn 数据包编号
     * @param recv_time 接收时间戳
     * @param should_instigate_ack 是否应触发ACK处理
     *
     * 处理流程：
     * 1. 加锁保护并发访问
     * 2. 忽略编号过小的数据包
     * 3. 检查数据包是否为**之前丢失的**
     * 4. 更新最大观察到的数据包编号和时间
     * 5. 将数据包添加到历史记录中
     * 6. 决定是否需要触发ACK处理
     */
    void ReceivedPacketTracker::receivedPacket(QuicPacketNumber pn, uint64_t recv_time,
                                               bool should_instigate_ack)
    {
        MutexType::Lock lock(m_mutex);

        // 忽略小于阈值的数据包
        if (pn < m_ignore_below) {
            return;
        }

        // 检查数据包是否为丢失的数据包
        bool is_missing = isMissing(pn);
        if (is_missing) {
            _LOG_INFO(g_logger) << "is_missing packet come";
        }

        // 更新最大观察到的数据包编号和接收时间
        if (pn >= m_largest_observed) {
            m_largest_observed = pn;
            m_largest_observed_received_time = recv_time;
        }

        // 将数据包添加到历史记录中（这里会控制历史记录的数量），并检查是否有新的ACK需要发送
        if (m_packet_history->receivedPacket(pn) && should_instigate_ack) {
            m_has_new_ack = true;
        }

        // 如果需要，触发ACK处理
        if (should_instigate_ack) {
            maybeQueueAck(pn, recv_time, is_missing);
        }
    }

    /**
     * @brief 获取ACK帧
     * @param only_if_queued 是否仅在ACK已排队时才生成
     * @return ACK帧指针，若不满足条件则返回nullptr
     *
     * 生成ACK帧的条件：
     * 1. 存在新的ACK信息(has_new_ack)
     * 2. 如果设置了only_if_queued，则需要ACK已排队或ACK延迟定时器已过期
     *
     * 生成ACK帧后，重置相关状态
     */
    QuicAckFrame::ptr ReceivedPacketTracker::getAckFrame(bool only_if_queued)
    {
        MutexType::Lock lock(m_mutex);

        // 没有新的ACK信息
        if (!m_has_new_ack) {
            return nullptr;
        }

        uint64_t now = GetCurrentUS();

        // 如果要求仅在ACK排队时才生成，如果 ACK未排队 + 定时器未过期，则不生成
        if (only_if_queued) {
            if (!m_ack_queued && (m_ack_alarm == 0 || m_ack_alarm > now)) {
                return nullptr;
            }
            _LOG_DEBUG(g_logger) << "Sending ACK because the ACK timer expired: "
                                 << "m_ack_queud: " << m_ack_queued
                                 << ", m_ack_alarm: " << m_ack_alarm << ", now: " << now;
        }

        // 创建并初始化ACK帧
        m_last_ack = std::make_shared<QuicAckFrame>();
        m_last_ack->setAckRanges(m_packet_history->getAckRanges());

        // 计算ACK延迟（当前时间减去最大观察到的数据包的接收时间），为了获取到更精确的RTT
        uint64_t delay =
            now < m_largest_observed_received_time ? 0 : now - m_largest_observed_received_time;
        m_last_ack->setAckDelay(delay);

        // 重置ACK相关状态
        m_ack_alarm = 0;
        m_ack_queued = false;
        m_has_new_ack = false;
        m_ack_eliciting_packets_received_since_last_ack = 0;

        return m_last_ack;
    }

    /**
     * @class SentPacketHistory
     * @brief 管理已发送数据包的历史记录，维护数据包的发送状态和处理ACK与丢包检测
     *
     * 主要功能：
     * 1. 记录发送的数据包信息并维护数据包顺序
     * 2. 处理数据包的丢失检测和确认状态
     * 3. 支持数据包遍历和查找
     * 4. 维护RTT统计信息的引用
     */

    /**
     * @brief 构造函数
     * @param rtt_stats RTT统计信息指针，用于获取往返时间估计
     */
    SentPacketHistory::SentPacketHistory(RTTStats::ptr rtt_stats) : m_rtt_stats(rtt_stats)
    {
        m_highest_sent = 0;
    }

    /**
     * @brief 记录发送的数据包
     * @param packet 数据包指针
     * @param is_ack_eliciting 数据包是否需要ACK
     * @param now 当前时间戳
     *
     * 处理流程：
     * 1. 加锁保护并发访问
     * 2. 验证数据包编号的连续性，不允许回退
     * 3. 为跳过的数据包编号创建占位符（确保数据包顺序连续性）
     * 4. 更新最高发送的数据包编号
     * 5. 对于需要ACK的数据包，将其添加到跟踪列表中
     *
     * 性能考虑：使用map和list的组合可以高效地进行数据包查找和顺序维护
     */
    void SentPacketHistory::sentPacket(QuicPacket::ptr packet, bool is_ack_eliciting, uint64_t now)
    {
        MutexType::Lock lock(m_mutex);

        // 确保数据包编号是递增的，不允许回退
        if (packet->packetNumber() < m_highest_sent) {
            _LOG_INFO(g_logger) << "non-sequential packet number use";
            _ASSERT(0);
        }

        // 为跳过的数据包编号创建占位符，保持数据包序列的连续性
        for (auto pn = m_highest_sent + 1; pn < packet->packetNumber(); pn++) {
            auto p = std::make_shared<QuicPacket>();
            p->setPacketNumber(pn);
            p->setTime(now);
            p->setSkip();
            m_packet_list.push_back(p);
            m_packet_map[pn] = --(m_packet_list.end());
        }

        // 更新最高发送的数据包编号
        m_highest_sent = packet->packetNumber();

        // 只有需要ACK的数据包才需要被跟踪
        if (is_ack_eliciting) {
            m_packet_list.push_back(packet);
            m_packet_map[packet->packetNumber()] = --(m_packet_list.end());
        }
    }

    /**
     * @brief 遍历所有已发送的数据包
     * @param cb 回调函数，对每个数据包执行的操作
     *
     * 遍历所有数据包，并对每个数据包调用回调函数。如果回调函数返回false，遍历将提前结束。
     * 这是一种高效的遍历方式，避免了复制整个数据包列表。
     */
    void SentPacketHistory::Iterate(std::function<bool(QuicPacket::ptr)> cb)
    {
        MutexType::Lock lock(m_mutex);
        for (const auto &packet : m_packet_list) {
            if (!cb(packet)) {
                return;
            }
        }
    }

    /**
     * @brief 获取第一个未完成的数据包（未确认且未丢失的数据包）
     * @return 第一个未完成的数据包指针，若不存在则返回nullptr
     *
     * 从未确认的数据包中找到最早发送的那个，用于丢包检测和重传决策
     */
    QuicPacket::ptr SentPacketHistory::firstOutstanding()
    {
        MutexType::Lock lock(m_mutex);
        for (const auto &packet : m_packet_list) {
            if (!packet->declaredLost() && !packet->skippedPacket()) {
                return packet;
            }
        }
        return nullptr;
    }

    /**
     * @brief 从历史记录中移除指定编号的数据包
     * @param pn 数据包编号
     * @return 是否成功移除
     *
     * 移除流程：
     * 1. 查找数据包是否存在
     * 2. 从列表和映射中同时移除，保持数据一致性
     * 3. 如果数据包不存在，记录日志并返回失败
     */
    bool SentPacketHistory::remove(QuicPacketNumber pn)
    {
        MutexType::Lock lock(m_mutex);
        auto it = m_packet_map.find(pn);
        if (it == m_packet_map.end()) {
            _LOG_INFO(g_logger) << "packet " << pn << " not found in sent packet history";
            return false;
        }

        // 同时从列表和映射中移除，保持数据结构的一致性
        m_packet_list.erase(it->second);
        m_packet_map.erase(it->first);
        return true;
    }

    /**
     * @brief 删除过期的数据包记录，优化内存使用
     * @param now 当前时间戳
     *
     * 删除策略：
     * 1. 计算最大保留时间（3倍PTO - 包超时时间）
     * 2. 从列表开头开始遍历（最早发送的数据包）
     * 3. 只删除已跳过或已声明丢失的数据包
     * 4. 一旦遇到未过期的数据包，停止遍历（列表是按发送顺序排序的）
     *
     * 性能优化：由于数据包列表是按时间顺序排列的，一旦遇到未过期的数据包就可以提前退出循环
     */
    void SentPacketHistory::deleteOldPackets(uint64_t now)
    {
        MutexType::Lock lock(m_mutex);
        // 最大保留时间设为3倍PTO，确保有足够时间处理可能的延迟ACK和丢包检测
        uint64_t max_age = 3 * m_rtt_stats->PTO(false);

        for (auto it = m_packet_list.begin(); it != m_packet_list.end();) {
            QuicPacket::ptr packet = *it;

            // 由于列表是按发送顺序排列的，一旦遇到未过期的数据包，后续数据包肯定也未过期
            if ((now - max_age) < packet->sendTime()) {
                break;
            }

            // 只删除已跳过或已声明丢失的数据包，保留未确认且未丢失的数据包
            if (!packet->skippedPacket() && !packet->declaredLost()) {
                ++it;
                continue;
            }

            // 从映射和列表中同时删除，保持数据一致性
            m_packet_map.erase(packet->packetNumber());
            m_packet_list.erase(it++);
        }
    }

    /**
     * @class SentPacketHandler
     * @brief 处理已发送数据包的核心组件，负责丢包检测、ACK处理和拥塞控制
     *
     * 主要功能：
     * 1. 管理数据包的发送状态和字节流控制
     * 2. 检测并处理已确认的数据包
     * 3. 实现丢包检测算法
     * 4. 维护拥塞控制状态
     * 5. 处理超时事件
     */

    /**
     * @brief 构造函数
     * @param rtt RTT统计信息指针，用于获取往返时间估计
     */
    SentPacketHandler::SentPacketHandler(const RTTStats::ptr &rtt) : m_rtt_stats(rtt)
    {
        // 初始化数据包历史记录
        m_data_packets.m_history = std::make_shared<SentPacketHistory>(m_rtt_stats);
        // 初始化CUBIC拥塞控制算法
        m_is_bbr = 1;
        if (m_is_bbr) {
            m_congestion = std::make_shared<BbrSender>(rtt, 1452);
        } else {
            m_congestion = std::make_shared<CubicSender>(GetCurrentUS(), rtt, false, 1452);
        }
    }

    /**
     * @brief 从飞行中的字节数中移除数据包大小
     * @param packet 数据包指针
     *
     * 当数据包被确认或丢失时调用此方法，更新飞行中的字节数统计
     * 飞行中的字节数是拥塞控制的关键参数
     */
    void SentPacketHandler::removeFromBytesInflight(QuicPacket::ptr packet)
    {
        if (packet->includedInBytesInflight()) {
            // 防御性检查，避免飞行中的字节数变为负数
            if (packet->len() > m_bytes_inflight) {
                _LOG_INFO(g_logger) << "negative bytes_in_flight";
                _ASSERT(0);
            }
            // 更新飞行中的字节数
            m_bytes_inflight -= packet->len();
            packet->setIncludedInBytesInflight(false);
        }
    }

    /**
     * @brief 丢弃数据包的方法（预留接口）
     *
     * 当前实现为空，可能用于未来扩展流量控制或拥塞控制策略
     */
    void SentPacketHandler::dropPackets()
    {
    }

    /**
     * @brief 处理数据包发送的核心实现
     * @param packet 数据包指针
     * @return 是否成功处理
     *
     * 处理流程：
     * 1. 更新最大发送的数据包编号
     * 2. 判断数据包是否需要ACK（包含帧）
     * 3. 对于需要ACK的数据包：
     *    - 计算发送间隔（用于拥塞控制）
     *    - 更新最后发送需要ACK的数据包时间
     *    - 将数据包添加到飞行中的字节数统计
     *    - 处理探测包计数
     * 4. 将数据包记录到历史中
     */
    bool SentPacketHandler::sentPacketImpl(QuicPacket::ptr packet)
    {
        // 更新最大发送的数据包编号
        m_data_packets.m_largest_sent = packet->packetNumber();

        // 判断数据包是否需要ACK（包含帧则需要ACK）
        bool is_ack_eliciting = packet->frames().size() > 0;

        if (is_ack_eliciting) {
            uint64_t packet_send_time = packet->sendTime();

            // 计算数据包发送间隔（用于拥塞控制和带宽估计）
            if (m_data_packets.m_last_ack_eliciting_packet_time) {
                m_send_interval =
                    packet_send_time - m_data_packets.m_last_ack_eliciting_packet_time;
            }

            // 更新最后发送需要ACK的数据包时间
            m_data_packets.m_last_ack_eliciting_packet_time = packet_send_time;

            // 将数据包添加到飞行中的字节数统计
            packet->setIncludedInBytesInflight(true);
            m_bytes_inflight += packet->len();

            // 处理带宽探测包计数
            if (m_num_probes_to_send > 0) {
                m_num_probes_to_send--;
            }
        }

        // 将数据包记录到历史中，用于后续的ACK处理和丢包检测
        m_data_packets.m_history->sentPacket(packet, is_ack_eliciting, packet->sendTime());

        // 通知拥塞控制器数据包已发送
        m_congestion->onPacketSent(packet->sendTime(), m_bytes_inflight, packet->packetNumber(),
                                   packet->len(), is_ack_eliciting);

        return is_ack_eliciting;
    }

    /**
     * @brief 检查是否受到放大限制
     * @return 是否受到放大限制
     *
     * 放大限制是一种安全机制，防止反射DDoS攻击
     * 当发送的字节数超过接收字节数的一定倍数时，可能会限制发送速率
     */
    bool SentPacketHandler::isAmplificationLimited()
    {
        return m_bytes_sent >= m_bytes_received * amplicationFactor;
    }

    /**
     * @brief 检查是否有未完成的数据包
     * @return 是否有未完成的数据包
     *
     * 未完成的数据包指未被确认且未被标记为丢失的数据包
     */
    bool SentPacketHandler::hasOutstandingPackets()
    {
        return m_data_packets.m_history->hasOutstandingPackets();
    }

    /**
     * @brief 设置丢包检测定时器
     * @param phase 定时器阶段
     *
     * 根据不同的阶段设置不同的超时时间，用于触发丢包检测
     */
    void SentPacketHandler::setLossDetectionTimer(int phase)
    {
        uint64_t old_alarm = m_alarm;
        uint64_t loss_time = m_data_packets.m_loss_time;
        if (loss_time) {
            _LOG_INFO(g_logger) << "has Schrodinger’s packet! can not be there!";
            _ASSERT(1);
            m_alarm = loss_time;
            return;
        }
        // isAmplificationLimited TODO
        if (!hasOutstandingPackets()) {
            m_alarm = 0;
            if (old_alarm) {
                _LOG_INFO(g_logger) << "Canceling loss detection timer. No packets in fligth.";
            }
            return;
        }
        // PTO alarm
        uint64_t pto = 0;
        uint64_t rtt_pto = m_rtt_stats->PTO(false);
        if (m_data_packets.m_last_ack_eliciting_packet_time) {
            pto = m_data_packets.m_last_ack_eliciting_packet_time + (rtt_pto << m_PTO_count);
        }
        _LOG_WARN(g_logger) << "sldt phase: " << phase << ", last_ack_elicit_time: "
                            << m_data_packets.m_last_ack_eliciting_packet_time
                            << ", pto/m_alarm: " << pto << ", [rtt->pto: " << rtt_pto
                            << ", pto_count: " << m_PTO_count << "]"
                            << ", packet_interval: " << m_send_interval;
        m_alarm = pto;
    }

    /**
     * @brief 处理数据包发送
     * @param packet 要发送的数据包
     * @param now 当前时间戳
     *
     * 记录发送字节数，更新数据包时间戳，调用内部实现处理数据包，并在需要时设置丢包检测定时器
     */
    void SentPacketHandler::sentPacket(QuicPacket::ptr packet, uint64_t now)
    {
        // 获取当前时间戳
        now = GetCurrentUS();

        // 更新发送字节数统计
        m_bytes_sent += packet->len();

        // 调用内部实现处理数据包发送
        bool is_ack_eliciting = sentPacketImpl(packet);

        // 设置数据包时间戳并再次记录到历史中
        packet->setTime(now);
        m_data_packets.m_history->sentPacket(packet, is_ack_eliciting, now);

        // 如果是需要ACK的数据包，设置丢包检测定时器
        if (is_ack_eliciting) {
            setLossDetectionTimer(0);
        }
    }

    /**
     * @brief 排队探测包进行重传
     * @return 是否成功排队探测包
     *
     * 获取第一个未完成的数据包，标记为丢失并排队其帧进行重传，更新字节流控
     */
    bool SentPacketHandler::queueProbePacket()
    {
        // 获取第一个未完成的数据包
        auto packet = m_data_packets.m_history->firstOutstanding();
        if (packet == nullptr) {
            return false;
        }

        _LOG_INFO(g_logger) << "queueProbePacket: packet " << packet->packetNumber()
                            << " pto lost! will retrans!!!";

        // 排队数据包中的帧进行重传
        queueFramesForRetransmission(packet);

        // 标记数据包为丢失
        packet->setLost();

        // 从飞行中的字节数中移除
        removeFromBytesInflight(packet);

        return true;
    }

    /**
     * @brief 排队数据包中的帧进行重传
     * @param packet 包含要重传帧的数据包
     *
     * 遍历数据包中的所有帧，通知它们已丢失以触发重传，并清空数据包中的帧
     */
    void SentPacketHandler::queueFramesForRetransmission(QuicPacket::ptr packet)
    {
        // 确保数据包包含帧
        if (packet->frames().size() == 0) {
            _LOG_INFO(g_logger) << "no frames";
            _ASSERT(0);
        }

        // 通知每个帧它们已丢失，触发重传逻辑
        for (const auto &frame : packet->frames()) {
            frame->onLost(frame);
        }

        // 清空数据包中的帧（注意内存释放问题）
        packet->clear_frames(); // TODO how to release mem ?
    }

    /**
     * @brief 检测丢失的数据包
     * @param now 当前时间戳
     * @return 是否检测到丢包
     *
     * 基于时间阈值检测丢失的数据包，将长时间未收到ACK的数据包标记为丢失
     */
    /**
     * @brief 检测丢失的数据包
     * @param now 当前时间戳
     * @return 是否检测到丢包
     *
     * 基于时间阈值检测丢失的数据包，将长时间未收到ACK的数据包标记为丢失
     */
    bool SentPacketHandler::detectLostPackets(uint64_t now,
                                              std::vector<QuicPacket::ptr> &lost_packets)
    {
        // 重置丢失时间
        m_data_packets.m_loss_time = 0;

        // 计算最大RTT（最新RTT和平滑RTT中的较大值）
        float max_rtt = float(std::max(m_rtt_stats->latestRTT(), m_rtt_stats->smoothedRTT()));

        // 计算丢包检测延迟时间（基于RTT的倍数）
        float loss_delay = max_rtt * timeThreshold;
        // 确保最小延迟为1ms
        loss_delay = loss_delay > 1.0 ? loss_delay : 1.0; // 1ms

        // 计算丢失时间阈值
        uint64_t lost_send_time = now - (uint64_t)(std::ceil(loss_delay));

        _LOG_DEBUG(g_logger) << "dlp max_rtt: " << max_rtt << ", loss_delay: " << loss_delay;

        // 记录当前飞行中的字节数
        uint64_t priori_inflight = m_bytes_inflight;

        // 遍历所有数据包进行丢包检测
        m_data_packets.m_history->Iterate([&](QuicPacket::ptr packet) -> bool {
            // 只检查已确认数据包范围内的包
            if (packet->packetNumber() > m_data_packets.m_largest_acked) {
                return false;
            }

            // 跳过已标记为丢失或跳过的数据包
            if (packet->declaredLost() || packet->skippedPacket()) {
                return true;
            }
            bool packet_lost = false;
            int reason = 0;
            if (packet->sendTime() < lost_send_time) {
                packet_lost = true;
                reason = 1;
            } else if (m_data_packets.m_largest_acked >= packet->packetNumber() + packetThreshold) {
                packet_lost = true;
                reason = 2;
            } else if (!m_data_packets.m_loss_time) {
                uint64_t loss_time = packet->sendTime() + (uint64_t)(std::ceil(loss_delay));
                m_data_packets.m_loss_time = loss_time;
                reason = 3;
                _LOG_INFO(g_logger)
                    << "detectLostPackets, has Schrodinger’s packet! packet->sendtime: "
                    << packet->sendTime() << "loss_delay: " << loss_delay;
            }
            // 如果检测到丢包，处理丢失的数据包
            if (packet_lost) {
                if (m_is_bbr) {
                    lost_packets.push_back(packet);
                }

                _LOG_INFO(g_logger) << "detectLostPackets: packet " << packet->packetNumber()
                                    << " lost!, reason: " << reason << ", will retrans!!!";

                // 标记数据包为丢失
                packet->setLost();

                // 从飞行中的字节数中移除
                removeFromBytesInflight(packet);

                // 排队帧进行重传
                queueFramesForRetransmission(packet);

                if (!m_is_bbr) {
                    m_congestion->onPacketLost(packet->packetNumber(), packet->len(),
                                               priori_inflight);
                }
            }
            return true;
        });
        return true;
    }

    /**
     * @brief 检测并移除已确认的数据包
     * @param frame ACK帧，包含确认信息
     * @return 已确认的数据包列表
     *
     * 根据ACK帧中的确认范围，找出所有已被确认接收的数据包，更新统计信息，并从飞行中的字节数中移除
     * 这是QUIC协议中关键的可靠性机制部分
     */
    std::vector<QuicPacket::ptr>
    SentPacketHandler::detectAndRemoveAckedPackets(QuicAckFrame::ptr frame)
    {
        // 清空已确认数据包列表
        std::vector<QuicPacket::ptr>().swap(m_acked_packets);
        _ASSERT(m_acked_packets.size() == 0);

        // 初始化ACK范围索引
        size_t ack_range_idx = 0;

        // 获取ACK帧中的最小和最大确认的数据包编号
        auto lowest_acked = frame->lowestAcked();
        auto largest_acked = frame->largestAcked();

        // 遍历所有数据包，找出已确认的数据包
        m_data_packets.m_history->Iterate([&](QuicPacket::ptr packet) -> bool {
            // 跳过小于最小确认编号的数据包
            if (packet->packetNumber() < lowest_acked) {
                return true;
            }

            // 超出最大确认编号范围，停止遍历
            if (packet->packetNumber() > largest_acked) {
                return false;
            }

            // 处理有缺失范围的ACK帧（选择性确认）
            if (frame->hasMissingRanges()) {
                const auto &ack_ranges = frame->ackRanges();
                auto ack_range = ack_ranges[ack_ranges.size() - 1 - ack_range_idx];

                // 找到当前数据包对应的ACK范围
                while (ack_range->m_largest < packet->packetNumber()
                       && ack_range_idx < ack_ranges.size() - 1) {
                    ack_range_idx++;
                    ack_range = ack_ranges[ack_ranges.size() - 1 - ack_range_idx];
                }

                // 数据包不在当前ACK范围内，跳过
                if (packet->packetNumber() < ack_range->m_smallest) {
                    return true;
                }

                // 数据包超出当前ACK范围，停止处理
                if (packet->packetNumber() > ack_range->m_largest) {
                    return false;
                }
            }

            // 跳过已跳过的数据包
            if (packet->skippedPacket()) {
                return false;
            }

            // 将数据包添加到已确认列表
            m_acked_packets.push_back(packet);
            return true;
        });
        // 处理所有已确认的数据包
        for (const auto &packet : m_acked_packets) {
            // 更新未确认的ACK范围
            if (packet->largestAcked() != ~0ULL) {
                m_lowest_not_confirmed_acked =
                    std::max(m_lowest_not_confirmed_acked, packet->largestAcked() + 1);
            }

            // 通知每个帧它们已被确认
            for (const auto &frame : packet->frames()) {
                _LOG_INFO(g_logger) << "onAcked, pn: " << packet->packetNumber()
                                    << ", frame: " << frame->toString();
                frame->onAcked(frame);
            }

            // 从历史记录中移除数据包
            if (!m_data_packets.m_history->remove(packet->packetNumber())) {
                return std::vector<QuicPacket::ptr>();
            }
        }

        // 返回已确认的数据包列表
        return m_acked_packets;
    }

    /**
     * @brief 处理收到的ACK帧
     * @param frame 收到的ACK帧
     * @param recv_time 接收时间戳
     * @return 是否成功处理ACK
     *
     * 处理ACK帧，更新RTT统计，检测并移除已确认的数据包，重置丢包检测计时器
     * 这是QUIC协议中处理确认的核心方法
     */
    bool SentPacketHandler::receivedAck(QuicAckFrame::ptr frame, uint64_t recv_time)
    {
        // 获取最大确认的数据包编号
        QuicPacketNumber largest_acked = frame->largestAcked();

        // 验证ACK的有效性（不能确认未发送的数据包）
        if (largest_acked > m_data_packets.m_largest_sent) {
            _LOG_INFO(g_logger) << "Received ACK for an unsent packet";
            return false;
        }

        // 更新最大确认的数据包编号
        m_data_packets.m_largest_acked = std::max(m_data_packets.m_largest_acked, largest_acked);
        uint64_t prior_inflight = m_bytes_inflight;

        // 检测并移除已确认的数据包
        auto acked_packets = detectAndRemoveAckedPackets(frame);
        if (acked_packets.size() == 0) {
            return false;
        }

        // 更新RTT统计（基于最大确认的数据包）
        if (acked_packets.size() > 0) {
            auto packet = acked_packets[acked_packets.size() - 1];
            if (packet->packetNumber() == frame->largestAcked()) {
                // 计算ACK延迟，确保不超过最大ACK延迟
                uint64_t ack_delay = std::min(frame->ack_delay(), m_rtt_stats->maxAckDelay());
                // 计算实际RTT
                uint64_t real_rtt = recv_time - packet->sendTime();
                // 更新RTT统计信息
                m_rtt_stats->updateRTT(real_rtt, ack_delay, recv_time);
                // 拥塞控制可能退出慢启动
                m_congestion->maybeExitSlowStart();
            }
        }
        std::vector<QuicPacket::ptr> lost_packets;
        if (!detectLostPackets(recv_time, lost_packets)) {
            _LOG_INFO(g_logger) << "after detectLostPackets m_data_packets.m_loss_time:"
                                << m_data_packets.m_loss_time;
            return false;
        }
        _LOG_DEBUG(g_logger) << "after detectLostPackets m_data_packets.m_loss_time:"
                             << m_data_packets.m_loss_time;
        std::vector<QuicPacket::ptr> acked_packets_for_event;
        std::vector<QuicPacket::ptr> lost_packets_for_event;
        bool acked_1RTT_packet = false;
        for (const auto &packet : acked_packets) {
            if (packet->includedInBytesInflight() && !packet->declaredLost()) {
                if (m_is_bbr) {
                    acked_packets_for_event.push_back(packet);
                } else {
                    m_congestion->onPacketAcked(packet->packetNumber(), packet->len(),
                                                prior_inflight, recv_time);
                }
            }
            // _LOG_INFO(g_logger) << "acked_packets.size: " << acked_packets.size() << ",
            // infly: " << m_bytes_inflight;
            removeFromBytesInflight(packet);
        }
        if (m_is_bbr) {
            if (lost_packets.size()) {
                for (const auto &packet : lost_packets) {
                    lost_packets_for_event.push_back(packet);
                }
            }
            BbrSender::ptr bbr_cong = std::dynamic_pointer_cast<BbrSender>(m_congestion);
            bbr_cong->onCongEvent(true, prior_inflight, bytesInflight(), recv_time,
                                  acked_packets_for_event, lost_packets_for_event, 0);
        }

        // 重置PTO(超时探测)计数
        m_PTO_count = 0;
        // 重置需要发送的探测包数量
        m_num_probes_to_send = 0;
        // 删除旧的数据包历史记录，避免内存泄漏
        m_data_packets.m_history->deleteOldPackets(recv_time);
        // 重新设置丢包检测定时器
        setLossDetectionTimer(1);
        // 返回是否确认了1RTT数据包
        return acked_1RTT_packet;
    }

    /**
     * @brief 处理丢包检测超时事件
     * @return 是否需要发送探测包
     *
     * 当丢包检测定时器超时时调用此方法，执行丢包检测或发送探测包
     * 这是QUIC协议中确保数据可靠传输的关键机制
     */

    /**
     * @brief 处理丢包检测超时事件
     * @return 是否需要发送探测包
     *
     * 当丢包检测定时器超时时调用此方法，执行丢包检测或发送探测包
     * 这是QUIC协议中确保数据可靠传输的关键机制
     */
    bool SentPacketHandler::onLossDetectionTimeout()
    {
        // 创建临时缓冲区并设置析构回调，确保在方法结束后重置丢包检测定时器
        std::shared_ptr<char> buffer(new char[1], [this](char *ptr) {
            delete[] ptr;
            this->setLossDetectionTimer(2); // 重新设置定时器类型2（超时后）
        });

        // 获取最早的丢包检测时间点
        uint64_t earliest_loss_time = m_data_packets.m_loss_time;

        // 如果有需要检测的丢包时间点，则执行丢包检测
        if (earliest_loss_time) {
            std::vector<QuicPacket::ptr> lost_packets;
            std::vector<QuicPacket::ptr> acked_packets;
            uint64_t prior_inflight = bytesInflight();
            bool ret = detectLostPackets(GetCurrentUS(), lost_packets);
            if (m_is_bbr && lost_packets.size()) {
                BbrSender::ptr bbr_cong = std::dynamic_pointer_cast<BbrSender>(m_congestion);
                bbr_cong->onCongEvent(true, prior_inflight, bytesInflight(), GetCurrentUS(),
                                      acked_packets, lost_packets, 0);
            }
            return ret;
        }

        // 这段代码被禁用（条件中包含false），原本可能用于处理无飞行数据时的超时
        if (m_bytes_inflight == 0 && false) {
            m_PTO_count++; // 增加超时探测计数
            m_num_probes_to_send++;
            return true;
        }

        // 如果没有未确认的数据包，则不需要发送探测包
        if (!m_data_packets.m_history->hasOutstandingPackets()) {
            return false;
        }

        // 增加PTO(超时探测)计数
        m_PTO_count++;
        _LOG_DEBUG(g_logger) << "onLossDetectionTimeout: pto timeout, retrans";

        // 增加需要发送的探测包数量（发送2个探测包以提高可靠性）
        m_num_probes_to_send += 2;
        return true;
    }

    /**
     * @brief 确定当前的数据包发送模式
     * @return 当前的数据包发送模式
     *
     * 根据跟踪的数据包数量、需要发送的探测包数量和拥塞控制状态，
     * 确定当前应该使用哪种数据包发送模式
     */
    PacketSendMode SentPacketHandler::sendMode()
    {
        // 获取当前跟踪的数据包数量
        uint64_t num_tracked_packets = m_data_packets.m_history->len();

        // 如果跟踪的数据包数量过多（超过4MB），暂停发送新数据以防止内存溢出
        if (num_tracked_packets >= 1024 * 1024 * 4) {
            return PacketSendMode::PACKET_SEND_NONE; // 不发送任何数据包
        }

        // 如果有待发送的探测包，则优先发送超时探测相关的应用数据
        if (m_num_probes_to_send > 0) {
            return PacketSendMode::PACKET_SEND_PTO_APP_DATA; // 发送超时探测应用数据
        }

        // 如果拥塞控制不允许发送新数据，则只发送ACK包
        if (!m_congestion->canSend(m_bytes_inflight)) {
            _LOG_WARN(g_logger) << "sendMode: PACKET_SEND_ACK";
            return PacketSendMode::PACKET_SEND_ACK; // 只发送ACK包
        }

        // 默认情况下，允许发送任何类型的数据包
        return PacketSendMode::PACKET_SEND_ANY; // 允许发送任何数据包
    }

} // namespace quic
} // namespace base
