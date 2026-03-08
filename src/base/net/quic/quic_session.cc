// QUIC 会话实现文件
// 实现了 QUIC 协议中的会话管理、帧处理、数据包收发等核心功能

#include "quic_session.h"        // 包含 QUIC 会话相关的头文件定义
#include "quic_server.h"         // 包含 QUIC 服务器相关定义
#include "base/log/log.h"        // 日志系统
#include "base/util.h"           // 工具函数
#include "base/coro/scheduler.h" // 协程调度器
#include "base/coro/iomanager.h" // IO 管理器
#include "base/mbuffer.h"        // 内存缓冲区
#include "base/net/address.h"    // 网络地址

#include <functional>   // 函数对象支持
#include "base/macro.h" // 宏定义

namespace base
{
namespace quic
{
    // 全局日志对象，用于 QUIC 模块的日志记录
    static base::Logger::ptr g_logger = _LOG_NAME("system");

    /// SessionSemaphore - QUIC会话信号量，用于协程间同步和事件通知

    /**
     * @brief 构造函数
     * 初始化会话信号量对象
     */
    SessionSemaphore::SessionSemaphore()
    {
    }

    /**
     * @brief 析构函数
     * 清理会话信号量资源
     */
    SessionSemaphore::~SessionSemaphore()
    {
    }

    /**
     * @brief 等待事件信号
     * 阻塞当前协程，直到有事件通知到达或超时
     * @return QuicSessionEvent 返回接收到的事件类型
     */
    QuicSessionEvent SessionSemaphore::wait()
    {
        _ASSERT(Scheduler::GetThis()); // 确保当前线程有协程调度器
        {
            MutexType::Lock lock(m_mutex); // 获取互斥锁
            if (m_events.size() > 0u) {    // 如果已有事件，直接返回第一个事件
                auto ev = m_events.front();
                m_events.pop_front();
                return ev;
            }
            // 没有事件时，将当前协程加入等待队列
            m_waiters.push_back(std::make_pair(Scheduler::GetThis(), Fiber::GetThis()));
        }
        // 挂起当前协程，等待被唤醒
        Fiber::GetThis()->YieldToHold();
        {
            MutexType::Lock lock(m_mutex); // 重新获取互斥锁
            // _ASSERT(m_events.size() > 0u); // 协程被唤醒时应该有事件
            auto ev = m_events.front(); // 获取第一个事件
            m_events.pop_front();
            return ev;
        }
    }

    /**
     * @brief 通知事件信号
     * 唤醒等待队列中的协程并传递事件
     * @param event 要通知的事件类型
     */
    void SessionSemaphore::notify(QuicSessionEvent event)
    {
        MutexType::Lock lock(m_mutex);     // 获取互斥锁
        m_events.push_back(event);         // 添加事件到队列
        if (!m_waiters.empty()) {          // 如果有等待的协程
            auto next = m_waiters.front(); // 获取第一个等待的协程
            m_waiters.pop_front();
            next.first->schedule(next.second); // 调度协程继续执行
        }
    }

    /**
     * @brief 获取信号量状态的字符串表示
     * 用于调试和日志记录
     * @return std::string 包含信号量当前状态的字符串
     */
    std::string SessionSemaphore::toString()
    {
        std::stringstream ss;
        ss << "concurrency: " << m_events.size(); // 显示当前事件队列大小
        return ss.str();
    }

    /// WinUpdateQueue - 窗口更新队列，用于管理QUIC连接和流的流量控制窗口更新

    /**
     * @brief 添加需要窗口更新的流ID
     * 将指定的流ID加入到窗口更新队列中
     * @param id 需要更新窗口的流ID
     */
    void WinUpdateQueue::addStream(QuicStreamId id)
    {
        MutexType::Lock lock(m_mutex); // 获取互斥锁
        m_queue.insert(id);            // 将流ID添加到队列中
    }

    /**
     * @brief 标记连接级别的窗口需要更新
     * 设置连接级别窗口更新标志
     */
    void WinUpdateQueue::addConnection()
    {
        MutexType::Lock lock(m_mutex); // 获取互斥锁
        m_queued_conn = true;          // 设置连接窗口更新标志
    }

    /**
     * @brief 处理所有排队的窗口更新
     * 为队列中的所有流和连接生成窗口更新帧并通过回调发送
     */
    void WinUpdateQueue::queueAll()
    {
        MutexType::Lock lock(m_mutex); // 获取互斥锁

        // 处理连接级别的窗口更新
        if (m_queued_conn) {
            // 创建最大数据帧，包含连接级别的窗口更新值
            auto max_data_frame =
                std::make_shared<QuicMaxDataFrame>(m_conn_flow_controller->getWinUpdate());
            m_cb(max_data_frame);  // 通过回调发送窗口更新帧
            m_queued_conn = false; // 重置连接窗口更新标志
        }

        // 处理流级别的窗口更新
        for (const auto &id : m_queue) {
            // 获取或打开对应的接收流
            auto stream = m_streams->getOrOpenReceiveStream(id);
            if (stream == nullptr) {
                continue; // 流不存在则跳过
            }

            // 获取流的窗口更新值
            uint64_t offset = stream->getWinUpdate();
            _LOG_DEBUG(g_logger) << "stream getWinUpdate offset: " << offset;
            if (offset == 0) {
                continue; // 没有更新则跳过
            }

            // 创建最大流数据帧，包含流ID和窗口更新值
            auto max_stream_data_frame = std::make_shared<QuicMaxStreamDataFrame>(id, offset);
            m_cb(max_stream_data_frame); // 通过回调发送窗口更新帧
        }

        m_queue.clear(); // 清空窗口更新队列
    }

    /// QuicSession - QUIC会话类，管理QUIC连接的生命周期、帧处理、流管理等核心功能

    /**
     * @brief 当流有新数据时的回调处理
     * 将流标记为活跃状态并触发写操作
     * @param stream_id 有新数据的流ID
     */
    void QuicSession::onHasStreamData(QuicStreamId stream_id)
    {
        addActiveStream(stream_id); // 添加到活跃流队列
        signalWrite();              // 触发写事件通知
    }

    /**
     * @brief 当流完成时的回调处理
     * 从流管理器中删除已完成的流
     * @param stream_id 已完成的流ID
     */
    void QuicSession::onStreamCompleted(QuicStreamId stream_id)
    {
        m_streams->deleteStream(stream_id); // 删除流
    }

    /**
     * @brief QuicSession构造函数
     * 初始化QUIC会话的各个组件和状态
     * @param server QUIC服务器实例指针
     * @param role 连接角色（客户端或服务器）
     * @param cid 连接ID
     * @param peer_addr 对端地址
     */
    QuicSession::QuicSession(std::shared_ptr<QuicServer> server, QuicRole role,
                             QuicConnectionId::ptr cid, Address::ptr peer_addr, Socket::ptr sock)
        : m_server(server), m_role(role), m_cid(cid), m_ssl(false), m_peer_addr(peer_addr),
          m_socket(sock)
    {
        // 初始化流管理器，绑定流量控制器创建回调
        m_streams = std::make_shared<QuicStreamManager>(
            role, std::bind(&QuicSession::newFlowController, this, std::placeholders::_1));

        // 初始化数据包编号管理器
        m_pn_mgr = std::make_shared<PacketNumberManager>(1, ~0ull);

        // 初始化RTT统计器
        m_rtt_stats = std::make_shared<RTTStats>();

        // 初始化发送数据包处理器
        m_sent_packet_handler = std::make_shared<SentPacketHandler>(m_rtt_stats);

        // 初始化接收数据包处理器
        m_received_packet_handler = std::make_shared<ReceivedPacketTracker>();

        // 初始化重传队列
        m_retrans_queue = std::make_shared<RetransmissionQueue>();

        // 初始化连接级流量控制器
        // 参数：初始窗口大小(768KB)，最大窗口大小(15MB)，RTT统计，窗口更新回调
        m_conn_flow_controler = std::make_shared<ConnectionFlowController>(
            1.5 * (1 << 10) * 512, 15 * (1 << 20), m_rtt_stats,
            std::bind(&QuicSession::onHasConnectionWinUpdate, this));

        // 初始化窗口更新队列
        m_win_update_queue = std::make_shared<WinUpdateQueue>(
            m_streams, m_conn_flow_controler,
            std::bind(&QuicSession::queueControlFrame, this, std::placeholders::_1));

        // 设置会话初始为活跃状态
        m_is_alive = true;
    }

    /**
     * @brief QuicSession析构函数
     * 清理会话资源
     */
    QuicSession::~QuicSession()
    {
        std::cout << "~QuicSession" << std::endl;
    }

    /// RetransmissionQueue - 重传队列内部类，管理需要重传的应用数据帧

    /**
     * @brief 添加应用数据帧到重传队列
     * @param frame 需要重传的QUIC帧
     */
    void QuicSession::RetransmissionQueue::addAppData(QuicFrame::ptr frame)
    {
        _LOG_INFO(g_logger) << "add frame to retrans: " << frame->toString();
        m_app_data.push_back(frame); // 添加帧到重传队列
    }

    /**
     * @brief 从队列获取一个应用数据帧用于重传
     * @param max_len 最大允许的帧长度
     * @return QuicFrame::ptr 获取到的帧，如果队列为空或帧太大则返回nullptr
     */
    QuicFrame::ptr QuicSession::RetransmissionQueue::getAppDataFrame(uint64_t max_len)
    {
        if (m_app_data.size() == 0) {
            return nullptr; // 队列为空
        }
        auto f = m_app_data.front();
        if (f->size() > max_len) {
            return nullptr; // 帧太大，无法在当前可用空间中发送
        }
        m_app_data.pop_front(); // 从队列中移除
        return f;               // 返回获取的帧
    }

    /**
     * @brief 处理接收到的QUIC帧
     * 根据帧类型执行相应的处理逻辑
     * @param frame 接收到的QUIC帧
     * @param now 当前时间戳
     * @return int 处理结果，0表示成功，-1表示失败
     */
    int QuicSession::handleFrame(const QuicFrame::ptr &frame, uint64_t now)
    {
        // 根据帧类型执行不同的处理逻辑
        switch (frame->type()) {
            case QuicFrameType::STREAM: { // 处理流数据帧
                // 转换为流帧类型
                const auto &stream_frame = std::dynamic_pointer_cast<QuicStreamFrame>(frame);
                // 获取或打开对应的接收流
                const auto &stream = m_streams->getOrOpenReceiveStream(stream_frame->stream_id());
                if (stream == nullptr) {
                    _LOG_INFO(g_logger)
                        << "handleFrame failed: cant get stream, id: " << stream_frame->stream_id();
                    return -1;
                }
                // 处理流帧数据
                auto res = stream->handleStreamFrame(stream_frame);
                if (res->m_code != 0) {
                    _ASSERT(0); // 断言失败
                }
                _LOG_WARN(g_logger) << "trace now: " << GetCurrentUS()
                                    << " handleStreamFrame offset " << stream_frame->offset();
                break;
            }
            case QuicFrameType::ACK: { // 处理ACK帧
                QuicAckFrame::ptr ack_frame = std::dynamic_pointer_cast<QuicAckFrame>(frame);
                _LOG_DEBUG(g_logger) << "trace now: " << GetCurrentUS()
                                     << " largest_ack: " << ack_frame->largestAcked()
                                     << " delay: " << ack_frame->ack_delay();
                // 通知发送包处理器收到了ACK
                m_sent_packet_handler->receivedAck(ack_frame, now);
                break;
            }
            case QuicFrameType::CONNECTION_CLOSE: { // 处理连接关闭帧
                QuicConnectionCloseFrame::ptr conn_close_frame =
                    std::dynamic_pointer_cast<QuicConnectionCloseFrame>(frame);
                if (conn_close_frame == nullptr) {
                    _LOG_INFO(g_logger) << "handleFrame failed: cant cast connection close frame";
                    return -1;
                }
                if (conn_close_frame->isAppErr()) {
                    // closeRemote(); // TODO: 应用错误处理
                }
                // closeRemote(); // TODO: 关闭连接
                break;
            }
            case QuicFrameType::MAX_DATA: { // 处理最大数据帧（连接级别流量控制）
                const auto &max_data_frame = std::dynamic_pointer_cast<QuicMaxDataFrame>(frame);
                if (max_data_frame == nullptr) {
                    _LOG_INFO(g_logger) << "handleFrame failed: cant cast max data frame";
                    return -1;
                }
                // 更新连接级别的发送窗口
                m_conn_flow_controler->updateSendWin(max_data_frame->maximum_stream_data());
                break;
            }
            case QuicFrameType::MAX_STREAM_DATA: { // 处理最大流数据帧（流级别流量控制）
                const auto &max_stream_data_frame =
                    std::dynamic_pointer_cast<QuicMaxStreamDataFrame>(frame);
                const auto &stream =
                    m_streams->getOrOpenSendStream(max_stream_data_frame->stream_id());
                if (stream == nullptr) {
                    _LOG_INFO(g_logger) << "handleFrame failed: cant get stream, id: "
                                        << max_stream_data_frame->stream_id();
                    return -1;
                }
                // 更新流级别的发送窗口
                stream->updateSendWin(max_stream_data_frame->maximum_stream_data());
                break;
            }
            case QuicFrameType::DATA_BLOCKED:        // 处理数据阻塞帧
            case QuicFrameType::STREAM_DATA_BLOCKED: // 处理流数据阻塞帧
            case QuicFrameType::STREAM_BLOCKED:      // 处理流阻塞帧
            case QuicFrameType::STOP_SENDING: {      // 处理停止发送帧
                const auto &stream = m_streams->getOrOpenReceiveStream(frame->stream_id());
                if (stream == nullptr) {
                    _LOG_INFO(g_logger)
                        << "handleFrame failed: cant get stream, id: " << frame->stream_id();
                    return -1;
                }
                // stream->writeStream()->cancelWrite(); // TODO: 处理流阻塞
                break;
            }
            case QuicFrameType::RESET_STREAM: { // 处理重置流帧
                const auto &reset_stream_frame =
                    std::dynamic_pointer_cast<QuicRstStreamFrame>(frame);
                const auto &stream =
                    m_streams->getOrOpenReceiveStream(reset_stream_frame->stream_id());
                if (stream == nullptr) {
                    _LOG_INFO(g_logger) << "handleFrame failed: cant get stream, id: "
                                        << reset_stream_frame->stream_id();
                    return -1;
                }
                // stream->readStream()->handleRstStreamFrame(reset_stream_frame); // TODO:
                // 处理流重置
                break;
            }
            default: { // 未处理的帧类型
                break;
            }
        }
        return 0; // 处理成功
    }

    /**
     * @brief 处理已解包的QUIC数据包
     * 解析数据包中的所有帧并进行处理
     * @param header 数据包头部
     * @param buffer_block 包含数据包内容的缓冲区
     * @return int 处理结果，0表示成功
     *
     * 已解包数据包处理流程：
     * 1. 解析数据包中的所有帧
     * 2. 遍历并处理每个帧
     * 3. 记录包含需要确认帧的数据包日志
     * 4. 更新接收包状态
     */
    int QuicSession::handleUnpackedPacket(const QuicEPacketHeader::ptr &header,
                                          const MBuffer::ptr &buffer_block)
    {
        QuicFrame::ptr frame = nullptr;     // 用于存储解析出的单个 QUIC 帧
        std::vector<QuicFrame::ptr> frames; // 用于存储一个数据包中包含的所有 QUIC 帧

        // 获取接收时间戳，用于RTT计算和超时处理
        uint64_t now = std::dynamic_pointer_cast<MBuffer_t>(buffer_block)->time;
        bool is_ack_eliciting = false; // 标志位，指示当前数据包是否包含需要对端确认的帧
        std::string tmp = ""; // 临时字符串，用于调试输出帧类型

        // --- 1. 循环解析数据包中的所有 QUIC 帧 ---
        while (1) {
            // 使用 QuicFrameCodec::parseNext 从 buffer_block 中解析下一个 QUIC 帧
            frame = QuicFrameCodec::parseNext(buffer_block);
            if (frame == nullptr) {
                // 解析完成或数据不足，退出循环
                break;
            }

            // 检查当前帧是否需要对端确认（如STREAM、CRYPTO等）
            if (isFrameAckEliciting(frame)) {
                is_ack_eliciting = true;
            }

            frames.push_back(frame); // 将解析出的帧添加到帧列表中
        }

        // --- 2. 遍历并处理所有解析出的 QUIC 帧 ---
        for (const auto &frame : frames) {
            // 调用 handleFrame 函数根据帧类型执行相应的处理逻辑
            handleFrame(frame, now);

            // 记录帧类型信息，用于调试
            tmp += (std::to_string((uint64_t)frame->type()) + " ");
        }

        // --- 3. 记录日志（如果数据包包含需要确认的帧） ---
        if (is_ack_eliciting) {
            _LOG_DEBUG(g_logger) << "received packet: " << header->toString()
                                 << ", ack_eliciting: " << is_ack_eliciting;
        }

        // --- 4. 更新接收到的数据包状态 ---
        // 通知接收包处理器收到了一个数据包，更新会话的接收状态
        // 这会触发ACK生成、拥塞控制状态更新等
        m_received_packet_handler->receivedPacket(header->m_packet_number, now, is_ack_eliciting);

        return 0; // 成功处理数据包
    }

    /**
     * @brief 处理接收到的QUIC数据包
     * 解析连接ID和数据包头部，并转发给handleUnpackedPacket进行帧处理
     * @param buffer_block 包含数据包内容的缓冲区
     * @return int 处理结果，0表示成功，-1表示失败
     *
     * 数据包处理流程：
     * 1. 解析目标连接ID
     * 2. 解析数据包头部
     * 3. 读取数据包编号
     * 4. 调用handleUnpackedPacket处理数据包中的帧
     */
    int QuicSession::handlePacket(const MBuffer::ptr &buffer_block)
    {
        // 1. 解析数据包中的目标连接ID
        // QUIC数据包的第一个字段是连接ID，用于标识接收连接
        const auto &dst_cid = QuicConnectionId::parseConnectionId(buffer_block);
        if (dst_cid == nullptr) {
            _LOG_INFO(g_logger) << "parseConnectionId failed";
            return -1; // 连接ID解析失败，返回错误
        }

        // 2. 解析数据包头部
        // 读取并解析QUIC数据包的头部信息，包括版本、类型等
        const auto &header = readPacketHeaderFrom(buffer_block);
        if (header == nullptr) {
            _LOG_INFO(g_logger) << "handlePacket failed";
            return -1; // 头部解析失败，返回错误
        }

        // 3. 读取数据包编号
        // 数据包编号用于去重和顺序确认
        header->readPacketNumberFrom(buffer_block);
        _LOG_INFO(g_logger) << "recv packet num: " << header->m_packet_number;

        // 4. 处理已解包的数据包，解析和处理其中的所有帧
        // handleUnpackedPacket会解析数据包中的每个帧并根据帧类型执行相应的处理
        handleUnpackedPacket(header, buffer_block);

        return 0; // 处理成功，返回0
    }

    /**
     * @brief 触发读取事件
     * 将接收到的数据包添加到接收队列，并在队列为空时通知会话信号量
     * @param buffer_block 接收到的数据包缓冲区，可为空（用于仅触发读取）
     * @return int 返回队列之前是否为空，1表示之前为空，0表示之前不为空
     *
     * 信号读取处理流程：
     * 1. 获取写锁保护接收队列
     * 2. 检查队列是否为空并记录状态
     * 3. 将数据包添加到接收队列（如果提供）
     * 4. 释放锁
     * 5. 如果队列之前为空，则通知会话信号量
     * 6. 返回队列之前的空状态
     */
    int QuicSession::signalRead(base::MBuffer::ptr buffer_block)
    {
        // 获取写锁保护接收队列，确保线程安全
        RWMutexType::WriteLock lock(m_mutex);

        // 检查队列是否为空，用于后续决定是否需要通知信号量
        bool empty = m_received_queue.empty();

        // 如果提供了缓冲区，将其添加到接收队列
        if (buffer_block) {
            m_received_queue.push_back(buffer_block);
        }

        // 释放锁，避免在通知信号量时持有锁
        lock.unlock();

        // 如果队列之前为空，表示这是新的一批数据
        // 需要通知会话信号量，唤醒可能正在等待数据的线程
        if (empty) {
            m_session_sem.notify(QuicSessionEvent::READ);
        }

        // 返回队列之前是否为空的状态
        // 1表示之前为空，0表示之前不为空
        return empty;
    }

    /**
     * @brief 发送数据包缓冲区
     * 通过服务器实例将构建好的QUIC数据包发送到对端地址
     * @param buffer_block 待发送的数据包缓冲区，包含完整的数据包内容
     *
     * 数据包发送流程：
     * 1. 获取服务器实例
     * 2. 检查服务器是否有效
     * 3. 调用服务器的sendPacket方法执行实际发送
     *
     * 注意：该方法是QUIC会话发送数据包的最终出口点，
     * 被sendPacket方法调用，负责将构建好的数据包通过服务器实例发送出去。
     */
    void QuicSession::sendPacketBuffer(MBuffer::ptr buffer_block)
    {
        // 获取服务器实例，该实例负责底层的网络传输
        const auto &server = getServer();

        // 检查服务器是否有效，无效则不执行任何操作
        if (server == nullptr) {
            return;
        }

        server->sendPacket(m_socket, buffer_block, m_peer_addr);
    }

    bool QuicSession::maybePackProbePacket(uint64_t now)
    {
        return sendPacket(now);
    }

    void QuicSession::sendProbePacket()
    {
        MBuffer::ptr buffer = nullptr;
        while (1) {
            uint64_t now = GetCurrentUS();
            bool was_queued = m_sent_packet_handler->queueProbePacket();
            if (!was_queued) {
                break;
            }
            if (maybePackProbePacket(now)) {
                break;
            }
        }
    }

    void QuicSession::sendPackets()
    {
        uint64_t count = 0;
        m_pacing_deadline = 0;
        bool sent_packet = false;
        while (1) {
            bool cont = false;
            uint64_t now = GetCurrentUS();
            PacketSendMode send_mode = m_sent_packet_handler->sendMode();
            if (send_mode == PacketSendMode::PACKET_SEND_ANY
                && !m_sent_packet_handler->hasPacingBudget()) {
                uint64_t deadline = m_sent_packet_handler->timeUntilSend();
                if (!deadline) {
                    deadline = now + 1;
                    _LOG_WARN(g_logger) << "timeUntilSend: imm";
                } else {
                    _LOG_WARN(g_logger) << "timeUntilSend: " << deadline - now;
                }
                m_pacing_deadline = deadline;
                if (sent_packet) {
                    return;
                }
                send_mode = PacketSendMode::PACKET_SEND_ACK;
            }
            switch (send_mode) {
                case PacketSendMode::PACKET_SEND_NONE: {
                    break;
                }
                case PacketSendMode::PACKET_SEND_ACK: {
                    break;
                }
                case PacketSendMode::PACKET_SEND_PTO_APP_DATA: {
                    sendProbePacket();
                    break;
                }
                case PacketSendMode::PACKET_SEND_ANY: {
                    cont = sendPacket(now);
                    _LOG_DEBUG(g_logger) << "sentPacket cont: " << cont;
                    count++;
                    break;
                }
                default: {
                    break;
                }
            }
            if (m_received_queue.size() > 0) {
                break;
            }
            if (!cont || count > 4) {
                break;
            }
        }
    }

    uint64_t QuicSession::appendControlFrames(std::list<QuicFrame::ptr> &frames,
                                              uint64_t max_packet_size)
    {
        if (m_control_frames.size() == 0) {
            return 0;
        }
        uint64_t payload_len = 0;
        for (auto it = m_control_frames.rbegin(); it != m_control_frames.rend();) {
            auto frame = *it;
            uint64_t frame_len = frame->size();
            if (payload_len + frame_len > max_packet_size) {
                break;
            }
            frames.push_back(frame);
            _LOG_INFO(g_logger) << "append control frame: " << frame->toString();
            payload_len += frame_len;
            it = std::list<QuicFrame::ptr>::reverse_iterator(m_control_frames.erase((++it).base()));
        }
        return payload_len;
    }

    /**
     * @brief 组合下一个数据包的有效载荷
     * 按照QUIC协议优先级顺序组装数据包内容：ACK帧 → 重传帧 → 控制帧 → 流帧
     * @param max_payload_size 最大有效载荷大小
     * @param ack_allow 是否允许添加ACK帧
     * @return QuicPacketPayload::ptr 组合好的数据包有效载荷
     *
     * 有效载荷组合流程：
     * 1. 创建有效载荷容器对象
     * 2. 按照优先级顺序添加各类帧：
     *    - 第一优先级：ACK帧（确保及时确认接收到的数据）
     *    - 第二优先级：重传帧（确保数据可靠传输）
     *    - 第三优先级：控制帧（确保连接状态同步）
     *    - 第四优先级：流帧（应用数据）
     * 3. 严格控制数据包大小，不超过限制
     */
    const QuicPacketPayload::ptr QuicSession::composeNextPacket(uint64_t max_payload_size,
                                                                bool ack_allow)
    {
        // 创建新的数据包有效载荷对象，用于存储所有待发送的帧和元数据
        auto payload = std::make_shared<QuicPacketPayload>();

        // 检查是否有待重传的数据，重传帧的优先级高于普通控制帧和流帧
        bool has_retrans = m_retrans_queue->hasAppData();

        // 第一优先级：添加ACK帧（如果允许）
        // ACK帧确保数据传输的可靠性和拥塞控制的正常工作
        if (ack_allow) {
            // 检查是否有控制帧或其他数据需要发送
            bool has_data = m_control_frames.size() > 0 || true; // TODO: 修复硬编码的true值
            // 如果没有重传和其他数据，则需要获取ACK帧
            // 即使当前只有ACK帧也要发送，避免对端超时重传
            bool get_ack_queue = !has_retrans && !has_data;
            _LOG_DEBUG(g_logger) << "getAckFrame: " << get_ack_queue
                                 << ", control_frame.size: " << m_control_frames.size()
                                 << ", retrans: " << has_retrans;

            // 从接收包处理器获取ACK帧，包含已确认的数据包编号等信息
            auto ack_frame = m_received_packet_handler->getAckFrame(get_ack_queue);
            if (ack_frame) {
                // 将ACK帧添加到有效载荷
                payload->ack = ack_frame;
                // 更新有效载荷总长度
                payload->length += ack_frame->size();
            }
        }

        // 第二优先级：添加重传数据（确保可靠性）
        // 重传帧包含之前未被确认的数据，优先级高于新数据
        if (has_retrans) {
            // 循环添加重传帧，直到没有更多重传帧或空间不足
            while (1) {
                // 计算剩余可用空间
                uint64_t remain_len = max_payload_size - payload->length;
                // 如果剩余空间小于最小阈值(128字节)，不足以添加有意义的帧，退出循环
                if (remain_len < 128) {
                    break;
                }

                // 从重传队列获取一个适合剩余空间大小的重传帧
                auto frame = m_retrans_queue->getAppDataFrame(remain_len);
                if (!frame) { // 没有更多适合的重传帧
                    break;
                }

                // 添加重传帧到有效载荷的帧列表
                payload->frames.push_back(frame);
                // 更新有效载荷总长度
                payload->length += frame->size();
            }
        }

        // 第三和第四优先级：添加控制帧和流帧（应用数据）
        // 注意：此处有一个待实现的TODO，应根据实际应用数据可用性判断
        if (true) { // bool has_app_data TODO: 待实现的应用数据检查
            // 添加控制帧，优先级高于普通流数据
            // appendControlFrames返回添加的控制帧总大小
            payload->length +=
                appendControlFrames(payload->frames, max_payload_size - payload->length);

            // 添加流帧，填充剩余空间
            // popStreamFrames返回添加的流帧总大小
            payload->length += popStreamFrames(payload->frames, max_payload_size - payload->length);
        }

        // 返回组装好的数据包有效载荷，包含所有按优先级排序的帧和总长度信息
        return payload;
    }

    /**
     * @brief 从流队列中弹出流帧
     * 按照流队列顺序获取流帧，确保不超过最大数据包大小限制
     * @param frames 输出参数，存储获取到的流帧
     * @param max_packet_size 最大数据包大小限制
     * @return int 添加的所有流帧的总大小
     */
    int QuicSession::popStreamFrames(std::list<QuicFrame::ptr> &frames, uint64_t max_packet_size)
    {
        // 加锁保护活跃流的并发访问
        MutexType::Lock lock(m_active_stream_mutex);

        int payload_len = 0;               // 已添加的流帧总大小
        int remain_size = max_packet_size; // 剩余可用空间
        std::list<QuicStreamId> stream_queue;

        // 交换流队列，避免在处理过程中修改原队列
        m_stream_queue.swap(stream_queue);

        // 遍历流队列中的所有流ID
        while (!stream_queue.empty() && remain_size > 0) {
            // 获取队首的流ID
            QuicStreamId id = stream_queue.front();
            stream_queue.pop_front();

            // 获取或打开对应的发送流
            auto stream = m_streams->getOrOpenSendStream(id);
            if (stream == nullptr) {
                // 流不存在，从活跃流集合中移除
                m_active_streams.erase(id);
                continue;
            }

            // 从流中获取一个流帧
            auto res = stream->popStreamFrame(remain_size);
            QuicFrame::ptr frame = std::get<0>(res);
            bool has_more_data = std::get<1>(res);

            // 如果流还有更多数据，将流ID重新加入队列
            if (has_more_data) {
                m_stream_queue.push_back(id);
            } else {
                // 流数据已发送完毕，从活跃流集合中移除
                m_active_streams.erase(id);
            }
            if (frame == nullptr) {
                continue;
            }
            frames.push_back(frame);
            payload_len += frame->size();
            remain_size -= payload_len;
        }

        _LOG_DEBUG(g_logger) << "payload_len: " << payload_len;
        return payload_len;
    }

    static MBuffer::ptr appendPacket(QuicPacketContents::ptr packet)
    {
        MBuffer::ptr buffer_block = std::make_shared<MBuffer>();
        auto header = packet->header;
        uint64_t pn_len = (int)header->m_packet_number_len;
        if (header->m_is_long_header) {
            header->m_length = pn_len + packet->length;
        }
        header->writeTo(buffer_block);
        if (packet->ack) {
            packet->ack->writeTo(buffer_block);
        }
        for (const auto &frame : packet->frames) {
            frame->writeTo(buffer_block);
            const auto &stream_frame = std::dynamic_pointer_cast<QuicStreamFrame>(frame);
            if (stream_frame) {
                _LOG_WARN(g_logger) << "trace now: " << GetCurrentUS()
                                    << " send offset: " << stream_frame->offset();
            }
        }
        return buffer_block;
    }

    /**
     * @brief 发送一个QUIC数据包
     * 构建数据包内容、处理流量控制、管理重传和发送数据包
     * @param now 当前时间戳
     * @return bool 是否成功发送数据包
     *
     * QUIC数据包发送完整流程：
     * 1. 处理流量控制状态（检查阻塞、队列窗口更新）
     * 2. 创建数据包内容和头部
     * 3. 组合数据包有效载荷（帧和ACK）
     * 4. 构建数据包缓冲区
     * 5. 创建数据包对象并设置重传回调
     * 6. 通知发送包处理器
     * 7. 调用sendPacketBuffer发送数据包
     * 8. 更新包序号管理器
     */
    bool QuicSession::sendPacket(uint64_t now)
    {
        // 第一步：处理流量控制状态
        // 检查连接级流量控制是否被阻塞
        uint64_t offset = m_conn_flow_controler->isNewlyBlocked();
        if (offset) {
            // 如果被阻塞，发送DATA_BLOCKED控制帧通知对端
            queueControlFrame(std::make_shared<QuicDataBlockedFrame>(offset));
        }

        // 队列所有流量控制窗口更新，确保对端及时了解可用窗口大小
        m_win_update_queue->queueAll();

        // 第二步：创建数据包结构
        // 设置最大数据包大小（基于MTU，QUIC推荐的标准值）
        uint64_t max_packet_size = 1252;

        // 创建数据包内容对象，用于存储数据包的所有组件
        QuicPacketContents::ptr packet_content = std::make_shared<QuicPacketContents>();

        // 设置数据包头部（使用短头部格式，初始类型）
        // TODO: 根据连接状态动态调整头部类型
        packet_content->header = getShortHeader(m_cid, QuicPacketType::INITIAL);

        // 计算可用的最大有效载荷大小 = 最大数据包大小 - 头部长度
        uint64_t max_payload_size = max_packet_size - packet_content->header->getLength();

        // 第三步：组合数据包有效载荷
        // 从待发送队列中组合下一个数据包的内容
        const auto &payload = composeNextPacket(max_payload_size);

        // 如果没有ACK帧和其他帧，不需要发送空数据包，返回失败
        if (payload->ack == nullptr && payload->frames.size() == 0) {
            return false;
        }

        // 设置数据包内容组件
        packet_content->frames = payload->frames; // 数据帧和控制帧
        packet_content->ack = payload->ack;       // ACK帧（如有）
        packet_content->length = payload->length; // 有效载荷总长度

        // 第四步：构建数据包二进制缓冲区
        // 将数据包头部、ACK帧和其他帧序列化为二进制数据
        packet_content->buffer = appendPacket(packet_content);

        // 第五步：创建数据包对象并设置重传机制
        auto packet = std::make_shared<QuicPacket>();
        packet->init(now, packet_content,
                     // 绑定重传队列回调，用于将数据包加入重传队列
                     std::bind(&QuicSession::RetransmissionQueue::addAppData,
                               shared_from_this()->m_retrans_queue, std::placeholders::_1));

        // 第六步：通知发送包处理器数据包已发送
        // 更新发送统计、拥塞控制状态等
        m_sent_packet_handler->sentPacket(packet, now);

        // 调试日志：记录当前发送时间和在途字节数
        _LOG_WARN(g_logger) << "trace now: " << GetCurrentUS()
                            << " session inflight: " << m_sent_packet_handler->bytesInflight();

        // 第七步：实际发送数据包
        // 调用sendPacketBuffer将数据包发送到底层网络
        sendPacketBuffer(packet_content->buffer);

        // 调试日志（当前禁用）：记录发送的每个帧的详细信息
        if (0) {
            for (const auto &frame : payload->frames) {
                _LOG_WARN(g_logger)
                    << "sent packet num: " << packet_content->header->m_packet_number
                    << ", frame: " << frame->toString();
            }
        }

        // 第八步：更新包序号管理器，为下一个数据包准备序号
        m_pn_mgr->pop();
        _LOG_WARN(g_logger) << "trace now: " << GetCurrentUS() << " send_pn "
                            << packet_content->header->m_packet_number;

        return true;
    }

    void QuicSession::signalWrite()
    {
        m_session_sem.notify(QuicSessionEvent::WRITE);
    }

    uint64_t QuicSession::nextKeepAliveTime()
    {
        return 0;
    }

    /**
     * @brief 计算并重置QUIC会话的定时器时间
     *
     * 该方法用于确定QUIC会话下一次需要触发的定时器时间点。它综合考虑了多种可能的超时事件，
     * 包括ACK确认超时、丢包检测超时和流量 pacing 超时，最终返回最早需要处理的超时时间。
     *
     * @return uint64_t 返回距离下次定时器触发需要等待的微秒数，如果已经超时则返回0
     */
    uint64_t QuicSession::maybeResetTimer()
    {
        // 获取当前时间（微秒级别）
        uint64_t now = GetCurrentUS();
        // 设置默认的超时时间为30ms（30*1000微秒）
        uint64_t deadline = now + 30 * 1000;

        // 获取ACK确认的警报时间
        uint64_t ack_alarm = m_received_packet_handler->ackAlarm();
        if (ack_alarm) {
            // 如果存在ACK警报，记录日志并将截止时间更新为两者中的较小值
            _LOG_INFO(g_logger) << "maybeResetTimer: now: " << now << ", deadline: " << deadline
                                << ", ack_alarm: " << ack_alarm;
            deadline = std::min(deadline, ack_alarm);
        }

        // 获取丢包检测的超时时间
        uint64_t loss_time = m_sent_packet_handler->getLossDetectionTimeout();
        if (loss_time) {
            // 如果存在丢包检测超时，将截止时间更新为两者中的较小值
            deadline = std::min(deadline, loss_time);
        }

        // 检查是否有流量pacing截止时间
        if (m_pacing_deadline) {
            // 如果存在pacing截止时间，将截止时间更新为两者中的较小值
            deadline = std::min(deadline, m_pacing_deadline);
        }

        // 如果截止时间已经过去，返回0表示需要立即处理
        if (deadline <= now) {
            return 0;
        }

        // 计算并返回需要等待的微秒数
        uint64_t res = deadline - now;
        _LOG_DEBUG(g_logger) << "maybeResetTimer: return deadline: " << res
                             << ", loss_time: " << loss_time << ", now: " << now;
        return res;
    }

    /**
     * @brief 会话的主运行循环
     * 处理读写事件、接收数据包、超时处理等核心逻辑
     * 运行在协程中，等待并响应各种会话事件
     */
    void QuicSession::run_impl()
    {
        try {
            // 主循环，只要会话处于活跃状态就继续运行
            while (isAlive()) {
                // 获取服务器实例
                const auto &server = getServer();
                if (server == nullptr) {
                    break; // 服务器不存在，退出循环
                }

                // 计算并重置各种定时器（ACK、丢包检测、Pacing等）
                uint64_t deadline = maybeResetTimer();
                base::Timer::ptr timer = nullptr;

                // 设置超时定时器
                if (deadline) {
                    timer = IOManager::GetThis()->addTimer(deadline / 1000, [this]() {
                        this->m_session_sem.notify(QuicSessionEvent::NONE);
                    });
                } else {
                    // 如果没有特定的超时时间，立即通知以避免无限等待
                    this->m_session_sem.notify(QuicSessionEvent::NONE);
                }

                // 等待事件发生（读、写或超时）
                QuicSessionEvent event = m_session_sem.wait();

                // 取消定时器（如果已触发，取消操作是安全的）
                if (timer) {
                    timer->cancel();
                }

                // 根据事件类型执行相应的处理
                switch (event) {
                    case QuicSessionEvent::READ: {
                        // 处理接收到的数据包
                        std::list<MBuffer::ptr> packets;
                        {
                            RWMutexType::WriteLock lock(m_mutex);
                            m_received_queue.swap(packets);
                        }
                        for (const auto &p : packets) {
                            handlePacket(p);
                        }
                        break;
                    }
                    case QuicSessionEvent::WRITE: {
                        // 处理写事件
                        break;
                    }
                    default: {
                        // 处理其他事件（如超时）
                        break;
                    }
                }

                // 再次检查并处理可能新收到的数据包
                if (m_received_queue.size() > 0) {
                    std::list<MBuffer::ptr> packets;
                    {
                        RWMutexType::WriteLock lock(m_mutex);
                        m_received_queue.swap(packets);
                    }
                    for (const auto &p : packets) {
                        handlePacket(p);
                    }
                }

                // 检查是否需要进行丢包检测
                uint64_t now = GetCurrentUS();
                uint64_t time_out = m_sent_packet_handler->getLossDetectionTimeout();
                if (time_out && time_out < now) {
                    _LOG_INFO(g_logger)
                        << "call onLossDetectionTimeout timeout: " << time_out << " < now: " << now;
                    m_sent_packet_handler->onLossDetectionTimeout();
                }

                // 尝试发送待发送的数据包
                sendPackets();
            }
        } catch (...) {
            // 捕获所有异常，防止程序崩溃
        }
    }

    /**
     * @brief 启动会话的运行循环
     * 将run_impl方法调度到IO管理器的协程中执行
     */
    void QuicSession::run()
    {
        // 将run_impl方法绑定到当前会话的共享指针，并提交到IO管理器执行
        base::IOManager::GetThis()->schedule(std::bind(&QuicSession::run_impl, shared_from_this()));
    }

    /**
     * @brief 打开一个新的发送流
     * 自动分配一个流ID并创建新的流对象
     * @return QuicStream::ptr 打开的流对象，如果失败则返回nullptr
     */
    const QuicStream::ptr QuicSession::openStream()
    {
        // 调用流管理器的openStream方法创建新流
        return m_streams->openStream();
    }

    /**
     * @brief 接受一个新的接收流
     * 从流管理器的待接受队列中获取下一个可用的流
     * @return QuicStream::ptr 接受的流对象，如果没有可用流则返回nullptr
     */
    const QuicStream::ptr QuicSession::acceptStream()
    {
        // 调用流管理器的acceptStream方法获取待接受的流
        return m_streams->acceptStream();
    }

    StreamFlowController::ptr QuicSession::newFlowController(QuicStreamId stream_id)
    {
        uint64_t initial_send_win = (1 << 10) * 512;
        return std::make_shared<StreamFlowController>(
            stream_id, m_conn_flow_controler,
            std::bind(&QuicSession::onHasStreamWinUpdate, shared_from_this(),
                      std::placeholders::_1),
            (1 << 10) * 512, (1 << 20) * 6, initial_send_win, m_rtt_stats);
    }

    void QuicSession::addActiveStream(QuicStreamId id)
    {
        MutexType::Lock lock(m_active_stream_mutex);
        if (m_active_streams.find(id) == m_active_streams.end()) {
            m_stream_queue.push_back(id);
            m_active_streams[id] = true;
        }
    }

    /**
     * @brief 获取短头部
     * 用于QUIC连接建立后的数据包传输，只包含目标连接ID和必要信息
     * @param cid 目标连接ID
     * @param type 数据包类型
     * @return QuicEPacketHeader::ptr 构建好的短头部对象
     */
    const QuicEPacketHeader::ptr QuicSession::getShortHeader(QuicConnectionId::ptr cid,
                                                             QuicPacketType type)
    {
        // 预取下一个数据包编号（不实际消费）
        QuicPacketNumber pn = m_pn_mgr->peek();

        // 计算数据包编号长度
        PacketNumberLen pn_len = PacketNumberManager::GetPacketNumberLengthForHeader(pn);

        // 构建类型字节，短头部标志位为0x40，低两位表示编号长度
        uint8_t type_byte = 0x40 | uint8_t((uint8_t)pn_len - 1);

        // 创建短头部对象
        QuicEPacketHeader::ptr header = std::make_shared<QuicEPacketHeader>(type_byte, false);

        // 设置数据包编号、长度和目标连接ID
        header->m_packet_number = pn;
        header->m_packet_number_len = pn_len;
        header->m_dst_cid = cid;
        header->m_type = type;

        return header;
    }

    /**
     * @brief 获取长头部
     * 用于QUIC连接建立阶段和连接迁移等场景，包含源和目标连接ID
     * @param sid 源连接ID
     * @param did 目标连接ID
     * @param type 数据包类型
     * @return QuicEPacketHeader::ptr 构建好的长头部对象
     */
    const QuicEPacketHeader::ptr QuicSession::getLongHeader(QuicConnectionId::ptr sid,
                                                            QuicConnectionId::ptr did,
                                                            QuicPacketType type)
    {
        // 预取下一个数据包编号（不实际消费）
        QuicPacketNumber pn = m_pn_mgr->peek();

        // 构建类型字节，长头部标志位为0xc0，设置版本信息
        uint8_t type_byte = 0xc0 | (0x01 << 4);

        // 创建长头部对象
        QuicEPacketHeader::ptr header = std::make_shared<QuicEPacketHeader>(type_byte, true);

        // 设置数据包编号、连接ID和类型信息
        header->m_packet_number = pn;
        // 设置数据包编号长度为1字节（TODO: 应根据实际情况动态计算）
        header->m_packet_number_len = PacketNumberLen::PACKET_NUMBER_LEN1;
        header->m_is_long_header = true;
        header->m_src_cid = sid;
        header->m_dst_cid = did;
        header->m_type = type;

        return header;
    }

    /// QuicSessionManager
    /**
     * @brief QUIC会话管理器
     * 负责管理所有活跃的QUIC会话，提供会话的创建、查找、删除和遍历功能
     * 使用连接ID的十六进制字符串表示作为键
     */

    /**
     * @brief 根据连接ID获取会话
     * 通过连接ID的十六进制字符串查找会话对象
     * @param cid 连接ID对象
     * @return QuicSession::ptr 会话对象，如果不存在则返回nullptr
     */
    const QuicSession::ptr QuicSessionManager::get(QuicConnectionId::ptr cid)
    {
        // 读锁保护，允许多个线程同时查询
        RWMutexType::ReadLock lock(m_mutex);
        const auto &it = m_sessions.find(cid->toHexString());
        return it == m_sessions.end() ? nullptr : it->second;
    }

    /**
     * @brief 添加新会话
     * 将会话添加到管理器中，使用会话的连接ID作为键
     * @param session 会话对象
     */
    void QuicSessionManager::add(QuicSession::ptr session)
    {
        // 写锁保护，确保线程安全的添加操作
        RWMutexType::WriteLock lock(m_mutex);
        m_sessions[session->getCid()->toHexString()] = session;
    }

    /**
     * @brief 删除会话
     * 从管理器中移除指定连接ID的会话
     * @param cid 连接ID的十六进制字符串表示
     */
    void QuicSessionManager::del(const std::string &cid)
    {
        // 写锁保护，确保线程安全的删除操作
        RWMutexType::WriteLock lock(m_mutex);
        m_sessions.erase(cid);
    }

    /**
     * @brief 清除所有会话
     * 清空管理器中的所有会话引用
     * 注意：当前实现仅复制会话集合，没有真正清空
     */
    void QuicSessionManager::clear()
    {
        // 写锁保护，确保线程安全的清空操作
        RWMutexType::WriteLock lock(m_mutex);
        auto sessions = m_sessions;
        lock.unlock();
    }

    /**
     * @brief 遍历所有会话
     * 对每个会话执行指定的回调函数
     * @param cb 回调函数，接收会话对象作为参数
     */
    void QuicSessionManager::foreach (std::function<void(QuicSession::ptr)> cb)
    {
        // 读锁保护，复制会话集合
        RWMutexType::ReadLock lock(m_mutex);
        auto m = m_sessions;
        lock.unlock();
        // 在锁外执行回调，避免死锁
        for (auto &i : m) {
            cb(i.second);
        }
    }

} // namespace quic
} // namespace base
