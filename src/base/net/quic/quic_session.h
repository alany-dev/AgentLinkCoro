#ifndef __QUIC_SESSION_HH__
#define __QUIC_SESSION_HH__

#include "base/noncopyable.h"
#include "base/mutex.h"
#include "base/net/stream.h"
#include "base/util/hash_util.h"
#include "base/coro/scheduler.h"
#include "quic_type.h"
#include "quic_frame.h"
#include "quic_packet.h"
#include "quic_stream.h"
#include "quic_packet_sorter.h"
#include "quic_flow_control.h"

#include <map>
#include <functional>

namespace base
{
namespace quic
{

    /**
     * @brief 会话信号量类，用于管理QUIC会话中的事件通知和等待机制
     *
     * 该类实现了一个专用的信号量机制，用于QUIC会话中的协程间通信，
     * 允许协程等待特定的会话事件并在事件发生时被唤醒。
     */
    class SessionSemaphore : public Noncopyable
    {
    public:
        typedef std::shared_ptr<SessionSemaphore> ptr;
        typedef Spinlock MutexType;

        /**
         * @brief 构造函数
         */
        SessionSemaphore();

        /**
         * @brief 析构函数
         */
        ~SessionSemaphore();

        /**
         * @brief 等待一个会话事件
         * @return 返回接收到的会话事件
         */
        QuicSessionEvent wait();

        /**
         * @brief 通知一个会话事件
         * @param event 要通知的事件类型
         */
        void notify(QuicSessionEvent event);

        /**
         * @brief 获取当前并发等待的事件数量
         * @return 事件数量
         */
        size_t concurrencySize() const { return m_events.size(); }

        /**
         * @brief 将信号量状态转换为字符串表示
         * @return 字符串表示
         */
        std::string toString();

    private:
        MutexType m_mutex;                                        // 互斥锁，保护内部状态
        std::list<QuicSessionEvent> m_events;                     // 事件列表
        std::list<std::pair<Scheduler *, Fiber::ptr> > m_waiters; // 等待协程列表
    };

    /**
     * @brief 窗口更新队列类，用于管理流控窗口更新
     *
     * 该类负责收集和管理连接级和流级的窗口更新请求，确保窗口更新帧被正确地排队和发送。
     */
    class WinUpdateQueue
    {
    public:
        typedef std::shared_ptr<WinUpdateQueue> ptr;
        typedef Mutex MutexType;

        /**
         * @brief 构造函数
         * @param streams 流管理器指针
         * @param conn_flow_controller 连接级流控器指针
         * @param cb 窗口更新帧回调函数
         */
        WinUpdateQueue(const QuicStreamManager::ptr &streams,
                       const ConnectionFlowController::ptr &conn_flow_controller,
                       const std::function<void(QuicFrame::ptr)> &cb)
            : m_streams(streams), m_conn_flow_controller(conn_flow_controller), m_cb(cb) {};

        /**
         * @brief 添加一个需要窗口更新的流
         * @param id 流ID
         */
        void addStream(QuicStreamId id);

        /**
         * @brief 添加连接级窗口更新请求
         */
        void addConnection();

        /**
         * @brief 处理所有排队的窗口更新请求
         */
        void queueAll();

    private:
        MutexType m_mutex;                                    // 互斥锁
        std::set<QuicStreamId> m_queue;                       // 需要窗口更新的流ID集合
        bool m_queued_conn = false;                           // 连接级窗口更新标志
        QuicStreamManager::ptr m_streams;                     // 流管理器
        ConnectionFlowController::ptr m_conn_flow_controller; // 连接流控器
        std::function<void(QuicFrame::ptr)> m_cb;             // 窗口更新回调
    };

    class QuicServer;

    /**
     * @brief QUIC会话类，管理QUIC连接的生命周期和状态
     *
     * 该类是QUIC协议实现的核心，负责处理QUIC连接的建立、维护和关闭，
     * 管理流的创建和销毁，以及处理各种QUIC帧和数据包。
     */
    class QuicSession : public std::enable_shared_from_this<QuicSession>, public StreamSender
    {
    public:
        friend QuicServer;
        typedef std::shared_ptr<QuicSession> ptr;
        typedef RWMutex RWMutexType;
        typedef Mutex MutexType;

        /**
         * @brief 当流有数据待发送时的回调
         * @param stream_id 流ID
         */
        virtual void onHasStreamData(QuicStreamId stream_id) override;

        /**
         * @brief 当流完成时的回调
         * @param stream_id 流ID
         */
        virtual void onStreamCompleted(QuicStreamId stream_id) override;

        /**
         * @brief 重传队列结构体，管理需要重传的应用数据帧
         */
        struct RetransmissionQueue {
            typedef std::shared_ptr<RetransmissionQueue> ptr;

            /**
             * @brief 检查是否有应用数据待重传
             * @return 如果有数据返回true，否则返回false
             */
            bool hasAppData() { return m_app_data.size() > 0; }

            /**
             * @brief 添加应用数据帧到重传队列
             * @param frame 要重传的帧
             */
            void addAppData(QuicFrame::ptr frame);

            /**
             * @brief 获取一个应用数据帧用于重传
             * @param max_len 最大长度限制
             * @return 应用数据帧指针
             */
            QuicFrame::ptr getAppDataFrame(uint64_t max_len);

            std::list<QuicFrame::ptr> m_app_data; // 待重传的应用数据帧列表
        };

        /**
         * @brief 构造函数
         * @param server QUIC服务器指针
         * @param role QUIC角色（客户端或服务器）
         * @param cid 连接ID
         * @param peer_addr 对端地址
         */
        QuicSession(std::shared_ptr<QuicServer> server, QuicRole role, QuicConnectionId::ptr cid,
                    Address::ptr peer_addr = nullptr, Socket::ptr m_sock = nullptr);

        /**
         * @brief 析构函数
         */
        ~QuicSession();

        /**
         * @brief 处理接收到的QUIC帧
         * @param frame 接收到的帧
         * @param now 当前时间戳
         * @return 处理结果
         */
        int handleFrame(const QuicFrame::ptr &frame, uint64_t now);

        /**
         * @brief 处理已解析的数据包
         * @param header 数据包头部
         * @param buffer_block 数据缓冲区
         * @return 处理结果
         */
        int handleUnpackedPacket(const QuicEPacketHeader::ptr &header,
                                 const MBuffer::ptr &buffer_block);

        /**
         * @brief 处理接收到的数据包
         * @param buffer_block 数据缓冲区
         * @return 处理结果
         */
        int handlePacket(const MBuffer::ptr &buffer_block);

        /**
         * @brief 触发读取操作
         * @param buffer_block 数据缓冲区
         * @return 处理结果
         */
        int signalRead(MBuffer::ptr buffer_block);

        /**
         * @brief 发送数据包缓冲区
         * @param buffer_block 数据缓冲区
         */
        void sendPacketBuffer(MBuffer::ptr buffer_block);

        /**
         * @brief 检查是否需要发送探测数据包
         * @param now 当前时间戳
         * @return 如果需要发送返回true
         */
        bool maybePackProbePacket(uint64_t now);

        /**
         * @brief 发送探测数据包
         */
        void sendProbePacket();

        /**
         * @brief 添加控制帧到帧列表
         * @param frames 帧列表
         * @param max_packet_size 最大数据包大小
         * @return 使用的字节数
         */
        uint64_t appendControlFrames(std::list<QuicFrame::ptr> &frames, uint64_t max_packet_size);

        /**
         * @brief 构建下一个数据包的负载
         * @param max_payload_size 最大负载大小
         * @param ack_allow 是否允许ACK帧
         * @return 数据包负载
         */
        const QuicPacketPayload::ptr composeNextPacket(uint64_t max_payload_size,
                                                       bool ack_allow = true);

        /**
         * @brief 从活跃流中获取帧
         * @param frames 帧列表
         * @param max_packet_size 最大数据包大小
         * @return 处理的帧数
         */
        int popStreamFrames(std::list<QuicFrame::ptr> &frames, uint64_t max_packet_size);

        /**
         * @brief 发送一个数据包
         * @param now 当前时间戳
         * @return 是否成功发送
         */
        bool sendPacket(uint64_t now);

        /**
         * @brief 发送所有待发送的数据包
         */
        void sendPackets();

        /**
         * @brief 触发写操作
         */
        void signalWrite();

        /**
         * @brief 获取下一次保活时间
         * @return 时间戳
         */
        uint64_t nextKeepAliveTime();

        /**
         * @brief 重置定时器
         * @return 下一次定时器触发时间
         */
        uint64_t maybeResetTimer();

        /**
         * @brief 会话运行实现函数
         */
        void run_impl();

        /**
         * @brief 启动会话处理
         */
        void run();

        /**
         * @brief 关闭会话
         */
        void closeSession()
        {
            m_is_alive = false;
            signalWrite();
            signalRead(nullptr);
        }

        /**
         * @brief 关闭本地连接
         */
        void closeLocal() { return closeSession(); }

        /**
         * @brief 关闭远程连接
         */
        void closeRemote() { return closeSession(); }

        /**
         * @brief 检查会话是否活跃
         * @return 如果活跃返回true
         */
        bool isAlive() const { return m_is_alive; }

        /**
         * @brief 获取服务器指针
         * @return 服务器智能指针
         */
        const std::shared_ptr<QuicServer> getServer() const { return m_server.lock(); }

        /**
         * @brief 获取流管理器
         * @return 流管理器指针
         */
        const QuicStreamManager::ptr &getStreamMgr() const { return m_streams; }

        /**
         * @brief 打开一个新的流
         * @return 新流的指针
         */
        const QuicStream::ptr openStream();

        /**
         * @brief 接受一个新的流
         * @return 接受的流的指针
         */
        const QuicStream::ptr acceptStream();

        /**
         * @brief 获取短头部
         * @param cid 连接ID
         * @param type 数据包类型
         * @return 扩展数据包头部
         */
        const QuicEPacketHeader::ptr getShortHeader(QuicConnectionId::ptr cid, QuicPacketType type);

        /**
         * @brief 获取长头部
         * @param sid 源连接ID
         * @param did 目标连接ID
         * @param type 数据包类型
         * @return 扩展数据包头部
         */
        const QuicEPacketHeader::ptr getLongHeader(QuicConnectionId::ptr sid,
                                                   QuicConnectionId::ptr did, QuicPacketType type);

        /**
         * @brief 获取连接ID
         * @return 连接ID指针
         */
        QuicConnectionId::ptr getCid() const { return m_cid; }

        /**
         * @brief 连接窗口更新回调
         */
        void onHasConnectionWinUpdate()
        {
            m_win_update_queue->addConnection();
            signalWrite();
        }

        /**
         * @brief 流窗口更新回调
         * @param stream_id 流ID
         */
        void onHasStreamWinUpdate(QuicStreamId stream_id)
        {
            m_win_update_queue->addStream(stream_id);
            signalWrite();
        }

        /**
         * @brief 创建新的流控制器
         * @param stream_id 流ID
         * @return 流控制器指针
         */
        StreamFlowController::ptr newFlowController(QuicStreamId stream_id);

        /**
         * @brief 排队控制帧
         * @param frame 控制帧
         */
        void queueControlFrame(QuicFrame::ptr frame) override
        {
            m_control_frames.push_back(frame);
            signalWrite();
        }

        /**
         * @brief 添加活跃流
         * @param id 流ID
         */
        void addActiveStream(QuicStreamId id);

    private:
        std::weak_ptr<QuicServer> m_server; // 服务器弱引用
        QuicRole m_role;                    // QUIC角色
        QuicConnectionId::ptr m_cid;        // 连接ID
        bool m_ssl;                         // SSL标志

        Address::ptr m_peer_addr;                 // 对端地址
        RWMutexType m_mutex;                      // 读写锁
        base::FiberSemaphore m_received_sem;      // 接收信号量
        std::list<MBuffer::ptr> m_received_queue; // 接收队列
        base::FiberSemaphore m_send_sem;          // 发送信号量
        std::list<MBuffer::ptr> m_send_queue;     // 发送队列
        base::FiberSemaphore m_timer_sem;         // 定时器信号量
        SessionSemaphore m_session_sem;           // 会话信号量
        uint64_t m_pacing_deadline = 0;           // 流量控制截止时间

        QuicStreamManager::ptr m_streams;                     // 流管理器
        PacketNumberManager::ptr m_pn_mgr;                    // 数据包编号管理器
        RTTStats::ptr m_rtt_stats;                            // RTT统计
        SentPacketHandler::ptr m_sent_packet_handler;         // 已发送数据包处理器
        ReceivedPacketTracker::ptr m_received_packet_handler; // 已接收数据包跟踪器
        RetransmissionQueue::ptr m_retrans_queue;             // 重传队列

        ConnectionFlowController::ptr m_conn_flow_controler; // 连接流控制器
        WinUpdateQueue::ptr m_win_update_queue;              // 窗口更新队列
        std::list<QuicFrame::ptr> m_control_frames;          // 控制帧列表

        MutexType m_active_stream_mutex;               // 活跃流互斥锁
        std::list<QuicStreamId> m_stream_queue;        // 流队列
        std::map<QuicStreamId, bool> m_active_streams; // 活跃流映射

        MutexType m_timer_snd_mutex; // 定时器发送互斥锁
        bool m_is_alive;             // 会话活跃标志

        Socket::ptr m_socket;
    };

    /**
     * @brief QUIC会话管理器，管理多个QUIC会话
     *
     * 该类负责管理服务器上的所有活跃QUIC会话，提供添加、删除、查找会话的功能。
     */
    class QuicSessionManager
    {
    public:
        typedef std::shared_ptr<QuicSessionManager> ptr;
        typedef RWMutex RWMutexType;

        /**
         * @brief 根据连接ID获取会话
         * @param cid 连接ID
         * @return 会话指针
         */
        const QuicSession::ptr get(QuicConnectionId::ptr cid);

        /**
         * @brief 添加一个会话
         * @param session 会话指针
         */
        void add(QuicSession::ptr session);

        /**
         * @brief 删除一个会话
         * @param cid 连接ID字符串
         */
        void del(const std::string &cid);

        /**
         * @brief 清空所有会话
         */
        void clear();

        /**
         * @brief 遍历所有会话并执行回调
         * @param cb 回调函数
         */
        void foreach (std::function<void(QuicSession::ptr)> cb);

    private:
        RWMutexType m_mutex;                                          // 读写锁
        std::unordered_map<std::string, QuicSession::ptr> m_sessions; // 会话映射表
    };

    /**
     * @brief 已关闭的本地会话类
     *
     * 该类用于处理已经关闭的本地会话，主要用于响应已关闭连接的数据包。
     */
    class QuicClosedLocalSession
    {
    public:
        typedef std::shared_ptr<QuicClosedLocalSession> ptr;

        /**
         * @brief 运行函数
         */
        void run()
        {
            for (;;) {
            }
        }

        /**
         * @brief 处理接收到的数据包
         * @param buffer_block 数据缓冲区
         */
        void handlePacket(const MBuffer::ptr &buffer_block);

        /**
         * @brief 处理数据包的实现
         * @param buffer_block 数据缓冲区
         */
        void handlePacketImpl(const MBuffer::ptr &buffer_block);

        /**
         * @brief 销毁会话
         */
        void destroy() {} // TODO

        /**
         * @brief 关闭会话
         */
        void shutdown() { return destroy(); }

    private:
        QuicRole m_role;        // QUIC角色
        uint64_t m_counter = 0; // 计数器
    };
} // namespace quic
} // namespace base

#endif
