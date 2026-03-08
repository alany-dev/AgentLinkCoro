#ifndef __QUIC_STREAM_HH__
#define __QUIC_STREAM_HH__

#include "base/thread.h"       // 线程同步（互斥锁、信号量）
#include "base/mutex.h"        // 互斥锁（保护并发访问）
#include "base/net/stream.h"   // 基础流接口
#include "base/mbuffer.h"      // 内存缓冲区（存储流数据）
#include "quic_type.h"         // QUIC基础类型（流ID、偏移量、版本等）
#include "quic_frame.h"        // QUIC帧结构（流帧、重置帧等）
#include "quic_frame_sorter.h" // 乱序帧排序器（处理流帧乱序到达）
#include "quic_flow_control.h" // 流级流量控制

#include <memory>
#include <list>
#include <utility>
#include <functional>
#include <queue>
#include <unordered_map>

namespace base
{
namespace quic
{
    // 前置声明：QUIC会话（流的上层管理者）
    class QuicSession;

    /**
     * @brief 定时器信息结构体（标记定时器是否已取消）
     * 用于流的超时控制（如读超时、写超时），避免超时回调重复执行
     */
    struct timer_info {
        int cancelled = 0; // 0=未取消，非0=已取消
    };

    /**
     * @brief 流ID生成工具类（遵循QUIC流ID格式规范）
     * QUIC流ID由3部分组成：角色（发起方）、流类型（双向/单向）、流序号
     */
    class QuicStreamNumber
    {
    public:
        /**
         * @brief 生成QUIC流ID
         * @param num 流序号（从1开始递增）
         * @param type 流类型（双向流/单向流，对应QUIC_STREAM_TYPE_BIDI/UNI）
         * @param role 流发起方角色（客户端/服务器，对应QUIC_ROLE_CLIENT/SERVER）
         * @return 生成的64位流ID（符合RFC 9000 第4.1节格式）
         */
        static QuicStreamId streamID(QuicStreamNum num, QuicStreamType type, QuicRole role);
    };

    /**
     * @brief 判断流ID由哪一方发起（客户端/服务器）
     * @param id 目标流ID
     * @return 流发起方角色（QUIC_ROLE_CLIENT/SERVER）
     */
    QuicRole StreamIdInitialedBy(QuicStreamId id);

    /**
     * @brief 从流ID中解析流类型（双向/单向）
     * @param id 目标流ID
     * @return 流类型（QUIC_STREAM_TYPE_BIDI/UNI）
     */
    QuicStreamType StreamIdType(QuicStreamId id);

    /**
     * @brief 从流ID中提取流序号（剥离角色和类型标识）
     * @param id 目标流ID
     * @return 流序号（纯数字，从1开始）
     */
    QuicStreamNum StreamID2Num(QuicStreamId id);

    /**
     * @brief QUIC连接信息结构体（预留扩展，存储连接级元数据）
     * 目前为空实现，可后续扩展（如连接超时时间、加密级别等）
     */
    class QuicConnectionInfo
    {
    public:
        typedef std::shared_ptr<QuicConnectionInfo> ptr;

    private:
    };

    /**
     * @brief 流操作结果结构体（统一封装读/写/关闭等操作的返回状态）
     * 替代传统错误码，包含操作完成状态、数据量、错误信息
     */
    class QuicStreamResult
    {
    public:
        typedef std::shared_ptr<QuicStreamResult> ptr;

        /**
         * @brief 流操作错误码（覆盖QUIC流常见异常场景）
         */
        enum class Error {
            OK = 0,                      // 操作成功
            STREAM_EOF = 1,              // 流已读至末尾（远程发送FIN）
            CANCEL_READ = 2,             // 读操作被主动取消
            RESET_BY_REMOTE = 3,         // 流被远程端重置（收到RST_STREAM帧）
            SHUTDOWN = 4,                // 流已关闭（本地主动关闭）
            TIMEOUT = 5,                 // 操作超时（读/写超时）
            WRITE_ON_CLOSED_STREAM = 10, // 向已关闭的流写数据
            CANCEL_WRITE = 11,           // 写操作被主动取消
            WRITE_BUFFER_EMPTY = 12,     // 写缓冲区无数据可发送
            UNKNOW = 99                  // 未知错误
        };

        /**
         * @brief 构造流操作结果
         * @param completed 操作是否完成（true=完成，false=未完成/阻塞）
         * @param bytes 实际读写的数据字节数（成功时有效）
         * @param result 错误码（Error枚举的整数形式）
         * @param err 错误描述字符串（补充错误详情）
         */
        QuicStreamResult(bool completed, int bytes, int result, const std::string &err = "")
            : m_stream_completed(completed), m_bytes_rw(bytes), m_result(result), m_error(err)
        {
        }

        /**
         * @brief 将结果转换为字符串（用于日志打印和调试）
         * @return 包含完成状态、字节数、错误信息的字符串
         */
        std::string toString() const;

        // 以下为结果查询接口
        bool isCompleted() const { return m_stream_completed; } // 操作是否完成
        int bytes_rw() const { return m_bytes_rw; }             // 读写字节数
        int err_no() const { return m_result; }                 // 错误码（Error枚举值）
        std::string strerr() const { return m_error; }          // 错误描述

    private:
        bool m_stream_completed = false; // 操作完成标记
        int m_bytes_rw = 0;              // 实际读写字节数
        int m_result = 0;                // 错误码（Error枚举的整数形式）
        std::string m_error = "";        // 错误描述信息
    };

    /**
     * @brief QUIC接收流类（处理流数据的接收逻辑）
     * 核心职责：接收流帧、乱序排序、流量控制、数据读取，对应RFC 9000 第4.3节
     */
    class QuicRcvStream : public std::enable_shared_from_this<QuicRcvStream>
    {
    public:
        typedef std::shared_ptr<QuicRcvStream> ptr;
        typedef Mutex MutexType; // 互斥锁（保证多线程下流状态安全）

        /**
         * @brief 构造接收流
         * @param stream_id 流ID（唯一标识当前流）
         * @param sender 流发送器弱引用（用于向会话反馈控制帧，如窗口更新）
         * @param fc 流级流量控制器（控制接收窗口，避免接收端缓冲区溢出）
         */
        QuicRcvStream(QuicStreamId stream_id, std::weak_ptr<StreamSender> sender,
                      const StreamFlowController::ptr &fc);
        virtual ~QuicRcvStream() {}

        /**
         * @brief 将接收流状态转换为字符串（调试用）
         * @return 包含流ID、读取偏移、流量控制窗口等信息的字符串
         */
        std::string toString() const;

        /**
         * @brief 处理收到的流帧（核心接收逻辑）
         * 步骤：1. 检查帧偏移合法性；2. 交给帧排序器排序；3. 更新流量控制窗口
         * @param frame 收到的流帧（含数据、偏移、FIN标记）
         * @return 连接级错误（如帧格式错误，无错误则返回nullptr）
         */
        const QuicConnectionError::ptr handleStreamFrame(const QuicStreamFrame::ptr &frame);

        /**
         * @brief 处理收到的流重置帧（RST_STREAM）
         * 逻辑：标记流被远程重置，唤醒等待读的协程，后续读操作返回RESET_BY_REMOTE
         * @param frame 收到的重置帧（含重置原因）
         * @return 连接级错误（无错误则返回nullptr）
         */
        const QuicConnectionError::ptr handleRstStreamFrame(const QuicRstStreamFrame::ptr &frame);

        /**
         * @brief 从排序器中取出下一个有序帧（供read()读取数据）
         * 逻辑：若当前无可用帧，从排序器取；若取到FIN帧，标记流读完成
         */
        void dequeueNextFrame();

        /**
         * @brief 等待流可读（协程阻塞接口）
         * 当无数据可读时，协程阻塞在信号量上，直到有新帧到达或流关闭
         */
        void waitRead();

        /**
         * @brief 唤醒等待读的协程（新帧到达或流关闭时调用）
         */
        void signalRead();

        /**
         * @brief 取消当前读操作（主动终止阻塞的读协程）
         * 逻辑：标记读取消状态，唤醒阻塞的协程，后续读操作返回CANCEL_READ
         */
        void cancelRead();

        /**
         * @brief 因会话关闭而关闭接收流（被动关闭）
         * 逻辑：标记流关闭状态，唤醒阻塞的协程，后续读操作返回SHUTDOWN
         */
        void closeForShutdown();

        /**
         * @brief 从接收流读取数据（应用层核心读取接口）
         * 逻辑：1. 检查流状态（是否关闭/重置）；2. 无数据则阻塞；3. 从当前帧复制数据
         * @param buffer_block 接收数据的缓冲区
         * @param length 期望读取的字节数
         * @return 读取结果（含是否完成、实际字节数、错误信息）
         */
        const QuicStreamResult::ptr read(const MBuffer::ptr &buffer_block, size_t length);

        // 以下为状态查询接口
        QuicStreamId stream_id() const { return m_stream_id; }                       // 获取流ID
        void set_stream_id(QuicStreamId id) { m_stream_id = id; }                    // 设置流ID
        const FrameSorter &getFrameSorter() const { return m_received_frame_queue; } // 获取帧排序器
        const StreamFlowController::ptr &getFlowController() const
        {
            return m_flow_controller;
        }                        // 获取流量控制器
        uint64_t getWinUpdate(); // 计算需要发送的窗口更新大小（触发WINDOW_UPDATE帧）

    private:
        int m_pop_failed_count = 0;   // 帧读取失败计数器（用于异常检测）
        MutexType m_mutex;            // 互斥锁（保护流状态和数据结构）
        QuicStreamId m_stream_id = 0; // 当前流的ID
        QuicOffset m_read_offset = 0; // 已读取的数据偏移量（从0开始递增）
        QuicOffset m_final_offset = ~0ull; // 流的最终偏移量（收到FIN后设置，标识流结束）

        MBuffer::ptr m_current_frame = nullptr; // 当前正在读取的流帧（已排序完成）
        std::function<void()> m_current_frame_done_cb = nullptr; // 当前帧处理完成后的回调
        bool m_current_frame_is_last = false; // 当前帧是否为流的最后一帧（含FIN）
        QuicOffset m_read_pos_in_frame = 0;   // 在当前帧中的读取位置（偏移量）
        std::weak_ptr<StreamSender> m_sender; // 流发送器弱引用（避免循环引用，用于发送控制帧）

        // 流状态标记
        bool m_shutdown = false;        // 流是否已关闭（会话触发）
        bool m_fin_read = false;        // 流是否已读至末尾（收到FIN且数据读完）
        bool m_canceld_read = false;    // 读操作是否被取消
        bool m_reset_by_remote = false; // 流是否被远程重置（收到RST_STREAM）

        FiberSemaphore m_wait_read_sem; // 读等待信号量（协程阻塞用）
        uint64_t m_deadline = 0; // 读操作超时时间戳（毫秒级，0表示无超时）

        FrameSorter m_received_frame_queue; // 帧排序器（处理乱序到达的流帧，按偏移排序）
        StreamFlowController::ptr m_flow_controller; // 流级流量控制器（控制接收窗口）
        QuicVersion m_version; // 当前使用的QUIC版本（影响帧格式和逻辑）
    };

    /**
     * @brief QUIC发送流类（处理流数据的发送逻辑）
     * 核心职责：数据写入、帧组装、重传管理、流量控制，对应RFC 9000 第4.2节
     */
    class QuicSndStream : public std::enable_shared_from_this<QuicSndStream>
    {
    public:
        typedef std::shared_ptr<QuicSndStream> ptr;
        typedef Mutex MutexType; // 互斥锁（保证多线程下流状态安全）

        /**
         * @brief 构造发送流
         * @param stream_id 流ID（唯一标识当前流）
         * @param sender 流发送器弱引用（用于将组装好的帧提交给会话发送）
         * @param fc 流级流量控制器（控制发送窗口，避免超过接收端允许的上限）
         */
        QuicSndStream(QuicStreamId stream_id, std::weak_ptr<StreamSender> sender,
                      const StreamFlowController::ptr &fc)
            : m_stream_id(stream_id), m_sender(sender), m_flow_controller(fc)
        {
        }
        virtual ~QuicSndStream() {}

        /**
         * @brief 等待流可写（协程阻塞接口）
         * 当发送窗口不足或缓冲区满时，协程阻塞在信号量上，直到窗口更新或缓冲区有空间
         */
        void waitWrite() { m_wait_write_sem.wait(); }

        /**
         * @brief 唤醒等待写的协程（窗口更新或缓冲区释放时调用）
         */
        void signalWrite() { m_wait_write_sem.notify(); }

        /**
         * @brief 检查是否可缓存流帧（判断缓冲区是否有空间）
         * @return true=可缓存，false=缓冲区满
         */
        bool canBufferStreamFrame();

        /**
         * @brief 向发送流写入数据（应用层核心写入接口）
         * 逻辑：1. 检查流状态（是否关闭/重置）；2. 无空间则阻塞；3. 数据写入缓冲区
         * @param buffer_block 待写入的数据缓冲区
         * @return 写入结果（含是否完成、实际字节数、错误信息）
         */
        const QuicStreamResult::ptr write(const MBuffer::ptr &buffer_block);

        // 以下为底层发送逻辑接口（由会话/包组装模块调用）
        /**
         * @brief 从缓冲区提取数据填充到流帧（供包组装使用）
         * @param stream_frame 待填充的流帧（空帧，需设置偏移、数据、FIN）
         * @param max_bytes 帧的最大允许字节数（受MTU限制）
         */
        void get_data_for_writing(QuicStreamFrame::ptr stream_frame, size_t max_bytes);

        /**
         * @brief 无缓冲直接获取新流帧（跳过缓冲区，用于紧急数据）
         * @param frame 待填充的流帧
         * @param max_bytes 帧最大字节数
         * @param send_win 当前可用发送窗口（流量控制限制）
         * @return true=成功获取帧，false=无数据可发
         */
        bool popNewStreamFrameWithoutBuffer(QuicStreamFrame::ptr frame, size_t max_bytes,
                                            size_t send_win);

        /**
         * @brief 获取新的发送帧（优先从缓冲区取数据，考虑发送窗口）
         * @param max_bytes 帧最大字节数
         * @param send_win 当前可用发送窗口
         * @return  tuple(流帧, 是否为流的最后一帧)
         */
        std::tuple<QuicStreamFrame::ptr, bool> popNewStreamFrame(size_t max_bytes, size_t send_win);

        /**
         * @brief 获取需要重传的流帧（从重传队列取）
         * @param max_bytes 帧最大字节数
         * @return tuple(重传帧, 是否为流的最后一帧)
         */
        std::tuple<QuicStreamFrame::ptr, bool> maybeGetRetransmission(size_t max_bytes);

        /**
         * @brief 获取新帧或重传帧（优先重传帧，保证可靠性）
         * @param max_bytes 帧最大字节数
         * @return tuple(帧, 是否为流的最后一帧)
         */
        std::tuple<QuicStreamFrame::ptr, bool> popNewOrRetransmissitedStreamFrame(size_t max_bytes);

        /**
         * @brief 统一获取发送帧（整合新帧和重传帧逻辑）
         * @param max_bytes 帧最大字节数
         * @return tuple(帧, 是否为流的最后一帧)
         */
        std::tuple<QuicStreamFrame::ptr, bool> popStreamFrame(size_t max_bytes);

        /**
         * @brief 将帧加入重传队列（帧发送后未确认时调用）
         * @param frame 待重传的帧（需包含偏移、数据等完整信息）
         */
        void queueRetransmission(const QuicFrame::ptr &frame);

        /**
         * @brief 处理帧的确认（收到ACK帧后调用）
         * 逻辑：1. 从重传队列删除已确认的帧；2. 更新发送偏移；3. 释放缓冲区空间
         * @param frame 已确认的帧
         */
        void frameAcked(const QuicFrame::ptr &frame);

        /**
         * @brief 关闭发送流（主动发送FIN标记）
         * 逻辑：1. 标记流写完成；2. 后续写入操作返回WRITE_ON_CLOSED_STREAM；3. 发送FIN帧
         * @return 关闭结果（含是否成功、错误信息）
         */
        const QuicStreamResult::ptr close();

        /**
         * @brief 检查流是否刚完成（FIN已发送且数据已确认）
         * @return true=刚完成，false=未完成
         */
        bool isNewlyCompleted();

        /**
         * @brief 取消当前写操作（主动终止阻塞的写协程）
         * 逻辑：标记写取消状态，唤醒阻塞的协程，后续写操作返回CANCEL_WRITE
         */
        void cancelWrite();

        /**
         * @brief 因会话关闭而关闭发送流（被动关闭）
         * 逻辑：标记流关闭状态，唤醒阻塞的协程，后续写操作返回SHUTDOWN
         */
        void closeForShutdown();

        // 以下为状态查询和设置接口
        QuicStreamId stream_id() const { return m_stream_id; }    // 获取流ID
        void set_stream_id(QuicStreamId id) { m_stream_id = id; } // 设置流ID
        const StreamFlowController::ptr &getFlowController() const
        {
            return m_flow_controller;
        }                                   // 获取流量控制器
        void updateSendWin(uint64_t limit); // 更新发送窗口（收到WINDOW_UPDATE帧后调用）
        void
        handleStopSendingFrame(QuicStopSendingFrame::ptr frame); // 处理停止发送帧（远程拒绝接收）
        const QuicStreamFrame::ptr &nextFrame() const { return m_next_frame; } // 获取下一个待发送帧
        QuicOffset writeOffset() const { return m_write_offset; } // 获取已发送的数据偏移量
        std::string toStatisticsString() const; // 生成发送流统计信息（发送字节数、重传次数等）

    private:
        MutexType m_mutex;                    // 互斥锁（保护流状态和数据结构）
        QuicStreamId m_stream_id = 0;         // 当前流的ID
        int64_t m_num_outstanding_frames = 0; // 未确认的帧数量（用于流量控制）
        std::list<QuicStreamFrame::ptr> m_retransmission_queue; // 重传队列（存储未确认的帧）
        QuicStreamFrame::ptr m_next_frame = nullptr;            // 下一个待发送的新帧
        QuicOffset m_write_offset = 0; // 已发送的数据偏移量（从0开始递增）
        MBuffer::ptr m_data_for_writing = nullptr; // 待发送数据的缓冲区
        std::weak_ptr<StreamSender> m_sender; // 流发送器弱引用（用于提交帧到会话）

        // 流状态标记
        bool m_shutdown = false;         // 流是否已关闭（会话触发）
        bool m_finished_writing = false; // 流是否已完成写操作（close()调用后）
        bool m_canceled_write = false;   // 写操作是否被取消
        bool m_reset_by_remote = false;  // 流是否被远程重置（收到STOP_SENDING）
        bool m_fin_sent = false;         // FIN标记是否已发送（流关闭的关键标记）
        bool m_complete = false;         // 流是否已完全完成（FIN已发送且确认）

        FiberSemaphore m_wait_write_sem; // 写等待信号量（协程阻塞用）
        uint64_t m_deadline = 0; // 写操作超时时间戳（毫秒级，0表示无超时）

        StreamFlowController::ptr m_flow_controller; // 流级流量控制器（控制发送窗口）
        QuicVersion m_version;                       // 当前使用的QUIC版本

        // 发送统计信息（用于监控和调试）
        uint64_t m_sum_sent_packet = 0;          // 总发送帧数
        uint64_t m_sum_retrans_packet = 0;       // 总重传帧数
        uint64_t m_sum_bytes_sent_packet = 0;    // 总发送字节数（含帧头）
        uint64_t m_sum_bytes_retrans_packet = 0; // 总重传字节数（含帧头）
    };

    /**
     * @brief QUIC流统一封装类（聚合发送流和接收流，对外提供统一接口）
     * 应用层无需关注收发流分离，通过此类直接操作流的读写和关闭
     */
    class QuicStream : public std::enable_shared_from_this<QuicStream>
    {
    public:
        friend QuicSession; // 允许QuicSession访问私有成员
        typedef std::shared_ptr<QuicStream> ptr;

        /**
         * @brief 构造QUIC流（同时初始化发送流和接收流）
         * @param stream_id 流ID（唯一标识当前流）
         * @param sender 流发送器弱引用（传递给收发流，用于控制帧交互）
         * @param fc 流级流量控制器（收发流共享同一流量控制器，保证窗口同步）
         */
        QuicStream(QuicStreamId stream_id, std::weak_ptr<StreamSender> sender,
                   const StreamFlowController::ptr &fc)
            : m_sender(sender)
        {
            m_send_stream = std::make_shared<QuicSndStream>(stream_id, m_sender, fc);
            m_receive_stream = std::make_shared<QuicRcvStream>(stream_id, m_sender, fc);
        }
        virtual ~QuicStream()
        {
            std::cout << "~QuicStream" << std::endl; // 析构日志（用于内存泄漏检测）
        }

        // 以下为对外统一接口（委托给内部的发送流/接收流）
        /**
         * @brief 获取流发送器（强引用，需避免长期持有导致循环引用）
         * @return 流发送器强引用（nullptr表示发送器已释放）
         */
        const std::shared_ptr<StreamSender> getSender() const { return m_sender.lock(); }

        /**
         * @brief 从流读取数据（委托给接收流）
         * @param buffer_block 接收数据的缓冲区
         * @param length 期望读取的字节数
         * @return 读取结果（同QuicRcvStream::read）
         */
        const QuicStreamResult::ptr read(MBuffer::ptr buffer_block, size_t length)
        {
            return m_receive_stream->read(buffer_block, length);
        }

        /**
         * @brief 向流写入数据（委托给发送流）
         * @param buffer_block 待写入的数据缓冲区
         * @return 写入结果（同QuicSndStream::write）
         */
        const QuicStreamResult::ptr write(MBuffer::ptr buffer_block)
        {
            return m_send_stream->write(buffer_block);
        }

        /**
         * @brief 关闭流（委托给发送流，发送FIN标记）
         * @return 关闭结果（同QuicSndStream::close）
         */
        const QuicStreamResult::ptr close() { return m_send_stream->close(); }

        /**
         * @brief 因会话关闭而关闭流（委托给收发流）
         */
        void closeForShutdown()
        {
            m_send_stream->closeForShutdown();
            m_receive_stream->closeForShutdown();
        }

        /**
         * @brief 更新流的发送窗口（委托给发送流）
         * @param limit 新的发送窗口上限
         */
        void updateSendWin(uint64_t limit) { return m_send_stream->updateSendWin(limit); }

        // 以下为内部流访问接口（供会话/管理类使用）
        const QuicRcvStream::ptr &readStream() const { return m_receive_stream; } // 获取接收流
        const QuicSndStream::ptr &writeStream() const { return m_send_stream; }   // 获取发送流
        QuicStreamId stream_id() const { return m_receive_stream->stream_id(); }  // 获取流ID

        /**
         * @brief 计算接收窗口更新大小（委托给接收流，用于发送WINDOW_UPDATE帧）
         * @return 需要更新的窗口大小（0表示无需更新）
         */
        uint64_t getWinUpdate();

        /**
         * @brief 获取发送流统计信息（委托给发送流）
         * @return 统计信息字符串（发送字节数、重传次数等）
         */
        std::string toSndStatisticsString() const { return m_send_stream->toStatisticsString(); }

    private:
        std::weak_ptr<StreamSender> m_sender; // 流发送器弱引用（避免循环引用）
        QuicRcvStream::ptr m_receive_stream = nullptr; // 内部接收流实例
        QuicSndStream::ptr m_send_stream = nullptr;    // 内部发送流实例
    };

    /**
     * @brief QUIC缓冲区类（封装流的读写缓存，关联远程地址）
     * 用于存储流的临时数据，隔离应用层与底层缓冲区操作
     */
    class QuicBuffer
    {
    public:
        typedef std::shared_ptr<QuicBuffer> ptr;

        QuicBuffer();
        ~QuicBuffer();

        /**
         * @brief 从缓冲区读取数据（复制到外部缓冲区）
         * @param data 外部数据缓冲区（需提前分配空间）
         * @param length 期望读取的字节数
         * @return 实际读取的字节数（0表示无数据，负数表示错误）
         */
        int bufferRead(void *data, size_t length); // copyOut

        /**
         * @brief 向缓冲区写入数据（从外部缓冲区复制）
         * @param data 外部数据缓冲区（含待写入数据）
         * @param length 待写入的字节数
         * @return 实际写入的字节数（负数表示错误）
         */
        int bufferWrite(void *data, size_t length);

        // 以下为缓冲区和地址查询接口
        const MBuffer::ptr &readBuffer() const { return m_read_buffer; } // 获取读缓冲区（接收数据）
        const MBuffer::ptr &writeBuffer() const
        {
            return m_write_buffer;
        } // 获取写缓冲区（待发送数据）
        const Address::ptr &getAddr() const
        {
            return m_remote_addr;
        } // 获取远程地址（流对应的对端地址）

    private:
        Address::ptr m_remote_addr; // 远程地址（对端IP+端口）
        MBuffer::ptr m_read_buffer; // 读缓冲区（存储接收的流数据，供应用层读取）
        MBuffer::ptr m_write_buffer; // 写缓冲区（存储应用层待发送的数据）
    };

    /**
     * @brief 流条目结构体（用于流映射表，标记流是否待删除）
     * 解决流删除的竞态问题：先标记待删除，再在安全时机清理
     */
    struct QuicStreamEntry {
        QuicStream::ptr stream = nullptr; // 流实例
        bool shouldDelete = false; // 标记是否待删除（true=需在下次清理时删除）
    };

    /**
     * @brief 传入双向流映射表（管理远程发起的双向流，服务器端常用）
     * 核心职责：接收远程发起的流、创建本地流实例、管理流的生命周期
     */
    class QuicIncomingBidiStreamsMap
    {
    public:
        typedef std::shared_ptr<QuicIncomingBidiStreamsMap> ptr;
        typedef RWMutex RWMutexType; // 读写锁（读多写少场景优化，如查询流vs创建流）

        /**
         * @brief 构造传入双向流映射表
         * @param new_stream_cb 创建新流的回调（由流管理器提供，统一创建流实例）
         * @param queue_control_frame_cb 提交控制帧的回调（用于发送MAX_STREAMS帧）
         * @param max_streams 最大允许的传入流数量（默认1024，用于流数量控制）
         */
        QuicIncomingBidiStreamsMap(
            const std::function<QuicStream::ptr(QuicStreamNum)> &new_stream_cb,
            const std::function<void(QuicFrame::ptr)> &queue_control_frame_cb,
            uint64_t max_streams = 1024)
            : m_new_stream_cb(new_stream_cb), m_queue_max_stream_id_cb(queue_control_frame_cb)
        {
        }

        /**
         * @brief 接受一个传入流（应用层主动获取远程发起的流）
         * 逻辑：1. 若无可用流，协程阻塞；2. 取出最早的可用流；3. 标记流为已接受
         * @return 接受的流实例（nullptr表示映射表已关闭）
         */
        QuicStream::ptr acceptStream();

        /**
         * @brief 获取或创建传入流（收到远程流帧时调用）
         * 逻辑：1. 检查流序号是否合法（未超过最大限制）；2. 存在则返回，不存在则创建
         * @param num 流序号（从远程流ID中提取）
         * @return 流实例（nullptr表示序号非法或映射表已关闭）
         */
        QuicStream::ptr getOrOpenStream(QuicStreamNum num);

        /**
         * @brief 标记流待删除（非立即删除，避免竞态）
         * @param num 流序号
         * @return true=标记成功，false=流不存在
         */
        bool deleteStream(QuicStreamNum num);

        /**
         * @brief 实际删除待删除的流（内部清理接口，在安全时机调用）
         * @param num 流序号
         * @return true=删除成功，false=流不存在或未标记待删除
         */
        bool deleteStreamImp(QuicStreamNum num);

        /**
         * @brief 关闭映射表（停止接受新流，标记所有流待删除）
         */
        void closeWithErr();

        // 以下为等待和查询接口
        void waitAccept() { m_wait_accept_sem.wait(); } // 等待新的传入流（协程阻塞）
        void signalAccept() { m_wait_accept_sem.notify(); } // 通知有新的传入流
        const std::unordered_map<QuicStreamNum, QuicStreamEntry> &streams() const
        {
            return m_streams;
        } // 获取所有流的映射

    public:
        RWMutexType m_mutex;                    // 读写锁（保护流映射表）
        base::FiberSemaphore m_wait_accept_sem; // 接受流等待信号量（协程阻塞用）
        // 流映射表：key=流序号，value=流条目（含流实例和待删除标记）
        std::unordered_map<QuicStreamNum, QuicStreamEntry> m_streams;
        QuicStreamNum m_next_stream_to_accept = 1; // 下一个待接受的流序号（按序号递增）
        QuicStreamNum m_next_stream_to_open = 1; // 下一个待创建的流序号（按序号递增）
        QuicStreamNum m_max_stream = ~0ull;      // 允许的最大流序号（初始为无上限）
        uint64_t m_max_num_streams = ~0ull;      // 允许的最大流数量（初始为无上限）
        std::function<QuicStream::ptr(QuicStreamNum)> m_new_stream_cb; // 创建新流的回调
        // 提交MAX_STREAMS帧的回调（用于通知远程当前允许的最大流数量）
        std::function<void(QuicMaxStreamsFrame::ptr)> m_queue_max_stream_id_cb;
        bool m_closed = false; // 映射表是否已关闭（true=不再接受新流）
    };

    /**
     * @brief 传出双向流映射表（管理本地发起的双向流，客户端常用）
     * 核心职责：创建本地流、管理流的发送限制、处理流创建阻塞
     */
    class QuicOutgoingBidiStreamsMap
    {
    public:
        typedef std::shared_ptr<QuicOutgoingBidiStreamsMap> ptr;
        typedef RWMutex RWMutexType; // 读写锁（读多写少场景优化）

        /**
         * @brief 构造传出双向流映射表
         * @param new_stream_cb 创建新流的回调（由流管理器提供）
         * @param queue_control_frame_cb 提交控制帧的回调（用于发送STREAMS_BLOCKED帧）
         */
        QuicOutgoingBidiStreamsMap(
            const std::function<QuicStream::ptr(QuicStreamNum)> &new_stream_cb,
            const std::function<void(QuicFrame::ptr)> &queue_control_frame_cb)
            : m_new_stream_cb(new_stream_cb), m_queue_streamid_blocked_cb(queue_control_frame_cb)
        {
        }

        /**
         * @brief 实际创建传出流（内部接口，处理流序号和限制检查）
         * @return 新创建的流实例（nullptr表示超过最大流限制或映射表已关闭）
         */
        QuicStream::ptr openStreamImp();

        /**
         * @brief 检查是否需要发送流阻塞帧（STREAMS_BLOCKED）
         * 逻辑：若流创建被限制且未发送过阻塞帧，则发送阻塞帧通知远程
         */
        void maybeSendBlockedFrame();

        /**
         * @brief 创建传出流（应用层接口，非阻塞）
         * @return 新创建的流实例（nullptr表示超过最大流限制）
         */
        QuicStream::ptr openStream();

        /**
         * @brief 阻塞式创建传出流（应用层接口，无可用流时阻塞）
         * @return 新创建的流实例（nullptr表示映射表已关闭）
         */
        QuicStream::ptr openStreamSync();

        /**
         * @brief 根据流序号获取传出流
         * @param num 流序号
         * @return 流实例（nullptr表示流不存在）
         */
        QuicStream::ptr getStream(QuicStreamNum num);

        /**
         * @brief 删除传出流（流关闭后调用）
         * @param num 流序号
         * @return 0=删除成功，-1=流不存在，-2=映射表已关闭
         */
        int deleteStream(QuicStreamNum num);

        /**
         * @brief 解除流创建阻塞（收到MAX_STREAMS帧后调用，更新最大流限制）
         */
        void unblockOpenSync();

        /**
         * @brief 设置允许的最大流序号（收到MAX_STREAMS帧后调用）
         * @param num 新的最大流序号
         */
        void setMaxStream(QuicStreamNum num);

        /**
         * @brief 更新所有传出流的发送窗口（全局流量控制调整）
         * @param limit 新的发送窗口上限
         */
        void updateSendWin(uint64_t limit);

        /**
         * @brief 关闭映射表（停止创建新流，标记所有流待删除）
         */
        void closeWithErr();

        /**
         * @brief 获取所有传出流的映射
         * @return 流序号到流实例的映射表
         */
        const std::unordered_map<QuicStreamNum, QuicStream::ptr> &streams() const
        {
            return m_streams;
        };

    private:
        RWMutexType m_mutex; // 读写锁（保护流映射表）
        // 流映射表：key=流序号，value=流实例
        std::unordered_map<QuicStreamNum, QuicStream::ptr> m_streams;
        // 待创建流的队列（用于阻塞式创建，存储等待的协程相关信息）
        std::unordered_map<uint64_t, QuicStream::ptr> m_open_streams;
        uint64_t m_lowest_in_queue = 0;      // 队列中最小的流序号（用于排序）
        uint64_t m_highest_in_queue = ~0ull; // 队列中最大的流序号
        QuicStreamNum m_next_stream = 1;     // 下一个待创建的流序号（按序号递增）
        QuicStreamNum m_max_stream = ~0ull; // 允许的最大流序号（远程通过MAX_STREAMS指定）
        bool m_blocked_sent = false;        // 是否已发送流阻塞帧（避免重复发送）
        std::function<QuicStream::ptr(QuicStreamNum)> m_new_stream_cb; // 创建新流的回调
        // 提交STREAMS_BLOCKED帧的回调（流创建被限制时通知远程）
        std::function<void(QuicStreamsBlockedFrame::ptr)> m_queue_streamid_blocked_cb;
        bool m_closed = false; // 映射表是否已关闭
    };

    /**
     * @brief QUIC流管理器（流的顶层管理者，统一管理传入/传出流）
     * 核心职责：初始化流映射表、提供流的创建/接受/删除接口、组装流帧
     */
    class QuicStreamManager
    {
    public:
        typedef std::shared_ptr<QuicStreamManager> ptr;
        typedef RWMutex RWMutexType; // 读写锁（保护流管理状态）

        /**
         * @brief 构造流管理器
         * @param role 本地角色（客户端/服务器，决定流的发起和接收逻辑）
         * @param new_fc 创建流级流量控制器的回调（每个流一个独立控制器）
         */
        QuicStreamManager(QuicRole role,
                          const std::function<StreamFlowController::ptr(QuicStreamId)> &new_fc);
        ~QuicStreamManager() {}

        /**
         * @brief 初始化流映射表（创建传入/传出双向流映射实例）
         */
        void initMaps();

        /**
         * @brief 关联QUIC会话（设置流发送器，用于帧交互）
         * @param session QUIC会话实例（强引用）
         */
        void setSessoin(const std::shared_ptr<QuicSession> &session);

        /**
         * @brief 获取流发送器（从会话中获取，用于提交帧）
         * @return 流发送器强引用（nullptr表示会话已释放）
         */
        std::shared_ptr<StreamSender> getSession() const;

        /**
         * @brief 判断流ID由哪一方发起（委托给StreamIdInitialedBy）
         * @param id 流ID
         * @return 0=本地发起，1=远程发起，-1=无效流ID
         */
        int streamInitiatedBy(QuicStreamId id);

        /**
         * @brief 创建传出流（本地发起新流，客户端常用）
         * @return 新创建的流实例（nullptr表示创建失败）
         */
        QuicStream::ptr openStream();

        /**
         * @brief 接受传入流（获取远程发起的流，服务器常用）
         * @return 接受的流实例（nullptr表示无可用流或管理器已关闭）
         */
        QuicStream::ptr acceptStream();

        /**
         * @brief 删除流（流关闭后调用，委托给对应映射表）
         * @param id 流ID
         */
        void deleteStream(QuicStreamId id);

        /**
         * @brief 获取或创建接收流（收到远程流帧时调用）
         * @param id 流ID
         * @return 接收流实例（nullptr表示创建失败）
         */
        QuicRcvStream::ptr getOrOpenReceiveStream(QuicStreamId id);

        /**
         * @brief 获取或创建发送流（本地发起流时调用）
         * @param id 流ID
         * @return 发送流实例（nullptr表示创建失败）
         */
        QuicSndStream::ptr getOrOpenSendStream(QuicStreamId id);

        /**
         * @brief 关闭流管理器（停止所有流操作，标记所有流待删除）
         */
        void closeWithErr();

        /**
         * @brief 检查是否有流数据待发送（供包组装模块判断是否需要发送包）
         * @return true=有数据待发送，false=无数据
         */
        bool hasData(); // TODO: 待实现具体逻辑

        /**
         * @brief 从所有流中提取待发送帧（供包组装模块使用）
         * 逻辑：1. 遍历所有发送流；2. 提取新帧或重传帧；3. 组装成帧列表
         * @param frames 输出的帧列表（存储提取的待发送帧）
         * @param max_packet_size 单个包的最大大小（限制帧的大小）
         * @return 0=成功，-1=无帧可提取，-2=管理器已关闭
         */
        int popStreamFrames(std::list<QuicFrame::ptr> &frames, uint64_t max_packet_size);

    private:
        RWMutexType m_mutex;                        // 读写锁（保护管理器状态）
        base::FiberSemaphore m_wait_accept_sem;     // 接受流等待信号量（复用）
        QuicRole m_role;                            // 本地角色（客户端/服务器）
        std::weak_ptr<StreamSender> m_sender;       // 流发送器弱引用（从会话获取）
        uint64_t m_num_incoming_streams = 0;        // 已接受的传入流数量
        QuicStreamId m_max_incoming_streams = 1024; // 最大允许的传入流数量
        QuicStreamId m_next_stream = 0;             // 下一个待创建的流ID
        QuicStreamId m_next_stream_to_accept = 0;   // 下一个待接受的流ID

        QuicStreamId m_highest_opened_by_peer = 0; // 远程发起的最大流ID（用于流数量控制）
        std::queue<QuicStream::ptr> m_open_streams; // 待接受的流队列（临时存储）
        // 创建流级流量控制器的回调（每个流独立创建，避免共享）
        std::function<StreamFlowController::ptr(QuicStreamId)> m_new_flow_control_cb;

        // 流映射表实例（传出双向流+传入双向流）
        QuicOutgoingBidiStreamsMap::ptr m_outgoing_bidi_streams_map;
        QuicIncomingBidiStreamsMap::ptr m_incoming_bidi_streams_map;
    };
} // namespace quic
} // namespace base
#endif