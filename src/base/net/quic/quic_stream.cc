#include "base/log/log.h"
#include "base/macro.h"
#include "base/util.h"
#include "base/coro/scheduler.h"
#include "base/coro/iomanager.h"
#include "base/mbuffer.h"
#include "base/net/address.h"
#include "base/util.h"
#include "base/coro/timer.h"

#include "quic_stream.h"
#include "quic_session.h"

namespace base
{
namespace quic
{
    static base::Logger::ptr g_logger = _LOG_NAME("system");

    QuicRole StreamIdInitialedBy(QuicStreamId id)
    {
        if (id % 2 == 0) {
            return QuicRole::QUIC_ROLE_CLIENT;
        }
        return QuicRole::QUIC_ROLE_SERVER;
    }

    QuicStreamType StreamIdType(QuicStreamId id)
    {
        if (id % 4 >= 2) {
            return QuicStreamType::QuicStreamTypeUni;
        }
        return QuicStreamType::QuicStreamTypeBidi;
    }

    QuicStreamNum StreamId2Num(QuicStreamId id)
    {
        return (QuicStreamNum)(id / 4) + 1;
    }

    QuicStreamId QuicStreamNumber::streamID(QuicStreamNum num, QuicStreamType type, QuicRole role)
    {
        if (num == 0) {
            return ~0ull;
        }
        QuicStreamId first = 0;
        switch ((uint8_t)type) {
            case (uint8_t)QuicStreamType::QuicStreamTypeBidi: {
                if (role == QuicRole::QUIC_ROLE_CLIENT) {
                    first = 0;
                } else if (role == QuicRole::QUIC_ROLE_SERVER) {
                    first = 1;
                }
                break;
            }
            case (uint8_t)QuicStreamType::QuicStreamTypeUni: {
                if (role == QuicRole::QUIC_ROLE_CLIENT) {
                    first = 2;
                } else if (role == QuicRole::QUIC_ROLE_SERVER) {
                    first = 3;
                }
                break;
            }
            default:
                break;
        }
        return first + 4 * (num - 1);
    }

    /// QuicRcvStream
    QuicRcvStream::QuicRcvStream(QuicStreamId stream_id, std::weak_ptr<StreamSender> sender,
                                 const StreamFlowController::ptr &fc)
        : m_stream_id(stream_id), m_sender(sender), m_wait_read_sem(0), m_flow_controller(fc)
    {
        m_current_frame = std::make_shared<MBuffer>();
    }

    std::string QuicRcvStream::toString() const
    {
        std::stringstream ss;
        ss << "stream_id: " << m_stream_id << ", read_offset: " << m_read_offset
           << ", final_offset: " << m_final_offset
           << ", current_frame: " << m_current_frame->toString();
        return ss.str();
    }

    void QuicRcvStream::waitRead()
    {
        m_wait_read_sem.wait();
    }

    void QuicRcvStream::signalRead()
    {
        m_wait_read_sem.notify();
    }

    const QuicConnectionError::ptr
    QuicRcvStream::handleStreamFrame(const QuicStreamFrame::ptr &frame)
    {
        MutexType::Lock lock(m_mutex);
        _ASSERT(m_stream_id == frame->stream_id());
        QuicOffset max_offset = frame->offset() + frame->data()->readAvailable();
        _LOG_DEBUG(g_logger) << "handleStreamFrame offset: " << max_offset;
        _ASSERT(max_offset >= 0);
        bool fc = m_flow_controller->updateHighestReceived(max_offset, frame->has_fin_flag());
        if (!fc) {
            return std::make_shared<QuicConnectionError>(QuicTransErrorCode::FLOW_CONTROL_ERROR);
        }
        if (frame->has_fin_flag()) {
            m_final_offset = frame->offset() + frame->data()->readAvailable();
            _LOG_INFO(g_logger) << "recv fin frame!";
        }
        if (m_canceld_read) {
            m_flow_controller->abandon();
            auto sender = m_sender.lock();
            if (sender) {
                sender->onStreamCompleted(m_stream_id);
            }
            return std::make_shared<QuicConnectionError>(QuicTransErrorCode::INTERNAL_ERROR);
        }
        FrameSorterResult::ptr ret =
            m_received_frame_queue.push(frame->data(), frame->offset(), nullptr);
        if (ret->err_no() > 1) {
            return std::make_shared<QuicConnectionError>(QuicTransErrorCode::INTERNAL_ERROR);
        }
        // _LOG_WARN(g_logger)<< "push frame success: " << frame->toString();
        signalRead();
        lock.unlock();

        return std::make_shared<QuicConnectionError>(QuicTransErrorCode::NO_ERROR);
    }

    const QuicConnectionError::ptr
    QuicRcvStream::handleRstStreamFrame(const QuicRstStreamFrame::ptr &frame)
    {
        MutexType::Lock lock(m_mutex);
        _ASSERT(m_stream_id == frame->stream_id());
        if (m_shutdown) {
            return nullptr;
        }
        bool fc = m_flow_controller->updateHighestReceived(frame->final_offset(), true);
        if (!fc) {
            return nullptr;
        }
        bool newly_recvd_final_offset = m_final_offset == ~0ull;
        m_final_offset = frame->final_offset();
        _LOG_WARN(g_logger) << "handleRstStreamFrame after final_offset: " << m_final_offset;
        if (m_reset_by_remote) {
            return nullptr;
        }
        m_reset_by_remote = true;
        signalRead();
        lock.unlock();
        if (newly_recvd_final_offset) {
            m_flow_controller->abandon();
            auto sender = m_sender.lock();
            if (sender) {
                sender->onStreamCompleted(m_stream_id);
            }
        }
        return nullptr;
    }

    void QuicRcvStream::dequeueNextFrame()
    {
        if (m_current_frame_done_cb) {
            m_current_frame_done_cb();
        }
        auto read_pos = m_received_frame_queue.read_pos();
        FrameSorterEntry::ptr entry = m_received_frame_queue.pop();
        m_current_frame->clear();
        if (entry) {
            m_current_frame_is_last = (read_pos + entry->size()) >= m_final_offset;
            m_current_frame = entry->data();
        } else {
            m_current_frame_is_last = read_pos >= m_final_offset;
        }
        m_read_pos_in_frame = 0;
    }

    void QuicRcvStream::cancelRead()
    {
        MutexType::Lock lock(m_mutex);
        if (m_fin_read || m_canceld_read || m_reset_by_remote) {
            return;
        }
        m_canceld_read = true;
        signalRead();
    }

    void QuicRcvStream::closeForShutdown()
    {
        MutexType::Lock lock(m_mutex);
        m_shutdown = true;
        lock.unlock();
        signalRead();
    }

    const QuicStreamResult::ptr QuicRcvStream::read(const MBuffer::ptr &buffer_block, size_t length)
    {
        MutexType::Lock lock(m_mutex);
        if (m_fin_read) {
            return std::make_shared<QuicStreamResult>(false, 0,
                                                      (int)QuicStreamResult::Error::STREAM_EOF);
        }
        if (m_canceld_read) {
            return std::make_shared<QuicStreamResult>(false, 0,
                                                      (int)QuicStreamResult::Error::CANCEL_READ);
        }
        if (m_reset_by_remote) {
            return std::make_shared<QuicStreamResult>(
                false, 0, (int)QuicStreamResult::Error::RESET_BY_REMOTE);
        }
        if (m_shutdown) {
            return std::make_shared<QuicStreamResult>(false, 0,
                                                      (int)QuicStreamResult::Error::SHUTDOWN);
        }

        uint64_t bytes_read = 0;
        while (bytes_read < length) {
            if (m_current_frame->readAvailable() == 0
                || m_read_pos_in_frame >= m_current_frame->readAvailable()) {
                dequeueNextFrame();
            }
            if (m_current_frame->readAvailable() == 0 && bytes_read > 0) {
                return std::make_shared<QuicStreamResult>(false, bytes_read,
                                                          (int)QuicStreamResult::Error::SHUTDOWN);
            }
            for (;;) {
                if (m_shutdown) {
                    return std::make_shared<QuicStreamResult>(
                        false, bytes_read, (int)QuicStreamResult::Error::SHUTDOWN);
                }
                if (m_canceld_read) {
                    return std::make_shared<QuicStreamResult>(
                        false, bytes_read, (int)QuicStreamResult::Error::CANCEL_READ);
                }
                if (m_reset_by_remote) {
                    return std::make_shared<QuicStreamResult>(
                        false, bytes_read, (int)QuicStreamResult::Error::RESET_BY_REMOTE);
                }
                if (m_current_frame->readAvailable() > 0 || m_current_frame_is_last) {
                    break;
                }
                lock.unlock();
                base::Timer::ptr timer = nullptr;
                std::shared_ptr<timer_info> tinfo(new timer_info);
                if (m_deadline) {
                    if (m_deadline <= base::GetCurrentMS()) {
                        return std::make_shared<QuicStreamResult>(
                            false, bytes_read, (int)QuicStreamResult::Error::TIMEOUT);
                    }
                    base::IOManager *iom = base::IOManager::GetThis();
                    std::weak_ptr<timer_info> winfo(tinfo);
                    timer = iom->addConditionTimer(
                        m_deadline,
                        [winfo, this]() {
                            auto t = winfo.lock();
                            if (!t || t->cancelled) {
                                return;
                            }
                            t->cancelled = ETIMEDOUT;
                            this->signalRead();
                        },
                        winfo);
                }
                waitRead(); // RaceCondition: 1: timer; 2: normal
                lock.lock();
                if (timer) {
                    timer->cancel();
                }
                if (tinfo->cancelled) {
                    return std::make_shared<QuicStreamResult>(
                        false, bytes_read, (int)QuicStreamResult::Error::TIMEOUT);
                }
                if (m_current_frame->readAvailable() == 0) {
                    dequeueNextFrame();
                }
            }
            if (bytes_read > length) {
                return std::make_shared<QuicStreamResult>(false, bytes_read,
                                                          (int)QuicStreamResult::Error::UNKNOW,
                                                          "BUG: bytes_read > length");
            }
            if (m_read_pos_in_frame > m_current_frame->readAvailable()) {
                return std::make_shared<QuicStreamResult>(
                    false, bytes_read, (int)QuicStreamResult::Error::UNKNOW,
                    "BUG: read_pos_in_frame > curr_frame size");
            }
            size_t copy_len = std::min(length - buffer_block->readAvailable(),
                                       m_current_frame->readAvailable() - m_read_pos_in_frame);
            buffer_block->copyIn(*m_current_frame.get(), copy_len, m_read_pos_in_frame);
            m_read_pos_in_frame += copy_len;
            bytes_read += copy_len;

            if (!m_reset_by_remote) {
                m_flow_controller->addBytesRead(copy_len);
            }
            if (m_read_pos_in_frame >= m_current_frame->readAvailable()
                && m_current_frame_is_last) {
                m_fin_read = true;
                return std::make_shared<QuicStreamResult>(true, bytes_read,
                                                          (int)QuicStreamResult::Error::STREAM_EOF);
            }
        }
        return std::make_shared<QuicStreamResult>(false, bytes_read,
                                                  (int)QuicStreamResult::Error::OK);
    }

    uint64_t QuicRcvStream::getWinUpdate()
    {
        return m_flow_controller->getWinUpdate();
    }

    /// QuicSndStream
    bool QuicSndStream::canBufferStreamFrame()
    {
        uint64_t l = 0;
        if (m_next_frame) {
            if (m_next_frame->data()) {
                l = m_next_frame->data()->readAvailable();
            }
        }
        if (m_data_for_writing) {
            l += m_data_for_writing->readAvailable();
        }
        return l <= 1452;
    }
    static uint64_t g_tmp_count = 1;
    const QuicStreamResult::ptr QuicSndStream::write(const MBuffer::ptr &buffer_block)
    {
        MutexType::Lock lock(m_mutex);
        if (m_finished_writing) {
            return std::make_shared<QuicStreamResult>(
                false, 0, (int)QuicStreamResult::Error::WRITE_ON_CLOSED_STREAM);
        }
        if (m_canceled_write) {
            return std::make_shared<QuicStreamResult>(false, 0,
                                                      (int)QuicStreamResult::Error::CANCEL_WRITE);
        }
        if (m_shutdown) {
            return std::make_shared<QuicStreamResult>(false, 0,
                                                      (int)QuicStreamResult::Error::SHUTDOWN);
        }
        if (m_deadline && m_deadline <= base::GetCurrentMS()) {
            return std::make_shared<QuicStreamResult>(false, 0,
                                                      (int)QuicStreamResult::Error::TIMEOUT);
        }
        if (buffer_block->readAvailable() == 0) {
            return std::make_shared<QuicStreamResult>(
                false, 0, (int)QuicStreamResult::Error::WRITE_BUFFER_EMPTY);
        }
        _ASSERT(m_data_for_writing == nullptr);
        m_data_for_writing = std::make_shared<MBuffer>(*buffer_block.get());
        uint64_t byte_written = 0;
        while (1) {
            bool copied = false;
            base::Timer::ptr timer = nullptr;
            std::shared_ptr<timer_info> tinfo(new timer_info);
            if (canBufferStreamFrame() && m_data_for_writing) {
                if (m_next_frame == nullptr) {
                    QuicStreamFrame::ptr frame = std::make_shared<QuicStreamFrame>();
                    frame->set_offset(m_write_offset);
                    frame->set_stream_id(m_stream_id);
                    frame->set_data(m_data_for_writing);
                    m_next_frame = frame;
                } else {
                    m_next_frame->data()->copyIn(*m_data_for_writing.get(),
                                                 m_data_for_writing->readAvailable());
                }
                byte_written = buffer_block->readAvailable();
                m_data_for_writing = nullptr;
                copied = true;
            } else {
                byte_written = buffer_block->readAvailable()
                               - (m_data_for_writing ? m_data_for_writing->readAvailable() : 0);
                if (m_deadline) {
                    if (m_deadline <= base::GetCurrentMS()) {
                        m_data_for_writing = nullptr;
                        return std::make_shared<QuicStreamResult>(
                            false, 0, (int)QuicStreamResult::Error::TIMEOUT);
                    }
                    base::IOManager *iom = base::IOManager::GetThis();
                    std::weak_ptr<timer_info> winfo(tinfo);
                    timer = iom->addConditionTimer(
                        m_deadline,
                        [winfo, this]() {
                            auto t = winfo.lock();
                            if (!t || t->cancelled) {
                                return;
                            }
                            t->cancelled = ETIMEDOUT;
                            this->signalWrite();
                        },
                        winfo);
                }
                if (m_data_for_writing == nullptr || m_canceled_write || m_shutdown) {
                    break;
                }
            }
            lock.unlock();
            {
                auto sender = m_sender.lock();
                if (sender) {
                    sender->onHasStreamData(m_stream_id);
                }
            }
            if (copied) {
                lock.lock();
                break;
            }
            waitWrite();
            if (timer) {
                timer->cancel();
            }
            if (tinfo->cancelled) {
                return std::make_shared<QuicStreamResult>(false, 0,
                                                          (int)QuicStreamResult::Error::TIMEOUT);
            }
            lock.lock();
        }
        if (byte_written == buffer_block->readAvailable()) {
            g_tmp_count++;
            return std::make_shared<QuicStreamResult>(true, byte_written,
                                                      (int)QuicStreamResult::Error::OK);
        }
        if (m_shutdown) {
            return std::make_shared<QuicStreamResult>(true, byte_written,
                                                      (int)QuicStreamResult::Error::SHUTDOWN);
        } else if (m_canceled_write) {
            return std::make_shared<QuicStreamResult>(true, byte_written,
                                                      (int)QuicStreamResult::Error::CANCEL_WRITE);
        }
        return std::make_shared<QuicStreamResult>(true, byte_written,
                                                  (int)QuicStreamResult::Error::OK);
    }

    void QuicSndStream::get_data_for_writing(QuicStreamFrame::ptr stream_frame, size_t max_bytes)
    {
        if (m_data_for_writing == nullptr || m_data_for_writing->readAvailable() <= max_bytes) {
            stream_frame->set_data(m_data_for_writing);
            m_data_for_writing = nullptr;
            signalWrite();
            return;
        }
        MBuffer::ptr data = std::make_shared<MBuffer>();
        m_data_for_writing->copyOut(*data.get(), max_bytes);
        m_data_for_writing->consume(max_bytes);
        stream_frame->set_data(data);
        if (canBufferStreamFrame()) {
            signalWrite();
        }
    }

    bool QuicSndStream::popNewStreamFrameWithoutBuffer(QuicStreamFrame::ptr frame, size_t max_bytes,
                                                       size_t send_win)
    {
        uint64_t max_data_len = frame->maxDataLen(max_bytes);
        if (max_data_len == 0) {
            return false;
        }
        get_data_for_writing(frame, std::min(max_data_len, send_win));
        return m_data_for_writing != nullptr || m_next_frame != nullptr || m_fin_sent;
    }

    std::tuple<QuicStreamFrame::ptr, bool> QuicSndStream::popNewStreamFrame(size_t max_bytes,
                                                                            size_t send_win)
    {
        if (m_next_frame) {
            QuicStreamFrame::ptr next_frame = m_next_frame;
            m_next_frame = nullptr;
            uint64_t max_data_len = std::min(send_win, next_frame->maxDataLen(max_bytes));
            if (next_frame->data() && next_frame->data()->readAvailable() > max_data_len) {
                MBuffer::ptr ori_data = next_frame->data();
                m_next_frame = std::make_shared<QuicStreamFrame>();
                m_next_frame->set_stream_id(m_stream_id);
                m_next_frame->set_offset(m_write_offset + max_data_len);
                m_next_frame->set_data(ori_data);

                MBuffer::ptr new_data = std::make_shared<MBuffer>();
                ori_data->copyOut(*new_data.get(), max_data_len);
                ori_data->consume(max_data_len);
                next_frame->set_data(new_data);
            } else {
                signalWrite();
            }
            return std::make_tuple(next_frame,
                                   m_next_frame != nullptr || m_data_for_writing != nullptr);
        }
        QuicStreamFrame::ptr frame = std::make_shared<QuicStreamFrame>();
        frame->set_stream_id(m_stream_id);
        frame->set_offset(m_write_offset);
        bool has_more_data = popNewStreamFrameWithoutBuffer(frame, max_bytes, send_win);
        if (frame->data() == nullptr && !frame->has_fin_flag()) {
            return std::make_tuple(nullptr, has_more_data);
        }
        return std::make_tuple(frame, has_more_data);
    }

    std::tuple<QuicStreamFrame::ptr, bool> QuicSndStream::maybeGetRetransmission(size_t max_bytes)
    {
        QuicStreamFrame::ptr frame = m_retransmission_queue.front();
        QuicStreamFrame::ptr new_frame = frame->maybeSplitOffFrame(max_bytes);
        if (new_frame) {
            return std::make_tuple(new_frame, true);
        }
        m_retransmission_queue.pop_front();
        return std::make_tuple(frame, m_retransmission_queue.size() > 0);
    }

    std::tuple<QuicStreamFrame::ptr, bool>
    QuicSndStream::popNewOrRetransmissitedStreamFrame(size_t max_bytes)
    {
        if (m_canceled_write || m_shutdown) {
            return std::make_tuple(nullptr, false);
        }
        QuicStreamFrame::ptr frame = nullptr;
        if (m_retransmission_queue.size() > 0) {
            auto res = maybeGetRetransmission(max_bytes);
            auto frame = std::get<0>(res);
            bool has_more_retrans = std::get<1>(res);
            if (frame || has_more_retrans) {
                if (frame == nullptr) {
                    return std::make_tuple(nullptr, true);
                }
                _LOG_DEBUG(g_logger) << "has retrans, frame: " << frame->toString();
                return std::make_tuple(frame, true);
            }
        }
        if (m_data_for_writing == nullptr && m_next_frame == nullptr) {
            if (m_finished_writing && !m_fin_sent) {
                m_fin_sent = true;
                frame = std::make_shared<QuicStreamFrame>();
                frame->set_stream_id(m_stream_id);
                frame->set_offset(m_write_offset);
                frame->set_fin_flag();
                return std::make_tuple(frame, false);
            }
            return std::make_tuple(nullptr, false);
        }
        uint64_t send_win = m_flow_controller->sendWinSize();
        _LOG_WARN(g_logger) << "trace now: " << GetCurrentUS() << " stream_send_win: " << send_win
                            << " sent_win: " << m_flow_controller->m_send_win
                            << " bytes_sent: " << m_flow_controller->m_bytes_sent;
        if (send_win == 0) {
            uint64_t offset = m_flow_controller->isNewlyBlocked();
            if (offset) {
                auto sender = m_sender.lock();
                if (sender) {
                    _LOG_DEBUG(g_logger)
                        << "popNewOrRetransmissitedStreamFrame send_win 0, m_write_offset: "
                        << m_write_offset << ", make StreamDataBlockedFrame offset: " << offset;
                    sender->queueControlFrame(
                        std::make_shared<QuicStreamDataBlockedFrame>(m_stream_id, offset));
                    return std::make_tuple(nullptr, false);
                }
            }
            return std::make_tuple(nullptr, true);
        }
        auto res = popNewStreamFrame(max_bytes, send_win);
        frame = std::get<0>(res);
        bool has_more_data = std::get<1>(res);
        if (frame != nullptr && frame->data() && frame->data()->readAvailable()) {
            m_write_offset += frame->data()->readAvailable();
            m_flow_controller->addBytesSent(frame->data()->readAvailable());
        }
        if (m_finished_writing && m_data_for_writing == nullptr && m_next_frame == nullptr
            && !m_fin_sent) {
            frame->set_fin_flag();
            m_fin_sent = true;
        }
        return std::make_tuple(frame, has_more_data);
    }

    std::tuple<QuicStreamFrame::ptr, bool> QuicSndStream::popStreamFrame(size_t max_bytes)
    {
        MutexType::Lock lock(m_mutex);
        auto res = popNewOrRetransmissitedStreamFrame(max_bytes);
        auto frame = std::get<0>(res);
        bool has_more_data = std::get<1>(res);
        if (frame) {
            m_num_outstanding_frames++;
            _ASSERT(frame->type() == QuicFrameType::STREAM);
            _LOG_DEBUG(g_logger) << "after popStreamFrame m_num_outstanding_frames: "
                                 << m_num_outstanding_frames << ", frame: " << frame->toString();
        }
        lock.unlock();
        if (frame == nullptr) {
            return std::make_tuple(nullptr, has_more_data);
        }
        if (frame->data() && frame->data()->readAvailable() > 1400) {
            _ASSERT(0);
        }
        frame->setOnAcked(
            std::bind(&QuicSndStream::frameAcked, shared_from_this(), std::placeholders::_1));
        frame->setOnLost(std::bind(&QuicSndStream::queueRetransmission, shared_from_this(),
                                   std::placeholders::_1));
        m_sum_sent_packet++;
        m_sum_bytes_sent_packet += frame->size();
        return std::make_tuple(frame, has_more_data);
    }

    void QuicSndStream::queueRetransmission(const QuicFrame::ptr &frame)
    {
        MutexType::Lock lock(m_mutex);
        if (m_canceled_write) {
            return;
        }
        m_retransmission_queue.push_back(std::dynamic_pointer_cast<QuicStreamFrame>(frame));
        _ASSERT(frame->type() == QuicFrameType::STREAM);
        m_num_outstanding_frames--;
        _LOG_DEBUG(g_logger) << "queueRetransmission m_num_outstanding_frames: "
                             << m_num_outstanding_frames;
        if (m_num_outstanding_frames < 0) {
            _ASSERT(0);
        }
        m_sum_retrans_packet++;
        m_sum_bytes_retrans_packet += frame->size();
        lock.unlock();
        {
            auto sender = m_sender.lock();
            if (sender) {
                sender->onHasStreamData(m_stream_id);
            }
        }
    }

    void QuicSndStream::frameAcked(const QuicFrame::ptr &frame)
    {
        QuicStreamFrame::ptr stream_frame = std::dynamic_pointer_cast<QuicStreamFrame>(frame);
        // mem free TODO
        if (stream_frame->has_fin_flag()) {
            _LOG_WARN(g_logger) << "stream frame has fin";
        }
        MutexType::Lock lock(m_mutex);
        if (m_canceled_write) {
            return;
        }
        _ASSERT(frame->type() == QuicFrameType::STREAM);
        m_num_outstanding_frames--;
        _LOG_DEBUG(g_logger) << "after frameAcked m_num_outstanding_frames: "
                             << m_num_outstanding_frames << ", frame: " << frame->toString();
        if (m_num_outstanding_frames < 0) {
            _ASSERT(0);
        }
        bool newly_complete = isNewlyCompleted();
        lock.unlock();
        if (newly_complete) {
            {
                auto sender = m_sender.lock();
                if (sender) {
                    sender->onStreamCompleted(m_stream_id);
                }
            }
        }
    }

    const QuicStreamResult::ptr QuicSndStream::close()
    {
        MutexType::Lock lock(m_mutex);
        if (m_canceled_write) {
            lock.unlock();
            return std::make_shared<QuicStreamResult>(
                false, 0, (int)QuicStreamResult::Error::CANCEL_WRITE,
                "close called for canceled stream " + std::to_string(m_stream_id));
        }
        m_finished_writing = true;
        lock.unlock();
        {
            auto sender = m_sender.lock();
            if (sender) {
                sender->onHasStreamData(m_stream_id);
            }
        }
        return nullptr;
    }

    bool QuicSndStream::isNewlyCompleted()
    {
        bool completed = (m_fin_sent || m_canceled_write) && m_num_outstanding_frames == 0
                         && m_retransmission_queue.size() == 0;
        if (completed && !m_complete) {
            m_complete = true;
            return true;
        }
        return false;
    }

    void QuicSndStream::cancelWrite()
    {
        MutexType::Lock lock(m_mutex);
        if (m_canceled_write) {
            return;
        }
        m_canceled_write = true;
        m_num_outstanding_frames = 0;
        std::list<QuicStreamFrame::ptr>().swap(m_retransmission_queue);
        lock.unlock();
        bool is_newly_completed = isNewlyCompleted();
        signalWrite();
        auto sender = m_sender.lock();
        if (sender) {
            sender->queueControlFrame(
                std::make_shared<QuicRstStreamFrame>(m_stream_id, m_write_offset));
            if (is_newly_completed) {
                sender->onStreamCompleted(m_stream_id);
            }
        }
    }

    void QuicSndStream::closeForShutdown()
    {
        MutexType::Lock lock(m_mutex);
        m_shutdown = true;
        lock.unlock();
        signalWrite();
    }

    void QuicSndStream::updateSendWin(uint64_t limit)
    {
        MutexType::Lock lock(m_mutex);
        bool has_stream_data = m_data_for_writing != nullptr || m_next_frame != nullptr;
        lock.unlock();
        m_flow_controller->updateSendWin(limit);
        _LOG_INFO(g_logger) << "recv update send win, m_bytes_sent: "
                            << m_flow_controller->m_bytes_sent
                            << ", m_sent_win: " << m_flow_controller->m_send_win;
        _LOG_WARN(g_logger) << "trace now: " << GetCurrentUS()
                            << " updateSendWin m_sent_win: " << m_flow_controller->m_send_win;
        if (has_stream_data) {
            auto sender = m_sender.lock();
            if (sender) {
                sender->onHasStreamData(m_stream_id);
            }
        }
    }

    void QuicSndStream::handleStopSendingFrame(QuicStopSendingFrame::ptr frame)
    {
        return;
    }

    std::string QuicSndStream::toStatisticsString() const
    {
        std::stringstream ss;
        ss << "packet send rate: " << m_sum_retrans_packet << "/" << m_sum_sent_packet << ":"
           << m_sum_retrans_packet * 1.0 / m_sum_sent_packet;
        ss << ", bytes send rate: " << m_sum_bytes_retrans_packet << "/" << m_sum_bytes_sent_packet
           << ":" << m_sum_bytes_retrans_packet * 1.0 / m_sum_bytes_sent_packet;
        return ss.str();
    }

    /// QuicStream
    uint64_t QuicStream::getWinUpdate()
    {
        if (!m_receive_stream) {
            return 0;
        }
        return m_receive_stream->getFlowController()->getWinUpdate();
    }

    /// QuicBuffer
    QuicBuffer::QuicBuffer()
    {
        m_remote_addr = std::make_shared<IPv4Address>();
        m_read_buffer = std::make_shared<MBuffer>();
        m_write_buffer = std::make_shared<MBuffer>();
    }

    QuicBuffer::~QuicBuffer()
    {
    }

    int QuicBuffer::bufferRead(void *data, size_t length)
    {
        m_read_buffer->copyOut(data, length);
        m_read_buffer->consume(length);
        return length;
    }

    /// QuicIncomingBidiStreamsMap
    QuicStream::ptr QuicIncomingBidiStreamsMap::acceptStream()
    {
        waitAccept();
        _LOG_WARN(g_logger) << "QuicIncomingBidiStreamsMap::acceptStream 1waitdone";
        RWMutexType::ReadLock lock(m_mutex);
        QuicStreamNum num;
        QuicStreamEntry entry;
        while (1) {
            num = m_next_stream_to_accept;
            if (m_closed) {
                return nullptr;
            }
            auto it = m_streams.find(num);
            if (it != m_streams.end()) {
                entry = it->second;
                break;
            }
            lock.unlock();
            _LOG_WARN(g_logger) << "QuicIncomingBidiStreamsMap::acceptStream not find num: " << num
                                << " 2wait";
            waitAccept();
            lock.lock();
        }
        _LOG_WARN(g_logger) << "QuicIncomingBidiStreamsMap::acceptStream ok ";
        m_next_stream_to_accept++;
        if (entry.shouldDelete) {
            if (!deleteStreamImp(num)) {
                lock.unlock();
                return nullptr;
            }
        }
        lock.unlock();
        return entry.stream;
    }

    QuicStream::ptr QuicIncomingBidiStreamsMap::getOrOpenStream(QuicStreamNum num)
    {
        {
            RWMutexType::ReadLock lock(m_mutex);
            if (num > m_max_stream) {
                lock.unlock();
                _LOG_DEBUG(g_logger) << "getOrOpenStream peer tried to open stream " << num;
                return nullptr;
            }
            if (num < m_next_stream_to_open) {
                auto it = m_streams.find(num);
                if (it != m_streams.end() && !it->second.shouldDelete) {
                    return it->second.stream;
                }
            }
        }
        {
            RWMutexType::WriteLock lock(m_mutex);
            for (auto new_num = m_next_stream_to_open; new_num <= num; new_num++) {
                QuicStreamEntry entry;
                entry.stream = m_new_stream_cb(new_num);
                m_streams[new_num] = entry;
                _LOG_WARN(g_logger) << "getOrOpenStream new stream, signalAccept";
                signalAccept();
            }
            m_next_stream_to_open = num + 1;
            QuicStreamEntry entry = m_streams[num];
            return entry.stream;
        }
    }

    bool QuicIncomingBidiStreamsMap::deleteStream(QuicStreamNum num)
    {
        RWMutexType::WriteLock lock(m_mutex);
        return deleteStreamImp(num);
    }

    bool QuicIncomingBidiStreamsMap::deleteStreamImp(QuicStreamNum num)
    {
        auto it = m_streams.find(num);
        if (it == m_streams.end()) {
            _LOG_DEBUG(g_logger) << "deleteStreamImp tried to delete unknow incoming stream "
                                 << num;
            return false;
        }
        if (num >= m_next_stream_to_accept) {
            _ASSERT(0);
            return true;
        }
        _LOG_WARN(g_logger) << "QuicIncomingBidiStreamsMap deleteStreamImp: num: " << num;
        m_streams.erase(num);
        if (m_streams.size() < m_max_num_streams) {
            uint64_t max_stream =
                m_next_stream_to_open + StreamId2Num(m_max_num_streams - m_streams.size()) - 1;
            if (max_stream <= 1024) { // TODO
                m_max_stream = max_stream;
                QuicMaxStreamsFrame::ptr max_streams_frame = std::make_shared<QuicMaxStreamsFrame>(
                    QuicStreamType::QuicStreamTypeBidi, m_max_stream);
                m_queue_max_stream_id_cb(max_streams_frame);
            }
        }
        return true;
    }

    void QuicIncomingBidiStreamsMap::closeWithErr()
    {
        RWMutexType::WriteLock lock(m_mutex);
        for (const auto &it : m_streams) {
            it.second.stream->closeForShutdown();
        }
    }

    /// QuicOutgoingBidiStreamsMap
    QuicStream::ptr QuicOutgoingBidiStreamsMap::openStreamImp()
    {
        QuicStream::ptr stream = m_new_stream_cb(m_next_stream);
        m_streams[m_next_stream] = stream;
        m_next_stream++;
        return stream;
    }

    void QuicOutgoingBidiStreamsMap::maybeSendBlockedFrame()
    {
        if (m_blocked_sent) {
            return;
        }
        QuicStreamNum stream_num = 0;
        if (m_max_stream != ~0ull) {
            stream_num = m_max_stream;
        }
        QuicStreamsBlockedFrame::ptr streams_blocked_frame =
            std::make_shared<QuicStreamsBlockedFrame>(QuicStreamType::QuicStreamTypeBidi,
                                                      stream_num);
        m_queue_streamid_blocked_cb(streams_blocked_frame);
        m_blocked_sent = true;
    }

    QuicStream::ptr QuicOutgoingBidiStreamsMap::openStream()
    {
        RWMutexType::WriteLock lock(m_mutex);
        if (m_closed) {
            return nullptr;
        }
        if (m_open_streams.size() > 0 || m_next_stream >= m_max_stream) {
            maybeSendBlockedFrame();
            return nullptr;
        }
        return openStreamImp();
    }

    QuicStream::ptr QuicOutgoingBidiStreamsMap::openStreamSync()
    {
        // TODO
        return nullptr;
    }

    QuicStream::ptr QuicOutgoingBidiStreamsMap::getStream(QuicStreamNum num)
    {
        RWMutexType::ReadLock lock(m_mutex);
        if (num >= m_next_stream) {
            lock.unlock();
            return nullptr;
        }
        if (m_streams.find(num) == m_streams.end()) {
            return nullptr;
        }
        return m_streams[num];
    }

    int QuicOutgoingBidiStreamsMap::deleteStream(QuicStreamNum num)
    {
        RWMutexType::WriteLock lock(m_mutex);
        if (m_streams.find(num) == m_streams.end()) {
            return -1;
        }
        m_streams.erase(num);
        return 0;
    }

    void QuicOutgoingBidiStreamsMap::unblockOpenSync()
    { // TODO
        if (m_open_streams.size() == 0) {
            return;
        }
    }

    void QuicOutgoingBidiStreamsMap::setMaxStream(QuicStreamNum num)
    {
        RWMutexType::WriteLock lock(m_mutex);
        if (num <= m_max_stream) {
            return;
        }
        m_max_stream = num;
        m_blocked_sent = false;
        if (m_max_stream < m_next_stream - 1 + StreamId2Num(m_streams.size())) {
            maybeSendBlockedFrame();
        }
        unblockOpenSync();
    }

    void QuicOutgoingBidiStreamsMap::updateSendWin(uint64_t limit)
    {
        RWMutexType::WriteLock lock(m_mutex);
        for (const auto &it : m_streams) {
            QuicStream::ptr stream = it.second;
            stream->updateSendWin(limit);
        }
    }

    void QuicOutgoingBidiStreamsMap::closeWithErr()
    {
        RWMutexType::WriteLock lock(m_mutex);
        for (const auto &it : m_streams) {
            QuicStream::ptr stream = it.second;
            stream->closeForShutdown();
        }
        /* TODO
        for (const auto &it : m_open_streams) {
            QuicStream::ptr stream = it.second;
            close(stream);
        }
         */
    }

    /// QuicStreamManager
    /**
     * @brief 设置当前会话的发送器。
     *        QuicStreamManager 需要知道如何通过会话发送控制帧和数据帧。
     * @param session 指向当前 QuicSession 对象的共享指针。
     */
    void QuicStreamManager::setSessoin(const std::shared_ptr<QuicSession> &session)
    {
        std::shared_ptr<StreamSender> sender = session;
        // 将转换后的 sender 存储为弱指针，避免循环引用。
        m_sender = sender;
    }

    /**
     * @brief 获取当前会话的发送器。
     * @return 指向 StreamSender 对象的共享指针。如果会话已失效，则返回 nullptr。
     */
    std::shared_ptr<StreamSender> QuicStreamManager::getSession() const
    {
        // 将弱指针提升为共享指针。如果原始对象已销毁，则返回空的共享指针。
        return m_sender.lock();
    }

    /**
     * @brief 判断给定流ID是由哪一方发起的。
     *        根据 QUIC 协议，流ID的最低两位决定了流的类型和发起者。
     *        这里简化为根据流ID的奇偶性判断。
     * @param stream_id 要判断的流ID。
     * @return 1 如果流由远程对端发起 (通常是偶数ID对于客户端，奇数ID对于服务器)。
     *         0 如果流由本地发起 (通常是奇数ID对于客户端，偶数ID对于服务器)。
     */
    int QuicStreamManager::streamInitiatedBy(QuicStreamId stream_id)
    {
        // 简单的奇偶判断，实际 QUIC 协议规则更复杂，取决于角色和流类型。
        if (stream_id % 2 == 0) {
            return 1; // 假设偶数ID由远程发起
        }
        return 0; // 假设奇数ID由本地发起
    }

    /**
     * @brief 静态辅助函数，用于创建一个新的 QuicStream 实例。
     * @param stream_id 新流的ID。
     * @param sender 流发送器的弱引用，用于流内部回调会话发送数据。
     * @param fc 流级流量控制器，用于管理该流的流量。
     * @return 新创建的 QuicStream 共享指针。
     */
    static const QuicStream::ptr newStream(QuicStreamId stream_id,
                                           const std::weak_ptr<StreamSender> &sender,
                                           const StreamFlowController::ptr &fc)
    {
        // 创建 QuicStream 对象，并返回其共享指针。
        QuicStream::ptr stream = std::make_shared<QuicStream>(stream_id, sender, fc);
        return stream;
    }

    /**
     * @brief QuicStreamManager 构造函数。
     * @param role 当前 QUIC 会话的角色 (客户端或服务器)。
     * @param new_fc 用于创建流级流量控制器的回调函数。
     */
    QuicStreamManager::QuicStreamManager(
        QuicRole role, const std::function<StreamFlowController::ptr(QuicStreamId)> &new_fc)
        : m_role(role), m_new_flow_control_cb(new_fc)
    {
        m_max_incoming_streams = 1024;    // TODO: 待实现，目前硬编码最大进站流数量
        QuicStreamId next_odd_stream = 1; // 奇数流ID起始值
        if (m_role == QuicRole::QUIC_ROLE_CLIENT) {
            // 客户端发起奇数ID流，接受偶数ID流
            m_next_stream = next_odd_stream; // 下一个要打开的本地流ID
            m_next_stream_to_accept = 2;     // 下一个要接受的远程流ID
        } else {
            // 服务器发起偶数ID流，接受奇数ID流
            m_next_stream = 2;                         // 下一个要打开的本地流ID
            m_next_stream_to_accept = next_odd_stream; // 下一个要接受的远程流ID
        }
    }

    /**
     * @brief 初始化进站和出站双向流映射。
     *        此函数在 QuicSession 初始化时调用，用于设置流管理器的内部状态。
     */
    void QuicStreamManager::initMaps()
    {
        // 获取会话发送器，如果获取失败则直接返回。
        auto sender = getSession();
        if (sender == nullptr) {
            return;
        }
        // 初始化出站双向流映射 (本地发起的流)。
        m_outgoing_bidi_streams_map = std::make_shared<QuicOutgoingBidiStreamsMap>(
            // 创建新流的回调函数：根据流编号、类型和角色生成流ID，并创建 QuicStream。
            [this](QuicStreamNum num) -> QuicStream::ptr {
                QuicStreamId id =
                    QuicStreamNumber::streamID(num, QuicStreamType::QuicStreamTypeBidi, m_role);
                return newStream(id, m_sender, m_new_flow_control_cb(id));
            },
            // 控制帧入队的回调函数：绑定到 StreamSender 的 queueControlFrame 方法。
            std::bind(&StreamSender::queueControlFrame, sender, std::placeholders::_1));
        // 初始化进站双向流映射 (远程发起的流)。
        m_incoming_bidi_streams_map = std::make_shared<QuicIncomingBidiStreamsMap>(
            // 创建新流的回调函数：根据流编号、类型和对端角色生成流ID，并创建 QuicStream。
            [this](QuicStreamNum num) -> QuicStream::ptr {
                QuicStreamId id = QuicStreamNumber::streamID(
                    num, QuicStreamType::QuicStreamTypeBidi, QuicRoleOpposite(m_role));
                return newStream(id, m_sender, m_new_flow_control_cb(id));
            },
            // 控制帧入队的回调函数：绑定到 StreamSender 的 queueControlFrame 方法。
            std::bind(&StreamSender::queueControlFrame, sender, std::placeholders::_1));
    }

    /**
     * @brief 打开一个新的出站双向流。
     * @return 新创建的 QuicStream 共享指针。
     */
    QuicStream::ptr QuicStreamManager::openStream()
    {
        // 加写锁保护对流映射的并发访问。
        RWMutexType::WriteLock lock(m_mutex);
        // 委托给 m_outgoing_bidi_streams_map 来实际打开流。
        return m_outgoing_bidi_streams_map->openStream();
    }

    /**
     * @brief 接受一个进站双向流。
     * @return 接受的 QuicStream 共享指针。
     */
    QuicStream::ptr QuicStreamManager::acceptStream()
    {
        // 加读锁保护对流映射的并发访问。
        RWMutexType::ReadLock lock(m_mutex);
        // 委托给 m_incoming_bidi_streams_map 来实际接受流。
        return m_incoming_bidi_streams_map->acceptStream();
    }

    /**
     * @brief 删除指定ID的流。
     *        根据流ID的类型和发起者，将删除操作委托给相应的流映射。
     * @param id 要删除的流ID。
     */
    void QuicStreamManager::deleteStream(QuicStreamId id)
    {
        // 从流ID中提取流编号和流类型。
        QuicStreamNum num = StreamId2Num(id);
        QuicStreamType type = StreamIdType(id);
        // 根据流类型进行处理。
        switch ((uint8_t)type) {
            case (uint8_t)QuicStreamType::QuicStreamTypeBidi: { // 双向流
                // 判断流是由本地还是远程发起。
                if (StreamIdInitialedBy(id) == m_role) {
                    // 本地发起的流，从出站映射中删除。
                    m_outgoing_bidi_streams_map->deleteStream(num);
                    return;
                }
                // 远程发起的流，从进站映射中删除。
                m_incoming_bidi_streams_map->deleteStream(num);
                return;
            }
            default: {
                // 对于不支持的流类型，断言并退出。
                _ASSERT(0);
                break;
            }
        }
        return;
    }

    /**
     * @brief 获取或打开一个接收流。
     *        如果流已存在则返回，否则根据流ID的类型和发起者创建并返回。
     * @param id 要获取或打开的流ID。
     * @return QuicRcvStream 共享指针。如果失败则返回 nullptr。
     */
    QuicRcvStream::ptr QuicStreamManager::getOrOpenReceiveStream(QuicStreamId id)
    {
        // 从流ID中提取流编号和流类型。
        QuicStreamNum num = StreamId2Num(id);
        QuicStreamType type = StreamIdType(id);
        // 根据流类型进行处理。
        switch ((uint8_t)type) {
            case (uint8_t)QuicStreamType::QuicStreamTypeBidi: { // 双向流
                // 判断流是由本地还是远程发起。
                if (StreamIdInitialedBy(id) == m_role) {
                    // 本地发起的流，从出站映射中获取，并返回其接收部分。
                    auto stream = m_outgoing_bidi_streams_map->getStream(num);
                    return stream ? stream->readStream() : nullptr;
                }
                // 远程发起的流，从进站映射中获取或打开，并返回其接收部分。
                auto stream = m_incoming_bidi_streams_map->getOrOpenStream(num);
                return stream ? stream->readStream() : nullptr;
            }
            default: {
                // 对于不支持的流类型，断言并退出。
                _ASSERT(0);
                break;
            }
        }
        return nullptr;
    }

    /**
     * @brief 获取或打开一个发送流。
     *        如果流已存在则返回，否则根据流ID的类型和发起者创建并返回。
     * @param id 要获取或打开的流ID。
     * @return QuicSndStream 共享指针。如果失败则返回 nullptr。
     */
    QuicSndStream::ptr QuicStreamManager::getOrOpenSendStream(QuicStreamId id)
    {
        // 从流ID中提取流编号和流类型。
        QuicStreamNum num = StreamId2Num(id);
        QuicStreamType type = StreamIdType(id);
        // 根据流类型进行处理。
        switch ((uint8_t)type) {
            case (uint8_t)QuicStreamType::QuicStreamTypeBidi: { // 双向流
                // 判断流是由本地还是远程发起。
                if (StreamIdInitialedBy(id) == m_role) {
                    // 本地发起的流，从出站映射中获取，并返回其发送部分。
                    auto stream = m_outgoing_bidi_streams_map->getStream(num);
                    return stream ? stream->writeStream() : nullptr;
                }
                // 远程发起的流，从进站映射中获取或打开，并返回其发送部分。
                auto stream = m_incoming_bidi_streams_map->getOrOpenStream(num);
                return stream ? stream->writeStream() : nullptr;
            }
            default: {
                // 对于不支持的流类型，断言并退出。
                _ASSERT(0);
                break;
            }
        }
        return nullptr;
    }

    /**
     * @brief 关闭所有流并标记为错误状态。
     *        通常在会话关闭或发生严重错误时调用。
     */
    void QuicStreamManager::closeWithErr()
    {
        // 委托给进站和出站映射来关闭各自管理的流。
        m_outgoing_bidi_streams_map->closeWithErr();
        m_incoming_bidi_streams_map->closeWithErr();
    }

    /**
     * @brief 从所有活动流中弹出待发送的流帧，用于构建 QUIC 数据包。
     *        此函数会遍历出站和进站流，收集它们准备发送的帧。
     * @param frames 用于存储弹出的流帧的列表。
     * @param max_packet_size 当前数据包的最大允许大小。
     * @return 实际填充到 frames 列表中的帧的总字节长度。
     */
    int QuicStreamManager::popStreamFrames(std::list<QuicFrame::ptr> &frames,
                                           uint64_t max_packet_size)
    {
        // 加读锁保护对流映射的并发访问。
        RWMutexType::ReadLock lock(m_mutex);
        int payload_len = 0;               // 已填充的有效载荷长度
        int remain_size = max_packet_size; // 剩余可填充空间
        // 遍历出站双向流，收集待发送帧。
        for (const auto &it : m_outgoing_bidi_streams_map->streams()) {
            if (remain_size <= 0) {
                break; // 如果数据包已满，则停止收集。
            }
            QuicStream::ptr stream = it.second;
            // 从流的发送部分弹出流帧。
            auto res = stream->writeStream()->popStreamFrame(remain_size);
            QuicFrame::ptr frame = std::get<0>(res); // 获取弹出的帧。
            if (frame == nullptr) {
                continue; // 如果没有帧弹出，则继续下一个流。
            }
            frames.push_back(frame);      // 将帧添加到待发送列表。
            payload_len += frame->size(); // 更新已填充长度。
            remain_size -= payload_len;   // 更新剩余空间。
        }
        // 遍历进站双向流，收集待发送帧 (通常是响应帧或流控制帧)。
        for (const auto &it : m_incoming_bidi_streams_map->streams()) {
            if (remain_size <= 0) {
                break; // 如果数据包已满，则停止收集。
            }
            QuicStream::ptr stream = it.second.stream;
            if (stream == nullptr) {
                _LOG_WARN(g_logger) << "incomingBidiStreamsMap stream: " << &stream;
            }
            // 从流的发送部分弹出流帧。
            auto res = stream->writeStream()->popStreamFrame(remain_size);
            QuicFrame::ptr frame = std::get<0>(res); // 获取弹出的帧。
            if (frame == nullptr) {
                continue; // 如果没有帧弹出，则继续下一个流。
            }
            frames.push_back(frame);      // 将帧添加到待发送列表。
            payload_len += frame->size(); // 更新已填充长度。
            remain_size -= payload_len;   // 更新剩余空间。
        }
        _LOG_DEBUG(g_logger) << "payload_len: " << payload_len; // 记录实际填充的有效载荷长度。
        return payload_len;                                     // 返回总的有效载荷长度。
    }
} // namespace quic
} // namespace base
