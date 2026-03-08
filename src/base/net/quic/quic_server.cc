#include "quic_server.h"
#include "base/net/quic/quic_type.h"
#include "base/util.h"
#include "quic_packet.h"
#include "quic_type.h"

namespace base
{
namespace quic
{
    static base::Logger::ptr g_logger = _LOG_NAME("system");

    QuicServer::QuicServer(base::IOManager *recv_worker, base::IOManager *worker,
                           base::IOManager *send_worker)
        : UdpServer(recv_worker, worker, send_worker)
    {
    }

    QuicSession::ptr QuicServer::accept()
    {
        m_accept_sem.wait();
        QuicSession::ptr session = nullptr;
        {
            RWMutexType::WriteLock lock(m_mutex);
            session = m_accept_queue.front();
            m_accept_queue.pop_front();
        }
        return session;
    }

    int QuicServer::handleData(Socket::ptr sock, const Address::ptr client, MBuffer::ptr buffer)
    {
        _LOG_DEBUG(g_logger) << "handleData "  << buffer->toString() << " from " << client->toString();
        // 1. 解析连接ID，根据连接ID路由到对应的流 QuicSession。
        // QuicConnectionId::parseConnectionId 快速路由的解析。
        QuicConnectionId::ptr dst_cid = QuicConnectionId::parseConnectionId(buffer);
        if (dst_cid == nullptr) {
            _LOG_DEBUG(g_logger) << "handleData parseConnectionId failed";
            return -1;
        }
        auto alternate_packet = std::make_shared<MBuffer_t>(*buffer.get(), GetCurrentUS());

        auto old_session = m_sessions_mgr.get(dst_cid);
        if (old_session) {
            // 2.1 有则路由到对应的流 QuicSession，由 QuicSession 处理
            return old_session->signalRead(alternate_packet);
        }

        auto header = readPacketHeaderFrom(buffer);
        if (header == nullptr) {
            _LOG_INFO(g_logger) << "handlePacket readPacketHeaderFrom failed";
            return -1;
        }
        int ret = header->readPacketNumberFrom(buffer);
        if (ret != 0) {
            _LOG_INFO(g_logger) << "handlePacket readPacketNumberFrom failed";
            return -1;
        }
        // 经过了更完整的协议解析，确保是 QUIC 包。
        auto ori_dcid = header->m_dst_cid;

        // 2.2 处理Initial包：创建 QuicSession，初始化流管理器，由 QuicSession 处理Initial包
        // 生成新的连接ID todo
        auto new_cid = generateConnectionId();

        // 创建新的会话
        auto new_session =
            std::make_shared<QuicSession>(std::dynamic_pointer_cast<QuicServer>(shared_from_this()),
                                          QuicRole::QUIC_ROLE_SERVER, ori_dcid, client, sock);
        // 存储会话
        m_sessions_mgr.add(new_session);
        // 初始化 流管理器
        new_session->getStreamMgr()->setSessoin(new_session);
        new_session->getStreamMgr()->initMaps();
        _LOG_INFO(g_logger) << "Adding cid " << ori_dcid->toHexString() << " and "
                            << new_cid->toHexString() << "for a new session";
        // 通知accept队列
        signalAccept(new_session);
        // 由 QuicSession 处理Initial包
        new_session->signalRead(alternate_packet);
        new_session->run();
        return 0;
    }

    QuicConnectionId::ptr QuicServer::generateConnectionId()
    {
        QuicConnectionId::ptr cid = nullptr;
        while (true) {
            std::string cid_str = random_string(4);
            cid = std::make_shared<QuicConnectionId>((const uint8_t *)&cid_str.c_str()[0], 4);
            // 循环生成新的连接ID，避免重复
            auto session = m_sessions_mgr.get(cid);
            if (session == nullptr) {
                break;
            }
        }
        return cid;
    }

    bool QuicServer::signalAccept(QuicSession::ptr session)
    {
        RWMutexType::WriteLock lock(m_mutex);
        bool empty = m_accept_queue.empty();
        m_accept_queue.push_back(session);
        lock.unlock();
        if (empty) {
            m_accept_sem.notify();
        }
        return empty;
    }

} // namespace quic
} // namespace base