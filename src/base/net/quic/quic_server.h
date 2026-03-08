#pragma once
#include "base/net/udp_server.h"
#include "quic_session.h"
#include "base/mutex.h"
#include <unordered_map>

namespace base
{
namespace quic
{
    class QuicServer : public UdpServer
    {
    public:
        using ptr = std::shared_ptr<QuicServer>;
        using RWMutexType = RWSpinlock;

        QuicServer(base::IOManager *recv_worker = base::IOManager::GetThis(), base::IOManager *worker = base::IOManager::GetThis(),
                   base::IOManager *send_worker = base::IOManager::GetThis());

        QuicSession::ptr accept();

    protected:
        virtual int handleData(Socket::ptr sock, const Address::ptr client, MBuffer::ptr buffer);

    private:
        // 生成新的连接ID
        QuicConnectionId::ptr generateConnectionId();
        bool signalAccept(QuicSession::ptr session);

    private:
        QuicSessionManager m_sessions_mgr;
        RWMutexType m_mutex;
        FiberSemaphore m_accept_sem;
        std::list<QuicSession::ptr> m_accept_queue;
    };

} // namespace quic
} // namespace base