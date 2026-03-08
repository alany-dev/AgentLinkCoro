#include "quic_client.h"
#include "base/net/quic/quic_type.h"
#include "base/util.h"
#include "quic_packet.h"
#include "quic_type.h"
#include "base/mutex.h" // 添加这个头文件来支持锁的使用

namespace base
{
namespace quic
{
    static base::Logger::ptr g_logger = _LOG_NAME("system");

    QuicClient::QuicClient(base::IOManager *worker, base::IOManager *io_worker)
        : UdpClient(worker, io_worker)
    {
    }

    bool QuicClient::connect(base::Address::ptr addr)
    {

        // 先建立UDP连接
        if (!UdpClient::connect(addr)) {
            _LOG_ERROR(g_logger) << "UDP connect failed";
            return false;
        }

        // 生成客户端连接ID
        m_cid = generateConnectionId();

        // 创建QUIC会话
        m_session = createSession();
        if (!m_session) {
            _LOG_ERROR(g_logger) << "Create QUIC session failed";
            UdpClient::close();
            return false;
        }

        // 初始化流管理器
        m_session->getStreamMgr()->setSessoin(m_session);
        m_session->getStreamMgr()->initMaps();
        m_session->run();

        _LOG_INFO(g_logger) << "QUIC client connected: " << addr->toString()
                            << " with cid: " << m_cid->toHexString();

        return true;
    }

    void QuicClient::close()
    {
        {
            RWMutexType::WriteLock lock(m_mutex);
            if (m_session) {
                m_session->closeSession();
                m_session = nullptr;
            }
        }
        UdpClient::close();
        m_cid = nullptr;
    }

    QuicSession::ptr QuicClient::getSession() const
    {
        RWMutexType::ReadLock lock(m_mutex);
        return m_session;
    }

    int QuicClient::handleData(MBuffer::ptr buffer)
    {
        RWMutexType::WriteLock lock(m_mutex);
        if (!m_session) {
            _LOG_ERROR(g_logger) << "No active session to handle data";
            return -1;
        }

        // 将接收到的数据转发给会话处理
        return m_session->handlePacket(buffer);
    }

    QuicStream::ptr QuicClient::createStream()
    {
        RWMutexType::WriteLock lock(m_mutex);
        if (!m_session) {
            _LOG_ERROR(g_logger) << "No active session";
            return nullptr;
        }

        // 通过流管理器创建新流
        return m_session->openStream();
    }

    QuicSession::ptr QuicClient::createSession()
    {
        // 创建客户端角色的QUIC会话
        auto session = std::make_shared<QuicSession>(nullptr, QuicRole::QUIC_ROLE_CLIENT, m_cid,
                                                     m_remoteAddr, m_sock);

        return session;
    }

    QuicConnectionId::ptr QuicClient::generateConnectionId()
    {
        // 生成随机的4字节连接ID
        std::string cid_str = random_string(4);
        return std::make_shared<QuicConnectionId>((const uint8_t *)&cid_str.c_str()[0], 4);
    }

} // namespace quic
} // namespace base