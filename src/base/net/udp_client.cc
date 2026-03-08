#include "udp_client.h"
#include "base/conf/config.h"
#include "base/log/log.h"
#include "base/net/socket.h"
#include "base/util.h"

namespace base
{

static base::ConfigVar<uint64_t>::ptr g_udp_client_read_timeout = base::Config::Lookup(
    "udp_client.read_timeout", (uint64_t)(60 * 1000 * 2), "udp client read timeout");

static base::Logger::ptr g_logger = _LOG_NAME("system");

UdpClient::UdpClient(base::IOManager *worker, base::IOManager *io_worker)
    : m_worker(worker), m_ioWorker(io_worker),
      m_recvTimeout(g_udp_client_read_timeout->getValue()), m_name("sylar/1.0.0"), m_isStop(true)
{
}

UdpClient::~UdpClient()
{
    close();
}

void UdpClient::setConf(const UdpClientConf &v)
{
    m_conf = std::make_shared<UdpClientConf>(v);
}

bool UdpClient::connect(base::Address::ptr addr)
{
    m_remoteAddr = addr;
    m_sock = Socket::CreateUDP(addr);
    if (!m_sock) {
        _LOG_ERROR(g_logger) << "CreateUDP socket failed";
        return false;
    }
    
    m_sock->setRecvTimeout(m_recvTimeout);
    if (!m_sock->connect(addr)) {
        _LOG_ERROR(g_logger) << "connect fail errno=" << errno << " errstr=" << strerror(errno)
                             << " addr=[" << addr->toString() << "]";
        m_sock->close();
        m_sock = nullptr;
        return false;
    }
    
    _LOG_INFO(g_logger) << "type=" << m_type << " name=" << m_name
                        << " client connect success: " << addr->toString();
    
    m_isStop = false;
    m_worker->schedule(std::bind(&UdpClient::startRecv, shared_from_this()));
    return true;
}

int UdpClient::send(const void *buffer, size_t size)
{
    if (!isConnected()) {
        return -1;
    }
    return m_sock->sendTo(buffer, size, m_remoteAddr, 0);
}

int UdpClient::send(MBuffer::ptr buffer)
{
    if (!isConnected()) {
        return -1;
    }
    return m_sock->sendTo(buffer, buffer->readAvailable(), m_remoteAddr, 0);
}

int UdpClient::recv(void *buffer, size_t size)
{
    if (!isConnected()) {
        return -1;
    }
    return m_sock->recvFrom(buffer, size, m_remoteAddr, 0);
}

int UdpClient::recv(MBuffer::ptr buffer, size_t size)
{
    if (!isConnected()) {
        return -1;
    }
    return m_sock->recvFrom(buffer, size, m_remoteAddr, 0);
}

void UdpClient::close()
{
    m_isStop = true;
    if (m_sock) {
        m_sock->cancelAll();
        m_sock->close();
        m_sock = nullptr;
    }
    m_remoteAddr = nullptr;
}

void UdpClient::startRecv()
{
    while (!m_isStop && isConnected()) {
        auto buffer = std::make_shared<MBuffer>();
        int len = m_sock->recvFrom(buffer, 1500, m_remoteAddr, 0);
        if (len > 0) {
            buffer->product(len);
            handleData(buffer);
        } else if (len == 0) {
            _LOG_INFO(g_logger) << "recv return 0, sock=" << *m_sock;
            break;
        } else {
            int err = m_sock->getError();
            if (err == EAGAIN || err == EWOULDBLOCK) {
                continue;
            }
            _LOG_ERROR(g_logger) << "recv error, errno=" << err << " errstr=" << strerror(err)
                                 << " sock=" << *m_sock;
            break;
        }
    }
}

int UdpClient::handleData(MBuffer::ptr buffer)
{
    _LOG_INFO(g_logger) << "handleData: size=" << buffer->readAvailable();
    return 0;
}

std::string UdpClient::toString(const std::string &prefix)
{
    std::stringstream ss;
    ss << prefix << "[type=" << m_type << " name=" << m_name
       << " worker=" << (m_worker ? m_worker->getName() : "")
       << " io_worker=" << (m_ioWorker ? m_ioWorker->getName() : "")
       << " recv_timeout=" << m_recvTimeout << "]" << std::endl;
    std::string pfx = prefix.empty() ? "    " : prefix;
    if (m_remoteAddr) {
        ss << pfx << pfx << "remote: " << m_remoteAddr->toString() << std::endl;
    }
    if (m_sock) {
        ss << pfx << pfx << *m_sock << std::endl;
    }
    return ss.str();
}

} // namespace base