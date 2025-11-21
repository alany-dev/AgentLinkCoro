#include "socket_stream.h"
#include "base/util.h"
#include "base/log/log.h"

namespace base
{

static uint64_t s_id = 0;
static base::Logger::ptr g_logger = _LOG_NAME("system");

SocketStream::SocketStream(Socket::ptr sock, bool owner) : m_socket(sock), m_owner(owner)
{
    m_id = base::Atomic::addFetch(s_id, 1);
}

SocketStream::~SocketStream()
{
    if (m_owner && m_socket) {
        m_socket->close();
    }
}

bool SocketStream::isConnected() const
{
    return m_socket && m_socket->isConnected();
}

bool SocketStream::checkConnected()
{
    return m_socket && m_socket->checkConnected();
}

int SocketStream::read(void *buffer, size_t length)
{
    if (!isConnected()) {
        return -1;
    }
    return m_socket->recv(buffer, length);
}

int SocketStream::read(ByteArray::ptr ba, size_t length)
{
    if (!isConnected()) {
        return -1;
    }
    std::vector<iovec> iovs;
    ba->getWriteBuffers(iovs, length);
    int rt = m_socket->recv(&iovs[0], iovs.size());
    if (rt > 0) {
        ba->setPosition(ba->getPosition() + rt);
    }
    return rt;
}

int SocketStream::write(const void *buffer, size_t length)
{
    if (!isConnected()) {
        return -1;
    }
    return m_socket->send(buffer, length);
}

int SocketStream::write(ByteArray::ptr ba, size_t length)
{
    if (!isConnected()) {
        return -1;
    }
    std::vector<iovec> iovs;
    ba->getReadBuffers(iovs, length);
    int rt = m_socket->send(&iovs[0], iovs.size());
    if (rt > 0) {
        ba->setPosition(ba->getPosition() + rt);
    } else {
        _LOG_ERROR(g_logger) << "write fail length=" << length << " errno=" << errno << ", "
                             << strerror(errno);
    }
    return rt;
    // int rrt = 0;
    // std::vector<iovec> iovs;
    // ba->getReadBuffers(iovs, length);
    // for(size_t i = 0; i < iovs.size(); ++i) {
    //     int rt = m_socket->send(&iovs[i], 1);
    //     if(rt > 0) {
    //         ba->setPosition(ba->getPosition() + rt);
    //         rrt += rt;
    //     } else {
    //         _LOG_ERROR(g_logger) << "write fail length=" << length
    //             << " errno=" << errno << ", " << strerror(errno);
    //         rrt = rt;
    //         break;
    //     }
    // }
    // return rrt;
}
int SocketStream::sendTo(const void *buffer, size_t length, const Address::ptr to, int flags)
{
    if (!m_socket) {
        return -1;
    }
    // UDP是无连接协议，不应该检查连接状态
    return m_socket->sendTo(buffer, length, to, flags);
}

int SocketStream::sendTo(const iovec *iov, size_t iovcnt, const Address::ptr to, int flags)
{
    if (!m_socket || !iov) {
        return -1;
    }
    return m_socket->sendTo(iov, iovcnt, to, flags);
}

int SocketStream::recvFrom(void *buffer, size_t length, Address::ptr from, int flags)
{
    if (!m_socket) {
        return -1;
    }
    return m_socket->recvFrom(buffer, length, from, flags);
}

int SocketStream::recvFrom(iovec *iov, size_t iovcnt, Address::ptr from, int flags)
{
    if (!m_socket || !iov) {
        return -1;
    }
    return m_socket->recvFrom(iov, iovcnt, from, flags);
}

void SocketStream::close()
{
    if (m_socket) {
        m_socket->close();
    }
}

Address::ptr SocketStream::getRemoteAddress()
{
    if (m_socket) {
        return m_socket->getRemoteAddress();
    }
    return nullptr;
}

Address::ptr SocketStream::getLocalAddress()
{
    if (m_socket) {
        return m_socket->getLocalAddress();
    }
    return nullptr;
}

std::string SocketStream::getRemoteAddressString()
{
    auto addr = getRemoteAddress();
    if (addr) {
        return addr->toString();
    }
    return "";
}

std::string SocketStream::getLocalAddressString()
{
    auto addr = getLocalAddress();
    if (addr) {
        return addr->toString();
    }
    return "";
}

} // namespace base
