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

int SocketStream::sendTo(MBuffer::ptr buf, size_t length, Address::ptr addr)
{
    if (!isConnected()) {
        return -1;
    }
    std::vector<iovec> iovs = buf->readBuffers(length);
    int ret = m_socket->sendTo(&iovs[0], iovs.size(), addr);
    if (ret >= 0) {
        _ASSERT((int)length == ret);
        _ASSERT(length < 1500);
        buf->consume(ret);
    }
    if (ret < 0) {
        std::cout << "errno: " << errno << " strerrno: " << strerror(errno) << std::endl;
    }
    return ret;
}

int SocketStream::recvFrom(MBuffer::ptr buf, size_t length, Address::ptr addr)
{
    if (!isConnected()) {
        return -1;
    }
    std::vector<iovec> iovs = buf->writeBuffers(length);
    int ret = m_socket->recvFrom(&iovs[0], iovs.size(), addr);
    if (ret > 0) {
        buf->product(ret);
    }
    return ret;
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
