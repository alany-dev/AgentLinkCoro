#include "udp_server.h"
#include "base/conf/config.h"
#include "base/log/log.h"
#include "base/net/socket.h"
#include "base/util.h"

namespace base
{

static base::ConfigVar<uint64_t>::ptr g_udp_server_read_timeout = base::Config::Lookup(
    "udp_server.read_timeout", (uint64_t)(60 * 1000 * 2), "udp server read timeout");

static base::Logger::ptr g_logger = _LOG_NAME("system");

UdpServer::UdpServer(base::IOManager *recv_worker, base::IOManager *worker,
                     base::IOManager *send_worker)
    : m_worker(worker), m_recvWorker(recv_worker), m_sendWorker(send_worker),
      m_recvTimeout(g_udp_server_read_timeout->getValue()), m_name("sylar/1.0.0"), m_isStop(true)
{
}

UdpServer::~UdpServer()
{
    for (auto &i : m_socks) {
        i->close();
    }
    m_socks.clear();
}

void UdpServer::setConf(const UdpServerConf &v)
{
    m_conf = std::make_shared<UdpServerConf>(v);
}

bool UdpServer::bind(base::Address::ptr addr)
{
    std::vector<Address::ptr> addrs;
    std::vector<Address::ptr> fails;
    addrs.push_back(addr);
    return bind(addrs, fails);
}

bool UdpServer::bind(const std::vector<Address::ptr> &addrs, std::vector<Address::ptr> &fails)
{
    for (auto &addr : addrs) {
        Socket::ptr sock = Socket::CreateUDP(addr);
        if (!sock->bind(addr)) {
            _LOG_ERROR(g_logger) << "bind fail errno=" << errno << " errstr=" << strerror(errno)
                                 << " addr=[" << addr->toString() << "]";
            fails.push_back(addr);
            continue;
        }
        sock->setRecvTimeout(m_recvTimeout);
        m_socks.push_back(sock);
    }

    if (!fails.empty()) {
        m_socks.clear();
        return false;
    }

    for (auto &i : m_socks) {
        _LOG_INFO(g_logger) << "type=" << m_type << " name=" << m_name
                            << " server bind success: " << *i;
    }
    return true;
}

void UdpServer::startRecv(Socket::ptr sock)
{
    while (!m_isStop) {
        IPv4Address::ptr addr = std::make_shared<IPv4Address>(); // 默认IPV4了。
        auto buffer = std::make_shared<MBuffer>();
        int len = sock->recvFrom(buffer, 1500, addr);
        if (len > 0) {
            buffer->product(len);
            auto alternate_buffer = std::make_shared<MBuffer_t>(std::move(*buffer), GetCurrentUS());
            m_worker->schedule(std::bind(&UdpServer::handleData, shared_from_this(), sock, addr,
                                         alternate_buffer));
        } else if (len == 0) {
            _LOG_INFO(g_logger) << "recvFrom return 0, sock=" << *sock;
        } else {
            int err = sock->getError();
            if (err == EAGAIN || err == EWOULDBLOCK) {
                continue;
            }
            _LOG_ERROR(g_logger) << "recvFrom error, errno=" << err << " errstr=" << strerror(err)
                                 << " sock=" << *sock;
            break;
        }
    }
}

bool UdpServer::start()
{
    if (!m_isStop) {
        return true;
    }
    m_isStop = false;
    for (auto &sock : m_socks) {
        m_recvWorker->schedule(std::bind(&UdpServer::startRecv, shared_from_this(), sock));
    }
    return true;
}

void UdpServer::stop()
{
    m_isStop = true;
    auto self = shared_from_this();
    m_recvWorker->schedule([this, self]() {
        for (auto &sock : m_socks) {
            sock->cancelAll();
            sock->close();
        }
        m_socks.clear();
    });
}

int UdpServer::handleData(Socket::ptr sock, Address::ptr client, MBuffer::ptr buffer)
{
    _LOG_INFO(g_logger) << "handleData: client=" << *client << " size=" << buffer->readAvailable();
    return 0;
}

int UdpServer::sendPacket(Socket::ptr sock, MBuffer::ptr buffer, Address::ptr address)
{
    m_sendWorker->schedule(
        [sock, buffer, address]() { sock->sendTo(buffer, buffer->readAvailable(), address); });
    return 0;
}

std::string UdpServer::toString(const std::string &prefix)
{
    std::stringstream ss;
    ss << prefix << "[type=" << m_type << " name=" << m_name
       << " worker=" << (m_worker ? m_worker->getName() : "")
       << " io_worker=" << (m_sendWorker ? m_sendWorker->getName() : "")
       << " recv_timeout=" << m_recvTimeout << "]" << std::endl;
    std::string pfx = prefix.empty() ? "    " : prefix;
    for (auto &i : m_socks) {
        ss << pfx << pfx << *i << std::endl;
    }
    return ss.str();
}

} // namespace base