#include "net_ping.hpp"
#include "base/net/socket.h"
#include "base/net/address.h"
#include "base/net/dns_client.h"
#include "base/macro.h"
#include "logger.hpp"
#include <cstdint>
#include <net/if.h>

using namespace base;

namespace monitor::weaknet
{
// 定义数据包缓冲区大小为4KB，足够存储完整的IP头部和ICMP包
static constexpr int kPacketSize = 4096;

int NetPing::ping(const std::string &host, const std::string &ifaceName, int timeoutMs)
{
    Socket::ptr sock = Socket::CreateICMPSocket();
    if (_UNLIKELY(sock <= 0)) {
        return -1;
    }

    // 解析目标主机IPv4地址
    auto addr = Address::AsyncLookupAny(host, AF_INET);
    if(!addr){
        sock->close();
        return -3;
    }

    if (_UNLIKELY(!sock->connect(addr, timeoutMs))) {
        sock->close();
        return -4;
    }

    // 绑定指定网口
    struct ::ifreq ifr {
    };
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifaceName.c_str());
    if (!(sock->setOption(SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)))) {
        sock->close();
        return -2;
    }

    // 优化接收缓存区大小
    constexpr int size = 64 * 1024;
    if (!(sock->setOption(SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)))) {
        sock->close();
        return -4;
    }

    // 构建ICMP Echo请求包（记录当前请求的ID和SEQ，用于后续校验）
    struct ::icmp icmpPacket {
    };
    uint16_t id = static_cast<uint16_t>(getpid());
    static uint16_t seq = 0;
    uint16_t currentSeq = ++seq; // 保存当前请求的序列号，循环中不变
    packIcmp(&icmpPacket, id, currentSeq);

    // 发送请求
    auto sendTime = std::chrono::steady_clock::now(); // 记录发送时间（用于计算总超时）
    ssize_t sent = sock->send(&icmpPacket, sizeof(icmpPacket), 0);
    if (sent < 0) {
        sock->close();
        return -5;
    }

    // 循环接收逻辑：在超时时间内持续接收，直到收到有效回复或超时
    char buf[kPacketSize];
    sock->setRecvTimeout(timeoutMs);
    while (timeoutMs > 0) {
        timeoutMs -= std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - sendTime)
                         .count();
        // 接收数据包
        ssize_t n = sock->recv(buf, sizeof(buf), 0);
        if (n < 0) {
            LOG_ERROR(LogModule::PING, "recvFrom error: " << errno << ", " << strerror(errno));
            // 其他接收错误
            sock->close();
            return -7;
        }

        // 解析IP头部
        struct ip *iphdr = reinterpret_cast<struct ip *>(buf);
        int iphdrlen = iphdr->ip_hl * 4; // IP头部长度（4字节为单位）

        // 校验数据包完整性（至少包含IP头部+ICMP头部）
        if (n < iphdrlen + static_cast<ssize_t>(sizeof(struct icmp))) {
            // 数据包不完整，忽略并继续接收
            continue;
        }

        // 提取ICMP包
        struct icmp *ricmp = reinterpret_cast<struct icmp *>(buf + iphdrlen);

        // 校验是否为当前请求的有效回复：
        // 1. 类型必须是ECHO回复 2. ID匹配当前进程 3. 序列号匹配当前请求
        if (ricmp->icmp_type != ICMP_ECHOREPLY || ricmp->icmp_id != id
            || ricmp->icmp_seq != currentSeq) {
            // 无关报文（如其他进程的ping回复、ICMP错误报文等），忽略并继续
            continue;
        }

        // 收到有效回复，计算RTT
        auto recvTime = std::chrono::steady_clock::now();
        int rttMs = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(recvTime - sendTime).count());

        sock->close();
        return rttMs; // 返回有效RTT
    }

    // 循环结束：未收到有效回复（超时）
    sock->close();
    return -10; // 新增错误码：超时未收到回复
}

uint16_t NetPing::checksum(uint8_t *addr, int len)
{
    uint32_t sum = 0;
    uint16_t *ptr = reinterpret_cast<uint16_t *>(addr);
    // 处理完整的16位字
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    // 处理剩余的单个字节（如果有）
    if (len == 1) {
        sum += static_cast<uint16_t>(*(reinterpret_cast<uint8_t *>(ptr))) << 8;
    }
    // 折叠32位和到16位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

int NetPing::packIcmp(struct ::icmp *icmp, uint16_t id, uint16_t seq)
{
    memset(icmp, 0, sizeof(struct ::icmp));
    icmp->icmp_type = ICMP_ECHO; // 设置类型为Echo请求
    icmp->icmp_code = 0;         // Echo请求的代码字段固定为0
    icmp->icmp_id = id;          // 设置标识符，用于匹配请求与回复
    icmp->icmp_seq = seq;        // 设置序列号，区分同一进程的多个请求

    struct timeval *tv = reinterpret_cast<struct timeval *>(icmp->icmp_data);
    gettimeofday(tv, nullptr);
    icmp->icmp_cksum = 0;
    // 计算整个ICMP包的16位校验和
    icmp->icmp_cksum = checksum(reinterpret_cast<uint8_t *>(icmp), sizeof(struct ::icmp));
    return sizeof(struct ::icmp);
}

} // namespace monitor::weaknet
