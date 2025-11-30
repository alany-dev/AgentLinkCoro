#include "net_tcp.hpp"
#include "base/bytearray.h"
#include "base/net/address.h"
#include "base/net/socket.h"
#include "logger.hpp"
#include "base/macro.h"
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

namespace monitor::weaknet
{

static int ifnameToIndex(const std::string &name)
{
    unsigned ifi = if_nametoindex(name.c_str());
    return ifi == 0 ? -1 : (int)ifi;
}

bool TcpLossMonitor::sample(TcpStats &outStats)
{
    base::Socket::ptr sock = base::Socket::CreateNetlinkSockDiagSocket();
    if (_UNLIKELY(!sock)) {
        return false;
    }
    uint64_t so4 = 0, si4 = 0, r4 = 0;
    uint64_t so6 = 0, si6 = 0, r6 = 0;
    bool ok4 = dumpTcpStatsByFamilyAndInterface(sock, AF_INET, -1, so4, si4, r4);
    bool ok6 = dumpTcpStatsByFamilyAndInterface(sock, AF_INET6, -1, so6, si6, r6);

    sock->close();
    if (!(ok4 || ok6))
        return false;

    outStats.retransSegs = r4 + r6; // 总重传段数
    outStats.outSegs = so4 + so6;   // 总发送段数（近似）
    outStats.inSegs = si4 + si6;    // 总接收段数（近似）
    outStats.valid = true;          // 标记数据有效

    return true;
}

bool TcpLossMonitor::sampleForInterface(const std::string &ifaceName, TcpStats &outStats)
{
    uint64_t so = 0, si = 0, r = 0;
    // 获取指定网卡的TCP统计
    if (!sampleTcpStatsForInterface(ifaceName, so, si, r))
        return false;
    // 填充网卡级TCP统计数据
    outStats.outSegs = so;    // 发送段数（近似）
    outStats.inSegs = si;     // 接收段数（近似）
    outStats.retransSegs = r; // 重传段数
    outStats.valid = true;    // 标记数据有效

    return true;
}

TcpLossResult TcpLossMonitor::compute(const TcpStats &prev, const TcpStats &curr, uint64_t minSent,
                                      double degradedThresholdPct, double poorThresholdPct)
{
    TcpLossResult r; // 初始化丢包计算结果

    if (!prev.valid || !curr.valid) {
        r.level = TcpLossLevel::Insufficient; // 数据无效
        return r;
    }

    // 检查统计数据是否重置或溢出（curr < prev，通常因系统重启或计数器溢出）
    if (curr.outSegs < prev.outSegs || curr.retransSegs < prev.retransSegs) {
        r.level = TcpLossLevel::Insufficient; // 数据无效
        return r;
    }

    // 计算发送段数增量和重传段数增量
    uint64_t deltaOut = curr.outSegs - prev.outSegs;             // 发送增量
    uint64_t deltaRetrans = curr.retransSegs - prev.retransSegs; // 重传增量

    // 填充结果中的增量信息
    r.sentDelta = deltaOut;
    r.retransDelta = deltaRetrans;

    // 检查发送增量是否达到最小阈值（避免小数据量导致的计算误差）
    if (deltaOut < minSent) {
        r.level = TcpLossLevel::Insufficient; // 数据量不足
        return r;
    }

    // 计算丢包率（百分比）：(重传增量 / 发送增量) * 100
    r.ratePercent = (deltaRetrans * 100.0) / (double)deltaOut;

    // 根据丢包率阈值划分丢包等级
    if (r.ratePercent >= poorThresholdPct) {
        r.level = TcpLossLevel::Poor; // 严重丢包
    } else if (r.ratePercent >= degradedThresholdPct) {
        r.level = TcpLossLevel::Degraded; // 轻度丢包
    } else {
        r.level = TcpLossLevel::Good; // 无明显丢包
    }

    return r;
}

bool TcpLossMonitor::dumpTcpStatsByFamilyAndInterface(base::Socket::ptr nlSock, int family,
                                                      int filterIfindex, uint64_t &segsOutApprox,
                                                      uint64_t &segsInApprox,
                                                      uint64_t &totalRetrans)
{
    segsOutApprox = segsInApprox = totalRetrans = 0;
    // 定义Netlink请求消息结构体：采用匿名结构体封装消息头和诊断请求
    // 这种设计可以确保内存布局的正确性，方便直接通过sendmsg发送
    struct {
        nlmsghdr nlh;         // Netlink消息通用头，定义消息类型、长度和标志等
        inet_diag_req_v2 req; // TCP socket诊断请求（v2版本），包含协议族和诊断参数
    } msg{};

    // 填充Netlink消息头，设置消息基本属性
    msg.nlh.nlmsg_len = sizeof(msg);                  // 消息总长度（头+请求体）
    msg.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;         // 消息类型：按协议族诊断socket
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; // 标志：请求操作 + 批量获取（dump）
    msg.nlh.nlmsg_seq = 1; // 消息序列号（用于匹配请求与响应）
    msg.nlh.nlmsg_pid = 0; // 发送进程PID（0表示内核）

    // 填充TCP诊断请求体，指定需要查询的协议细节
    msg.req.sdiag_family =
        static_cast<uint8_t>(family); // 目标协议族（IPv4/IPv6），使用static_cast进行类型安全转换
    msg.req.sdiag_protocol = IPPROTO_TCP; // 目标协议：TCP
    msg.req.idiag_states = 0xFFFFFFFFu; // 监控所有TCP状态（ESTABLISHED、LISTEN、TIME_WAIT等）
    msg.req.idiag_ext = (1 << (INET_DIAG_INFO - 1)); // 请求扩展信息：需要tcp_info结构体

    iovec iov{};
    iov.iov_base = &msg;       // 缓冲区起始地址（请求消息）
    iov.iov_len = sizeof(msg); // 缓冲区长度
    base::Address::ptr addr = base::NetlinkAddress::Create();
    if (nlSock->sendTo(&iov, 1, addr, 0) < 0) {
        LOG_ERROR_F(LogModule::TCP_LOSS, "sendTo failed, errno %d, strerror=%s", errno,
                    strerror(errno));
        return false;
    }

    std::vector<char> buf(256 * 1024);

    while (true) {
        iovec riov{buf.data(), buf.size()};
        ssize_t len = nlSock->recvFrom(&riov, 1, addr);
        if (len < 0) {
            if (errno == EINTR)
                continue;
            LOG_ERROR_F(LogModule::TCP_LOSS, "recvFrom failed, errno %d, strerror=%s", errno,
                        strerror(errno));
            return false;
        }
        if (len == 0)
            break;

        // 遍历Netlink消息列表（响应可能包含多个消息块）
        // 使用NLMSG_OK和NLMSG_NEXT宏安全地遍历消息链
        for (nlmsghdr *h = reinterpret_cast<nlmsghdr *>(buf.data());
             NLMSG_OK(h, (unsigned)len); // 检查消息有效性（长度是否合法）
             h = NLMSG_NEXT(h, len)) {   // 移动到下一个消息

            // 消息类型判断和处理
            if (h->nlmsg_type == NLMSG_DONE)
                return true;
            if (h->nlmsg_type == NLMSG_ERROR)
                return false;
            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY)
                continue;

            // 解析TCP socket诊断消息体（inet_diag_msg）
            // NLMSG_DATA宏用于获取消息头之后的实际数据部分
            inet_diag_msg *im = reinterpret_cast<inet_diag_msg *>(NLMSG_DATA(h));

            // 按网卡索引过滤：仅处理绑定到目标网卡的socket
            // 如果filterIfindex <= 0，则不过滤网卡
            if (filterIfindex > 0 && im->id.idiag_if != static_cast<uint32_t>(filterIfindex)) {
                continue;
            }

            // 计算扩展属性的总长度
            int rtalen =
                h->nlmsg_len - NLMSG_LENGTH(sizeof(*im)); // NLMSG_LENGTH返回包含填充的头长度

            // 遍历所有扩展属性（使用RTA_OK和RTA_NEXT宏安全遍历）
            // NLMSG_ALIGN确保内存对齐
            for (rtattr *attr = (rtattr *)(((char *)im) + NLMSG_ALIGN(sizeof(*im)));
                 RTA_OK(attr, rtalen);            // 检查属性有效性
                 attr = RTA_NEXT(attr, rtalen)) { // 移动到下一个属性

                LOG_INFO(LogModule::TCP_LOSS, "rta_type=" << attr->rta_type);

                // 找到包含tcp_info的属性（INET_DIAG_INFO）
                if (attr->rta_type == INET_DIAG_INFO) {
                    // 解析tcp_info结构体（包含TCP连接的详细统计信息）
                    // RTA_DATA宏获取属性值的起始地址
                    tcp_info *ti = reinterpret_cast<tcp_info *>(RTA_DATA(attr));

                    // 累加总重传次数，这是计算丢包率的关键指标
                    totalRetrans += ti->tcpi_total_retrans;

                    // 近似计算发送段数：由于无法直接获取tcpi_segs_out，
                    // 采用未确认段数+已重传段数+已SACK段数的总和作为估算值
                    segsOutApprox += static_cast<uint64_t>(ti->tcpi_unacked)
                                     + static_cast<uint64_t>(ti->tcpi_retrans)
                                     + static_cast<uint64_t>(ti->tcpi_sacked);
                }
            }
        }
    }
    return true;
}

bool TcpLossMonitor::sampleTcpStatsForInterface(const std::string &iface, uint64_t &segsOutApprox,
                                                uint64_t &segsInApprox, uint64_t &totalRetrans)
{
    segsOutApprox = segsInApprox = totalRetrans = 0;
    int ifidx = ifnameToIndex(iface);
    if (ifidx <= 0)
        return false; // 网卡不存在或转换失败

    // 创建Netlink SOCK_DIAG socket（用于获取TCP socket诊断信息）
    auto nl = base::Socket::CreateNetlinkSockDiagSocket();
    if (!nl)
        return false; // socket创建失败

    // 分别获取IPv4和IPv6的TCP统计数据
    uint64_t so4 = 0, si4 = 0, r4 = 0; // IPv4统计：发送段、接收段、重传段
    uint64_t so6 = 0, si6 = 0, r6 = 0; // IPv6统计：发送段、接收段、重传段
    bool ok4 = dumpTcpStatsByFamilyAndInterface(nl, AF_INET, ifidx, so4, si4, r4); // 获取IPv4数据
    bool ok6 = dumpTcpStatsByFamilyAndInterface(nl, AF_INET6, ifidx, so6, si6, r6); // 获取IPv6数据
    LOG_INFO(LogModule::TCP_LOSS, "TCP stats for iface "
                                      << iface << "  IPV4 ok= " << ok4 << ", so=" << so4
                                      << ", si=" << si4 << ", r=" << r4 << ", IPV6 ok=" << ok6
                                      << ", so=" << so6 << ", si=" << si6 << ", r=" << r6);
    nl->close();

    // 若IPv4和IPv6数据均获取失败，返回整体失败
    if (!(ok4 || ok6))
        return false;

    // 汇总IPv4和IPv6的统计数据
    segsOutApprox = so4 + so6; // 总发送段数（近似）
    segsInApprox = si4 + si6;  // 总接收段数（近似，当前为0）
    totalRetrans = r4 + r6;    // 总重传段数

    // 异常处理：若TCP发送段数估算为0，用L2层发送数据包数补充（避免后续计算分母为0）
    if (segsOutApprox == 0) {
        uint64_t txp = 0;
        if (getInterfaceTxPackets(ifidx, txp)) {
            segsOutApprox = txp; // 用L2层发送包数作为发送段数近似值
        }
    }

    return true;
}

bool TcpLossMonitor::getInterfaceTxPackets(int ifindex, uint64_t &txPackets)
{
    txPackets = 0;
    base::Socket::ptr nl = base::Socket::CreateNetlinkRouteSocket();
    if (_UNLIKELY(!nl))
        return false;

    // 定义Netlink请求消息：获取网卡链接信息（RTM_GETLINK）
    struct {
        nlmsghdr nlh;  // Netlink消息头
        ifinfomsg ifm; // 网卡信息请求体
    } req{};           // 初始化所有成员为0

    // 填充消息头
    req.nlh.nlmsg_len = sizeof(req);                 // 消息总长度
    req.nlh.nlmsg_type = RTM_GETLINK;                // 消息类型：获取网卡链接信息
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK; // 标志：请求操作 + 要求响应确认
    req.ifm.ifi_family = AF_UNSPEC;                  // 不限制地址族（IPv4/IPv6通用）
    req.ifm.ifi_index = ifindex;                     // 目标网卡索引

    // 配置Netlink地址和IO向量（同diagDumpFamilyIface）
    auto nladdr = base::NetlinkAddress::Create();
    iovec iov{&req, sizeof(req)};

    if (nl->sendTo(&iov, 1, nladdr, 0) < 0) {
        nl->close();
        return false;
    }

    std::vector<char> buf(16 * 1024);
    iov = {buf.data(), buf.size()};

    ssize_t len = nl->recvFrom(&iov, 1, nladdr, 0);
    nl->close();
    if (len < 0) {
        return false;
    }
    // 遍历Netlink响应消息
    for (nlmsghdr *h = reinterpret_cast<nlmsghdr *>(buf.data()); NLMSG_OK(h, (unsigned)len);
         h = NLMSG_NEXT(h, len)) {

        if (h->nlmsg_type == NLMSG_ERROR)
            return false; // 消息错误
        if (h->nlmsg_type != RTM_NEWLINK)
            continue; // 非网卡信息消息，跳过

        // 解析网卡信息结构体（ifinfomsg）
        ifinfomsg *ifm = reinterpret_cast<ifinfomsg *>(NLMSG_DATA(h));
        // 过滤目标网卡（避免响应中包含其他网卡信息）
        if ((int)ifm->ifi_index != ifindex)
            continue;

        // 解析网卡扩展属性（统计信息在扩展属性中）
        int attrlen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifm));
        for (rtattr *attr = IFLA_RTA(ifm); // 获取属性起始地址（IFLA_RTA为宏定义）
             RTA_OK(attr, attrlen); attr = RTA_NEXT(attr, attrlen)) {

            // 情况1：64位统计结构（IFLA_STATS64），优先使用（避免32位溢出）
            if (attr->rta_type == IFLA_STATS64) {
                // 定义64位统计结构体（仅包含需要的tx_packets字段）
                struct rtnl_link_stats64 {
                    uint64_t rx_packets, tx_packets, rx_bytes, tx_bytes;
                };
                // 检查属性长度是否足够存储结构体
                if (RTA_PAYLOAD(attr) >= sizeof(rtnl_link_stats64)) {
                    auto *st = reinterpret_cast<const rtnl_link_stats64 *>(RTA_DATA(attr));
                    txPackets = st->tx_packets; // 提取发送数据包数
                    return true;
                }
            }
            // 情况2：32位统计结构（IFLA_STATS），兼容旧内核
            else if (attr->rta_type == IFLA_STATS) {
                // 定义32位统计结构体（仅包含需要的tx_packets字段）
                struct rtnl_link_stats {
                    uint32_t rx_packets, tx_packets;
                };
                if (RTA_PAYLOAD(attr) >= sizeof(rtnl_link_stats)) {
                    auto *st = reinterpret_cast<const rtnl_link_stats *>(RTA_DATA(attr));
                    txPackets = st->tx_packets; // 转换为64位存储
                    return true;
                }
            }
        }
    }
    return false;
}

} // namespace monitor::weaknet