#include "net_iface.hpp"
#include "base/net/address.h"
#include "base/net/socket.h"
#include "logger.hpp"
#include <algorithm>
#include <net/if.h>
#include <stdexcept>
#include <vector>

namespace monitor::weaknet
{

/**
 * @brief 解析 Netlink 属性的模板函数
 *
 * 将 Netlink 消息中的属性数据解析并存储到指定的数组中，
 * 方便后续处理接口和路由信息。
 *
 * @tparam T 属性类型
 * @tparam N 数组大小
 * @param rta 指向属性数据的指针
 * @param len 属性数据长度
 * @param attrs 存储解析后属性的数组
 */
template <typename T, size_t N>
void parseRtAttributes(struct rtattr *rta, int len, T (&attrs)[N])
{
    // 初始化所有属性指针为 nullptr
    std::fill(std::begin(attrs), std::end(attrs), nullptr);

    // 遍历所有有效的属性
    while (RTA_OK(rta, len)) {
        // 仅存储类型在数组范围内的属性
        if (rta->rta_type < N) {
            attrs[rta->rta_type] = rta;
        }
        // 移动到下一个属性
        rta = RTA_NEXT(rta, len);
    }
}

NetInterfaceManager::NetInterfaceManager()
{
    openSocket();
}

NetInterfaceManager::~NetInterfaceManager()
{
    nlSocket_->close();
}

std::vector<std::string> NetInterfaceManager::collect()
{
    sendGetLinkDump();
    receiveDump();
    sendGetRouteDump(AF_INET);
    receiveDump();
    sendGetRouteDump(AF_INET6);
    receiveDump();
    updateManagedIfaces();
    updateCurrentIfName();
    return namesOfManaged();
}

void NetInterfaceManager::openSocket()
{
    nlSocket_ = base::Socket::CreateNetlinkRouteSocket();
    if (!nlSocket_) {
        LOG_ERROR_F(LogModule::INTERFACE, "socket AF_NETLINK failed errno=%d", errno);
    }
    nlAddress_ = base::NetlinkAddress::Create(RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE);
    if (!nlAddress_) {
        LOG_ERROR_F(LogModule::INTERFACE, "NetlinkAddress::Create failed errno=%d", errno);
    }
    if (!(nlSocket_->bind(nlAddress_))) {
        LOG_ERROR_F(LogModule::INTERFACE, "Bind failed errno=%d", errno);
    }
}

void NetInterfaceManager::sendNetlinkRequest(uint16_t nlmsgType, uint16_t flags, uint8_t family)
{
    struct {
        nlmsghdr nlh;
        rtgenmsg gen;
    } req{};

    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = nlmsgType;
    req.nlh.nlmsg_flags = flags | NLM_F_REQUEST;
    req.nlh.nlmsg_seq = static_cast<uint32_t>(::time(nullptr));
    req.nlh.nlmsg_pid = 0;
    req.gen.rtgen_family = family;

    struct iovec iov {
        &req, sizeof(req)
    };

    auto nladdr = base::NetlinkAddress::Create();

    ssize_t len = nlSocket_->sendTo(&iov, 1, nladdr);
    if (len < 0) {
        LOG_ERROR_F(LogModule::INTERFACE, "sendNetlinkRequest failed errno=%d", errno);
    }
}

void NetInterfaceManager::receiveDump()
{
    std::vector<char> buffer(64 * 1024);
    while (true) {
        auto nladdr = base::NetlinkAddress::Create();
        struct iovec iov {
            buffer.data(), buffer.size()
        };
        ssize_t len = nlSocket_->recvFrom(&iov, 1, nladdr);
        if (len < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            throw std::runtime_error("recvmsg 失败");
        }
        if (len == 0)
            break;

        for (nlmsghdr *hdr = reinterpret_cast<nlmsghdr *>(buffer.data());
             NLMSG_OK(hdr, static_cast<unsigned>(len)); hdr = NLMSG_NEXT(hdr, len)) {
            // NLMSG_DONE 就作为这一批消息的 “终止符”
            if (hdr->nlmsg_type == NLMSG_DONE)
                return;
            if (hdr->nlmsg_type == NLMSG_ERROR) {
                continue;
            }
            dispatchNetlinkMessage(hdr);
        }
    }
}

void NetInterfaceManager::dispatchNetlinkMessage(struct nlmsghdr *hdr)
{
    switch (hdr->nlmsg_type) {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            handleLink(reinterpret_cast<ifinfomsg *>(NLMSG_DATA(hdr)),
                       IFLA_RTA(reinterpret_cast<ifinfomsg *>(NLMSG_DATA(hdr))), IFLA_PAYLOAD(hdr));
            break;
        case RTM_NEWROUTE:
        case RTM_DELROUTE:
            handleRoute(reinterpret_cast<rtmsg *>(NLMSG_DATA(hdr)),
                        RTM_RTA(reinterpret_cast<rtmsg *>(NLMSG_DATA(hdr))), RTM_PAYLOAD(hdr),
                        hdr->nlmsg_type);
            break;
        default:
            break;
    }
}

void NetInterfaceManager::handleLink(ifinfomsg *info, void *attrHead, int attrLen)
{
    // 定义属性数组，用于存储解析后的接口属性（索引对应属性类型，如IFLA_IFNAME）
    // IFLA_MAX是接口属性类型的最大值，+1确保数组索引覆盖所有可能的属性类型
    struct rtattr *attrs[IFLA_MAX + 1];

    // 解析属性列表：将attrHead指向的rtattr数组按类型分类，存入attrs数组
    // 解析后可通过attrs[属性类型]快速访问对应属性（如attrs[IFLA_IFNAME]获取接口名称属性）
    parseRtAttributes(reinterpret_cast<struct rtattr *>(attrHead), attrLen, attrs);

    int ifindex = info->ifi_index;
    std::string ifname;

    if (attrs[IFLA_IFNAME]) {
        char name[IFNAMSIZ]{};
        // RTA_DATA(attr)：获取属性的具体数据部分（跳过rtattr头部）
        // 复制属性数据到name缓冲区，确保不越界
        std::snprintf(name, sizeof(name), "%s",
                      reinterpret_cast<char *>(RTA_DATA(attrs[IFLA_IFNAME])));
        ifname = name;
        // 更新"接口索引->名称"的映射（方便后续通过索引快速查名称）
        ifindexToName_[ifindex] = ifname;
    } else {
        auto it = ifindexToName_.find(ifindex);
        if (it != ifindexToName_.end()) {
            ifname = it->second;
        }
    }

    // 解析接口类型
    ifnameToType_[ifname] = NetTypefromString(info->ifi_type);

    // 判断是否为回环接口：检查接口标志（ifi_flags）是否包含IFF_LOOPBACK（回环标志）
    bool isLoopback = (info->ifi_flags & IFF_LOOPBACK) != 0;
    // 判断接口是否启用：检查接口标志是否包含IFF_UP（启用标志）
    bool isUp = (info->ifi_flags & IFF_UP) != 0;

    // 维护"已启用且非回环"的接口集合（upInterfaces_）
    if (isUp && !isLoopback) {
        // 接口启用且非回环，加入集合
        upInterfaces_.insert(ifindex);
    } else {
        // 接口未启用或为回环，从集合中移除
        upInterfaces_.erase(ifindex);
    }

    // 处理接口删除的场景（启发式判断）：
    // - ifi_change为~0U（全1）：表示接口所有标志已变更（通常是删除时的特征）
    // - ifi_flags为0：表示接口所有标志已清除（也可能是删除时的特征）
    if (info->ifi_change == ~0U || (info->ifi_flags == 0)) {
        // 清理该接口在默认路由中的关联记录（IPv4和IPv6）
        defaultRouteIfacesV4_.erase(ifindex); // 移除IPv4默认路由关联的该接口
        defaultRouteIfacesV6_.erase(ifindex); // 移除IPv6默认路由关联的该接口
    }

    (void)ifname;
}

void NetInterfaceManager::handleRoute(rtmsg *rtm, void *attrHead, int attrLen, int nlmsgType)
{
    // 定义数组用于存储解析后的路由属性，RTA_MAX是路由属性类型的最大值，+1避免越界
    struct rtattr *attrs[RTA_MAX + 1];
    // 解析路由属性：将原始属性数据(attrHead)按类型解析到attrs数组中，方便后续按属性类型获取数据
    parseRtAttributes(reinterpret_cast<struct rtattr *>(attrHead), attrLen, attrs);

    // 仅处理默认路由：如果当前路由不是默认路由，则直接返回，不做后续处理
    if (!isDefaultRoute(rtm)) {
        return;
    }

    // 初始化输出接口索引为无效值(-1)，标记是否存在网关为false
    int oif = -1; // oif: Output Interface，路由的输出接口索引
    bool hasGateway = false;

    // 若存在RTA_OIF属性（路由的输出接口属性），则提取接口索引
    // oif：输出接口索引
    if (attrs[RTA_OIF]) {
        // RTA_DATA(attrs[RTA_OIF])获取属性值的起始地址，转换为int*并解引用得到接口索引
        oif = *reinterpret_cast<int *>(RTA_DATA(attrs[RTA_OIF]));
    }
    // 若存在RTA_GATEWAY属性（路由的网关属性），则标记存在网关
    if (attrs[RTA_GATEWAY]) {
        hasGateway = true;
    }

    // 过滤无效的默认路由：若输出接口索引无效（<=0）或无网关，则视为无上网能力，不处理
    if (oif <= 0 || !hasGateway) {
        // 没有明确网关或未绑定有效接口的默认路由，不纳入管理
        return;
    }

    // 根据路由的地址族（IPv4/IPv6）选择对应的默认路由接口集合
    // defaultRouteIfacesV4_：存储IPv4默认路由对应的接口集合
    // defaultRouteIfacesV6_：存储IPv6默认路由对应的接口集合
    auto &targetSet = (rtm->rtm_family == AF_INET) ? defaultRouteIfacesV4_ : defaultRouteIfacesV6_;

    // 根据netlink消息类型更新接口集合
    if (nlmsgType == RTM_NEWROUTE) {
        // 新增路由：将输出接口添加到对应地址族的默认路由接口集合中
        targetSet.insert(oif);
    } else if (nlmsgType == RTM_DELROUTE) {
        // 删除路由：将输出接口从对应地址族的默认路由接口集合中移除
        targetSet.erase(oif);
    }

    // 抑制编译器关于未使用变量的警告（实际逻辑中已使用，此处可能为兼容旧版本或冗余代码）
    (void)nlmsgType;
    (void)rtm;
}

std::vector<std::string> NetInterfaceManager::namesOfManaged() const
{
    std::vector<std::string> names;
    names.reserve(managedIfaces_.size());
    for (int idx : managedIfaces_) {
        auto it = ifindexToName_.find(idx);
        if (it != ifindexToName_.end())
            names.push_back(it->second);
    }
    std::sort(names.begin(), names.end());
    return names;
}

} // namespace monitor::weaknet