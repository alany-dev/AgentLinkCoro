#pragma once

#include "base/noncopyable.h"
#include "base/singleton.h"
#include "base/net/socket.h"
#include "net_info.hpp"
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>

namespace monitor::weaknet
{
enum UsingMethodFlag : uint8_t {
    None = 0x0,
    IPv4Default = 0x1,
    IPv6Default = 0x2,
};

class NetInterfaceManager
{
public:
    using ptr = std::shared_ptr<NetInterfaceManager>;
    NetInterfaceManager();
    ~NetInterfaceManager();

    /**
     * @brief 收集具备互联网连接能力的网络接口列表
     *
     * 该方法执行以下步骤：
     * 1. 打开 Netlink socket
     * 2. 请求网络接口信息转储
     * 3. 请求 IPv4 路由表信息转储
     * 4. 请求 IPv6 路由表信息转储
     * 5. 更新 managedIfaces_ 集合，包含 up ∩ (v4默认网关 ∪ v6默认网关)
     * 6. 遍历 managedIfaces_ 集合，根据 methodFlags_ 确定使用的网络连接方式：
     *    - 如果 methodFlags_ 包含 IPv4Default，则使用 IPv4 连接
     *    - 如果 methodFlags_ 包含 IPv6Default，则使用 IPv6 连接
     *    - 如果 methodFlags_ 同时包含 IPv4Default 和 IPv6Default，则使用 IPv4 和 IPv6 连接
     * 7. 关闭 socket 并返回结果
     *
     * @return std::vector<std::string> 具备互联网连接能力的网络接口名称列表
     */
    std::vector<std::string> collect();

    std::string getCurrentIfName() const { return currentIfName_; }
    UsingMethodFlag getUsingMethod() const { return methodFlags_; }
    NetType getIfaceType(std::string ifname) const
    {
        auto it = ifnameToType_.find(ifname);
        return (it != ifnameToType_.end()) ? it->second : NetType::Unknown;
    }

private:
    base::Socket::ptr nlSocket_;
    base::NetlinkAddress::ptr nlAddress_;
    std::unordered_map<int, std::string> ifindexToName_;        // 接口索引到名称的映射
    std::unordered_map<std::string, NetType> ifnameToType_; // 接口名称到类型的映射
    std::unordered_set<int> upInterfaces_;         // 状态为 UP 的接口索引集合
    std::unordered_set<int> defaultRouteIfacesV4_; // 有 IPv4 默认路由的接口索引集合
    std::unordered_set<int> defaultRouteIfacesV6_; // 有 IPv6 默认路由的接口索引集合
    std::unordered_set<int> managedIfaces_; // 管理的接口集合：up ∩ (v4默认网关 ∪ v6默认网关)
    std::string currentIfName_;                           // 当前正在处理的接口名称
    UsingMethodFlag methodFlags_ = UsingMethodFlag::None; // 当前使用的网络连接方式

    /**
     * @brief 打开并配置 Netlink socket
     *
     * 创建 AF_NETLINK 类型的原始套接字，设置组播组以接收链路、IPv4 和 IPv6 路由事件，
     * 并将 socket 设置为非阻塞模式。
     *
     * @throws std::runtime_error 如果 socket 创建或绑定失败
     */
    void openSocket();

    /**
     * @brief 发送 Netlink 请求消息
     *
     * 构造并发送通用的 Netlink 请求消息，用于获取链路或路由信息。
     *
     * @param nlmsgType 消息类型（如 RTM_GETLINK、RTM_GETROUTE）
     * @param flags 消息标志（如 NLM_F_DUMP）
     * @param family 地址族（如 AF_PACKET、AF_INET、AF_INET6）
     * @throws std::runtime_error 如果消息发送失败
     */
    void sendNetlinkRequest(uint16_t nlmsgType, uint16_t flags, uint8_t family);

    /**
     * @brief 请求网络接口信息转储
     *
     * 调用 sendNetlinkRequest 获取所有网络接口的详细信息。
     */
    void sendGetLinkDump() { sendNetlinkRequest(RTM_GETLINK, NLM_F_DUMP, AF_PACKET); }

    /**
     * @brief 请求指定地址族的路由表信息转储
     *
     * 调用 sendNetlinkRequest 获取指定地址族（IPv4 或 IPv6）的路由表信息。
     *
     * @param family 地址族（AF_INET 或 AF_INET6）
     */
    void sendGetRouteDump(int family)
    {
        sendNetlinkRequest(RTM_GETROUTE, NLM_F_DUMP, static_cast<uint8_t>(family));
    }

    /**
     * @brief 接收并处理 Netlink 消息转储
     *
     * 从 Netlink socket 接收数据，解析消息，并将其分发给相应的处理函数。
     * 处理 EAGAIN 错误以适应非阻塞 socket，并在收到 NLMSG_DONE 时停止接收。
     *
     * @throws std::runtime_error 如果 recvmsg 失败
     */
    void receiveDump();

    /**
     * @brief 根据消息类型分发 Netlink 消息到相应的处理函数
     *
     * 根据消息类型（如链路消息、路由消息）将 Netlink 消息转发给对应的处理函数。
     *
     * @param hdr Netlink 消息头部指针
     */
    void dispatchNetlinkMessage(struct nlmsghdr *hdr);

    /**
     * @brief 处理网络接口信息消息
     *
     * 解析网络接口的基本信息和属性，如接口名称、状态等，并更新内部状态。
     *
     * @param info 接口信息结构体指针
     * @param attrHead 属性数据头部指针
     * @param attrLen 属性数据长度
     */
    void handleLink(ifinfomsg *info, void *attrHead, int attrLen);

    /**
     * @brief 判断给定的路由是否为默认路由
     *
     * 默认路由的判定条件:
     * 1. 目标网络长度为0 (rtm_dst_len == 0)
     * 2. 路由表为以下之一:
     *    - RT_TABLE_MAIN: 主路由表
     *    - RT_TABLE_DEFAULT: 默认路由表
     *    - RT_TABLE_UNSPEC: 未指定路由表
     * 3. 路由作用域为以下之一:
     *    - RT_SCOPE_UNIVERSE: 全局路由
     *    - RT_SCOPE_NOWHERE: 目标不存在(特殊情况下也视为默认路由)
     *    - RT_SCOPE_SITE: 本地自治系统内部路由
     *
     * @param rtm 指向路由消息结构的指针
     * @return bool 如果是默认路由返回true，否则返回false
     */
    static bool isDefaultRoute(const rtmsg *rtm)
    {
        return rtm->rtm_dst_len == 0
               && (rtm->rtm_table == RT_TABLE_MAIN || rtm->rtm_table == RT_TABLE_DEFAULT
                   || rtm->rtm_table == RT_TABLE_UNSPEC)
               && (rtm->rtm_scope == RT_SCOPE_UNIVERSE || rtm->rtm_scope == RT_SCOPE_NOWHERE
                   || rtm->rtm_scope == RT_SCOPE_SITE);
    }

    /**
     * @brief 处理路由信息消息
     *
     * 解析路由信息，判断是否为默认路由，并更新对应的接口集合。
     *
     * @param rtm 路由消息结构体指针
     * @param attrHead 属性数据头部指针
     * @param attrLen 属性数据长度
     * @param nlmsgType 消息类型（RTM_NEWROUTE 或 RTM_DELROUTE）
     */
    void handleRoute(rtmsg *rtm, void *attrHead, int attrLen, int nlmsgType);

    /**
     * @brief 重新计算具备互联网连接能力的接口集合
     *
     * 根据当前的接口状态和路由信息，重新计算哪些接口具备互联网连接能力（UP 且有默认路由）。
     */
    void updateManagedIfaces()
    {
        std::unordered_set<int> newManaged;
        for (int ifindex : upInterfaces_) {
            if (defaultRouteIfacesV4_.count(ifindex) || defaultRouteIfacesV6_.count(ifindex)) {
                newManaged.insert(ifindex);
            }
        }
        managedIfaces_.swap(newManaged);
    }

    void updateCurrentIfName()
    {
        int chosen = -1;
        for (int idx : defaultRouteIfacesV4_) {
            if (upInterfaces_.count(idx)) {
                chosen = idx;
                methodFlags_ = UsingMethodFlag(methodFlags_ | IPv4Default);
                break;
            }
        }

        for (int idx : defaultRouteIfacesV6_) {
            if (upInterfaces_.count(idx)) {
                if (chosen == -1)
                    chosen = idx;
                methodFlags_ = UsingMethodFlag(methodFlags_ | IPv6Default);
                break;
            }
        }

        if (chosen != -1) {
            auto it = ifindexToName_.find(chosen);
            if (it != ifindexToName_.end())
                currentIfName_ = it->second;
            else
                currentIfName_ = std::string("ifindex=") + std::to_string(chosen);
        }
    }

    /**
     * @brief 获取具备互联网连接能力的接口名称列表
     *
     * 将内部存储的接口索引转换为对应的接口名称列表。
     *
     * @return std::vector<std::string> 接口名称列表
     */
    std::vector<std::string> namesOfManaged() const;
};

} // namespace monitor::weaknet