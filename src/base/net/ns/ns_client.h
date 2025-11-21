#pragma once

#include "base/net/rock/rock_stream.h"
#include "ns_protocol.h"

namespace base
{
namespace ns
{

    /**
     * @brief 名称服务客户端类
     * 用于与名称服务器进行通信，管理查询域名列表并维护节点信息缓存
     */
    class NSClient : public RockConnection
    {
    public:
        typedef std::shared_ptr<NSClient> ptr;

        /**
         * @brief 构造函数
         * 初始化客户端，创建域名集合对象
         */
        NSClient();

        /**
         * @brief 析构函数
         * 清理资源
         */
        ~NSClient();

        /**
         * @brief 获取查询域名列表
         * @return 查询域名集合的常量引用
         */
        const std::set<std::string> &getQueryDomains();

        /**
         * @brief 设置查询域名列表
         * @param v 新的查询域名集合
         */
        void setQueryDomains(const std::set<std::string> &v);

        /**
         * @brief 添加查询域名
         * @param domain 要添加的域名
         */
        void addQueryDomain(const std::string &domain);

        /**
         * @brief 删除查询域名
         * @param domain 要删除的域名
         */
        void delQueryDomain(const std::string &domain);

        /**
         * @brief 检查是否包含指定查询域名
         * @param domain 要检查的域名
         * @return 如果包含返回true，否则返回false
         */
        bool hasQueryDomain(const std::string &domain);

        /**
         * @brief 查询节点信息
         * 向名称服务器发送查询请求，获取所有查询域名下的节点信息
         * @return 查询结果
         */
        RockResult::ptr query();

        /**
         * @brief 初始化客户端
         * 设置连接、断开连接和通知处理回调
         */
        void init();

        /**
         * @brief 反初始化客户端
         * 清除所有回调，取消定时器
         */
        void uninit();

        /**
         * @brief 获取域名集合
         * @return 域名集合的智能指针
         */
        NSDomainSet::ptr getDomains() const { return m_domains; }

    private:
        /**
         * @brief 查询域名变更处理
         * 当查询域名列表发生变化时调用，重新发起查询
         */
        void onQueryDomainChange();

        /**
         * @brief 连接建立回调
         * 当与名称服务器建立连接时调用
         * @param stream 建立的连接流
         * @return 处理结果
         */
        bool onConnect(base::AsyncSocketStream::ptr stream);

        /**
         * @brief 连接断开回调
         * 当与名称服务器断开连接时调用
         * @param stream 断开的连接流
         */
        void onDisconnect(base::AsyncSocketStream::ptr stream);

        /**
         * @brief 通知处理回调
         * 处理来自名称服务器的通知，如节点变更通知
         * @param notify 通知对象
         * @param stream 连接流
         * @return 处理结果
         */
        bool onNotify(base::RockNotify::ptr, base::RockStream::ptr);

        /**
         * @brief 定时器回调
         * 定期发送心跳并更新节点信息
         */
        void onTimer();

    private:
        base::RWMutex m_mutex;                // 读写锁，用于线程安全
        std::set<std::string> m_queryDomains; // 查询域名集合
        NSDomainSet::ptr m_domains;           // 域名信息缓存
        uint32_t m_sn = 0;                    // 请求序列号
        base::Timer::ptr m_timer;             // 定时器，用于心跳和更新
    };

} // namespace ns
} // namespace base