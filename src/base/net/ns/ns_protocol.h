#pragma once

#include <memory>
#include <string>
#include <map>
#include <iostream>
#include <stdint.h>
#include "base/mutex.h"
#include "ns_protobuf.pb.h"

namespace base
{
namespace ns
{

    /**
     * @brief 名称服务命令枚举
     * 定义了名称服务系统中支持的各种命令类型
     */
    enum class NSCommand {
        /// 注册节点信息命令，服务节点向名称服务器注册自身信息
        REGISTER = 0x10001,
        /// 查询节点信息命令，客户端向名称服务器查询某个域名下的节点信息
        QUERY = 0x10002,
        /// 设置黑名单命令，设置节点黑名单
        SET_BLACKLIST = 0x10003,
        /// 查询黑名单命令，查询节点黑名单
        QUERY_BLACKLIST = 0x10004,
        /// 心跳命令，保持连接活跃
        TICK = 0x10005,
    };

    /**
     * @brief 名称服务通知枚举
     * 定义了名称服务系统中支持的各种通知类型
     */
    enum class NSNotify {
        /// 节点变更通知，当节点信息发生变化时发送
        NODE_CHANGE = 0x10001,
    };

    /**
     * @brief 名称服务节点类
     * 表示一个注册到名称服务的服务节点，包含节点的IP、端口和权重信息
     */
    class NSNode
    {
    public:
        typedef std::shared_ptr<NSNode> ptr;

        /**
         * @brief 构造函数
         * @param ip 节点IP地址
         * @param port 节点端口号
         * @param weight 节点权重，用于负载均衡
         */
        NSNode(const std::string &ip, uint16_t port, uint32_t weight);

        /**
         * @brief 获取节点IP地址
         * @return 节点IP地址
         */
        const std::string &getIp() const { return m_ip; }

        /**
         * @brief 获取节点端口号
         * @return 节点端口号
         */
        uint16_t getPort() const { return m_port; }

        /**
         * @brief 获取节点权重
         * @return 节点权重
         */
        uint32_t getWeight() const { return m_weight; }

        /**
         * @brief 设置节点权重
         * @param v 新的权重值
         */
        void setWeight(uint32_t v) { m_weight = v; }

        /**
         * @brief 获取节点唯一标识
         * @return 节点ID
         */
        uint64_t getId() const { return m_id; }

        /**
         * @brief 根据IP和端口生成节点ID
         * @param ip 节点IP地址
         * @param port 节点端口号
         * @return 生成的节点ID
         */
        static uint64_t GetID(const std::string &ip, uint16_t port);

        /**
         * @brief 将节点信息输出到流中
         * @param os 输出流
         * @param prefix 前缀字符串
         * @return 输出流
         */
        std::ostream &dump(std::ostream &os, const std::string &prefix = "");

        /**
         * @brief 将节点信息转换为字符串
         * @param prefix 前缀字符串
         * @return 节点信息字符串
         */
        std::string toString(const std::string &prefix = "");

    private:
        uint64_t m_id;     // 节点唯一标识，由IP和端口生成
        std::string m_ip;  // 节点IP地址
        uint16_t m_port;   // 节点端口号
        uint32_t m_weight; // 节点权重，用于负载均衡
    };

    /**
     * @brief 名称服务节点集合类
     * 表示同一命令下的一组服务节点，用于管理特定命令的所有节点
     */
    class NSNodeSet
    {
    public:
        typedef std::shared_ptr<NSNodeSet> ptr;

        /**
         * @brief 构造函数
         * @param cmd 命令标识
         */
        NSNodeSet(uint32_t cmd);

        /**
         * @brief 添加节点
         * @param info 节点信息
         */
        void add(NSNode::ptr info);

        /**
         * @brief 删除节点
         * @param id 节点ID
         * @return 被删除的节点信息，如果不存在则返回nullptr
         */
        NSNode::ptr del(uint64_t id);

        /**
         * @brief 获取节点
         * @param id 节点ID
         * @return 节点信息，如果不存在则返回nullptr
         */
        NSNode::ptr get(uint64_t id);

        /**
         * @brief 获取命令标识
         * @return 命令标识
         */
        uint32_t getCmd() const { return m_cmd; }

        /**
         * @brief 设置命令标识
         * @param v 新的命令标识
         */
        void setCmd(uint32_t v) { m_cmd = v; }

        /**
         * @brief 获取所有节点
         * @param infos 用于存储节点信息的向量
         */
        void listAll(std::vector<NSNode::ptr> &infos);

        /**
         * @brief 将节点集合信息输出到流中
         * @param os 输出流
         * @param prefix 前缀字符串
         * @return 输出流
         */
        std::ostream &dump(std::ostream &os, const std::string &prefix = "");

        /**
         * @brief 将节点集合信息转换为字符串
         * @param prefix 前缀字符串
         * @return 节点集合信息字符串
         */
        std::string toString(const std::string &prefix = "");

        /**
         * @brief 获取节点数量
         * @return 节点数量
         */
        size_t size();

    private:
        base::RWMutex m_mutex;                   // 读写锁，用于线程安全
        uint32_t m_cmd;                          // 命令标识
        std::map<uint64_t, NSNode::ptr> m_datas; // 节点ID到节点信息的映射
    };

    /**
     * @brief 名称服务域名类
     * 表示一个域名，包含该域名下所有命令的节点集合
     */
    class NSDomain
    {
    public:
        typedef std::shared_ptr<NSDomain> ptr;

        /**
         * @brief 构造函数
         * @param domain 域名
         */
        NSDomain(const std::string &domain) : m_domain(domain) {}

        /**
         * @brief 获取域名
         * @return 域名
         */
        const std::string &getDomain() const { return m_domain; }

        /**
         * @brief 设置域名
         * @param v 新的域名
         */
        void setDomain(const std::string &v) { m_domain = v; }

        /**
         * @brief 添加节点集合
         * @param info 节点集合信息
         */
        void add(NSNodeSet::ptr info);

        /**
         * @brief 向指定命令添加节点
         * @param cmd 命令标识
         * @param info 节点信息
         */
        void add(uint32_t cmd, NSNode::ptr info);

        /**
         * @brief 删除指定命令的所有节点
         * @param cmd 命令标识
         */
        void del(uint32_t cmd);

        /**
         * @brief 删除指定命令下的指定节点
         * @param cmd 命令标识
         * @param id 节点ID
         * @return 被删除的节点信息，如果不存在则返回nullptr
         */
        NSNode::ptr del(uint32_t cmd, uint64_t id);

        /**
         * @brief 获取指定命令的节点集合
         * @param cmd 命令标识
         * @return 节点集合信息，如果不存在则返回nullptr
         */
        NSNodeSet::ptr get(uint32_t cmd);

        /**
         * @brief 获取所有节点集合
         * @param infos 用于存储节点集合信息的向量
         */
        /**
         * @brief 获取所有节点集合
         * @param infos 用于存储节点集合信息的向量
         */
        void listAll(std::vector<NSNodeSet::ptr> &infos);

        /**
         * @brief 将域名信息输出到流中
         * @param os 输出流
         * @param prefix 前缀字符串
         * @return 输出流
         */
        std::ostream &dump(std::ostream &os, const std::string &prefix = "");

        /**
         * @brief 将域名信息转换为字符串
         * @param prefix 前缀字符串
         * @return 域名信息字符串
         */
        std::string toString(const std::string &prefix = "");

        /**
         * @brief 获取节点集合数量
         * @return 节点集合数量
         */
        size_t size();

    private:
        std::string m_domain;                       // 域名
        base::RWMutex m_mutex;                      // 读写锁，用于线程安全
        std::map<uint32_t, NSNodeSet::ptr> m_datas; // 命令标识到节点集合信息的映射
    };

    /**
     * @brief 名称服务域名集合类
     * 管理所有域名信息，是名称服务数据的顶层容器
     */
    class NSDomainSet
    {
    public:
        typedef std::shared_ptr<NSDomainSet> ptr;

        /**
         * @brief 添加域名
         * @param info 域名信息
         */
        void add(NSDomain::ptr info);

        /**
         * @brief 删除域名
         * @param domain 域名
         */
        void del(const std::string &domain);

        /**
         * @brief 获取域名信息
         * @param domain 域名
         * @param auto_create 如果为true且域名不存在，则自动创建
         * @return 域名信息
         */
        NSDomain::ptr get(const std::string &domain, bool auto_create = false);

        /**
         * @brief 删除指定域名下指定命令的指定节点
         * @param domain 域名
         * @param cmd 命令标识
         * @param id 节点ID
         */
        void del(const std::string &domain, uint32_t cmd, uint64_t id);

        /**
         * @brief 获取所有域名信息
         * @param infos 用于存储域名信息的向量
         */
        void listAll(std::vector<NSDomain::ptr> &infos);

        /**
         * @brief 将域名集合信息输出到流中
         * @param os 输出流
         * @param prefix 前缀字符串
         * @return 输出流
         */
        std::ostream &dump(std::ostream &os, const std::string &prefix = "");

        /**
         * @brief 将域名集合信息转换为字符串
         * @param prefix 前缀字符串
         * @return 域名集合信息字符串
         */
        std::string toString(const std::string &prefix = "");

        /**
         * @brief 交换两个域名集合的数据
         * @param ds 另一个域名集合
         */
        void swap(NSDomainSet &ds);

    private:
        base::RWMutex m_mutex;                        // 读写锁，用于线程安全
        std::map<std::string, NSDomain::ptr> m_datas; // 域名到域名信息的映射
    };

} // namespace ns
} // namespace base