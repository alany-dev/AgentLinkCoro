#pragma once
#include <memory>
#include "address.h"
#include "base/coro/iomanager.h"
#include "socket.h"
#include "base/noncopyable.h"
#include "base/conf/config.h"
#include "base/mbuffer.h"

namespace base
{

struct UdpClientConf {
    typedef std::shared_ptr<UdpClientConf> ptr;

    std::string address;
    int timeout = 1000 * 2 * 60;
    std::string id;
    std::string type = "udp";
    std::string name;
    std::string io_worker;
    std::map<std::string, std::string> args;

    bool isValid() const { return !address.empty(); }

    bool operator==(const UdpClientConf &oth) const
    {
        return address == oth.address && timeout == oth.timeout && name == oth.name && id == oth.id
               && type == oth.type && io_worker == oth.io_worker && args == oth.args;
    }
};

template <>
class LexicalCast<std::string, UdpClientConf>
{
public:
    UdpClientConf operator()(const std::string &v)
    {
        YAML::Node node = YAML::Load(v);
        UdpClientConf conf;
        conf.id = node["id"].as<std::string>(conf.id);
        conf.type = node["type"].as<std::string>(conf.type);
        conf.timeout = node["timeout"].as<int>(conf.timeout);
        conf.name = node["name"].as<std::string>(conf.name);
        conf.io_worker = node["io_worker"].as<std::string>();
        conf.args = LexicalCast<std::string, std::map<std::string, std::string> >()(
            node["args"].as<std::string>(""));
        if (node["address"].IsDefined()) {
            conf.address = node["address"].as<std::string>();
        }
        return conf;
    }
};

template <>
class LexicalCast<UdpClientConf, std::string>
{
public:
    std::string operator()(const UdpClientConf &conf)
    {
        YAML::Node node;
        node["id"] = conf.id;
        node["type"] = conf.type;
        node["name"] = conf.name;
        node["timeout"] = conf.timeout;
        node["io_worker"] = conf.io_worker;
        node["args"] = 
            YAML::Load(LexicalCast<std::map<std::string, std::string>, std::string>()(conf.args));
        node["address"] = conf.address;
        std::stringstream ss;
        ss << node;
        return ss.str();
    }
};

/**
 * @brief UDP客户端封装
 */
class UdpClient : public std::enable_shared_from_this<UdpClient>, Noncopyable
{
public:
    typedef std::shared_ptr<UdpClient> ptr;
    /**
     * @brief 构造函数
     * @param[in] worker socket客户端工作的协程调度器
     * @param[in] io_worker 客户端socket执行IO操作的协程调度器
     */
    UdpClient(base::IOManager *worker = base::IOManager::GetThis(),
              base::IOManager *io_worker = base::IOManager::GetThis());

    /**
     * @brief 析构函数
     */
    virtual ~UdpClient();

    /**
     * @brief 连接到服务器
     * @param[in] addr 服务器地址
     * @return 返回是否连接成功
     */
    virtual bool connect(base::Address::ptr addr);

    /**
     * @brief 发送数据
     * @param[in] buffer 数据缓冲区
     * @param[in] size 数据大小
     * @return 返回发送的字节数
     */
    virtual int send(const void *buffer, size_t size);

    /**
     * @brief 发送数据
     * @param[in] buffer 数据缓冲区
     * @return 返回发送的字节数
     */
    virtual int send(MBuffer::ptr buffer);

    /**
     * @brief 接收数据
     * @param[out] buffer 数据缓冲区
     * @param[in] size 数据大小
     * @return 返回接收的字节数
     */
    virtual int recv(void *buffer, size_t size);

    /**
     * @brief 接收数据
     * @param[out] buffer 数据缓冲区
     * @return 返回接收的字节数
     */
    virtual int recv(MBuffer::ptr buffer, size_t size);

    /**
     * @brief 关闭连接
     */
    virtual void close();

    /**
     * @brief 返回读取超时时间(毫秒)
     */
    uint64_t getRecvTimeout() const { return m_recvTimeout; }

    /**
     * @brief 返回客户端名称
     */
    std::string getName() const { return m_name; }

    /**
     * @brief 设置读取超时时间(毫秒)
     */
    void setRecvTimeout(uint64_t v) { m_recvTimeout = v; }

    /**
     * @brief 设置客户端名称
     */
    virtual void setName(const std::string &v) { m_name = v; }

    /**
     * @brief 是否连接
     */
    bool isConnected() const { return m_sock && m_sock->isConnected(); }

    UdpClientConf::ptr getConf() const { return m_conf; }
    void setConf(UdpClientConf::ptr v) { m_conf = v; }
    void setConf(const UdpClientConf &v);

    virtual std::string toString(const std::string &prefix = "");

    Socket::ptr getSocket() const { return m_sock; }
    Address::ptr getRemoteAddress() const { return m_remoteAddr; }

protected:
    /**
     * @brief 处理UDP数据包
     * 具体实现，由子类继承重写。
     */
    virtual int handleData(MBuffer::ptr buffer);

    /**
     * @brief 开始接收数据
     */
    virtual void startRecv();

protected:
    /// 客户端Socket
    Socket::ptr m_sock;
    /// 远程地址
    Address::ptr m_remoteAddr;
    /// 工作的调度器
    IOManager *m_worker;
    /// IO操作的调度器
    IOManager *m_ioWorker;
    /// 接收超时时间(毫秒)
    uint64_t m_recvTimeout;
    /// 客户端名称
    std::string m_name;
    /// 客户端类型
    std::string m_type = "udp";
    /// 客户端是否停止
    bool m_isStop;

    UdpClientConf::ptr m_conf;
};

} // namespace base