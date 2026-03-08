#pragma once
#include "base/net/udp_client.h"
#include "quic_session.h"
#include "base/mutex.h"

namespace base
{
namespace quic
{
    class QuicClient : public UdpClient
    {
    public:
        using ptr = std::shared_ptr<QuicClient>;
        using RWMutexType = RWSpinlock;

        QuicClient(base::IOManager *worker = base::IOManager::GetThis(), base::IOManager *io_worker = base::IOManager::GetThis());
        
        /**
         * @brief 连接到QUIC服务器
         * @param[in] addr 服务器地址
         * @return 返回是否连接成功
         */
        virtual bool connect(base::Address::ptr addr) override;
        
        /**
         * @brief 关闭连接
         */
        virtual void close() override;
        
        /**
         * @brief 获取当前会话
         * @return 会话智能指针
         */
        QuicSession::ptr getSession() const;
        
        /**
         * @brief 创建一个新的流
         * @return 流智能指针
         */
        QuicStream::ptr createStream();
        
    protected:
        /**
         * @brief 处理接收到的数据
         * @param[in] buffer 数据缓冲区
         * @return 处理结果
         */
        virtual int handleData(MBuffer::ptr buffer) override;
        
        /**
         * @brief 创建客户端会话
         * @return 会话智能指针
         */
        virtual QuicSession::ptr createSession();
        
    private:
        /**
         * @brief 生成客户端连接ID
         * @return 连接ID智能指针
         */
        QuicConnectionId::ptr generateConnectionId();
        
    private:
        QuicSession::ptr m_session;         // 当前会话
        mutable RWMutexType m_mutex;        // 读写锁
        QuicConnectionId::ptr m_cid;        // 客户端连接ID
    };

} // namespace quic
} // namespace base