#pragma once

#include <string>
#include <cstdint>
#include <memory>
#include <mutex>
#include <netinet/ip_icmp.h>

namespace monitor::weaknet
{
/**
 * @class NetPing
 * @brief ICMP Echo (Ping) 网络诊断工具类
 *
 * 该类提供了基于ICMP协议的网络连通性检测功能
 * 支持指定网络接口发送ping请求，并计算往返时间(RTT)。
 */
class NetPing
{
public:
    NetPing() = default;

    ~NetPing() = default;

    /**
     * @brief 执行ICMP Echo请求(ping)并返回往返时间
     *
     * 通过指定的网络接口向目标主机发送ICMP Echo请求，并等待回复，
     * 计算往返时间(RTT)。该函数创建原始套接字，绑定到指定接口，
     * 发送请求并等待回复，最后返回测量结果。
     *
     * @param[in] host
     * 目标主机地址，可以是域名(如"www.example.com")或IPv4地址字符串(如"192.168.1.1")
     * @param[in] ifaceName 网络接口名称，如"eth0"、"wlan0"等
     * @param[in] timeoutMs 等待回复的超时时间(毫秒)，默认1000ms
     * @return int 成功时返回RTT值(毫秒)；失败时返回负数错误码：
     *             -1: 原始套接字创建失败
     *             -2: 绑定到指定网络接口失败
     *             -3: 解析目标主机IPv4地址失败
     *             -4: 发送ICMP包失败
     *             -5: 等待回复超时
     *             -6: select函数调用错误
     *             -7: 接收回复数据包失败
     *             -8: 接收到的数据包不完整
     *             -9: 接收到的ICMP包不是目标回显应答
     */
    static int ping(const std::string &host, const std::string &ifaceName, int timeoutMs = 1000);

private:
    /**
     * @brief 计算16位校验和
     *
     * 用于计算ICMP数据包的校验和，确保数据传输完整性。
     * 采用标准的互联网校验和算法，将数据按16位累加并处理进位。
     *
     * @param[in] addr 指向待计算校验和的数据缓冲区
     * @param[in] len 数据长度(字节)
     * @return uint16_t 计算得到的16位校验和值
     */
    static uint16_t checksum(uint8_t *addr, int len);

    /**
     * @brief 构建ICMP Echo请求包
     *
     * 填充ICMP Echo请求包的各个字段，包括类型、代码、标识符、序列号，
     * 并在数据部分嵌入发送时间戳，最后计算校验和。
     *
     * @param[in,out] icmp 指向ICMP结构体的指针，将被填充为有效的Echo请求包
     * @param[in] id ICMP包的标识符，通常使用进程ID
     * @param[in] seq ICMP包的序列号，用于区分多次请求
     * @return int 构建完成的ICMP包大小(字节)
     */
    static int packIcmp(struct ::icmp *icmp, uint16_t id, uint16_t seq);
};

} // namespace monitor::weaknet