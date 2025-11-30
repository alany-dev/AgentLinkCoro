#pragma once

#include <string>
#include <memory>
#include <mutex>
#include "base/net/socket.h"

namespace monitor::weaknet
{
/**
 * @class WiFiRssiClient
 * @brief WiFi信号强度（RSSI）监控客户端类
 *
 * 该类通过UNIX域数据报套接字与wpa_supplicant控制接口通信，
 * 提供了获取WiFi接口信号强度（RSSI）的核心功能。

 * 主要功能：
 * - 通过UNIX域套接字与wpa_supplicant通信
 * - 支持自动发现wpa_supplicant控制接口
 * - 发送SIGNAL_POLL命令获取RSSI值
 * - 支持多接口同时监控
 * - 自动清理资源，避免套接字泄漏
 */
class WiFiRssiClient
{
public:
    /**
     * @brief 默认构造函数
     *
     * 初始化成员变量的默认状态，如套接字文件描述符设为-1表示未连接状态。
     * 实际的资源分配和连接建立在connect方法中进行。
     */
    WiFiRssiClient() = default;

    /**
     * @brief 析构函数
     *
     * 负责清理资源：关闭已打开的套接字文件描述符，
     * 删除本地套接字文件，避免资源泄漏和套接字残留。
     */
    ~WiFiRssiClient();

    /**
     * @brief 连接到wpa_supplicant控制套接字
     *
     * 尝试连接到指定WiFi接口的wpa_supplicant控制套接字。该方法会：
     * 1. 创建UNIX域数据报套接字
     * 2. 绑定本地套接字地址
     * 3. 尝试连接到指定或自动发现的wpa_supplicant控制目录
     * 4. 必要时尝试自动启动wpa_supplicant进程
     *
     * @param ifaceName WiFi接口名称（如"wlan0"）
     * @param ctrlDir wpa_supplicant控制目录路径（默认为"/var/run/wpa_supplicant"）
     * @return bool 连接成功返回true，失败返回false
     */
    bool connect(const std::string &ifaceName,
                 const std::string &ctrlDir = "/var/run/wpa_supplicant");

    /**
     * @brief 获取当前WiFi接口的RSSI（接收信号强度指示）值
     *
     * 向wpa_supplicant发送SIGNAL_POLL命令，并解析返回结果中的RSSI值。
     * RSSI值通常以dBm为单位，范围一般在-100到0之间，值越大表示信号越强。
     *
     * @return int 成功返回RSSI值（dBm），失败返回-1000（表示无效值）
     */
    int getRssi();

private:
    /**
     * @brief 套接字文件描述符
     *
     * 用于与wpa_supplicant通信的UNIX域数据报套接字，初始值为-1表示未创建。
     */
    base::Socket::ptr sock_ = nullptr;

    /**
     * @brief 当前操作的WiFi接口名称
     *
     * 存储要查询RSSI的WiFi接口名称，如"wlan0"、"wlp2s0"等。
     */
    std::string iface_;

    /**
     * @brief wpa_supplicant控制目录路径
     *
     * 存储wpa_supplicant控制套接字所在的目录路径。
     */
    std::string ctrlDir_;

    /**
     * @brief 本地套接字路径
     *
     * 存储本地UNIX域套接字的文件路径，用于wpa_supplicant回传数据。
     */
    std::string localSockPath_;

    /**
     * @brief 绑定本地套接字地址
     *
     * 创建并绑定唯一的本地UNIX域套接字地址，用于与wpa_supplicant通信。
     * 生成的套接字路径包含进程ID和接口名，确保唯一性。
     *
     * @return bool 绑定成功返回true，失败返回false
     */
    bool bindLocal();

    /**
     * @brief 连接到远程wpa_supplicant控制套接字
     *
     * 尝试连接到wpa_supplicant的控制套接字，设置套接字超时参数。
     *
     * @return bool 连接成功返回true，失败返回false
     */
    bool connectRemote();

    /**
     * @brief 向wpa_supplicant发送命令并获取响应
     *
     * 通过套接字向wpa_supplicant发送指定命令，并接收响应结果。
     * 内部实现了超时处理和错误检查机制。
     *
     * @param cmd 要发送的命令字符串（如"SIGNAL_POLL\n"）
     * @return std::string 命令响应结果，失败时返回空字符串
     */
    std::string sendCommand(const std::string &cmd);
};
} // namespace monitor::weaknet