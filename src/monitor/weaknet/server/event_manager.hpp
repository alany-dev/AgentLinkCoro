#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <functional>
#include <memory>
#include "base/singleton.h"
#include "net_info.hpp"

namespace monitor::weaknet
{

/**
 * @enum EventType
 * @brief 网络事件类型枚举，定义了系统中所有可能的网络事件种类
 */
enum class EventType {
    InterfaceChanged,      // 网卡变化（添加/移除）
    ConnectionModeChanged, // 上网方式改变（如从WiFi切换到以太网）
    NetworkQualityChanged, // 网络质量变化
    TcpLossRateChanged,    // TCP丢包率变化
    RttChanged,            // 往返时间(Round Trip Time)变化
    RssiChanged            // 信号强度(Received Signal Strength Indicator)变化
};

/**
 * @struct NetworkEvent
 * @brief 网络事件数据结构，包含事件的所有相关信息
 */
struct NetworkEvent {
    EventType type;                                  // 事件类型
    std::string message;                             // 事件消息描述
    std::chrono::system_clock::time_point timestamp; // 事件发生时间戳
    std::string source;                              // 触发源（网卡名/服务名等）
    std::string details;                             // 详细信息（JSON格式可选）
    int32_t priority;                                // 优先级（0-10，10最高）

    /**
     * @brief 默认构造函数
     */
    NetworkEvent() = default;

    /**
     * @brief 构造函数
     * @param t 事件类型
     * @param msg 事件消息
     * @param src 事件触发源
     * @param prio 事件优先级
     */
    NetworkEvent(EventType t, const std::string &msg, const std::string &src = "", int32_t prio = 0)
        : type(t), message(msg), timestamp(std::chrono::system_clock::now()), source(src),
          priority(prio)
    {
    }
};

/**
 * @typedef EventCallback
 * @brief 事件回调函数类型，用于处理网络事件
 */
using EventCallback = std::function<void(const NetworkEvent &)>;

class WeakNetServer;

/**
 * @class NetworkEventManager
 * @brief 网络事件管理器，负责事件的注册、触发和分发
 *
 * 该类实现了观察者模式，允许组件注册对特定类型事件的感兴趣，
 * 当事件发生时，会通知所有注册的观察者。同时，它还负责将事件
 * 通过DBus信号发送给客户端应用程序。
 */
class NetworkEventManager
{
public:
    /**
     * @brief 构造函数
     * 初始化事件管理器，设置默认状态
     */
    NetworkEventManager();

    /**
     * @brief 析构函数
     * 虚析构函数，确保正确释放派生类资源
     */
    ~NetworkEventManager() = default;

    /**
     * @brief 注册事件回调函数
     * @param type 要注册的事件类型
     * @param callback 事件发生时要调用的回调函数
     */
    void registerCallback(EventType type, EventCallback callback);

    /**
     * @brief 注销指定事件类型的所有回调函数
     * @param type 要注销的事件类型
     */
    void unregisterCallback(EventType type);

    /**
     * @brief 发送一个网络事件
     * @param event 要发送的事件对象
     */
    void emitEvent(const NetworkEvent &event);

    /**
     * @brief 便捷方法：发送网卡变化事件
     * @param message 事件消息
     * @param source 事件触发源
     */
    void emitInterfaceChanged(const std::string &message, const std::string &source = "");

    /**
     * @brief 便捷方法：发送上网方式改变事件
     * @param message 事件消息
     * @param source 事件触发源
     */
    void emitConnectionModeChanged(const std::string &message, const std::string &source = "");

    /**
     * @brief 便捷方法：发送网络质量变化事件
     * @param message 事件消息
     * @param details 详细信息（JSON格式）
     * @param source 事件触发源
     */
    void emitNetworkQualityChanged(const std::string &message, const std::string &details = "",
                                   const std::string &source = "");

    /**
     * @brief 便捷方法：发送TCP丢包率变化事件
     * @param message 事件消息
     * @param source 事件触发源
     */
    void emitTcpLossRateChanged(const std::string &message, const std::string &source = "");

    /**
     * @brief 便捷方法：发送RTT变化事件
     * @param message 事件消息
     * @param source 事件触发源
     */
    void emitRttChanged(const std::string &message, const std::string &source = "");

    /**
     * @brief 便捷方法：发送RSSI变化事件
     * @param message 事件消息
     * @param source 事件触发源
     */
    void emitRssiChanged(const std::string &message, const std::string &source = "");

    /**
     * @brief 启动事件监控
     * @param server 服务器上下文，包含DBus服务等信息
     */
    void startEventMonitoring(WeakNetServer *server);

    /**
     * @brief 停止事件监控
     */
    void stopEventMonitoring();

private:
    // 各种事件类型的回调函数列表
    std::vector<EventCallback> interface_callbacks_;       // 网卡变化事件回调
    std::vector<EventCallback> connection_mode_callbacks_; // 上网方式变化事件回调
    std::vector<EventCallback> network_quality_callbacks_; // 网络质量变化事件回调
    std::vector<EventCallback> tcp_loss_callbacks_;        // TCP丢包率变化事件回调
    std::vector<EventCallback> rtt_callbacks_;             // RTT变化事件回调
    std::vector<EventCallback> rssi_callbacks_;            // RSSI变化事件回调

    WeakNetServer *server_ctx_; // 服务器上下文指针
    bool monitoring_active_;    // 事件监控活动状态标志

    /**
     * @brief 调用指定类型事件的所有回调函数
     * @param type 事件类型
     * @param event 事件对象
     */
    void invokeCallbacks(EventType type, const NetworkEvent &event);

    /**
     * @brief 根据事件类型获取对应的DBus信号名称
     * @param type 事件类型
     * @return DBus信号名称
     */
    std::string getSignalName(EventType type) const;
};

using EventManager = base::Singleton<NetworkEventManager>;

} // namespace monitor::weaknet 