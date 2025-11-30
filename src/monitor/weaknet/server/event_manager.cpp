// event_manager.cpp
// 事件管理器实现：处理网卡更换和上网方式改变事件，提供事件注册、触发和分发机制

#include "event_manager.hpp"
#include "server.hpp"
#include "dbus_service.hpp"
#include "common.hpp"
#include "logger.hpp"
#include <cstdio>
#include <chrono>
#include <thread>

using namespace std::chrono_literals;

namespace monitor::weaknet
{
/**
 * @brief NetworkEventManager构造函数
 * 初始化事件管理器的成员变量，设置默认状态
 */
NetworkEventManager::NetworkEventManager() : server_ctx_(nullptr), monitoring_active_(false)
{
    LOG_INFO(LogModule::EVENT_MGR, "NetworkEventManager initialized");
}

/**
 * @brief 注册事件回调函数
 * 将回调函数添加到对应事件类型的回调列表中，当该类型事件发生时，将调用所有注册的回调函数
 * @param type 要注册的事件类型
 * @param callback 事件发生时要调用的回调函数
 */
void NetworkEventManager::registerCallback(EventType type, EventCallback callback)
{
    // 根据事件类型将回调函数添加到对应的回调列表
    switch (type) {
        case EventType::InterfaceChanged:
            interface_callbacks_.push_back(callback);
            break;
        case EventType::ConnectionModeChanged:
            connection_mode_callbacks_.push_back(callback);
            break;
        case EventType::NetworkQualityChanged:
            network_quality_callbacks_.push_back(callback);
            break;
        case EventType::TcpLossRateChanged:
            tcp_loss_callbacks_.push_back(callback);
            break;
        case EventType::RttChanged:
            rtt_callbacks_.push_back(callback);
            break;
        case EventType::RssiChanged:
            rssi_callbacks_.push_back(callback);
            break;
    }
    LOG_INFO(LogModule::EVENT_MGR, "registered callback for event type " << static_cast<int>(type));
}

/**
 * @brief 注销指定事件类型的所有回调函数
 * 清空对应事件类型的回调函数列表，后续该类型事件不会触发任何回调
 * @param type 要注销的事件类型
 */
void NetworkEventManager::unregisterCallback(EventType type)
{
    // 根据事件类型清空对应的回调列表
    switch (type) {
        case EventType::InterfaceChanged:
            interface_callbacks_.clear();
            break;
        case EventType::ConnectionModeChanged:
            connection_mode_callbacks_.clear();
            break;
        case EventType::NetworkQualityChanged:
            network_quality_callbacks_.clear();
            break;
        case EventType::TcpLossRateChanged:
            tcp_loss_callbacks_.clear();
            break;
        case EventType::RttChanged:
            rtt_callbacks_.clear();
            break;
        case EventType::RssiChanged:
            rssi_callbacks_.clear();
            break;
    }
    LOG_INFO(LogModule::EVENT_MGR,
             "unregistered all callbacks for event type " << static_cast<int>(type));
}

/**
 * @brief 根据事件类型获取对应的DBus信号名称
 * 用于将内部事件类型映射到DBus信号名称，便于信号发送
 * @param type 事件类型
 * @return 对应的DBus信号名称
 */
std::string NetworkEventManager::getSignalName(EventType type) const
{
    switch (type) {
        case EventType::InterfaceChanged:
            return kSignalInterfaceChanged;
        case EventType::ConnectionModeChanged:
            return kSignalConnectionModeChanged;
        case EventType::NetworkQualityChanged:
            return kSignalNetworkQualityChanged;
        default:
            return kSignalChanged; // 默认使用通用信号
    }
}

/**
 * @brief 发送一个网络事件
 * 这是事件发送的核心方法，负责调用注册的回调函数并通过DBus发送信号
 * @param event 要发送的事件对象
 */
void NetworkEventManager::emitEvent(const NetworkEvent &event)
{
    LOG_INFO(LogModule::EVENT_MGR, "emitting event: type=" << static_cast<int>(event.type)
                                                           << ", message='" << event.message
                                                           << "', source='" << event.source << "'");

    // 调用所有注册的回调函数
    invokeCallbacks(event.type, event);

    // 如果有DBus服务，发送信号给客户端
    if (server_ctx_ && server_ctx_->getDbusService()) {
        std::string signalName = getSignalName(event.type);
        // 构建完整的消息文本，包含源信息
        std::string fullMessage =
            event.source.empty() ? event.message : "[" + event.source + "] " + event.message;

        static int32_t eventCounter = 0; // 事件计数器，用于区分不同事件

        // 对于网络质量事件，发送包含详细信息的特殊信号
        if (event.type == EventType::NetworkQualityChanged && !event.details.empty()) {
            server_ctx_->getDbusService()->emitNetworkQualitySignal(fullMessage, event.details,
                                                                    eventCounter++);
        } else {
            // 其他事件发送普通信号
            server_ctx_->getDbusService()->emitSpecificSignal(signalName, fullMessage,
                                                              eventCounter++);
        }
    }
}

/**
 * @brief 便捷方法：发送网卡变化事件
 * 创建并发送网卡变化事件，优先级设为8
 * @param message 事件消息
 * @param source 事件触发源
 */
void NetworkEventManager::emitInterfaceChanged(const std::string &message,
                                               const std::string &source)
{
    emitEvent(NetworkEvent(EventType::InterfaceChanged, message, source, 8));
}

/**
 * @brief 便捷方法：发送上网方式改变事件
 * 创建并发送上网方式改变事件，优先级设为9
 * @param message 事件消息
 * @param source 事件触发源
 */
void NetworkEventManager::emitConnectionModeChanged(const std::string &message,
                                                    const std::string &source)
{
    emitEvent(NetworkEvent(EventType::ConnectionModeChanged, message, source, 9));
}

/**
 * @brief 便捷方法：发送网络质量变化事件
 * 创建并发送网络质量变化事件，包含详细信息，优先级设为7
 * @param message 事件消息
 * @param details 详细信息（JSON格式）
 * @param source 事件触发源
 */
void NetworkEventManager::emitNetworkQualityChanged(const std::string &message,
                                                    const std::string &details,
                                                    const std::string &source)
{
    NetworkEvent event(EventType::NetworkQualityChanged, message, source, 7);
    event.details = details;
    emitEvent(event);
}

/**
 * @brief 便捷方法：发送TCP丢包率变化事件
 * 创建并发送TCP丢包率变化事件，优先级设为6
 * @param message 事件消息
 * @param source 事件触发源
 */
void NetworkEventManager::emitTcpLossRateChanged(const std::string &message,
                                                 const std::string &source)
{
    emitEvent(NetworkEvent(EventType::TcpLossRateChanged, message, source, 6));
}

/**
 * @brief 便捷方法：发送RTT变化事件
 * 创建并发送RTT变化事件，优先级设为5
 * @param message 事件消息
 * @param source 事件触发源
 */
void NetworkEventManager::emitRttChanged(const std::string &message, const std::string &source)
{
    emitEvent(NetworkEvent(EventType::RttChanged, message, source, 5));
}

/**
 * @brief 便捷方法：发送RSSI变化事件
 * 创建并发送RSSI变化事件，优先级设为4
 * @param message 事件消息
 * @param source 事件触发源
 */
void NetworkEventManager::emitRssiChanged(const std::string &message, const std::string &source)
{
    emitEvent(NetworkEvent(EventType::RssiChanged, message, source, 4));
}

/**
 * @brief 启动事件监控
 * 设置服务器上下文并激活事件监控功能，同时注册默认的日志记录回调
 * @param server 服务器上下文，包含DBus服务等信息
 */
void NetworkEventManager::startEventMonitoring(WeakNetServer *server)
{
    server_ctx_ = server;      // 设置服务器上下文
    monitoring_active_ = true; // 激活事件监控

    LOG_INFO(LogModule::EVENT_MGR, "event monitoring started");

    // 注册默认回调，将事件记录到日志系统
    registerCallback(EventType::InterfaceChanged, [](const NetworkEvent &event) {
        LOG_INFO(LogModule::EVENT_MGR, "Interface change event: " << event.message);
    });

    registerCallback(EventType::ConnectionModeChanged, [](const NetworkEvent &event) {
        LOG_INFO(LogModule::EVENT_MGR, "Connection mode change event: " << event.message);
    });
}

/**
 * @brief 停止事件监控
 * 停用事件监控功能，不再发送DBus信号
 */
void NetworkEventManager::stopEventMonitoring()
{
    monitoring_active_ = false;
    LOG_INFO(LogModule::EVENT_MGR, "event monitoring stopped");
}

/**
 * @brief 调用指定类型事件的所有回调函数
 * 遍历对应事件类型的回调列表，依次调用每个回调函数
 * @param type 事件类型
 * @param event 事件对象
 */
void NetworkEventManager::invokeCallbacks(EventType type, const NetworkEvent &event)
{
    switch (type) {
        case EventType::InterfaceChanged:
            for (const auto &callback : interface_callbacks_) {
                callback(event);
            }
            break;
        case EventType::ConnectionModeChanged:
            for (const auto &callback : connection_mode_callbacks_) {
                callback(event);
            }
            break;
        case EventType::NetworkQualityChanged:
            for (const auto &callback : network_quality_callbacks_) {
                callback(event);
            }
            break;
        case EventType::TcpLossRateChanged:
            for (const auto &callback : tcp_loss_callbacks_) {
                callback(event);
            }
            break;
        case EventType::RttChanged:
            for (const auto &callback : rtt_callbacks_) {
                callback(event);
            }
            break;
        case EventType::RssiChanged:
            for (const auto &callback : rssi_callbacks_) {
                callback(event);
            }
            break;
    }
}

} // namespace monitor::weaknet