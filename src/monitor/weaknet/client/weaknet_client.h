#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "logger.hpp"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * WeakNet 客户端动态库 API
     *
     * 此库提供与WeakNet D-Bus服务端通信的C接口，包括：
     * - 网络接口信息获取
     * - 网络状态监控
     * - 事件监听和订阅
     * - TCP丢包率监控
     * - RTT延迟监控
     *
     * 使用示例：
     *   weaknet_init();                          // 初始化
     *   weaknet_get_interfaces(buf, sz, err, errsz);  // 获取信息
     *   weaknet_subscribe_event("InterfaceChanged", callback);  // 订阅事件
     *   weaknet_check_events(...);                // 检查事件
     *   weaknet_cleanup();                       // 清理
     */

    // ============== 库初始化和清理 ==============

    /**
     * 初始化WeakNet客户端库
     * 必须在调用其他任何函数之前调用此函数
     *
     * @return true-成功, false-失败
     */
    bool weaknet_init();

    /**
     * 清理WeakNet客户端资源
     * 应在应用程序退出前调用此函数
     */
    void weaknet_cleanup();

    /**
     * 检查客户端连接状态
     *
     * @return true-已连接, false-未连接
     */
    bool weaknet_is_connected();

    // ============== 网络接口信息获取 ==============

    /**
     * 获取当前网络接口信息
     *
     * @param buffer 结果缓冲区，将存储网络接口信息
     * @param buffer_size 缓冲区大小
     * @param error_buffer 错误信息缓冲区（如果调用失败）
     * @param error_size 错误信息缓冲区大小
     * @return true-成功, false-失败
     */
    bool weaknet_get_interfaces(char *buffer, size_t buffer_size, char *error_buffer,
                                size_t error_size);

    /**
     * 网络健康检查
     *
     * @param result_buffer 结果缓冲区，将存储健康检查结果
     * @param result_size 结果缓冲区大小
     * @param error_buffer 错误信息缓冲区（如果调用失败）
     * @param error_size 错误信息缓冲区大小
     * @return true-成功, false-失败
     */
    bool weaknet_health_check(char *result_buffer, size_t result_size, char *error_buffer,
                              size_t error_size);

    /**
     * 从序列化文件读取最新状态（离线模式）
     *
     * @param buffer 结果缓冲区，将存储文件中的内容
     * @param buffer_size 缓冲区大小
     * @param error_buffer 错误信息缓冲区（如果调用失败）
     * @param error_size 错误信息缓冲区大小
     * @return true-成功, false-失败
     */
    bool weaknet_get_from_file(char *buffer, size_t buffer_size, char *error_buffer,
                               size_t error_size);

    /**
     * Ping指定主机（通过当前上网网卡）
     *
     * @param hostname 目标主机名或IP地址
     * @param result_buffer 结果缓冲区，将存储ping结果
     * @param result_size 结果缓冲区大小
     * @param error_buffer 错误信息缓冲区（如果调用失败）
     * @param error_size 错误信息缓冲区大小
     * @return true-成功, false-失败
     */
    bool weaknet_ping_host(const char *hostname, char *result_buffer, size_t result_size,
                           char *error_buffer, size_t error_size);

    // ============== 网络状态变化监控 ==============

    /**
     * 检查网络状态变化（非阻塞）
     *
     * @param message_buffer 消息缓冲区，将存储变化消息
     * @param message_size 消息缓冲区大小
     * @param counter 计数器（输出参数）
     * @param error_buffer 错误信息缓冲区（如果没有变化）
     * @param error_size 错误信息缓冲区大小
     * @return true-有变化, false-无变化或错误
     */
    bool weaknet_check_changes(char *message_buffer, size_t message_size, int32_t *counter,
                               char *error_buffer, size_t error_size);

    // ============== 事件监听和订阅系统 ==============

    /**
     * 事件回调函数类型
     *
     * @param event_type 事件类型（如"InterfaceChanged"）
     * @param message 事件消息内容
     * @param counter 事件计数器
     * @param source 事件来源
     */
    typedef void weaknet_event_callback_t(const char *event_type, const char *message,
                                          int32_t counter, const char *source);

    /**
     * 网络质量事件回调函数类型
     *
     * @param quality 网络质量等级（如"poor", "fair", "good", "excellent"）
     * @param details 详细质量信息（JSON格式的指标数据）
     * @param counter 事件计数器
     * @return true-继续监听, false-停止监听
     */
    typedef bool (*weaknet_network_quality_callback_t)(const char *quality, const char *details,
                                                       int32_t counter);

    /**
     * 订阅特定事件类型
     *
     * @param event_type 要订阅的事件类型（如"InterfaceChanged", "ConnectionModeChanged"）
     * @param callback 事件回调函数（可为nullptr，此时只添加DBus订阅）
     * @return true-成功, false-失败
     */
    bool weaknet_subscribe_event(const char *event_type, weaknet_event_callback_t callback);

    /**
     * 取消订阅事件
     *
     * @param event_type 要取消订阅的事件类型
     * @return true-成功, false-失败
     */
    bool weaknet_unsubscribe_event(const char *event_type);

    /**
     * 获取支持的事件类型列表
     *
     * @param buffer 结果缓冲区，将存储事件类型列表（逗号分隔）
     * @param buffer_size 缓冲区大小
     * @param error_buffer 错误信息缓冲区（如果调用失败）
     * @param error_size 错误信息缓冲区大小
     * @return true-成功, false-失败
     */
    bool weaknet_get_event_types(char *buffer, size_t buffer_size, char *error_buffer,
                                 size_t error_size);

    /**
     * 非阻塞检查事件
     *
     * @param event_type_buffer 事件类型缓冲区（输出参数）
     * @param event_type_size 事件类型缓冲区大小
     * @param message_buffer 消息缓冲区（输出参数）
     * @param message_size 消息缓冲区大小
     * @param counter 计数器（输出参数）
     * @param source_buffer 事件来源缓冲区（输出参数）
     * @param source_size 事件来源缓冲区大小
     * @param error_buffer 错误信息缓冲区（如果没有事件）
     * @param error_size 错误信息缓冲区大小
     * @return true-检测到事件, false-没有事件或错误
     */
    bool weaknet_check_events(char *event_type_buffer, size_t event_type_size, char *message_buffer,
                              size_t message_size, int32_t *counter, char *source_buffer,
                              size_t source_size, char *error_buffer, size_t error_size);

    // ============== 网络质量监控 ==============

    /**
     * 订阅网络质量事件
     *
     * @param callback 网络质量事件回调函数
     * @return true-成功, false-失败
     */
    bool weaknet_subscribe_network_quality(weaknet_network_quality_callback_t callback);

    /**
     * 非阻塞检查网络质量事件
     *
     * @param quality_buffer 网络质量等级缓冲区（输出）
     * @param quality_size 质量等级缓冲区大小
     * @param details_buffer 详细质量信息缓冲区（输出）
     * @param details_size 详细信息缓冲区大小
     * @param counter 事件计数器（输出）
     * @param error_buffer 错误信息缓冲区（如果没有事件）
     * @param error_size 错误信息缓冲区大小
     * @return true-有质量事件, false-无事件或错误
     */
    bool weaknet_check_network_quality(char *quality_buffer, size_t quality_size,
                                       char *details_buffer, size_t details_size, int32_t *counter,
                                       char *error_buffer, size_t error_size);

    // ============== 版本和状态信息 ==============

    /**
     * 获取WeakNet客户端库版本信息
     *
     * @param buffer 结果缓冲区
     * @param buffer_size 缓冲区大小
     * @return true-成功, false-失败
     */
    bool weaknet_get_version(char *buffer, size_t buffer_size);

    /**
     * 获取库的编译时间和编译选项信息
     *
     * @param buffer 结果缓冲区
     * @param buffer_size 缓冲区大小
     * @return true-成功, false-失败
     */
    bool weaknet_get_build_info(char *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

namespace monitor::weaknet
{

class WeakNetClient
{
private:
    DBusConnection *conn_;
    bool connected_;

    // 初始化DBus连接
    bool initConnection()
    {
        DBusError err;
        dbus_error_init(&err);
        conn_ = dbus_bus_get(DBUS_BUS_SESSION, &err);
        if (dbus_error_is_set(&err)) {
            LOG_ERROR(LogModule::CLIENT, "连接DBus总线失败: " << err.message);
            dbus_error_free(&err);
        }
        connected_ = (conn_ != nullptr);
        return connected_;
    }

public:
    WeakNetClient() : conn_(nullptr), connected_(false) {}

    ~WeakNetClient()
    {
        if (conn_) {
            dbus_connection_unref(conn_);
        }
    }

    // 连接到服务
    bool connect() { return initConnection(); }

    // 检查连接状态
    bool isConnected() const { return connected_ && conn_ != nullptr; }

    // 调用Get方法获取当前网络接口信息
    bool getInterfaces(std::string &result, std::string &errorMsg)
    {
        if (!isConnected()) {
            errorMsg = "客户端未连接";
            return false;
        }

        DBusMessage *msg =
            dbus_message_new_method_call(kBusName, kObjectPath, kInterface, kMethodGet);
        if (!msg) {
            errorMsg = "创建方法调用消息失败";
            return false;
        }

        DBusError err;
        dbus_error_init(&err);

        DBusMessage *reply = dbus_connection_send_with_reply_and_block(conn_, msg, 2000, &err);
        dbus_message_unref(msg);

        if (dbus_error_is_set(&err)) {
            errorMsg = std::string("调用失败: ") + err.message;
            dbus_error_free(&err);
            return false;
        }

        if (!reply) {
            errorMsg = "未收到应答";
            return false;
        }

        const char *s = nullptr;
        if (!dbus_message_get_args(reply, &err, DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID)) {
            if (dbus_error_is_set(&err)) {
                errorMsg = std::string("解析返回失败: ") + err.message;
                dbus_error_free(&err);
            } else {
                errorMsg = "解析返回失败";
            }
            dbus_message_unref(reply);
            return false;
        }

        result = s ? s : "";
        dbus_message_unref(reply);
        return true;
    }

    // 订阅网络状态变化信号
    bool subscribeToChanges(bool (*callback)(const std::string &message, int32_t counter) = nullptr)
    {
        if (!isConnected()) {
            return false;
        }

        DBusError err;
        dbus_error_init(&err);

        std::string rule = std::string("type='signal',interface='") + kInterface + "',member='"
                           + kSignalChanged + "'";
        dbus_bus_add_match(conn_, rule.c_str(), &err);
        dbus_connection_flush(conn_);

        if (dbus_error_is_set(&err)) {
            LOG_ERROR(LogModule::CLIENT, "添加匹配规则失败: " << err.message);
            dbus_error_free(&err);
            return false;
        }

        LOG_INFO(LogModule::CLIENT, "已订阅 " << kSignalChanged << " 信号，等待变化通知...");

        // 定期输出客户端状态
        auto lastStatusTime = std::chrono::steady_clock::now();
        const auto statusInterval = std::chrono::seconds(5);

        while (true) {
            dbus_connection_read_write(conn_, 100);
            DBusMessage *msg = dbus_connection_pop_message(conn_);

            // 定期输出客户端状态
            auto now = std::chrono::steady_clock::now();
            if (now - lastStatusTime >= statusInterval) {
                LOG_INFO(LogModule::CLIENT, "CLIENT_STATUS: 连接正常，等待网络变化信号...");
                lastStatusTime = now;
            }

            if (!msg)
                continue;

            if (dbus_message_is_signal(msg, kInterface, kSignalChanged)) {
                const char *text = nullptr;
                int32_t counter = 0;
                DBusError e;
                dbus_error_init(&e);

                if (dbus_message_get_args(msg, &e, DBUS_TYPE_STRING, &text, DBUS_TYPE_INT32,
                                          &counter, DBUS_TYPE_INVALID)) {
                    LOG_INFO(LogModule::CLIENT, "收到网络状态变化: '" << (text ? text : "<null>")
                                                                      << "', counter=" << counter);

                    // 调用回调函数（如果提供）
                    if (callback && callback(text ? std::string(text) : "", counter)) {
                        dbus_message_unref(msg);
                        break; // 回调返回true时停止监听
                    }
                } else if (dbus_error_is_set(&e)) {
                    LOG_ERROR(LogModule::CLIENT, "解析信号失败: " << e.message);
                    dbus_error_free(&e);
                }

                // 读取服务端序列化到文件的信号负载
                ChangedPayload restored{};
                std::string ferr;
                if (deserializeChangedPayloadFromFile(kSignalSerializedFile, &restored, &ferr)) {
                    LOG_INFO(LogModule::CLIENT, "从文件读取的详细信息: text='"
                                                    << restored.message
                                                    << "', counter=" << restored.counter);
                }
            }

            dbus_message_unref(msg);
        }
        return true;
    }

    // 单次检查网络状态变化（非阻塞）
    bool checkForChanges(std::string &message, int32_t &counter)
    {
        if (!isConnected()) {
            return false;
        }

        dbus_connection_read_write(conn_, 0); // 非阻塞轮询
        DBusMessage *msg = dbus_connection_pop_message(conn_);
        if (!msg)
            return false;

        if (dbus_message_is_signal(msg, kInterface, kSignalChanged)) {
            const char *text = nullptr;
            DBusError e;
            dbus_error_init(&e);

            if (dbus_message_get_args(msg, &e, DBUS_TYPE_STRING, &text, DBUS_TYPE_INT32, &counter,
                                      DBUS_TYPE_INVALID)) {
                message = text ? std::string(text) : "";
                dbus_message_unref(msg);
                return true;
            } else if (dbus_error_is_set(&e)) {
                dbus_error_free(&e);
            }
        }

        dbus_message_unref(msg);
        return false;
    }

    // 发送网络健康检查请求
    bool requestHealthCheck(std::string &result, std::string &errorMsg)
    {
        return getInterfaces(result, errorMsg);
    }

    // 读取最新的网络接口状态（从序列化文件）
    bool getLatestFromFile(std::string &result, std::string &errorMsg)
    {
        std::string file_err;
        if (deserializeGetReplyFromFile(kGetReplySerializedFile, &result, &file_err)) {
            return true;
        } else {
            errorMsg = std::string("读取序列化文件失败: ") + file_err;
            return false;
        }
    }

    // Ping指定主机
    bool pingHost(const std::string &hostname, std::string &result, std::string &errorMsg)
    {
        if (!isConnected()) {
            errorMsg = "客户端未连接";
            return false;
        }

        if (hostname.empty()) {
            errorMsg = "主机名不能为空";
            return false;
        }

        DBusMessage *msg =
            dbus_message_new_method_call(kBusName, kObjectPath, kInterface, kMethodPing);
        if (!msg) {
            errorMsg = "创建ping方法调用消息失败";
            return false;
        }

        DBusMessageIter args;
        dbus_message_iter_init_append(msg, &args);
        const char *host = hostname.c_str();
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &host)) {
            dbus_message_unref(msg);
            errorMsg = "添加主机名参数失败";
            return false;
        }

        DBusError err;
        dbus_error_init(&err);

        DBusMessage *reply =
            dbus_connection_send_with_reply_and_block(conn_, msg, 10000, &err); // 10秒超时
        dbus_message_unref(msg);

        if (dbus_error_is_set(&err)) {
            errorMsg = std::string("ping调用失败: ") + err.message;
            dbus_error_free(&err);
            return false;
        }

        if (!reply) {
            errorMsg = "未收到ping应答";
            return false;
        }

        const char *s = nullptr;
        if (!dbus_message_get_args(reply, &err, DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID)) {
            if (dbus_error_is_set(&err)) {
                errorMsg = std::string("解析ping返回失败: ") + err.message;
                dbus_error_free(&err);
            } else {
                errorMsg = "解析ping返回失败";
            }
            dbus_message_unref(reply);
            return false;
        }

        result = s ? s : "";
        dbus_message_unref(reply);
        return true;
    }

    // 断开连接
    void disconnect()
    {
        if (conn_) {
            dbus_connection_unref(conn_);
            conn_ = nullptr;
            connected_ = false;
        }
    }

    // 获取连接对象（用于C接口）
    DBusConnection *getConnection() const { return conn_; }

    // 订阅特定事件类型
    bool subscribeToEvent(const std::string &eventType)
    {
        if (!isConnected())
            return false;

        DBusError err;
        dbus_error_init(&err);

        // 添加事件信号匹配规则
        std::string rule =
            std::string("type='signal',interface='") + kInterface + "',member='" + eventType + "'";
        dbus_bus_add_match(conn_, rule.c_str(), &err);
        dbus_connection_flush(conn_);

        if (dbus_error_is_set(&err)) {
            LOG_ERROR(LogModule::CLIENT, "添加事件匹配规则失败: " << err.message);
            dbus_error_free(&err);
            return false;
        }

        LOG_INFO(LogModule::CLIENT, "已订阅事件: " << eventType);
        return true;
    }

    // 订阅网络质量事件
    bool subscribeToNetworkQuality(bool (*callback)(const std::string &quality,
                                                    const std::string &details,
                                                    int32_t counter) = nullptr)
    {
        if (!isConnected()) {
            return false;
        }

        DBusError err;
        dbus_error_init(&err);

        // 订阅网络质量变化信号
        std::string rule = std::string("type='signal',interface='") + kInterface + "',member='"
                           + kSignalNetworkQualityChanged + "'";
        dbus_bus_add_match(conn_, rule.c_str(), &err);
        dbus_connection_flush(conn_);

        if (dbus_error_is_set(&err)) {
            LOG_ERROR(LogModule::CLIENT, "添加网络质量事件匹配规则失败: " << err.message);
            dbus_error_free(&err);
            return false;
        }

        LOG_INFO(LogModule::CLIENT, "已订阅网络质量事件，等待质量变化通知...");

        // 定期输出客户端状态
        auto lastStatusTime = std::chrono::steady_clock::now();
        const auto statusInterval = std::chrono::seconds(5);

        while (true) {
            dbus_connection_read_write(conn_, 100);
            DBusMessage *msg = dbus_connection_pop_message(conn_);

            // 定期输出客户端状态
            auto now = std::chrono::steady_clock::now();
            if (now - lastStatusTime >= statusInterval) {
                LOG_INFO(LogModule::CLIENT, "CLIENT_STATUS: 连接正常，等待网络质量变化信号...");
                lastStatusTime = now;
            }

            if (!msg)
                continue;

            if (dbus_message_is_signal(msg, kInterface, kSignalNetworkQualityChanged)) {
                const char *quality = nullptr;
                const char *details = nullptr;
                int32_t counter = 0;
                DBusError e;
                dbus_error_init(&e);

                if (dbus_message_get_args(msg, &e, DBUS_TYPE_STRING, &quality, DBUS_TYPE_STRING,
                                          &details, DBUS_TYPE_INT32, &counter, DBUS_TYPE_INVALID)) {
                    LOG_INFO(LogModule::CLIENT,
                             "收到网络质量变化: quality='"
                                 << (quality ? quality : "<null>") << "', details='"
                                 << (details ? details : "<null>") << "', counter=" << counter);

                    // 调用回调函数（如果提供）
                    if (callback
                        && callback(quality ? std::string(quality) : "",
                                    details ? std::string(details) : "", counter)) {
                        dbus_message_unref(msg);
                        break; // 回调返回true时停止监听
                    }
                } else if (dbus_error_is_set(&e)) {
                    LOG_ERROR(LogModule::CLIENT, "解析网络质量信号失败: " << e.message);
                    dbus_error_free(&e);
                }
            }

            dbus_message_unref(msg);
        }
        return true;
    }

    // 非阻塞检查事件
    bool checkForEvents(std::string &eventType, std::string &message, int32_t &counter,
                        std::string &source)
    {
        if (!isConnected())
            return false;

        dbus_connection_read_write(conn_, 0); // 非阻塞轮询
        DBusMessage *msg = dbus_connection_pop_message(conn_);
        if (!msg)
            return false;

        // 检查是否为事件信号
        if (dbus_message_is_signal(msg, kInterface, kSignalInterfaceChanged)
            || dbus_message_is_signal(msg, kInterface, kSignalConnectionModeChanged)
            || dbus_message_is_signal(msg, kInterface, kSignalNetworkQualityChanged)) {

            const char *signal_name = dbus_message_get_member(msg);
            const char *text = nullptr;
            DBusError e;
            dbus_error_init(&e);

            if (dbus_message_get_args(msg, &e, DBUS_TYPE_STRING, &text, DBUS_TYPE_INT32, &counter,
                                      DBUS_TYPE_INVALID)) {
                eventType = signal_name ? signal_name : "unknown";
                message = text ? std::string(text) : "";
                source = "event_manager";
                dbus_message_unref(msg);
                return true;
            } else if (dbus_error_is_set(&e)) {
                dbus_error_free(&e);
            }
        }

        dbus_message_unref(msg);
        return false;
    }

private:
    std::string getSignalMember(DBusMessage *msg)
    {
        const char *member = dbus_message_get_member(msg);
        return member ? std::string(member) : "";
    }
};
} // namespace monitor::weaknet