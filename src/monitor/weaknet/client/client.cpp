#include <dbus/dbus.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>

#include "common.hpp"
#include "serializer.hpp"
#include "weaknet_client.h"
#include "logger.hpp"

namespace weaknet_dbus
{
// 全局客户端实例（单例模式）
static WeakNetClient *g_client = nullptr;

// 初始化客户端
extern "C" bool weaknet_init()
{
    if (g_client) {
        return g_client->isConnected();
    }

    g_client = new WeakNetClient();
    return g_client->connect();
}

// 清理客户端
extern "C" void weaknet_cleanup()
{
    if (g_client) {
        g_client->disconnect();
        delete g_client;
        g_client = nullptr;
    }
}

// 获取当前网络接口信息
extern "C" bool weaknet_get_interfaces(char *buffer, size_t buffer_size, char *error_buffer,
                                       size_t error_size)
{
    if (!g_client || !g_client->isConnected()) {
        snprintf(error_buffer, error_size, "客户端未连接");
        return false;
    }

    std::string result, errorMsg;
    if (g_client->getInterfaces(result, errorMsg)) {
        snprintf(buffer, buffer_size, "%s", result.c_str());
        return true;
    } else {
        snprintf(error_buffer, error_size, "%s", errorMsg.c_str());
        return false;
    }
}

// 获取网络状态变化（非阻塞）
extern "C" bool weaknet_check_changes(char *message_buffer, size_t message_size, int32_t *counter,
                                      char *error_buffer, size_t error_size)
{
    if (!g_client || !g_client->isConnected()) {
        snprintf(error_buffer, error_size, "客户端未连接");
        return false;
    }

    std::string message;
    if (g_client->checkForChanges(message, *counter)) {
        snprintf(message_buffer, message_size, "%s", message.c_str());
        return true;
    }

    snprintf(error_buffer, error_size, "无新的状态变化");
    return false;
}

// 请求网络健康检查
extern "C" bool weaknet_health_check(char *result_buffer, size_t result_size, char *error_buffer,
                                     size_t error_size)
{
    if (!g_client || !g_client->isConnected()) {
        snprintf(error_buffer, error_size, "客户端未连接");
        return false;
    }

    std::string result, errorMsg;
    if (g_client->requestHealthCheck(result, errorMsg)) {
        snprintf(result_buffer, result_size, "%s", result.c_str());
        return true;
    } else {
        snprintf(error_buffer, error_size, "%s", errorMsg.c_str());
        return false;
    }
}

// 从文件读取最新状态（离线模式）
extern "C" bool weaknet_get_from_file(char *buffer, size_t buffer_size, char *error_buffer,
                                      size_t error_size)
{
    if (!g_client) {
        snprintf(error_buffer, error_size, "客户端未初始化");
        return false;
    }

    std::string result, errorMsg;
    if (g_client->getLatestFromFile(result, errorMsg)) {
        snprintf(buffer, buffer_size, "%s", result.c_str());
        return true;
    } else {
        snprintf(error_buffer, error_size, "%s", errorMsg.c_str());
        return false;
    }
}

// Ping指定主机
extern "C" bool weaknet_ping_host(const char *hostname, char *result_buffer, size_t result_size,
                                  char *error_buffer, size_t error_size)
{
    if (!g_client || !g_client->isConnected()) {
        snprintf(error_buffer, error_size, "客户端未连接");
        return false;
    }

    if (!hostname || strlen(hostname) == 0) {
        snprintf(error_buffer, error_size, "主机名不能为空");
        return false;
    }

    std::string result, errorMsg;
    if (g_client->pingHost(std::string(hostname), result, errorMsg)) {
        snprintf(result_buffer, result_size, "%s", result.c_str());
        return true;
    } else {
        snprintf(error_buffer, error_size, "%s", errorMsg.c_str());
        return false;
    }
}

} // namespace weaknet_dbus

// C接口函数实现

// 订阅特定事件类型
extern "C" bool weaknet_subscribe_event(const char *event_type, weaknet_event_callback_t callback)
{
    if (!weaknet_dbus::g_client || !weaknet_dbus::g_client->isConnected()) {
        return false;
    }
    return weaknet_dbus::g_client->subscribeToEvent(std::string(event_type));
}

// 取消订阅事件（简化实现）
extern "C" bool weaknet_unsubscribe_event(const char *event_type)
{
    // 注意：这个简化实现只是返回成功，实际项目中可能需要更复杂的去订阅逻辑
    // 简化实现，不记录日志
    return true;
}

// 获取支持的事件类型列表
extern "C" bool weaknet_get_event_types(char *buffer, size_t buffer_size, char *error_buffer,
                                        size_t error_size)
{
    snprintf(buffer, buffer_size, "%s,%s,%s", weaknet_dbus::kSignalInterfaceChanged,
             weaknet_dbus::kSignalConnectionModeChanged,
             weaknet_dbus::kSignalNetworkQualityChanged);
    return true;
}

// 非阻塞检查事件
extern "C" bool weaknet_check_events(char *event_type_buffer, size_t event_type_size,
                                     char *message_buffer, size_t message_size, int32_t *counter,
                                     char *source_buffer, size_t source_size, char *error_buffer,
                                     size_t error_size)
{
    if (!weaknet_dbus::g_client || !weaknet_dbus::g_client->isConnected()) {
        snprintf(error_buffer, error_size, "客户端未连接");
        return false;
    }

    std::string eventType, message, source;
    if (weaknet_dbus::g_client->checkForEvents(eventType, message, *counter, source)) {
        snprintf(event_type_buffer, event_type_size, "%s", eventType.c_str());
        snprintf(message_buffer, message_size, "%s", message.c_str());
        snprintf(source_buffer, source_size, "%s", source.c_str());
        return true;
    }

    snprintf(error_buffer, error_size, "没有检测到事件");
    return false;
}

// 检查客户端连接状态
extern "C" bool weaknet_is_connected()
{
    return weaknet_dbus::g_client && weaknet_dbus::g_client->isConnected();
}

// 获取WeakNet客户端库版本信息
extern "C" bool weaknet_get_version(char *buffer, size_t buffer_size)
{
    snprintf(buffer, buffer_size, "WeakNet Client Library v1.0.0");
    return true;
}

// 获取库的编译时间和编译选项信息
extern "C" bool weaknet_get_build_info(char *buffer, size_t buffer_size)
{
    snprintf(buffer, buffer_size, "Built: %s %s | DBus-enabled | C++17", __DATE__, __TIME__);
    return true;
}

// 订阅网络质量事件
extern "C" bool weaknet_subscribe_network_quality(weaknet_network_quality_callback_t callback)
{
    if (!weaknet_dbus::g_client || !weaknet_dbus::g_client->isConnected()) {
        return false;
    }

    // 创建C++回调包装器
    static weaknet_network_quality_callback_t s_callback = nullptr;
    s_callback = callback;

    auto cpp_callback = [](const std::string &quality, const std::string &details,
                           int32_t counter) -> bool {
        if (s_callback) {
            return s_callback(quality.c_str(), details.c_str(), counter);
        }
        return false;
    };

    return weaknet_dbus::g_client->subscribeToNetworkQuality(cpp_callback);
}

// 非阻塞检查网络质量事件
extern "C" bool weaknet_check_network_quality(char *quality_buffer, size_t quality_size,
                                              char *details_buffer, size_t details_size,
                                              int32_t *counter, char *error_buffer,
                                              size_t error_size)
{
    if (!weaknet_dbus::g_client || !weaknet_dbus::g_client->isConnected()) {
        snprintf(error_buffer, error_size, "客户端未连接");
        return false;
    }

    if (!weaknet_dbus::g_client->isConnected())
        return false;

    dbus_connection_read_write(weaknet_dbus::g_client->getConnection(), 0); // 非阻塞轮询
    DBusMessage *msg = dbus_connection_pop_message(weaknet_dbus::g_client->getConnection());
    if (!msg)
        return false;

    if (dbus_message_is_signal(msg, weaknet_dbus::kInterface,
                               weaknet_dbus::kSignalNetworkQualityChanged)) {
        const char *quality = nullptr;
        const char *details = nullptr;
        DBusError e;
        dbus_error_init(&e);

        if (dbus_message_get_args(msg, &e, DBUS_TYPE_STRING, &quality, DBUS_TYPE_STRING, &details,
                                  DBUS_TYPE_INT32, counter, DBUS_TYPE_INVALID)) {
            snprintf(quality_buffer, quality_size, "%s", quality ? quality : "");
            snprintf(details_buffer, details_size, "%s", details ? details : "");
            dbus_message_unref(msg);
            return true;
        } else if (dbus_error_is_set(&e)) {
            snprintf(error_buffer, error_size, "解析网络质量信号失败: %s", e.message);
            dbus_error_free(&e);
        }
    }

    dbus_message_unref(msg);
    snprintf(error_buffer, error_size, "没有检测到网络质量事件");
    return false;
}

// 注意: 此文件现在作为动态库使用，不包含main函数
// 所有的API通过C接口函数提供，供其他应用程序调用