// dbus_service.hpp
// 封装 DBus 方法处理与信号发送
//
// 该头文件定义了 DbusService 类，用于处理 D-Bus 服务的方法调用和信号发送
// 提供了网络接口信息查询、网络质量监控和网络诊断等功能的 D-Bus 接口封装

#pragma once
#include <dbus/dbus.h>
#include <string>
#include <vector>
#include <mutex>

namespace monitor::weaknet
{

class WeakNetServer;

/**
 * @class DbusService
 * @brief D-Bus 服务类，负责处理 D-Bus 方法调用和发送信号通知
 *
 * 该类封装了所有与 D-Bus 通信相关的功能，包括方法注册、消息处理和信号发送
 * 是整个网络诊断服务对外暴露接口的核心组件
 */
class DbusService
{
public:
    /**
     * @brief 构造函数
     * @param ctx 服务器上下文指针，包含连接信息和共享资源
     */
    explicit DbusService(WeakNetServer *server);

    /**
     * @brief 默认析构函数
     */
    ~DbusService() = default;

    /**
     * @brief 在 D-Bus 连接上注册对象路径和消息处理器
     * @param conn D-Bus 连接对象指针
     * @return 注册成功返回 true，失败返回 false
     */
    bool register_on_connection(DBusConnection *conn);

    /**
     * @brief 发送接口变化信号
     * @param message 接口变化的详细描述信息
     * @param counter 变化计数器，用于标识不同的变化事件
     * @return 信号发送成功返回 true，失败返回 false
     */
    bool emitChanged(const std::string &message, int32_t counter);

    /**
     * @brief 发送特定类型的事件信号
     * @param signalName 要发送的信号名称
     * @param message 信号携带的消息内容
     * @param counter 事件计数器
     * @return 信号发送成功返回 true，失败返回 false
     */
    bool emitSpecificSignal(const std::string &signalName, const std::string &message,
                            int32_t counter);

    /**
     * @brief 发送网络质量变化信号
     * @param message 网络质量等级描述
     * @param details 网络质量详细信息
     * @param counter 事件计数器
     * @return 信号发送成功返回 true，失败返回 false
     */
    bool emitNetworkQualitySignal(const std::string &message, const std::string &details,
                                  int32_t counter);

    /**
     * @brief 处理 Get 方法调用
     * @param conn D-Bus 连接对象指针
     * @param msg 请求消息对象指针
     * @return 处理成功返回 true，失败返回 false
     */
    bool handleGet(DBusConnection *conn, DBusMessage *msg);

    /**
     * @brief 处理 ListInterfaces/GetInterfaces 方法调用
     * @param conn D-Bus 连接对象指针
     * @param msg 请求消息对象指针
     * @return 处理成功返回 true，失败返回 false
     */
    bool handleListInterfaces(DBusConnection *conn, DBusMessage *msg);

    /**
     * @brief 处理 Ping 方法调用
     * @param conn D-Bus 连接对象指针
     * @param msg 请求消息对象指针
     * @return 处理成功返回 true，失败返回 false
     */
    bool handlePing(DBusConnection *conn, DBusMessage *msg);

private:
    /**
     * @brief 向客户端返回字符串数组
     * @param conn D-Bus 连接对象指针
     * @param msg 请求消息对象指针
     * @param arr 要返回的字符串数组
     * @return 回复发送成功返回 true，失败返回 false
     */
    bool replyStringArray(DBusConnection *conn, DBusMessage *msg,
                          const std::vector<std::string> &arr);

private:
    /**
     * @brief 服务器上下文指针，包含共享资源和连接信息
     */
    WeakNetServer *server_;
};

} // namespace monitor::weaknet
