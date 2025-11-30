// dbus_service.cpp
// 实现 DBus 服务类：方法处理与信号发送
//
// 该文件实现了 DbusService 类的所有方法，包括：
// - D-Bus 消息的接收与处理
// - 各种方法调用的具体实现（Get、ListInterfaces、Ping 等）
// - 不同类型信号的发送逻辑
// - 网络状态变化通知
// - 网络质量监控与诊断

#include <cstdio>
#include <cstring>
#include "logger.hpp"
#include "common.hpp"
#include "serializer.hpp"
#include "server.hpp"
#include "dbus_service.hpp"
#include "event_manager.hpp"
#include "net_info.hpp"
#include "net_ping.hpp"

namespace monitor::weaknet
{

/**
 * @brief DbusService构造函数
 * @param server WeakNetServer指针，包含连接信息和共享资源
 *
 * 初始化DbusService实例，保存服务器上下文指针供后续方法调用使用。
 */
DbusService::DbusService(WeakNetServer *server) : server_(server)
{
}

/**
 * @brief 静态消息处理函数，作为D-Bus消息的入口点
 * @param conn D-Bus连接对象指针
 * @param msg 接收到的D-Bus消息对象指针
 * @param user_data 用户数据指针，实际指向DbusService实例
 * @return 消息处理结果，表示消息是否已处理
 *
 * 该函数是D-Bus消息的静态入口点，负责根据消息类型将调用转发到相应的处理方法。
 * 它解析消息类型，然后调用对应的成员函数进行实际处理。
 */
static DBusHandlerResult MessageHandlerStatic(DBusConnection *conn, DBusMessage *msg,
                                              void *user_data)
{
    // 将用户数据转换为DbusService指针
    auto *self = reinterpret_cast<DbusService *>(user_data);
    // 验证指针有效性
    if (!self)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    // 根据不同的方法名分发到对应的处理函数
    // 处理 Get 方法
    if (dbus_message_is_method_call(msg, kInterface, kMethodGet)) {
        self->handleGet(conn, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    // 处理 ListInterfaces 方法
    if (dbus_message_is_method_call(msg, kInterface, kMethodListInterfaces)) {
        self->handleListInterfaces(conn, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    // 处理 GetInterfaces 方法（与ListInterfaces功能相同）
    if (dbus_message_is_method_call(msg, kInterface, kMethodGetInterfaces)) {
        self->handleListInterfaces(conn, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    // 处理 Ping 方法
    if (dbus_message_is_method_call(msg, kInterface, kMethodPing)) {
        self->handlePing(conn, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    // 未处理的消息，返回未处理结果
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/**
 * @brief 在D-Bus连接上注册对象路径和消息处理器
 * @param conn D-Bus连接对象指针
 * @return 注册成功返回true，失败返回false
 *
 * 该方法负责在D-Bus连接上注册对象路径，并将静态消息处理函数与该路径关联。
 * 这使得D-Bus守护进程能够将发送到该对象路径的消息正确地路由到应用程序。
 */
bool DbusService::register_on_connection(DBusConnection *conn)
{
    // 初始化对象路径虚拟表，用于定义对象路径的行为
    static DBusObjectPathVTable vtable{};
    // 设置消息处理函数，当消息到达时将调用MessageHandlerStatic
    vtable.message_function = &MessageHandlerStatic;

    // 注册对象路径，将对象路径与虚拟表和用户数据（this指针）关联起来
    return dbus_connection_register_object_path(conn, kObjectPath, &vtable, this);
}

/**
 * @brief 发送DBus信号通知接口变化，并将变化信息序列化到文件
 * @param message 接口变化的详细描述信息（如新增/移除的接口列表）
 * @param counter 变化计数器（用于标识不同的变化事件，递增以区分）
 * @return 信号发送是否成功（true表示发送成功，false表示失败）
 *
 * 该函数负责创建并发送DBus信号，通知外部（如其他进程）网络接口发生了变化，
 * 同时将变化信息（消息和计数器）序列化到文件中，可能用于持久化记录或调试。
 */
bool DbusService::emitChanged(const std::string &message, int32_t counter)
{
    // 创建DBus信号消息：参数分别为信号路径（kObjectPath）、接口名（kInterface）、信号名（kSignalChanged）
    // 信号用于通知其他DBus客户端“接口已变化”的事件
    DBusMessage *sig = dbus_message_new_signal(kObjectPath, kInterface, kSignalChanged);
    if (!sig) { // 信号创建失败时返回false
        return false;
    }

    // 初始化消息迭代器，用于向信号中添加参数
    DBusMessageIter args;
    dbus_message_iter_init_append(sig, &args);

    // 将message字符串作为第一个参数添加到信号中（DBUS_TYPE_STRING类型）
    const char *s = message.c_str();
    if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &s)) {
        // 参数添加失败时，释放信号对象并返回false
        dbus_message_unref(sig);
        return false;
    }

    // 将counter作为第二个参数添加到信号中（DBUS_TYPE_INT32类型）
    if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, &counter)) {
        // 参数添加失败时，释放信号对象并返回false
        dbus_message_unref(sig);
        return false;
    }

    // 发送信号到DBus连接：
    // server_->getDbusConnection()是当前DBus连接对象，nullptr表示不关心消息序列号
    bool ok = dbus_connection_send(server_->getDbusConnection(), sig, nullptr);
    // 刷新连接，确保信号立即发送（避免缓冲延迟）
    dbus_connection_flush(server_->getDbusConnection());
    // 释放信号对象（DBus对象需手动管理生命周期）
    dbus_message_unref(sig);

    // 构建变化信息的payload（包含消息和计数器）
    ChangedPayload payload{message, counter};
    std::string err; // 用于存储序列化过程中的错误信息
    // 将payload序列化到文件（kSignalSerializedFile为目标文件路径）
    // 该操作可能用于持久化记录变化事件，方便后续排查或恢复
    serializeChangedPayloadToFile(payload, kSignalSerializedFile, &err);

    // 返回信号发送是否成功的结果
    return ok;
}

// MessageHandler 实现已移动到静态自由函数

/**
 * @brief 处理D-Bus服务的"Get"方法调用，生成回复并发送，同时将回复序列化到文件
 * @param conn D-Bus连接对象指针，用于发送回复消息
 * @param msg 接收到的D-Bus方法调用消息指针，包含客户端的请求信息
 * @return 处理成功返回true，失败返回false
 */
bool DbusService::handleGet(DBusConnection *conn, DBusMessage *msg)
{
    // 定义回复文本内容，将作为"Get"方法的返回数据
    const char *reply_text = "Hello from WeakNet Server";

    // 创建方法调用的回复消息：与原请求消息(msg)关联，确保D-Bus总线能正确路由回复到对应客户端
    DBusMessage *reply = dbus_message_new_method_return(msg);
    // 若回复消息创建失败（如内存不足），直接返回失败
    if (!reply)
        return false;

    // 定义D-Bus消息迭代器，用于向回复消息中添加参数（D-Bus消息参数通过迭代器构建）
    DBusMessageIter args;
    // 初始化迭代器，使其可用于向reply消息追加参数
    dbus_message_iter_init_append(reply, &args);

    // 将回复文本赋值给临时变量（D-Bus要求传入参数的指针地址，此处确保指针有效性）
    const char *s = reply_text;
    // 向回复消息中追加字符串类型参数：类型为DBUS_TYPE_STRING，数据为s指向的字符串
    // 若追加失败（如参数类型不匹配或内存不足），释放回复消息并返回失败
    if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &s)) {
        dbus_message_unref(reply); // 释放回复消息（减少引用计数，避免内存泄漏）
        return false;
    }

    // 通过D-Bus连接发送回复消息：conn为连接对象，reply为待发送消息，nullptr表示不关心序列号
    // 若发送失败（如连接断开），释放回复消息并返回失败
    if (!dbus_connection_send(conn, reply, nullptr)) {
        dbus_message_unref(reply);
        return false;
    }

    // 刷新D-Bus连接，确保发送队列中的消息被立即发送（避免消息滞留于缓冲区）
    dbus_connection_flush(conn);

    // 释放回复消息（此时消息已发送，不再需要，减少引用计数至0时自动销毁）
    dbus_message_unref(reply);

    // 定义错误信息字符串，用于接收序列化过程中的错误描述
    std::string err;
    // 将回复文本序列化到指定文件（自定义功能，可能用于日志或持久化）
    serializeGetReplyToFile(reply_text, kGetReplySerializedFile, &err);

    // 所有步骤执行成功，返回true
    return true;
}

/**
 * @brief 处理D-Bus服务的消息回复，向客户端返回一个字符串数组
 * @param conn D-Bus连接对象指针，用于发送回复消息
 * @param msg 接收到的客户端请求消息指针，用于关联回复消息的路由
 * @param arr 待返回的字符串数组（std::vector<std::string>类型）
 * @return 回复发送成功返回true，失败返回false
 */
bool DbusService::replyStringArray(DBusConnection *conn, DBusMessage *msg,
                                   const std::vector<std::string> &arr)
{
    // 创建与请求消息关联的回复消息，确保D-Bus总线能将回复正确路由到客户端
    DBusMessage *reply = dbus_message_new_method_return(msg);
    // 若回复消息创建失败（如内存不足），返回失败
    if (!reply)
        return false;

    // 定义外层消息迭代器，用于构建回复消息的整体结构
    DBusMessageIter iter;
    // 初始化外层迭代器，使其可用于向reply消息追加内容
    dbus_message_iter_init_append(reply, &iter);

    // 定义数组专用迭代器，用于向数组容器中添加元素
    DBusMessageIter array_iter;
    // 打开一个数组类型的容器：外层迭代器为iter，容器类型为DBUS_TYPE_ARRAY，
    // 数组元素类型为字符串（DBUS_TYPE_STRING_AS_STRING是"string"的宏定义，对应DBUS_TYPE_STRING），
    // 数组迭代器array_iter用于后续添加元素
    if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING,
                                          &array_iter)) {
        dbus_message_unref(reply); // 打开容器失败，释放回复消息
        return false;
    }

    // 遍历输入的字符串数组，将每个字符串添加到D-Bus数组容器中
    for (const auto &s : arr) {
        // 将std::string转换为C风格字符串（const char*）
        const char *cs = s.c_str();
        // 向数组迭代器中追加字符串类型的基本元素（DBUS_TYPE_STRING）
        if (!dbus_message_iter_append_basic(&array_iter, DBUS_TYPE_STRING, &cs)) {
            // 追加失败时，先关闭已打开的数组容器，再释放回复消息，避免资源泄漏
            dbus_message_iter_close_container(&iter, &array_iter);
            dbus_message_unref(reply);
            return false;
        }
    }

    // 关闭数组容器，完成数组的构建（必须与open_container配对使用）
    if (!dbus_message_iter_close_container(&iter, &array_iter)) {
        dbus_message_unref(reply); // 关闭容器失败，释放回复消息
        return false;
    }

    // 通过D-Bus连接发送回复消息，nullptr表示不关心消息序列号
    bool ok = dbus_connection_send(conn, reply, nullptr);
    // 刷新连接，确保消息立即发送（避免滞留于缓冲区）
    dbus_connection_flush(conn);
    // 释放回复消息（已发送，不再需要）
    dbus_message_unref(reply);

    // 返回发送结果（true表示消息成功加入发送队列）
    return ok;
}

/**
 * @brief 处理ListInterfaces和GetInterfaces方法调用
 * @param conn D-Bus连接对象指针，用于发送回复消息
 * @param msg 请求消息对象指针
 * @return 处理成功返回true，失败返回false
 *
 * 该方法获取当前系统中的所有网络接口名称，并以字符串数组的形式返回给客户端。
 */
bool DbusService::handleListInterfaces(DBusConnection *conn, DBusMessage *msg)
{
    // 使用replyStringArray方法将字符串数组作为D-Bus回复发送给客户端
    return replyStringArray(conn, msg, server_->getIfaceNames());
}

/**
 * @brief 发送特定名称的DBus信号，携带消息和计数器参数
 * @param signalName 要发送的DBus信号名称（标识具体事件类型）
 * @param message 信号携带的字符串消息（描述事件详情）
 * @param counter 事件计数器（用于区分不同的事件实例，通常递增）
 * @return 信号发送是否成功（true表示发送成功，false表示失败）
 *
 * 该函数是通用的DBus信号发送接口，可根据传入的信号名称发送特定事件，
 * 适用于需要区分多种信号类型的场景。信号会携带字符串消息和整数计数器，
 * 并在发送后记录日志便于调试。
 */
bool DbusService::emitSpecificSignal(const std::string &signalName, const std::string &message,
                                     int32_t counter)
{
    // 安全性检查：确保上下文和DBus连接有效（避免空指针访问）
    if (!server_ || !server_->getDbusConnection())
        return false;

    // 创建DBus信号消息：参数分别为信号路径（kObjectPath）、接口名（kInterface）、目标信号名（signalName）
    // 信号路径和接口名固定，信号名由外部指定，实现“特定信号”的发送
    DBusMessage *signal = dbus_message_new_signal(kObjectPath, kInterface, signalName.c_str());
    // dbus_message_new_signal(kObjectPath, kInterface, kSignalChanged);
    if (!signal) { // 信号对象创建失败（如内存不足），返回失败
        return false;
    }

    // 初始化消息迭代器，用于向信号中追加参数（DBus消息参数通过迭代器添加）
    DBusMessageIter iter;
    dbus_message_iter_init_append(signal, &iter);

    // 向信号中添加第一个参数：消息字符串（DBUS_TYPE_STRING类型）
    const char *msg = message.c_str(); // 转换std::string为C字符串（DBus接口要求）
    if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &msg)) {
        // 参数添加失败时，释放已创建的信号对象（避免内存泄漏）并返回失败
        dbus_message_unref(signal);
        return false;
    }

    // 向信号中添加第二个参数：计数器（DBUS_TYPE_INT32类型）
    if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &counter)) {
        // 参数添加失败时，释放信号对象并返回失败
        dbus_message_unref(signal);
        return false;
    }

    // 发送信号到DBus连接：
    // server_->getDbusConnection()为当前有效的DBus连接，nullptr表示无需跟踪消息序列号
    bool ok = dbus_connection_send(server_->getDbusConnection(), signal, nullptr);
    // 刷新连接缓冲区，确保信号立即发送（避免延迟，适用于需要实时通知的场景）
    dbus_connection_flush(server_->getDbusConnection());
    // 释放信号对象（DBus对象需手动管理生命周期，避免内存泄漏）
    dbus_message_unref(signal);

    // 记录日志：输出发送的信号名称、消息内容和计数器，便于调试和事件追踪
    LOG_INFO(LogModule::DBUS, "emitted signal: " << signalName << ", message='" << message
                                                 << "', counter=" << counter);

    // 返回信号发送结果（true表示发送成功，false表示发送失败）
    return ok;
}

bool DbusService::emitNetworkQualitySignal(const std::string &message, const std::string &details,
                                           int32_t counter)
{
    if (!server_ || !server_->getDbusConnection())
        return false;

    DBusMessage *signal =
        dbus_message_new_signal(kObjectPath, kInterface, kSignalNetworkQualityChanged);
    if (!signal)
        return false;

    DBusMessageIter iter;
    dbus_message_iter_init_append(signal, &iter);

    // 添加质量等级参数
    const char *quality = message.c_str();
    if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &quality)) {
        dbus_message_unref(signal);
        return false;
    }

    // 添加详细信息参数
    const char *details_str = details.c_str();
    if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &details_str)) {
        dbus_message_unref(signal);
        return false;
    }

    // 添加计数器参数
    if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &counter)) {
        dbus_message_unref(signal);
        return false;
    }

    bool ok = dbus_connection_send(server_->getDbusConnection(), signal, nullptr);
    dbus_connection_flush(server_->getDbusConnection());
    dbus_message_unref(signal);

    LOG_INFO(LogModule::DBUS, "emitted network quality signal: quality='"
                                  << message << "', details='" << details
                                  << "', counter=" << counter);
    return ok;
}

/**
 * @brief 处理D-Bus服务的"Ping"方法调用，解析客户端传入的主机名，通过活跃网卡执行ping测试并返回结果
 * @param conn D-Bus连接对象指针，用于发送回复消息
 * @param msg 接收到的客户端Ping请求消息，包含待ping的主机名参数
 * @return
 * 处理成功（无论ping成功与否，只要消息流程正常）返回true；处理失败（如消息创建/发送失败）返回false
 */
bool DbusService::handlePing(DBusConnection *conn, DBusMessage *msg)
{
    // 记录日志：Ping处理函数被调用
    LOG_INFO(LogModule::DBUS, "handlePing called");

    // 解析参数：从请求消息中提取目标主机名
    DBusError err;         // D-Bus错误对象，用于存储参数解析过程中的错误信息
    dbus_error_init(&err); // 初始化错误对象（必须先初始化才能使用）
    const char *hostname = nullptr; // 用于存储解析出的主机名字符串

    // 从消息中提取参数：期望1个字符串类型（DBUS_TYPE_STRING）参数，后续以DBUS_TYPE_INVALID结束
    // 若解析失败（如参数类型不匹配、数量错误），err会被设置错误信息
    if (!dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &hostname, DBUS_TYPE_INVALID)) {
        // 记录参数解析错误日志
        LOG_ERROR(LogModule::DBUS, "Ping method error: " << err.message);
        dbus_error_free(&err); // 释放错误对象（避免内存泄漏）

        // 发送错误回复：创建错误消息，错误名称为"com.example.WeakNet.Error"，描述为"Invalid
        // arguments"
        DBusMessage *reply =
            dbus_message_new_error(msg, "com.example.WeakNet.Error", "Invalid arguments");
        dbus_connection_send(conn, reply, nullptr); // 发送错误消息
        dbus_message_unref(reply);                  // 释放错误消息
        return false;                               // 解析参数失败，返回false
    }

    // 检查主机名是否为空（解析成功但主机名为空字符串）
    if (!hostname || strlen(hostname) == 0) {
        LOG_ERROR(LogModule::DBUS, "Ping method error: empty hostname");

        // 发送错误回复：提示主机名为空
        DBusMessage *reply =
            dbus_message_new_error(msg, "com.example.WeakNet.Error", "Empty hostname");
        dbus_connection_send(conn, reply, nullptr);
        dbus_message_unref(reply);
        return false;
    }

    // 记录日志：获取到的ping目标主机名
    LOG_INFO(LogModule::DBUS, "Ping request for host: " << hostname);

    // 获取当前正在使用的上网网卡（活跃网卡）
    std::string currentIface = server_->getCurrentIface();

    // 检查是否找到活跃网卡
    if (currentIface.empty()) {
        LOG_ERROR(LogModule::DBUS, "Ping method error: no active interface found");

        // 发送错误回复：提示无活跃网卡
        DBusMessage *reply =
            dbus_message_new_error(msg, "com.example.WeakNet.Error", "No active network interface");
        dbus_connection_send(conn, reply, nullptr);
        dbus_message_unref(reply);
        return false;
    }

    // 记录日志：使用的活跃网卡名称
    LOG_INFO(LogModule::DBUS, "Using interface: " << currentIface << " for ping to " << hostname);

    // 执行ping：参数为目标主机名、使用的网卡、超时时间（3000ms）
    // 返回值：>=0表示ping成功（往返时间，单位ms）；<0表示失败（错误码）
    int pingResult = NetPing::ping(hostname, currentIface, 3000);

    // 构建回复消息（正常回复，非错误）
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply) { // 回复消息创建失败（如内存不足）
        LOG_ERROR(LogModule::DBUS, "Failed to create ping reply message");
        return false;
    }

    // 初始化回复消息的参数迭代器
    DBusMessageIter args;
    dbus_message_iter_init_append(reply, &args);

    // 构建ping结果字符串
    std::string result;
    if (pingResult >= 0) {
        // ping成功：拼接主机名、网卡、往返时间
        result = std::string("PING ") + hostname + " via " + currentIface + ": "
                 + std::to_string(pingResult) + "ms";
        LOG_INFO(LogModule::DBUS, "Ping successful: " << result);
    } else {
        // ping失败：拼接主机名、网卡、错误码
        result = std::string("PING ") + hostname + " via " + currentIface
                 + ": FAILED (error code: " + std::to_string(pingResult) + ")";
        LOG_INFO(LogModule::DBUS, "Ping failed: " << result);
    }

    // 将结果字符串转换为C风格字符串，准备添加到回复消息
    const char *resultStr = result.c_str();
    // 向回复消息中添加字符串参数
    if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &resultStr)) {
        LOG_ERROR(LogModule::DBUS, "Failed to append ping result to reply");
        dbus_message_unref(reply); // 添加失败，释放回复消息
        return false;
    }

    // 发送回复消息
    bool ok = dbus_connection_send(conn, reply, nullptr);
    dbus_connection_flush(conn); // 刷新连接，确保消息立即发送
    dbus_message_unref(reply);   // 释放回复消息

    // 打印调试信息：回复发送结果
    std::printf("[dbus] Ping reply sent: %s\n", ok ? "success" : "failed");
    return ok; // 返回发送结果
}

} // namespace monitor::weaknet
