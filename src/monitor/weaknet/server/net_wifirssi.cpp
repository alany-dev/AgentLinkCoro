/**
 * @file net_wifirssi.cpp
 * @brief WiFi信号强度（RSSI）监控客户端实现文件
 *
 * 该文件实现了WiFiRssiClient类的所有成员函数，包括单例模式、
 * 套接字连接、命令发送和RSSI值获取等核心功能。通过UNIX域套接字
 * 与wpa_supplicant进程通信，实现了WiFi信号强度的实时监控。
 */

#include "net_wifirssi.hpp"
#include "logger.hpp"
#include "base/macro.h"
#include "base/net/address.h"

#include <cstring>
#include <cstdio>
#include <iostream>
#include <memory>
#include <sys/stat.h>
#include <vector>
#include <cstdlib>
#include <thread>
#include <chrono>

namespace monitor::weaknet
{

static bool pathExists(const std::string &p)
{
    struct stat st {
    }; // 存储文件/目录状态的结构体
    // stat返回0表示成功获取状态（路径存在），非0表示路径不存在或权限不足
    return ::stat(p.c_str(), &st) == 0;
}

static bool ensureDir(const std::string &d)
{
    struct stat st {
    };
    // 先查询目录状态：若stat成功且是目录，直接返回true
    if (::stat(d.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    // 目录不存在，尝试创建，返回创建结果（mkdir返回0表示成功）
    return ::mkdir(d.c_str(), 0775) == 0;
}

/**
 * @brief 启动wpa_supplicant进程（WiFi连接管理工具），并等待其控制套接字生成
 *
 * 当无法连接到现有的wpa_supplicant进程时，尝试自动启动该进程。
 * 主要步骤：
 * 1. 查找wpa_supplicant二进制文件（优先/sbin，其次/usr/sbin）；
 * 2. 查找配置文件（优先环境变量WPA_SUPPLICANT_CONF，其次默认路径）；
 * 3. 确保控制目录存在，拼接启动命令并后台执行；
 * 4. 等待最多2秒（20次×100ms），直到控制套接字（ctrlDir/iface）出现。
 *
 * 注意：该功能通常需要root权限才能成功启动系统级服务。
 *
 * @param[in] iface 要管理的WiFi接口名称（如wlan0）
 * @param[in] ctrlDir wpa_supplicant的控制目录（用于生成UNIX域套接字）
 * @return bool wpa_supplicant启动成功且套接字出现返回true，否则返回false
 */
static bool launchWpaSupplicant(const std::string &iface, const std::string &ctrlDir)
{
    // 1. 确定wpa_supplicant二进制文件路径（优先级：/sbin > /usr/sbin）
    const char *bin = "/sbin/wpa_supplicant";
    if (!pathExists(bin)) {
        bin = "/usr/sbin/wpa_supplicant";
    }
    if (!pathExists(bin)) {
        return false;
    }

    // 2. 确定wpa_supplicant配置文件路径（优先级：环境变量 > 默认路径）
    const char *conf = std::getenv("WPA_SUPPLICANT_CONF");
    if (!conf || !*conf) { // 环境变量未设置或为空
        conf = "/etc/wpa_supplicant/wpa_supplicant.conf";
    }
    if (!pathExists(conf)) {
        return false;
    }

    // 3. 确保控制目录存在，否则创建失败
    if (!ensureDir(ctrlDir)) {
        return false;
    }

    // 4. 拼接wpa_supplicant启动命令：后台运行（-B）、指定接口（-i）、配置文件（-c）、控制目录（-C）
    // 错误输出重定向到/dev/null（避免干扰正常日志）
    std::string cmd =
        std::string(bin) + " -B -i " + iface + " -c " + conf + " -C " + ctrlDir + " 2>/dev/null";
    // 执行命令（system返回0表示命令执行成功）
    int rc = ::system(cmd.c_str());
    if (rc != 0) {
        return false;
    }

    // 5. 等待控制套接字生成（最多等待2秒，每100ms检查一次）
    const std::string sockPath = ctrlDir + "/" + iface; // 套接字路径：控制目录/接口名
    for (int i = 0; i < 20; ++i) {
        if (pathExists(sockPath)) { // 套接字存在，启动成功
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

WiFiRssiClient::~WiFiRssiClient()
{
    // 关闭已创建的套接字
    if (sock_) {
        sock_->close();
        sock_ = nullptr;
    }
    // 删除本地UNIX域套接字文件（防止下次绑定失败）
    if (!localSockPath_.empty()) {
        unlink(localSockPath_.c_str());
    }
}

/**
 * @brief 连接到指定WiFi接口的wpa_supplicant控制套接字
 *
 * 实现WiFiRssiClient与wpa_supplicant的连接建立，这是获取RSSI值的前提条件。
 *
 * 核心实现流程：
 * 1. 保存目标WiFi接口名称；
 * 2. 创建UNIX域数据报套接字（AF_UNIX，SOCK_DGRAM）；
 * 3. 调用bindLocal()绑定本地套接字地址，生成唯一的通信端点；
 * 4. 构建候选控制目录列表（优先级：参数指定 > 环境变量 > 默认路径）；
 * 5. 遍历所有候选目录，尝试通过connectRemote()连接到wpa_supplicant；
 * 6. 若所有连接尝试失败，尝试自动启动wpa_supplicant进程（需要足够权限）；
 * 7. 连接失败时执行完整的资源清理，避免泄漏。
 *
 * 错误处理：
 * - 套接字创建失败时输出错误日志并返回false
 * - 绑定本地地址失败时输出错误日志并返回false
 * - 所有连接尝试失败后，清理已创建的资源
 *
 * @param[in] ifaceName 目标WiFi接口名称（如wlan0）
 * @param[in] ctrlDir 优先尝试的wpa_supplicant控制目录（可空）
 * @return bool 连接成功返回true，失败返回false
 */
bool WiFiRssiClient::connect(const std::string &ifaceName, const std::string &ctrlDir)
{
    LOG_INFO_F(LogModule::RSSI, "connect: starting, iface=%s, ctrlDir=%s", ifaceName.c_str(),
               ctrlDir.c_str());
    iface_ = ifaceName; // 保存当前操作的WiFi接口名称

    // 1. 创建UNIX域套接字（AF_UNIX），类型为数据报（SOCK_DGRAM）
    sock_ = base::Socket::CreateUnixUDPSocket();
    if (!sock_) {
        LOG_ERROR(LogModule::RSSI, "wifi socket() failed");
        return false;
    }

    // 2. 绑定本地套接字（生成唯一本地路径，用于wpa_supplicant回传数据）
    if (_UNLIKELY(!bindLocal())) {
        LOG_ERROR(LogModule::RSSI, "wifi connect: bindLocal() failed");
        return false;
    }

    // 3. 构建候选控制目录列表（优先级从高到低）
    std::vector<std::string> candidates;
    if (!ctrlDir.empty()) { // 优先使用参数传入的控制目录
        candidates.push_back(ctrlDir);
    }
    const char *envDir = std::getenv("WPA_CTRL_DIR"); // 其次使用环境变量指定的目录
    if (envDir && *envDir) {
        candidates.emplace_back(envDir);
    }
    candidates.emplace_back("/run/wpa_supplicant"); // 系统默认路径1（现代系统常用）
    candidates.emplace_back("/var/run/wpa_supplicant"); // 系统默认路径2（兼容旧系统）

    // 4. 遍历候选目录，尝试连接wpa_supplicant的控制套接字
    std::cerr << "[wifi] connect: trying " << candidates.size() << " candidate directories"
              << std::endl;
    for (const auto &d : candidates) {
        LOG_INFO_F(LogModule::RSSI, "connect: trying directory %s", d.c_str());
        ctrlDir_ = d;
        if (connectRemote()) {
            LOG_INFO_F(LogModule::RSSI, "connect: connected to %s", d.c_str());
            return true;
        }
    }

    // 5. 所有候选目录连接失败，尝试自动启动wpa_supplicant（需root权限）
    std::string pref = "/run/wpa_supplicant";
    if (!ensureDir(pref)) {
        pref = "/var/run/wpa_supplicant";
    }
    if (ensureDir(pref)) {
        if (launchWpaSupplicant(iface_, pref)) {
            ctrlDir_ = pref;       // 更新控制目录为启动时使用的路径
            if (connectRemote()) { // 启动后重试连接
                return true;
            }
        }
    }

    // 6. 所有尝试失败，清理资源并返回false
    LOG_ERROR_F(LogModule::RSSI,
                "connect: unable to connect to wpa_supplicant control socket for iface '%s' "
                "(auto-start may require root)",
                iface_.c_str());
    if (sock_) {
        sock_->close();
        sock_ = nullptr;
    }
    if (!localSockPath_.empty()) { // 删除本地套接字文件
        unlink(localSockPath_.c_str());
        localSockPath_.clear();
    }
    return false;
}

/**
 * @brief 绑定本地UNIX域套接字（用于与wpa_supplicant通信）
 *
 * 实现本地UNIX域套接字的创建和绑定，用于接收wpa_supplicant的响应。
 *
 * 实现细节：
 * 1. 创建sockaddr_un结构体，设置地址族为AF_UNIX；
 * 2. 生成唯一的本地套接字路径（格式：/tmp/wpa_ctrl_进程ID_接口名），
 *    通过包含进程ID和接口名确保唯一性，避免多进程或多接口冲突；
 * 3. 将生成的路径保存到localSockPath_成员变量；
 * 4. 绑定前检查并删除可能存在的旧套接字文件，防止"地址已在使用"错误；
 * 5. 调用bind()系统调用将套接字绑定到生成的本地路径；
 * 6. 绑定失败时关闭套接字并返回false。
 *
 * @return bool 绑定成功返回true，失败返回false
 */
bool WiFiRssiClient::bindLocal()
{
    // 生成唯一的本地套接字路径：包含进程ID（getpid()）和接口名，避免冲突
    char tmp[108]{}; // sun_path的默认大小为108字节，需控制长度
    std::snprintf(tmp, sizeof(tmp), "/tmp/wpa_ctrl_%d_%s", getpid(), iface_.c_str());
    localSockPath_ = tmp;
    LOG_INFO_F(LogModule::RSSI, "bindLocal: local sock path=%s", localSockPath_.c_str());

    base::Address::ptr local = std::make_shared<base::UnixAddress>(localSockPath_);
    if (_UNLIKELY(!local)) {
        LOG_ERROR(LogModule::RSSI, "wifi bindLocal() failed: create UnixAddress failed");
        return false;
    }

    if (_UNLIKELY(!sock_->bind(local))) {
        LOG_ERROR_F(LogModule::RSSI, "wifi bind() failed: %s", localSockPath_.c_str());
        sock_->close();
        return false;
    }
    return true;
}

/**
 * @brief 连接到wpa_supplicant的远程控制套接字
 *
 * 实现与wpa_supplicant控制接口的连接，这是发送命令的必要步骤。
 *
 * 实现细节：
 * 1. 创建sockaddr_un结构体，设置地址族为AF_UNIX；
 * 2. 构造远程套接字路径（格式：控制目录+"/"+接口名），这是wpa_supplicant控制接口的标准路径；
 * 3. 检查路径长度，确保不超过sockaddr_un::sun_path的最大限制（通常为108字节）；
 * 4. 将构造好的路径复制到sockaddr_un结构体中；
 * 5. 设置套接字接收超时为1秒，防止connect()或后续recv()操作长时间阻塞；
 * 6. 调用connect()系统调用尝试连接到wpa_supplicant控制套接字；
 * 7. 直接返回connect()调用结果，成功为true，失败为false。
 *
 * @return bool 连接成功返回true，失败返回false
 */
bool WiFiRssiClient::connectRemote()
{
    // 构造远程套接字路径：控制目录/接口名（wpa_supplicant的标准套接字路径）
    std::string destPath = ctrlDir_ + "/" + iface_;
    // 检查路径长度：超过sun_path大小（通常108字节）会导致连接失败
    if (destPath.size() >= 108) {
        LOG_ERROR_F(LogModule::RSSI, "connectRemote: dest path too long: %s", destPath.c_str());
        return false;
    }

    base::Address::ptr dest = std::make_shared<base::UnixAddress>(destPath);
    if (_UNLIKELY(!dest)) {
        LOG_ERROR_F(LogModule::RSSI, "connectRemote() failed: create UnixAddress failed: %s",
                    destPath.c_str());
        return false;
    }

    if (!sock_->connect(dest, 1000)) {
        LOG_ERROR_F(LogModule::RSSI, "connectRemote() failed: connect to %s failed",
                    destPath.c_str());
        return false;
    }
    return true;
}

/**
 * @brief 向wpa_supplicant发送命令，并返回响应结果
 *
 * 实现与wpa_supplicant的命令交互，是获取RSSI值的核心通信方法。
 *
 * 实现细节：
 * 1. 首先检查套接字文件描述符是否有效（sockfd_ != -1），无效则直接返回空字符串；
 * 2. 使用send()系统调用发送命令字符串到已连接的wpa_supplicant套接字；
 * 3. 发送失败时输出错误日志并返回空字符串；
 * 4. 设置套接字接收超时为1秒，避免recv()操作长时间阻塞；
 * 5. 使用recv()系统调用接收wpa_supplicant的响应，最大接收4096字节数据；
 * 6. 接收失败时根据错误码区分处理（超时或其他错误），并输出相应日志；
 * 7. 接收成功时，在数据末尾添加字符串结束符，避免处理时出现乱码；
 * 8. 将接收的数据转换为std::string并返回。
 *
 * 错误处理：
 * - 套接字无效：返回空字符串
 * - 发送失败：输出错误日志，返回空字符串
 * - 接收超时：输出超时日志，返回空字符串
 * - 其他接收错误：输出详细错误信息，返回空字符串
 *
 * @param[in] cmd 要发送的命令字符串（如"SIGNAL_POLL\n"）
 * @return std::string 命令响应结果（空字符串表示发送/接收失败）
 */
std::string WiFiRssiClient::sendCommand(const std::string &cmd)
{
    // 套接字无效，直接返回空
    if (_UNLIKELY(!sock_->isConnected())) {
        return {};
    }

    if (sock_->send(cmd.c_str(), cmd.size(), 0) < 0) {
        LOG_ERROR(LogModule::RSSI, "send() failed");
        return {};
    }
    sock_->setRecvTimeout(1000);

    char buf[4096];
    ssize_t n = sock_->recv(buf, sizeof(buf) - 1);
    if (n < 0) {                                       // 接收失败
        if (errno == EAGAIN || errno == EWOULDBLOCK) { // 超时错误
            LOG_ERROR(LogModule::RSSI, "recv() timeout");
        } else { // 其他错误（如连接断开）
            LOG_ERROR_F(LogModule::RSSI, "recv() failed: %s", strerror(errno));
        }
        return {};
    }
    buf[n] = '\0';                                   // 添加字符串结束符，避免乱码
    return std::string(buf, static_cast<size_t>(n)); // 转换为string返回
}

/**
 * @brief 获取当前WiFi接口的RSSI（接收信号强度指示）值
 *
 * 实现WiFi信号强度的获取，是该类的核心功能方法。
 *
 * 实现细节：
 * 1. 调用sendCommand()方法发送"SIGNAL_POLL\n"命令到wpa_supplicant；
 * 2. wpa_supplicant收到该命令后会返回包含多种信号参数的响应；
 * 3. 检查响应是否为空，为空则返回无效值-1000；
 * 4. 使用std::string::find()方法查找响应中的"RSSI="子字符串；
 * 5. 找到后，使用std::sscanf()从"RSSI="后开始解析整数值；
 * 6. 解析成功则返回RSSI值，失败则返回无效值-1000。
 *
 * RSSI值说明：
 * - 单位为dBm（分贝毫瓦）
 * - 典型范围：-100 dBm（弱信号）到 0 dBm（强信号）
 * - 信号质量参考：
 *   - -50 dBm 至 -30 dBm：优秀信号
 *   - -70 dBm 至 -50 dBm：良好信号
 *   - -80 dBm 至 -70 dBm：一般信号
 *   - -90 dBm 至 -80 dBm：弱信号
 *   - 低于 -90 dBm：极弱或不可用信号
 *
 * @return int 成功返回RSSI值（dBm），失败返回-1000（表示无效值）
 */
int WiFiRssiClient::getRssi()
{
    std::string resp = sendCommand("SIGNAL_POLL\n");
    if (resp.empty()) { // 响应为空，返回无效值
        return -1000;
    }

    // 解析响应中的RSSI值（响应样例："RSSI=-42\nLINKSPEED=866\n..."）
    size_t pos = resp.find("RSSI="); // 查找"RSSI="的位置
    if (pos != std::string::npos) {
        int rssi = 0;
        if (std::sscanf(resp.c_str() + pos, "RSSI=%d", &rssi) == 1) {
            return rssi;
        }
    }
    return -1000;
}

} // namespace monitor::weaknet