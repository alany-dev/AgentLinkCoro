#include "dns_client.h"
#include "base/net/socket.h"
#include "base/bytearray.h"
#include "base/coro/iomanager.h"
#include "base/log/log.h"
#include <arpa/inet.h>
#include <cstring>
#include <cstdio>
#include <vector>
#include <random>

namespace base
{
static base::Logger::ptr g_logger = _LOG_NAME("system");

// 辅助类：用于安全地解析 DNS 数据包，防止越界
class DnsPacketReader {
public:
    DnsPacketReader(const std::string& buffer) 
        : data_(reinterpret_cast<const uint8_t*>(buffer.data())), size_(buffer.size()), pos_(0) {}

    size_t remaining() const { return pos_ < size_ ? size_ - pos_ : 0; }
    
    // 安全跳过指定字节
    bool skip(size_t len) {
        if (pos_ + len > size_) return false;
        pos_ += len;
        return true;
    }

    // 读取 uint8
    bool readU8(uint8_t& out) {
        if (pos_ + 1 > size_) return false;
        out = data_[pos_++];
        return true;
    }

    // 读取 uint16 (网络字节序转主机字节序)
    bool readU16(uint16_t& out) {
        if (pos_ + 2 > size_) return false;
        uint16_t val;
        memcpy(&val, data_ + pos_, 2);
        out = ntohs(val);
        pos_ += 2;
        return true;
    }

    // 读取 uint32
    bool readU32(uint32_t& out) {
        if (pos_ + 4 > size_) return false;
        uint32_t val;
        memcpy(&val, data_ + pos_, 4);
        out = ntohl(val);
        pos_ += 4;
        return true;
    }

    // 读取原始字节到缓冲区
    bool readBytes(void* dest, size_t len) {
        if (pos_ + len > size_) return false;
        memcpy(dest, data_ + pos_, len);
        pos_ += len;
        return true;
    }

    // 解析域名（支持压缩指针防循环）
    // jumps_allowed: 防止死循环的最大跳转次数
    bool readDomainName(std::string& out_name, int jumps_allowed = 5) {
        out_name.clear();
        size_t current_pos = pos_;
        bool jumped = false;
        size_t final_pos = pos_; // 如果发生了跳转，最后要恢复到的位置

        int jump_count = 0;
        
        while (true) {
            if (current_pos >= size_) return false;
            
            uint8_t len = data_[current_pos];
            
            // 检查是否为压缩指针 (高两位为 11)
            if ((len & 0xC0) == 0xC0) {
                if (jump_count++ > jumps_allowed) return false; // 防止循环指针
                if (current_pos + 1 >= size_) return false;

                // 计算偏移量: ((Byte1 & 0x3F) << 8) | Byte2
                uint16_t offset = ((len & 0x3F) << 8) | data_[current_pos + 1];
                
                if (!jumped) {
                    final_pos = current_pos + 2; // 记录第一次跳转前的下一个位置
                    jumped = true;
                }
                
                current_pos = offset; // 跳转
            } 
            else if (len == 0) {
                // 域名结束
                if (!jumped) {
                    final_pos = current_pos + 1;
                }
                break;
            } 
            else {
                // 普通标签
                current_pos++;
                if (current_pos + len > size_) return false;
                
                if (!out_name.empty()) {
                    out_name.push_back('.');
                }
                out_name.append(reinterpret_cast<const char*>(data_ + current_pos), len);
                current_pos += len;
            }
        }

        pos_ = final_pos; // 更新读取游标
        return true;
    }

private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_;
};

// 填充 DNS 头部
int AsyncDnsResolver::dns_create_header(struct dns_header &header)
{
    memset(&header, 0, sizeof(struct dns_header));
    
    // 使用更现代的随机数生成方式
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint16_t> dist(0, 65535);
    
    header.id = htons(dist(rng));
    header.flags = htons(0x0100); // QR=0(Query), RD=1(Recursion Desired)
    header.questions = htons(1);
    return 0;
}

// 构造 Question 部分
int AsyncDnsResolver::dns_create_question(struct dns_question &question,
                                          const std::string &hostname)
{
    if (hostname.empty()) return -1;

    question.name.clear();
    question.qtype = htons(DNS_HOST); // A Record
    question.qclass = htons(1);       // IN Class

    // 预留空间，避免频繁 realloc
    question.name.reserve(hostname.size() + 2);

    size_t start = 0;
    size_t len = hostname.length();

    while (start < len) {
        size_t dot_pos = hostname.find('.', start);
        size_t label_len;
        
        if (dot_pos == std::string::npos) {
            label_len = len - start;
        } else {
            label_len = dot_pos - start;
        }

        if (label_len > 63 || label_len == 0) {
            return -1; // 标签过长或为空
        }

        question.name.push_back(static_cast<char>(label_len));
        question.name.append(hostname, start, label_len);

        if (dot_pos == std::string::npos) break;
        start = dot_pos + 1;
    }

    question.name.push_back('\0'); // 根域结束符
    return 0;
}

// 构造完整的请求报文
int AsyncDnsResolver::dns_build_requestion(struct dns_header &header, struct dns_question &question,
                                           std::string &request)
{
    request.clear();
    // 预分配大致大小
    request.reserve(sizeof(header) + question.name.size() + 4);

    // 1. Header
    request.append(reinterpret_cast<const char*>(&header), sizeof(header));

    // 2. Question Name
    request.append(question.name);

    // 3. QType & QClass
    request.append(reinterpret_cast<const char*>(&question.qtype), sizeof(question.qtype));
    request.append(reinterpret_cast<const char*>(&question.qclass), sizeof(question.qclass));

    return request.size();
}

// 解析响应报文
int AsyncDnsResolver::dns_parse_response(const std::string &buffer,
                                         std::vector<struct dns_item> &items)
{
    DnsPacketReader reader(buffer);
    struct dns_header header;
    
    // 1. 读取 Header
    if (!reader.readBytes(&header, sizeof(header))) return -1;

    uint16_t q_count = ntohs(header.questions);
    uint16_t a_count = ntohs(header.answers);
    // 我们主要关心 answers，但也需要正确跳过 Authority 和 Additional
    // uint16_t auth_count = ntohs(header.authority);
    // uint16_t add_count = ntohs(header.additional);

    // 2. 跳过 Questions 部分 (通常响应包会附带请求的问题)
    std::string temp_name;
    for (int i = 0; i < q_count; ++i) {
        if (!reader.readDomainName(temp_name)) return -2;
        if (!reader.skip(4)) return -2; // 跳过 QTYPE(2) + QCLASS(2)
    }

    // 3. 解析 Answers
    int found = 0;
    for (int i = 0; i < a_count; ++i) {
        std::string aname;
        uint16_t type, class_val, data_len;
        uint32_t ttl;

        // 解析 Name
        if (!reader.readDomainName(aname)) break;

        // 解析 Type, Class, TTL, DataLen
        if (!reader.readU16(type) || 
            !reader.readU16(class_val) || 
            !reader.readU32(ttl) || 
            !reader.readU16(data_len)) {
            break;
        }

        if (type == DNS_CNAME) {
            // CNAME 记录，data 是域名
            // 可以在这里处理 CNAME 别名，如果需要的话
            // reader.readDomainName(cname_str); // 需要根据 data_len 限制读取范围吗？通常 readDomainName 处理压缩
            // 这里简单跳过数据部分
            if (!reader.skip(data_len)) break;
        } 
        else if (type == DNS_HOST) { // A 记录 (IPv4)
            if (data_len == 4) {
                uint8_t ip_raw[4];
                if (reader.readBytes(ip_raw, 4)) {
                    char ip_str[INET_ADDRSTRLEN];
                    if (inet_ntop(AF_INET, ip_raw, ip_str, sizeof(ip_str))) {
                        struct dns_item item;
                        item.domain = aname;
                        item.ip = ip_str;
                        items.push_back(item);
                        found++;
                    }
                }
            } else {
                reader.skip(data_len);
            }
        } 
        else {
            // 其他记录，跳过
            if (!reader.skip(data_len)) break;
        }
    }

    return found;
}

int AsyncDnsResolver::resolveAny(const std::string &domain, std::string &domain_ip, const std::string &server_ip)
{
    auto sockfd_ = std::make_shared<base::Socket>(AF_INET, SOCK_DGRAM, 0);
    auto dns_server_addr_ = Address::LookupAny(server_ip);

    sockfd_->connect(dns_server_addr_);

    if (!sockfd_) {
        _LOG_ERROR(g_logger) << "Socket not initialized";
        return -1;
    }

    struct dns_header header;
    dns_create_header(header);

    struct dns_question question;
    if (dns_create_question(question, domain) != 0) {
        return -1;
    }

    std::string request;
    dns_build_requestion(header, question, request);

    // 发送
    int rt = sockfd_->send(request.data(), request.size());
    if (rt < 0) {
        _LOG_ERROR(g_logger) << "DNS send failed: " << strerror(errno);
        return -1;
    }

    // 接收
    std::string response;
    response.resize(4096); // 给足空间
    rt = sockfd_->recv(&response[0], response.size());
    if (rt <= 0) {
        return -1;
    }
    response.resize(rt); // 调整为实际大小

    std::vector<struct dns_item> dns_items;
    int cnt = dns_parse_response(response, dns_items);
    
    if (cnt > 0) {
        // 简单的负载均衡：如果有多个 IP，可以随机选一个，这里默认选第一个
        domain_ip = dns_items[0].ip;
    } else {
        _LOG_DEBUG(g_logger) << "No A record found for " << domain;
    }

    return cnt;
}

} // namespace base