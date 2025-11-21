#pragma once

#include <memory>
#include <vector>
#include <string>
#include "base/net/address.h"
#include "base/net/socket.h"

namespace base
{

struct dns_header {
    uint16_t id;         // 随机标识符，用于匹配请求/响应
    uint16_t flags;      // 标志位：QR/Opcode/AA/TC/RD/RA... 这里设置 RD=1（递归）
    uint16_t questions;  // Question 个数（一般为 1）
    uint16_t answers;     // Answer 个数
    uint16_t authority;  // Authority 个数
    uint16_t additional; // Additional 个数
};

// DNS 查询问题段（Question），紧随 header 之后：QNAME + QTYPE + QCLASS
struct dns_question {
    uint16_t qtype;   // 查询类型：A(1)、CNAME(5) 等
    uint16_t qclass;  // 查询类：一般为 IN(1)
    std::string name; // QNAME：按标签编码的域名，例如 3www6google3com0
};

// 解析到的结果项：域名 + IP，用于简单展示
struct dns_item {
    std::string domain; // 例如 "www.example.com"
    std::string ip;     // 点分十进制 IP 字符串
};

class AsyncDnsResolver
{
public:
    static int resolveAny(const std::string &domain, std::string &domain_ip, const std::string &server_ip = "114.114.114.114:53");

private:
    enum DnsType : uint16_t {
        DNS_HOST = 0x01,
        DNS_CNAME = 0x05,
    };

    static int dns_create_header(struct dns_header &header);
    static int dns_create_question(struct dns_question &question, const std::string &hostname);
    static int dns_build_requestion(struct dns_header &header, struct dns_question &question,
                             std::string &request);
    static void dns_parse_name(const std::string& chunk, char *ptr, std::string &out, int32_t *len);
    static int dns_parse_response(const std::string &buffer, std::vector<struct dns_item> &items);
};

} // namespace base