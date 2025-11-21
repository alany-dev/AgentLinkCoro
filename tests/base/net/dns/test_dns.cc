// 该文件实现一个最小的 DNS 客户端测试：构造查询报文、发送到公共 DNS 服务器，
// 接收响应并解析其中的 A 记录（IPv4地址）。代码演示了 DNS 报文格式、域名“标签化”
//（length + label）编码以及名称压缩（0xC0 指针）的基本解析方法。
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#define nullptr NULL

// mark
// 目标 DNS 服务器配置：端口固定为 53，IP 可按需修改为本地/公共 DNS
#define DNS_SERVER_PORT 53
#define DNS_SERVER_IP "114.114.114.114"

#define DNS_HOST 0x01
#define DNS_CNAME 0x05

// DNS 报文头部（12 字节），见 RFC1035
struct dns_header {
    uint16_t id;         // 随机标识符，用于匹配请求/响应
    uint16_t flags;      // 标志位：QR/Opcode/AA/TC/RD/RA... 这里设置 RD=1（递归）
    uint16_t questions;  // Question 个数（一般为 1）
    uint16_t answer;     // Answer 个数
    uint16_t authority;  // Authority 个数
    uint16_t additional; // Additional 个数
};

// DNS 查询问题段（Question），紧随 header 之后：QNAME + QTYPE + QCLASS
struct dns_question {
    int32_t length;      // QNAME 的总长度（包含末尾 0）
    uint16_t qtype;      // 查询类型：A(1)、CNAME(5) 等
    uint16_t qclass;     // 查询类：一般为 IN(1)
    unsigned char *name; // QNAME：按标签编码的域名，例如 3www6google3com0
};

// 解析到的结果项：域名 + IP，用于简单展示
struct dns_item {
    char *domain; // 例如 "www.example.com"
    char *ip;     // 点分十进制 IP 字符串
};

// client send to dns server

// 填充 DNS 头部：启用递归查询（RD=1），问题数设为 1
int dns_create_header(struct dns_header *header)
{
    if (header == nullptr)
        return -1;
    memset(header, 0, sizeof(struct dns_header));

    // 生成随机 ID，用于匹配响应
    srandom(time(nullptr));
    header->id = (uint16_t)random();

    header->flags = htons(0x0100); // RD=1，其它位为 0
    header->questions = htons(1);

    return 0;
}

// 将域名编码为 QNAME（标签化：每个标签前置长度字节，结尾加 0），并设置 QTYPE/QCLASS
// 示例：host="www.example.com" => name=3www7example3com0
int dns_create_question(struct dns_question *question, const char *hostname)
{
    if (question == nullptr || hostname == nullptr)
        return -1;
    memset(question, 0, sizeof(struct dns_question));

    // 至少多分配 2 字节：一个用于可能的标签长度字节，一个用于末尾的 0 终止
    question->name = (unsigned char *)malloc(strlen(hostname) + 2);
    if (question->name == nullptr) {
        return -2;
    }

    // 预估长度（标签化后长度 <= 原始长度 + 2），实际构造后尾部补一个 0
    question->length = (int32_t)(strlen(hostname) + 2);

    question->qtype = htons(1);
    question->qclass = htons(1);

    // name
    const char delim[2] = "."; // 按点分隔标签
    unsigned char *qname = question->name;

    char *hostname_dup = strdup(hostname); // strdup 会分配内存，便于使用 strtok
    char *token = strtok(hostname_dup, delim);

    while (token != nullptr) {

        size_t len = strlen(token); // 当前标签长度

        *qname = len; // 写入长度字节
        qname++;

        memcpy(qname, token, len); // 写入标签内容（不包含 \0）
        qname += len;

        token = strtok(nullptr, delim);
    }

    // QNAME 以 0 结束，表示域名结束
    *qname = 0;

    free(hostname_dup);

    return 0;
}

// 114.114.114.114    8.8.8.8

// 将 header 与 question 按顺序拷贝到请求缓冲区

// 返回请求总长度，用于 sendto 发送
int dns_build_requestion(struct dns_header *header, struct dns_question *question, char *request,
                         int rlen)
{

    if (header == nullptr || question == nullptr || request == nullptr)
        return -1;
    memset(request, 0, rlen);
    // header --> request

    // 写入头部
    memcpy(request, header, sizeof(struct dns_header));
    int offset = sizeof(struct dns_header);

    // question --> request
    // 写入 QNAME
    memcpy(request + offset, question->name, question->length);
    offset += question->length;

    // 写入 QTYPE
    memcpy(request + offset, &question->qtype, sizeof(question->qtype));
    offset += sizeof(question->qtype);

    // 写入 QCLASS
    memcpy(request + offset, &question->qclass, sizeof(question->qclass));
    offset += sizeof(question->qclass);

    return offset;
}

// 判断名称是否使用压缩指针（高两位为 11，即 0xC0）
static int is_pointer(uint8_t in)
{
    return ((in & 0xC0) == 0xC0);
}

// 解析压缩名称：
// - 若首字节高两位为 11，则为指针，低 14 位为偏移；跳转并递归解析
// - 否则首字节为标签长度，随后复制标签内容；在标签之间插入 '.'
static void dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int32_t *len)
{
    uint8_t flag = 0;
    uint16_t n = 0;
    char *pos = out + (*len);

    while (1) {

        flag = ptr[0];
        if (flag == 0)
            break;

        if (is_pointer(flag)) {

            // 指针的偏移仅取低 14 位，这里简化为读取第二字节作为偏移
            n = (int)ptr[1];
            ptr = chunk + n;
            dns_parse_name(chunk, ptr, out, len);
            break;
        } else {

            ptr++;
            // 复制标签内容，并在非结尾处追加 '.'
            memcpy(pos, ptr, flag);
            pos += flag;
            ptr += flag;

            *len += flag;
            if (ptr[0] != 0) {
                memcpy(pos, ".", 1);
                pos += 1;
                (*len) += 1;
            }
        }
    }
}

// 解析响应报文，提取 A 记录并返回条目数；domains 输出为动态数组
static int32_t dns_parse_response(unsigned char *buffer, struct dns_item **domains)
{
    int32_t i = 0;
    unsigned char *ptr = buffer;

    // 跳过 ID 与 FLAGS（共 4 字节）
    ptr += 4;
    uint16_t querys = ntohs(*(uint16_t *)ptr);

    // 读取 Answer 计数
    ptr += 2;
    uint16_t answers = ntohs(*(uint16_t *)ptr);

    // 跳过 Authority 与 Additional 共 6 字节
    ptr += 6;
    for (i = 0; i < querys; i++) {
        while (1) {

            int flag = (int)ptr[0];
            ptr += (flag + 1);

            if (flag == 0)
                break;
        }
        // 跳过 QTYPE + QCLASS
        ptr += 4;
    }

    char cname[128], aname[128], ip[20];
    uint8_t netip[4];
    int32_t len;
    uint16_t type, ttl, datalen;

    int32_t cnt = 0;
    struct dns_item *list = (struct dns_item *)calloc(answers, sizeof(struct dns_item));
    if (list == nullptr)
        return -1;

    for (i = 0; i < answers; i++) {
        bzero(aname, sizeof(aname));
        len = 0;

        // 解析资源记录名称
        dns_parse_name(buffer, ptr, aname, &len);
        ptr += 2;

        // TYPE（A=1，CNAME=5 等）
        type = htons(*(uint16_t *)ptr);
        ptr += 4;

        // TTL（这里仅取 16 位演示，标准为 32 位）
        ttl = htons(*(uint16_t *)ptr);
        ptr += 4;

        // 数据长度
        datalen = ntohs(*(uint16_t *)ptr);
        ptr += 2;

        if (type == DNS_CNAME) {

            bzero(cname, sizeof(cname));
            len = 0;
            // CNAME：进一步解析别名
            dns_parse_name(buffer, ptr, cname, &len);
            ptr += datalen;

        } else if (type == DNS_HOST) {
            bzero(ip, sizeof(ip));

            if (datalen == 4) {
                memcpy(netip, ptr, datalen);
                inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));

                printf("%s has address %s\n", aname, ip);
                printf("\tTime to live: %d minutes, %d seconds\n", ttl / 60, ttl % 60);

                // 保存结果项（域名+IP），方便上层使用/打印
                list[cnt].domain = (char *)calloc(strlen(aname) + 1, 1);
                memcpy(list[cnt].domain, aname, strlen(aname));

                list[cnt].ip = (char *)calloc(strlen(ip) + 1, 1);
                memcpy(list[cnt].ip, ip, strlen(ip));

                cnt++;
            }

            ptr += datalen;
        }
    }

    *domains = list; // 返回解析结果数组
    ptr += 2;

    return cnt;
}

// 执行一次 DNS 查询：
// - 构造请求并通过 UDP 发送至 DNS 服务器
// - 接收响应并解析 A 记录
// 返回接收到的字节数（n）
int dns_client_commit(const char *domain)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -1;

    struct sockaddr_in servaddr = {0}; // 目标服务器地址
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(DNS_SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

    int ret = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    printf("connect : %d\n", ret);

    struct dns_header header = {0}; // 构造头部
    dns_create_header(&header);

    struct dns_question question = {0}; // 构造 Question
    dns_create_question(&question, domain);

    char request[1024] = {0}; // 请求缓冲区
    int32_t length = dns_build_requestion(&header, &question, request, 1024);

    // request
    // 发送请求（connect + sendto 可简化为 send）
    printf("sendto : %d\n", (int)sendto(sockfd, request, length, 0, (struct sockaddr *)&servaddr,
                                        sizeof(struct sockaddr)));

    // recvfrom
    unsigned char response[1024] = {0}; // 响应缓冲区
    struct sockaddr_in addr;
    size_t addr_len = sizeof(struct sockaddr_in);

    int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&addr,
                     (socklen_t *)&addr_len);

    struct dns_item *dns_domain = nullptr;
    dns_parse_response(response, &dns_domain); // 解析响应

    free(dns_domain); // 释放解析结果（仅演示用途）

    return n;
}

// 入口：传入域名作为参数
int main(int argc, char *argv[])
{
    if (argc < 2)
        return -1;
    dns_client_commit(argv[1]);
}
