#include "base/log/log.h"
#include "base/macro.h"
#include "quic_packet.h"
#include "base/log/log.h"
#include "base/util.h"
#include "base/coro/scheduler.h"
#include "base/coro/iomanager.h"
#include "base/mbuffer.h"
#include "base/net/address.h"
#include "base/util.h"
#include "base/coro/timer.h"

#include "quic_type.h"
#include "quic_packet.h"

namespace base
{
namespace quic
{
    static base::Logger::ptr g_logger = _LOG_NAME("system");

    static int read_cid(MBuffer::ptr buffer_block, QuicPacketHeader *header)
    {
        int ret = 0;        // 用于存储函数调用的返回值
        int parsed_len = 0; // 用于记录已解析的字节长度

        // --- 读取目标连接 ID (Destination Connection ID) ---

        // 1. 读取目标连接 ID 的长度 (dst_cid_len)
        // 尝试从缓冲区读取 1 字节，这个字节表示目标连接 ID 的长度。
        ret = stream_read_assert(buffer_block, 1);
        if (ret < 0) {
            // 如果读取失败，记录错误并返回 -1。
            _LOG_INFO(g_logger) << "read_cid failed, ret: " << ret << ", " << strerror(errno);
            return -1;
        }
        uint8_t dst_cid_len = buffer_block->readFUint8(); // 读取目标连接 ID 的长度
        buffer_block->consume(1);                         // 消耗掉已经读取的 1 字节
        parsed_len += 1;                                  // 更新已解析长度

        // 2. 读取目标连接 ID 的实际数据
        // 尝试从缓冲区读取 dst_cid_len 字节，这是目标连接 ID 的实际数据。
        ret = stream_read_assert(buffer_block, dst_cid_len);
        if (ret < 0) {
            // 如果读取失败，记录错误并返回 -1。
            _LOG_INFO(g_logger) << "read_cid failed, ret: " << ret << ", " << strerror(errno);
            return -1;
        }
        std::string cid = buffer_block->toString(); // 将缓冲区中的数据转换为字符串
        // 创建 QuicConnectionId 对象，并将其赋值给 header 的 m_dst_cid 成员。
        header->m_dst_cid =
            std::make_shared<QuicConnectionId>((const uint8_t *)cid.c_str(), dst_cid_len);
        buffer_block->consume(dst_cid_len); // 消耗掉已经读取的 dst_cid_len 字节
        parsed_len += dst_cid_len;          // 更新已解析长度

        // --- 读取源连接 ID (Source Connection ID) ---

        // 3. 读取源连接 ID 的长度 (src_cid_len)
        // 尝试从缓冲区读取 1 字节，这个字节表示源连接 ID 的长度。
        uint8_t src_cid_len = buffer_block->readFUint8();
        buffer_block->consume(1); // 消耗掉已经读取的 1 字节
        parsed_len += 1;          // 更新已解析长度
        ret = stream_read_assert(buffer_block, src_cid_len);
        if (ret < 0) {
            // 如果读取失败，记录错误并返回 -1。
            _LOG_INFO(g_logger) << "read_cid failed, ret: " << ret << ", " << strerror(errno);
            return -1;
        }
        // 4. 读取源连接 ID 的实际数据
        cid = buffer_block->toString(); // 将缓冲区中的数据转换为字符串
        // 创建 QuicConnectionId 对象，并将其赋值给 header 的 m_src_cid 成员。
        header->m_src_cid =
            std::make_shared<QuicConnectionId>((const uint8_t *)cid.c_str(), src_cid_len);
        buffer_block->consume(src_cid_len); // 消耗掉已经读取的 src_cid_len 字节
        parsed_len += src_cid_len;          // 更新已解析长度

        return parsed_len; // 返回总共解析的字节长度
    }

    QuicEPacketHeader::ptr readPacketHeaderFrom(const MBuffer::ptr &buffer_block, size_t cid_len)
    {
        try {
            // 尝试从缓冲区读取至少一个字节。如果失败，说明缓冲区数据不足，记录错误并返回空指针。
            int ret = stream_read_assert(buffer_block, 1);
            if (ret < 0) {
                _LOG_INFO(g_logger) << "readFrom failed, ret: " << ret << ", " << strerror(errno);
                return nullptr;
            }
            // 读取第一个字节，这个字节包含了头部类型信息。
            uint8_t type_byte = buffer_block->readFUint8();
            // 消耗掉已经读取的这个字节。
            buffer_block->consume(1);

            // 根据 type_byte 的最高位 (0x80) 判断是长头部还是短头部，并创建一个 QuicEPacketHeader
            // 对象。
            QuicEPacketHeader::ptr header(new QuicEPacketHeader(type_byte, (type_byte & 0x80) > 0));

            // 如果是短头部 (m_is_long_header 为 false)
            if (!header->m_is_long_header) {
                // QUIC 协议规定，短头部的 Fixed Bit (第二个位，0x40) 必须为 1。
                // 如果不为 1，则认为头部格式错误，记录错误并返回空指针。
                if ((header->m_type_byte & 0x40) == 0) {
                    _LOG_INFO(g_logger)
                        << "readFrom failed, ret: " << ret << ", " << strerror(errno);
                    return nullptr;
                }
                // 调用 readShortHeaderFrom 方法解析短头部的其余部分。
                header->readShortHeaderFrom(buffer_block, cid_len);
                return header; // 返回解析好的头部。
            }
            // 如果是长头部
            header->readLongHeaderFrom(
                buffer_block); // 调用 readLongHeaderFrom 方法解析长头部的其余部分。
            return header;     // 返回解析好的头部。
        } catch (std::exception &e) {
            // 捕获 C++ 标准异常，记录错误信息。
            _LOG_INFO(g_logger) << "readFrom failed";
        } catch (...) {
            // 捕获其他未知异常，记录错误信息。
            _LOG_INFO(g_logger) << "readFrom failed";
        }
        return nullptr; // 如果发生任何异常或解析失败，返回空指针。
    }

    QuicPacketHeader::QuicPacketHeader(uint8_t type_byte, bool is_long_header)
        : m_type_byte(type_byte), m_is_long_header(is_long_header)
    {
    }

    int QuicPacketHeader::readShortHeaderFrom(MBuffer::ptr buffer_block, size_t cid_len)
    {
        int ret = stream_read_assert(buffer_block, cid_len);
        if (ret < 0) {
            _LOG_INFO(g_logger) << "readShortHeaderFrom failed, ret: " << ret << ", "
                                << strerror(errno);
            return 0;
        }
        std::string cid = "";
        cid.resize(cid_len);
        buffer_block->read(&cid[0], cid.size());
        buffer_block->consume(cid_len);
        m_parsed_len += cid_len;
        m_dst_cid = std::make_shared<QuicConnectionId>((const uint8_t *)cid.c_str(), cid.size());
        return 0;
    }

    int QuicPacketHeader::readLongHeaderFrom(MBuffer::ptr buffer_block)
    {
        try {
            // --- 1. 读取 QUIC 版本 (Version) ---
            // 尝试从缓冲区读取 4 字节，这 4 字节代表 QUIC 协议版本。
            int ret = stream_read_assert(buffer_block, 4);
            if (ret < 0) {
                _LOG_INFO(g_logger)
                    << "readLongHeaderFrom failed, ret: " << ret << ", " << strerror(errno);
                return -1; // 读取失败，返回 -1。
            }
            m_version = buffer_block->readFUint32(); // 读取 4 字节的无符号整数作为版本号。
            buffer_block->consume(4);                // 消耗掉已经读取的 4 字节。
            m_parsed_len += 4;                       // 更新已解析长度。

            // 检查版本号和 Fixed Bit (0x40) 的有效性。
            // 如果版本不为 0 且 Fixed Bit 为 0，则认为头部格式错误。
            if (m_version != 0 && (m_type_byte & 0x40) == 0) {
                _LOG_INFO(g_logger)
                    << "readLongHeaderFrom failed, ret: " << ret << ", " << strerror(errno);
                return -1;
            }

            // --- 2. 读取连接 ID (Connection IDs) ---
            // 调用 read_cid 函数来读取目标连接 ID (Destination Connection ID) 和源连接 ID (Source
            // Connection ID)。 read_cid 函数会将解析出的 Connection ID 设置到当前 header 对象的
            // m_dst_cid 和 m_src_cid 成员中。
            ret = read_cid(buffer_block, this);
            if (ret <= 0) { // 如果 read_cid 返回错误或没有解析任何字节。
                return -1;  // 返回 -1。
            }
            m_parsed_len += ret; // 将 read_cid 返回的解析长度加到总已解析长度中。

            // 如果版本号为 0，也认为是错误情况。
            if (m_version == 0) {
                _LOG_INFO(g_logger)
                    << "readLongHeaderFrom failed, ret: " << ret << ", " << strerror(errno);
                return -1;
            }

            // --- 3. 根据 Type Byte 确定 QUIC 包类型 ---
            // 根据 m_type_byte 的第 5 和第 6 位 (0x30) 来确定 QUIC 包的类型。
            switch ((m_type_byte & 0x30) >> 4) {
                case 0x0: {                           // 00b
                    m_type = QuicPacketType::INITIAL; // 初始化包
                    break;
                }
                case 0x1: {                                      // 01b
                    m_type = QuicPacketType::ZERO_RTT_PROTECTED; // 0-RTT 受保护包
                    break;
                }
                case 0x2: {                             // 10b
                    m_type = QuicPacketType::HANDSHAKE; // 握手包
                    break;
                }
                case 0x3: {                         // 11b
                    m_type = QuicPacketType::RETRY; // 重试包
                    break;
                }
            }

            size_t field_len = 0; // 用于存储变长整数 (varint) 的长度。

            // --- 4. 处理 RETRY 包类型特有的 Token 字段 ---
            if (m_type == QuicPacketType::RETRY) {
                // 对于 RETRY 包，Token 字段的长度是 MBuffer 中剩余可读字节数减去 16 (通常是 ODCID
                // 的长度)。
                uint64_t token_len = buffer_block->readAvailable() - 16;
                if (token_len <= 0) {
                    return -1; // Token 长度无效，返回 -1。
                }
                m_token.resize(token_len); // 调整 m_token 的大小以存储 Token。
                buffer_block->copyOut(&m_token[0], token_len); // 将 Token 数据复制到 m_token 中。
                buffer_block->consume(token_len); // 消耗掉已经读取的 Token 字节。
                m_parsed_len += token_len;        // 更新已解析长度。
            }

            // --- 5. 处理 INITIAL 包类型特有的 Token 字段 ---
            if (m_type == QuicPacketType::INITIAL) {
                size_t token_len = 0;
                // 读取 Token 字段的长度，这是一个变长整数。
                if (!read_varint(buffer_block, token_len, field_len)) {
                    return -1; // 读取变长整数失败，返回 -1。
                }
                m_parsed_len += field_len; // 更新已解析长度（变长整数的长度）。
                m_token.resize(token_len); // 调整 m_token 的大小以存储 Token。
                ret = stream_read_assert(buffer_block, token_len);
                if (ret < 0) {
                    _LOG_INFO(g_logger)
                        << "readLongHeaderFrom failed, ret: " << ret << ", " << strerror(errno);
                    return -1; // 读取 Token 数据失败，返回 -1。
                }
                buffer_block->copyOut(&m_token[0],
                                      m_token.size()); // 将 Token 数据复制到 m_token 中。
                buffer_block->consume(m_token.size()); // 消耗掉已经读取的 Token 字节。
                m_parsed_len += token_len;             // 更新已解析长度。
            }

            // --- 6. 读取 Length 字段 ---
            // 读取 Length 字段，这是一个变长整数，表示 QUIC 包的长度（不包括头部）。
            read_varint(buffer_block, m_length, field_len);
            m_parsed_len += field_len; // 更新已解析长度。

        } catch (std::exception &e) {
            // 捕获 C++ 标准异常，记录错误信息。
            _LOG_INFO(g_logger) << "readLongHeaderFrom failed";
        } catch (...) {
            // 捕获其他未知异常，记录错误信息。
            _LOG_INFO(g_logger) << "readLongHeaderFrom failed";
        }
        return 0; // 成功解析长头部，返回 0。
    }

    /// QuicEPacketHeader
    int QuicEPacketHeader::readPacketNumberFrom(const MBuffer::ptr &buffer_block)
    {
        // 根据 m_type_byte 的低两位 (0x3) 来确定 Packet Number 的长度。
        // QUIC 协议规定，这两个位的值加上 1 就是 Packet Number 的字节长度 (1, 2, 3 或 4 字节)。
        int packet_number_len = (m_type_byte & 0x3) + 1;
        switch (packet_number_len) {
            case 1: { // 如果 Packet Number 长度为 1 字节
                // 尝试从缓冲区读取 1 字节。如果失败，记录错误并返回 -1。
                int ret = stream_read_assert(buffer_block, 1);
                if (ret < 0) {
                    _LOG_INFO(g_logger)
                        << "readPacketNumberFrom failed, ret: " << ret << ", " << strerror(errno);
                    return -1;
                }
                // 设置成员变量 m_packet_number_len 为 PACKET_NUMBER_LEN1。
                m_packet_number_len = PacketNumberLen::PACKET_NUMBER_LEN1;
                // 从缓冲区读取 1 字节的无符号整数作为 Packet Number。
                // buffer_block 之前处理了Length之前的部分，所以这里可以直接读取。
                m_packet_number = buffer_block->readFUint8();
                // 消耗掉已经读取的 1 字节。
                buffer_block->consume(1);
                break;
            }
            case 2: { // 如果 Packet Number 长度为 2 字节
                // 尝试从缓冲区读取 2 字节。如果失败，记录错误并返回 -1。
                int ret = stream_read_assert(buffer_block, 2);
                if (ret < 0) {
                    _LOG_INFO(g_logger)
                        << "readPacketNumberFrom failed, ret: " << ret << ", " << strerror(errno);
                    return -1;
                }
                // 设置成员变量 m_packet_number_len 为 PACKET_NUMBER_LEN2。
                m_packet_number_len = PacketNumberLen::PACKET_NUMBER_LEN2;
                // 从缓冲区读取 2 字节的无符号整数作为 Packet Number。
                m_packet_number = buffer_block->readFUint16();
                // 消耗掉已经读取的 2 字节。
                buffer_block->consume(2);
                break;
            }
            case 3: { // 如果 Packet Number 长度为 3 字节
                // 尝试从缓冲区读取 3 字节。如果失败，记录错误并返回 -1。
                int ret = stream_read_assert(buffer_block, 3);
                if (ret < 0) {
                    _LOG_INFO(g_logger)
                        << "readPacketNumberFrom failed, ret: " << ret << ", " << strerror(errno);
                    return -1;
                }
                // 设置成员变量 m_packet_number_len 为 PACKET_NUMBER_LEN3。
                m_packet_number_len = PacketNumberLen::PACKET_NUMBER_LEN3;
                // 从缓冲区读取 3 字节的无符号整数作为 Packet Number。
                m_packet_number = buffer_block->readFUint24();
                // 消耗掉已经读取的 3 字节。
                buffer_block->consume(3);
                break;
            }
            case 4: { // 如果 Packet Number 长度为 4 字节
                // 尝试从缓冲区读取 4 字节。如果失败，记录错误并返回 -1。
                int ret = stream_read_assert(buffer_block, 4);
                if (ret < 0) {
                    _LOG_INFO(g_logger)
                        << "readPacketNumberFrom failed, ret: " << ret << ", " << strerror(errno);
                    return -1;
                }
                // 设置成员变量 m_packet_number_len 为 PACKET_NUMBER_LEN4。
                m_packet_number_len = PacketNumberLen::PACKET_NUMBER_LEN4;
                // 从缓冲区读取 4 字节的无符号整数作为 Packet Number。
                m_packet_number = buffer_block->readFUint32();
                // 消耗掉已经读取的 4 字节。
                buffer_block->consume(4);
                break;
            }
            default: { // 处理 Packet Number 长度的非法值
                _LOG_INFO(g_logger) << "readPacketNumberFrom failed"
                                    << ", " << strerror(errno);
                return -1;
            }
        }
        return 0; // 成功读取并解析 Packet Number，返回 0。
    }

    int QuicEPacketHeader::writePacketNumberTo(const MBuffer::ptr &buffer_block)
    {
        switch ((int)m_packet_number_len) {
            case 1: {
                buffer_block->writeFuint8(m_packet_number);
                break;
            }
            case 2: {
                buffer_block->writeFuint16(m_packet_number);
                break;
            }
            case 3: {
                buffer_block->writeFuint24(m_packet_number);
                break;
            }
            case 4: {
                buffer_block->writeInt32(m_packet_number);
                break;
            }
            default: {
                return -1;
            }
        }
        return 0;
    }

    int QuicEPacketHeader::writeLongHeaderTo(const MBuffer::ptr &buffer_block)
    {
        uint8_t packet_type = 0;
        switch (m_type) {
            case QuicPacketType::INITIAL: {
                packet_type = 0x0;
                break;
            }
            case QuicPacketType::ZERO_RTT_PROTECTED: {
                packet_type = 0x01;
                break;
            }
            case QuicPacketType::HANDSHAKE: {
                packet_type = 0x02;
                break;
            }
            case QuicPacketType::RETRY: {
                packet_type = 0x03;
                break;
            }
            default: {
                return -1;
            }
        }
        uint8_t type_byte = 0xc0 | (packet_type << 4);
        if (m_type != QuicPacketType::RETRY) {
            type_byte |= uint8_t((int)m_packet_number_len - 1);
        }
        buffer_block->writeFuint8(type_byte);
        buffer_block->writeFuint32(m_version);
        buffer_block->writeFuint8(m_dst_cid->length());
        buffer_block->copyIn(std::string((char *)(const uint8_t *)*m_dst_cid, m_dst_cid->length()));
        buffer_block->writeFuint8(m_src_cid->length());
        buffer_block->copyIn(std::string((char *)(const uint8_t *)*m_src_cid, m_src_cid->length()));

        switch (m_type) {
            case QuicPacketType::RETRY: {
                buffer_block->copyIn(m_token);
                return 0;
            }
            case QuicPacketType::INITIAL: {
                buffer_block->var_encode(m_token.size());
                buffer_block->copyIn(m_token);
            }
            default: {
                break;
            }
        }
        buffer_block->var_encode(m_length);
        return writePacketNumberTo(buffer_block);
    }

    int QuicEPacketHeader::writeShortHeaderTo(const MBuffer::ptr &buffer_block)
    {
        uint8_t type_byte = 0x40 | uint8_t((int)m_packet_number_len - 1);
        if (m_key_phase == QuicKeyPhase::PHASE_1) {
            type_byte |= (1 << 2);
        }
        buffer_block->writeFuint8(type_byte);
        buffer_block->copyIn(std::string((char *)(const uint8_t *)*m_dst_cid, m_dst_cid->length()));
        return writePacketNumberTo(buffer_block);
    }

    int QuicEPacketHeader::writeTo(const MBuffer::ptr &buffer_block)
    {
        if (m_is_long_header) {
            return writeLongHeaderTo(buffer_block);
        }
        return writeShortHeaderTo(buffer_block);
    }

    uint64_t QuicEPacketHeader::getLength()
    {
        if (m_is_long_header) {
            uint64_t len = 1 /*type byte*/ + 4                         /* version */
                           + 1 /* dst_cid_len */ + m_dst_cid->length() /* dst_cid */
                           + 1 /* src_cid_len */ + m_src_cid->length() /* src_cid */
                           + (int)m_packet_number_len + 2 /* length */;
            if (m_type == QuicPacketType::INITIAL) {
                len += (MBuffer::var_size(m_token.length()) + m_token.length());
            }
            return len;
        }
        uint64_t len = 1 /* type byte*/ + m_dst_cid->length();
        len += (int)m_packet_number_len;
        return len;
    }

    std::string QuicEPacketHeader::toString() const
    {
        std::stringstream ss;
        if (m_is_long_header) {
            ss << "long header, type_byte: " << std::hex << std::setw(2) << (int)m_type_byte
               << ", type: " << packetTypeString(m_type) << ", version: " << m_version
               << ", dcid_len: " << (int)m_dst_cid->length()
               << ", dcid: " << m_dst_cid->toHexString()
               << ", scid_len: " << (int)m_src_cid->length()
               << ", scid: " << m_src_cid->toHexString();
            if (m_type == QuicPacketType::RETRY) {
                // TODO
                return ss.str();
            }
            if (m_type == QuicPacketType::INITIAL) {
                ss << ", token_len: " << m_token.size() << ", token: " << m_token;
            }
            ss << ", length: " << m_length;
            ss << ", packet_number_len: " << (int)m_packet_number_len
               << ", packet_number: " << m_packet_number;
        } else {
            ss << "short header, type_byte: " << std::hex << std::setw(2) << (int)m_type_byte
               << ", type: " << packetTypeString(m_type)
               << ", dcid_len: " << (int)m_dst_cid->length()
               << ", dcid: " << m_dst_cid->toHexString() << ", packet_number: " << m_packet_number;
        }
        return ss.str();
    }

    /// QuicPacket
    void QuicPacket::init(uint64_t now, QuicPacketContents::ptr packet,
                          const std::function<void(QuicFrame::ptr)> &lost_fun)
    {
        m_pn = packet->header->m_packet_number;
        m_largest_acked = ~0ull;
        if (packet->ack) {
            m_largest_acked = packet->ack->largestAcked();
        }
        for (const auto &frame : packet->frames) {
            if (!frame->lostCb()) {
                frame->setOnLost(lost_fun);
            }
        }
        m_frames = packet->frames;
        m_length = packet->buffer->readAvailable();
        m_send_time = now;
    }

    uint64_t QuicPacket::len()
    {
        return m_length;
    }

    /// QuicPacketCodec
    static QuicPacketNumber unpackHeader(MBuffer::ptr buffer_block, QuicPacketHeader::ptr header)
    {
        QuicPacketNumber no = buffer_block->readFUint32();
        buffer_block->consume(4);
        return no;
    }

    QuicPacket::ptr QuicPacketCodec::readFrom(MBuffer::ptr buffer_block,
                                              QuicPacketHeader::ptr header)
    {
        return nullptr;
    }

    /// PacketNumberManager
    PacketNumberLen PacketNumberManager::GetPacketNumberLengthForHeader(QuicPacketNumber pn)
    {
        if (pn < (1 << (16 - 1))) {
            return PacketNumberLen::PACKET_NUMBER_LEN2;
        }
        if (pn < (1 << (24 - 1))) {
            return PacketNumberLen::PACKET_NUMBER_LEN3;
        }
        return PacketNumberLen::PACKET_NUMBER_LEN4;
    }

    uint16_t PacketNumberManager::getRandomNumber()
    {
        std::random_device rnd;
        uint32_t x = rnd();
        return x % 2 ^ 16;
    }

    void PacketNumberManager::generateNewSkip()
    {
        QuicPacketNumber num = getRandomNumber();
        QuicPacketNumber skip = num * (m_average_period - 1) / (((1 << 16) - 1) / 2);
        m_next_to_skip = m_next + 2 + skip;
    }

    QuicPacketNumber PacketNumberManager::peek() const
    {
        return m_next;
    }

    QuicPacketNumber PacketNumberManager::pop()
    {
        QuicPacketNumber next = m_next;
        m_next++;
        return next;
    }

    /// RetransmissionQueue
    void RetransmissionQueue::addAppData(QuicFrame::ptr frame)
    {
        m_app_data.push_back(frame);
    }

    QuicFrame::ptr RetransmissionQueue::getAppDataFrame()
    {
        if (m_app_data.size() == 0) {
            return nullptr;
        }
        QuicFrame::ptr frame = m_app_data.front();
        m_app_data.pop_front();
        return frame;
    }

    /// QuicPacketPack
    int QuicPacketPack::composeNextPacket(QuicSndStream::ptr send_stream,
                                          std::deque<QuicFrame::ptr> &frames)
    {
        return 0;
    }

    size_t QuicPacketPack::packetLength(QuicEPacketHeader::ptr header,
                                        const std::deque<QuicFrame::ptr> &payload)
    {
        size_t padding_len = 0;
        uint64_t pn_len = (int)header->m_packet_number_len;
        if (payload.size() < 4 - pn_len) {
            padding_len = 4 - pn_len - payload.size();
        }
        return header->getLength() + payload.size() + padding_len;
    }

    MBuffer::ptr QuicPacketPack::dump_into_packet_buffer(QuicEPacketHeader::ptr header,
                                                         std::list<QuicFrame::ptr> frames,
                                                         size_t payload_len)
    {
        MBuffer::ptr buffer_block = std::make_shared<MBuffer>();
        uint64_t pn_len = (int)header->m_packet_number_len;
        if (header->m_is_long_header) {
            header->m_length = pn_len + payload_len;
        }
        header->writeTo(buffer_block);

        for (auto &i : frames) {
            i->writeTo(buffer_block);
        }
        return buffer_block;
    }

    MBuffer::ptr QuicPacketPack::packPacket(PacketNumberManager::ptr pnm,
                                            QuicSndStream::ptr send_stream)
    {
        return nullptr;
    }

    /// PacketNumberLength
    PacketNumberLen
    PacketNumberLength::getPacketNumberLengthForHeader(QuicPacketNumber packet_num,
                                                       QuicPacketNumber least_unacked)
    {
        uint64_t diff = (uint64_t)(packet_num - least_unacked);
        if (diff < (1 << ((uint8_t)PacketNumberLen::PACKET_NUMBER_LEN2 * 8 - 1))) {
            return PacketNumberLen::PACKET_NUMBER_LEN2;
        }
        return PacketNumberLen::PACKET_NUMBER_LEN4;
    }

    PacketNumberLen PacketNumberLength::getPacketNumberLength(QuicPacketNumber packet_num)
    {
        if (packet_num < (1 << ((uint8_t)PacketNumberLen::PACKET_NUMBER_LEN1 * 8))) {
            return PacketNumberLen::PACKET_NUMBER_LEN1;
        }
        if (packet_num < (1 << ((uint8_t)PacketNumberLen::PACKET_NUMBER_LEN2 * 8))) {
            return PacketNumberLen::PACKET_NUMBER_LEN2;
        }
        if (packet_num < (1UL << ((uint8_t)PacketNumberLen::PACKET_NUMBER_LEN3 * 8))) {
            return PacketNumberLen::PACKET_NUMBER_LEN3;
        }
        return PacketNumberLen::PACKET_NUMBER_LEN4;
    }

} // namespace quic
} // namespace base
