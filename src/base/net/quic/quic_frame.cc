#include <cstdint>
#include <stdio.h>
#include "base/macro.h"
#include "quic_frame.h"

/**
 * @file quic_frame.cc
 * @brief QUIC帧实现文件
 *
 * 本文件实现了QUIC协议中各种帧类型的具体逻辑，包括帧的编码、解码、大小计算等功能。
 * 帧是QUIC协议的基本传输单元，用于在连接上传输不同类型的控制和数据信息。
 */

namespace base
{
namespace quic
{
    /** @brief 日志记录器实例 */
    static base::Logger::ptr g_logger = _LOG_NAME("system");

    /**
     * @brief 根据缓冲区的第一个字节确定帧类型
     * @param buf 包含帧数据的缓冲区指针
     * @return 帧类型枚举值
     *
     * 该方法根据帧的第一个字节判断帧的类型，处理了一些特殊的帧类型范围判断。
     * 某些帧类型可能有一个类型范围，比如STREAM帧类型范围是0x08-0x0f。
     */
    QuicFrameType QuicFrame::type(const uint8_t *buf)
    {
        // 检查类型是否超出已知范围
        if (buf[0] >= static_cast<uint8_t>(QuicFrameType::UNKNOWN)) {
            return QuicFrameType::UNKNOWN;
        }
        // 处理ACK帧类型范围 (0x02-0x03)
        else if (static_cast<uint8_t>(QuicFrameType::ACK) <= buf[0]
                 && buf[0] < static_cast<uint8_t>(QuicFrameType::RESET_STREAM)) {
            return QuicFrameType::ACK;
        }
        // 处理STREAM帧类型范围 (0x08-0x0f)
        else if (static_cast<uint8_t>(QuicFrameType::STREAM) <= buf[0]
                 && buf[0] < static_cast<uint8_t>(QuicFrameType::MAX_DATA)) {
            return QuicFrameType::STREAM;
        }
        // 处理MAX_STREAMS帧类型范围 (0x12-0x13)
        else if (static_cast<uint8_t>(QuicFrameType::MAX_STREAMS) <= buf[0]
                 && buf[0] < static_cast<uint8_t>(QuicFrameType::DATA_BLOCKED)) {
            return QuicFrameType::MAX_STREAMS;
        }
        // 处理STREAM_BLOCKED帧类型范围 (0x14-0x15)
        else if (static_cast<uint8_t>(QuicFrameType::STREAM_BLOCKED) <= buf[0]
                 && buf[0] < static_cast<uint8_t>(QuicFrameType::NEW_CONNECTION_ID)) {
            return QuicFrameType::STREAM_BLOCKED;
        }
        // 处理CONNECTION_CLOSE帧类型范围 (0x1c-0x1d)
        else if (static_cast<uint8_t>(QuicFrameType::CONNECTION_CLOSE) <= buf[0]
                 && buf[0] < static_cast<uint8_t>(QuicFrameType::HANDSHAKE_DONE)) {
            return QuicFrameType::CONNECTION_CLOSE;
        }
        // 其他情况，直接转换为对应的帧类型
        else {
            return static_cast<QuicFrameType>(buf[0]);
        }
    }

    /**
     * @brief 将帧转换为字符串表示
     * @return 帧的字符串描述
     *
     * 基类实现返回空字符串，子类应根据自己的类型实现相应的字符串表示。
     */
    std::string QuicFrame::toString() const
    {
        return std::string("");
    };

    /// QuicStreamFrame 类实现
    /**
     * @brief 读取并解析流帧的类型字节
     * @param type_byte 帧类型字节
     * @return 解析是否成功
     *
     * 流帧类型字节的低3位包含控制标志：
     * - 0x01: FIN标志，表示流结束
     * - 0x02: 长度字段标志，表示存在长度字段
     * - 0x04: 偏移字段标志，表示存在偏移字段
     */
    bool QuicStreamFrame::readTypeByte(uint8_t type_byte)
    {
        if (type_byte) {
            // 解析FIN标志位 (0x01)
            m_has_fin = (type_byte & 0x1) > 0;
            // 解析长度字段标志位 (0x02)
            m_has_length_field = (type_byte & 0x2) > 0;
            // 解析偏移字段标志位 (0x04)
            m_has_offset_field = (type_byte & 0x4) > 0;
        }
        return true;
    }

    /**
     * @brief 从缓冲区读取流帧数据
     * @param buffer_block 包含帧数据的缓冲区
     * @return 读取是否成功
     *
     * 按照流帧的格式依次解析：
     * 1. 读取流ID (变长整数)
     * 2. 如果有偏移字段，读取偏移量 (变长整数)
     * 3. 如果有长度字段，读取数据长度 (变长整数)
     * 4. 读取流数据内容
     */
    bool QuicStreamFrame::readFrom(MBuffer::ptr buffer_block)
    {
        int ret = 0;
        size_t streamid_len = 0;
        // 1. 读取流ID (变长整数)
        if (!read_varint(buffer_block, m_stream_id, streamid_len)) {
            return false;
        }
        size_t offset_len = 0;
        // 2. 如果偏移字段标志为true，读取偏移量 (变长整数)
        if (m_has_offset_field && !read_varint(buffer_block, m_offset, offset_len)) {
            return false;
        }
        size_t data_len = 0;
        uint64_t len = 0;
        // 3. 如果长度字段标志为true，读取数据长度 (变长整数)
        if (m_has_length_field && !read_varint(buffer_block, data_len, len)) {
            return false;
        }
        // 4. 确保缓冲区中有足够的数据可读
        ret = stream_read_assert(buffer_block, data_len);
        if (ret < 0) {
            _LOG_INFO(g_logger) << "stream bufferRead failed, ret: " << ret << ", "
                                << strerror(errno);
            return false;
        }
        // 5. 初始化数据缓冲区并复制数据
        if (m_data == nullptr) {
            m_data = std::make_shared<MBuffer>();
        }
        m_data->copyIn(*buffer_block.get(), data_len);
        buffer_block->consume(data_len); // 消费已读取的数据

        // 6. 设置帧的有效状态和总大小
        m_valid = true;
        // 帧总大小 = 类型字节(1) + 流ID长度 + 偏移量长度 + 数据长度值长度 + 数据内容长度
        m_size = 1 + streamid_len + offset_len + data_len + len;
        return true;
    }

    /**
     * @brief 将流帧数据写入缓冲区
     * @param buffer_block 输出缓冲区
     * @return 写入是否成功
     *
     * 按照流帧的格式依次写入：
     * 1. 写入类型字节（包含标志位）
     * 2. 写入流ID (变长整数)
     * 3. 如果有偏移字段，写入偏移量 (变长整数)
     * 4. 如果有长度字段，写入数据长度 (变长整数)
     * 5. 写入流数据内容
     */
    bool QuicStreamFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 构建类型字节，设置相应的标志位
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::STREAM);
            if (has_offset_field()) {
                type_byte ^= 0x04; // 设置偏移字段标志
            }
            if (has_length_field()) {
                type_byte ^= 0x02; // 设置长度字段标志
            }
            if (has_fin_flag()) {
                type_byte ^= 0x01; // 设置FIN标志
            }
            // 2. 写入类型字节
            buffer_block->writeFuint8(type_byte);
            // 3. 写入流ID (变长整数)
            buffer_block->var_encode(m_stream_id);
            // 4. 如果有偏移字段，写入偏移量 (变长整数)
            if (has_offset_field()) {
                buffer_block->var_encode(m_offset);
            }
            // 5. 如果有长度字段，写入数据长度 (变长整数)
            if (has_length_field()) {
                buffer_block->var_encode(m_data ? m_data->readAvailable() : 0);
            }
            // 6. 写入流数据内容
            if (m_data && m_data->readAvailable() > 0) {
                buffer_block->copyIn(*m_data.get(), m_data->readAvailable());
            }
            return true;
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算流帧的总大小
     * @return 帧的总字节数
     *
     * 流帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 流ID的变长整数编码长度
     * 3. 如果有偏移字段，偏移量的变长整数编码长度
     * 4. 如果有长度字段，数据长度的变长整数编码长度 + 数据内容的长度
     */
    size_t QuicStreamFrame::size() const
    {
        // 如果已有缓存的大小值，直接返回
        if (m_size) {
            return m_size;
        }
        // 初始大小为类型字节(1字节)
        size_t size = 1;
        // 获取数据长度
        size_t data_len = m_data ? m_data->readAvailable() : 0;

        // 加上流ID的变长整数编码长度
        size += MBuffer::var_size(m_stream_id);
        // 如果有偏移字段，加上偏移量的变长整数编码长度
        if (has_offset_field()) {
            size += MBuffer::var_size(m_offset);
        }
        // 如果有长度字段，加上数据长度的变长整数编码长度和数据内容的长度
        if (has_length_field()) {
            size += MBuffer::var_size(data_len);
            size += data_len;
        }
        return size;
    }

    /**
     * @brief 生成流帧的可读字符串表示
     * @return 流帧的字符串描述
     *
     * 包含帧大小、流ID、偏移量、数据长度和FIN标志等信息
     */
    std::string QuicStreamFrame::toString() const
    {
        std::stringstream ss;
        ss << "[StreamFrame size: " << size() << ", id: " << m_stream_id << ", offset: " << m_offset
           << ", data_len: " << m_data->readAvailable() << ", fin: " << has_fin_flag() << "]";
        return ss.str();
    }

    /**
     * @brief 获取流帧的数据偏移量
     * @return 数据偏移量
     *
     * 如果帧包含偏移字段，则返回偏移量；否则返回0
     */
    QuicOffset QuicStreamFrame::offset() const
    {
        if (has_offset_field()) {
            return m_offset;
        }
        return 0;
    }

    /**
     * @brief 尝试将当前帧分割为两个帧，确保新帧不超过最大字节数
     * @param max_bytes 新帧数据的最大字节数
     * @return 分割出的新帧，如果不需要分割则返回nullptr
     *
     * 分割逻辑：
     * 1. 检查当前帧数据是否超过最大字节数
     * 2. 创建新帧并设置相同的流ID和偏移量
     * 3. 从当前帧复制数据到新帧
     * 4. 调整当前帧的数据和偏移量
     */
    QuicStreamFrame::ptr QuicStreamFrame::maybeSplitOffFrame(size_t max_bytes)
    {
        // 如果当前帧的数据量不超过最大字节数，不需要分割
        if (m_data->readAvailable() <= max_bytes) {
            return nullptr;
        }
        // 创建新帧
        QuicStreamFrame::ptr frame = std::make_shared<QuicStreamFrame>();
        MBuffer::ptr data = std::make_shared<MBuffer>();

        // 设置新帧的流ID和偏移量
        frame->set_stream_id(m_stream_id);
        frame->set_offset(m_offset);
        // 从当前帧复制max_bytes大小的数据到新帧
        m_data->copyOut(*data.get(), max_bytes);
        // 消费当前帧已复制的数据
        m_data->consume(max_bytes);
        // 设置新帧的数据
        frame->set_data(data);
        // 更新当前帧的偏移量
        m_offset += max_bytes;
        return frame;
    }

    /**
     * @brief 计算在给定最大大小限制下，流帧可以包含的最大数据长度
     * @param max_size 帧的最大总大小
     * @return 可容纳的最大数据长度
     *
     * 计算逻辑：
     * 1. 计算帧头部的最小大小
     * 2. 从最大大小中减去头部大小，得到可用的数据长度
     * 3. 调整数据长度以确保长度字段的变长编码不超过1字节
     */
    uint64_t QuicStreamFrame::maxDataLen(uint64_t max_size)
    {
        // 初始头部大小为类型字节(1字节)
        size_t header_len = 1;

        // 加上流ID的变长整数编码长度
        header_len += MBuffer::var_size(m_stream_id);
        // 如果有偏移字段，加上偏移量的变长整数编码长度
        if (has_offset_field()) {
            header_len += MBuffer::var_size(m_offset);
        }
        // 如果有长度字段，加上至少1字节的长度字段空间
        if (has_length_field()) {
            header_len += 1;
        }
        // 如果头部大小超过最大大小，返回0
        if (header_len > max_size) {
            return 0;
        }
        // 计算可用于数据的最大长度
        uint64_t max_data_len = max_size - header_len;
        // 如果有长度字段且数据长度的变长编码超过1字节，则减少数据长度
        if (has_length_field() && MBuffer::var_size(max_data_len) != 1) {
            max_data_len--;
        }
        return max_data_len;
    }

    /**
     * @brief 从缓冲区读取加密帧数据
     * @param buffer_block 包含帧数据的缓冲区
     * @return 读取是否成功
     *
     * 按照加密帧的格式依次解析：
     * 1. 读取偏移量 (变长整数)
     * 2. 读取数据长度 (变长整数)
     * 3. 读取加密数据内容
     */
    bool QuicCryptoFrame::readFrom(MBuffer::ptr buffer_block)
    {
        int ret = 0;
        size_t offset_len = 0;
        // 1. 读取偏移量 (变长整数)
        if (!read_varint(buffer_block, m_offset, offset_len)) {
            return false;
        }
        size_t data_len = 0;
        uint64_t len = 0;
        // 2. 读取数据长度 (变长整数)
        if (!read_varint(buffer_block, data_len, len)) {
            return false;
        }
        // 3. 确保缓冲区中有足够的数据可读
        ret = stream_read_assert(buffer_block, data_len);
        if (ret < 0) {
            _LOG_INFO(g_logger) << "stream bufferRead failed, ret: " << ret << ", "
                                << strerror(errno);
            return false;
        }
        // 4. 调整数据缓冲区大小并复制数据
        m_data.resize(data_len);
        buffer_block->copyOut(&m_data[0], m_data.size());
        buffer_block->consume(m_data.size()); // 消费已读取的数据
        // 5. 设置帧的有效状态和总大小
        m_valid = true;
        // 帧总大小 = 类型字节(1) + 偏移量长度 + 数据长度值长度 + 数据内容长度
        m_size = 1 + offset_len + data_len + len;
        return true;
    }

    /**
     * @brief 将加密帧数据写入缓冲区
     * @param buffer_block 输出缓冲区
     * @return 写入是否成功
     *
     * 按照加密帧的格式依次写入：
     * 1. 写入类型字节
     * 2. 写入偏移量 (变长整数)
     * 3. 写入数据长度 (变长整数)
     * 4. 写入加密数据内容
     */
    bool QuicCryptoFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入类型字节
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::CRYPTO);
            buffer_block->writeFuint8(type_byte);
            // 2. 写入偏移量 (变长整数)
            buffer_block->var_encode(m_offset);
            // 3. 写入数据长度 (变长整数)
            buffer_block->var_encode(m_data.size());
            // 4. 写入加密数据内容
            buffer_block->write(m_data.c_str(), m_data.size());
            return true;
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算加密帧的总大小
     * @return 帧的总字节数
     *
     * 加密帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 偏移量的变长整数编码长度
     * 3. 数据长度的变长整数编码长度
     * 4. 数据内容的长度
     */
    size_t QuicCryptoFrame::size() const
    {
        // 如果已有缓存的大小值，直接返回
        if (this->m_size) {
            return this->m_size;
        }
        // 计算总大小 = 类型字节 + 数据内容长度 + 偏移量变长编码长度 + 数据长度变长编码长度
        return 1 + m_data.size() + MBuffer::var_size(m_offset) + MBuffer::var_size(m_data.size());
    }

    /**
     * @brief 生成加密帧的可读字符串表示
     * @return 加密帧的字符串描述
     *
     * 包含帧大小、偏移量和数据长度等信息
     */
    std::string QuicCryptoFrame::toString() const
    {
        std::stringstream ss;
        ss << "[CryptoFrame size: " << size() << ", offset: " << m_offset
           << ", data_len: " << m_data.size() << "]";
        return ss.str();
    }

    /**
     * @brief ACK帧类，表示对已接收数据的确认
     *
     * ACK帧用于通知发送方哪些数据包已经被成功接收，包含以下主要信息：
     * 1. 最大已确认数据包编号
     * 2. 确认延迟时间
     * 3. 已确认的数据包范围列表
     * 4. 可选的ECN (显式拥塞通知) 信息
     */
    QuicAckFrame::QuicAckFrame(const std::vector<AckRange::ptr> &ack_ranges)
    {
        for (size_t i = 0; i < ack_ranges.size(); i++) {
            m_ack_ranges.push_back(ack_ranges[i]);
        }
    }

    /**
     * @brief 解析ACK帧的类型字节
     * @param type_byte 类型字节值
     * @return 解析是否成功
     *
     * 检查是否为带ECN信息的ACK帧
     */
    bool QuicAckFrame::readTypeByte(uint8_t type_byte)
    {
        if (type_byte) {
            // 检查是否为带ECN信息的ACK帧
            m_has_ecn = type_byte == static_cast<uint8_t>(QuicFrameType::ACK_WITH_ECN);
        }
        return true;
    }

    /**
     * @brief 从缓冲区读取ACK帧数据
     * @param buffer_block 包含帧数据的缓冲区
     * @return 读取是否成功
     *
     * 按照ACK帧的格式依次解析：
     * 1. 最大已确认数据包编号 (变长整数)
     * 2. 确认延迟时间 (变长整数)
     * 3. ACK块数量 (变长整数)
     * 4. 第一个ACK块长度 (变长整数)
     * 5. 其他ACK块信息 (间隙和块长度)
     * 6. 可选的ECN信息
     */
    bool QuicAckFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 1. 读取最大已确认数据包编号
        uint64_t largest = 0;
        size_t largest_ack_len = 0;
        if (!read_varint(buffer_block, largest, largest_ack_len)) {
            return false;
        }
        // 2. 读取确认延迟时间
        size_t ack_delay_len = 0;
        if (!read_varint(buffer_block, m_ack_delay, ack_delay_len)) {
            return false;
        }
        // 3. 读取ACK块数量
        uint64_t ack_block_count = 0;
        size_t ack_block_count_len = 0;
        if (!read_varint(buffer_block, ack_block_count, ack_block_count_len)) {
            return false;
        }
        // 4. 读取第一个ACK块长度
        uint64_t first_ack_block = 0;
        size_t first_ack_block_len = 0;
        if (!read_varint(buffer_block, first_ack_block, first_ack_block_len)) {
            return false;
        }
        // 计算第一个ACK范围的最小数据包编号
        QuicPacketNumber smallest = largest - first_ack_block;
        // 添加第一个ACK范围
        m_ack_ranges.push_back(std::make_shared<AckRange>(smallest, largest));

        // 5. 读取其他ACK块信息
        for (size_t i = 0; i < ack_block_count; i++) {
            uint64_t gap = 0;
            size_t gap_len = 0;
            uint64_t ack_block = 0;
            size_t ack_block_len = 0;

            // 读取间隙长度
            if (!read_varint(buffer_block, gap, gap_len)) {
                return false;
            }
            if (gap == 0) {
                // _ASSERT(0);
            }
            // 计算当前ACK范围的最大数据包编号，跳过 gap
            uint64_t largest = smallest - gap - 2;
            // 读取当前ACK块长度
            if (!read_varint(buffer_block, ack_block, ack_block_len)) {
                return false;
            }
            // 计算当前ACK范围的最小数据包编号
            smallest = largest - ack_block;
            // 添加当前ACK范围
            m_ack_ranges.push_back(std::make_shared<AckRange>(smallest, largest));
        }

        // 6. 如果有ECN标志，读取ECN信息
        if (m_has_ecn) {
            size_t ecn_count_len = 0;
            m_ecn_section = std::make_shared<EcnSection>();
            // 读取ECT0标记的数据包数量
            if (!read_varint(buffer_block, m_ecn_section->m_ect0_count, ecn_count_len)) {
                return false;
            }
            // 读取ECT1标记的数据包数量
            if (!read_varint(buffer_block, m_ecn_section->m_ect1_count, ecn_count_len)) {
                return false;
            }
            // 读取ECN-CE标记的数据包数量
            if (!read_varint(buffer_block, m_ecn_section->m_ecn_ce_count, ecn_count_len)) {
                return false;
            }
        }

        // 设置帧的有效状态
        m_valid = true;
        return true;
    }

    /**
     * @brief 将ACK帧数据写入缓冲区
     * @param buffer_block 输出缓冲区
     * @return 写入是否成功
     *
     * 按照ACK帧的格式依次写入：
     * 1. 类型字节
     * 2. 最大已确认数据包编号 (变长整数)
     * 3. 确认延迟时间 (变长整数)
     * 4. ACK块数量 (变长整数，实际数量减1)
     * 5. 第一个ACK块长度 (变长整数)
     * 6. 其他ACK块的间隙和长度信息
     */
    bool QuicAckFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入类型字节
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::ACK);
            buffer_block->writeFuint8(type_byte);
            // 2. 写入最大已确认数据包编号
            buffer_block->var_encode(largestAcked());
            // 3. 写入确认延迟时间
            buffer_block->var_encode(m_ack_delay);
            // 4. 获取可编码的ACK范围数量
            int ack_block_count = numEncodableAckRanges();
            // 写入ACK块数量（实际数量减1）
            buffer_block->var_encode(ack_block_count - 1);
            // 5. 写入第一个ACK块长度
            buffer_block->var_encode(encodeAckRange(0).len);
            // 6. 写入其他ACK块的间隙和长度信息
            for (auto i = 1; i < ack_block_count; i++) {
                buffer_block->var_encode(encodeAckRange(i).gap);
                buffer_block->var_encode(encodeAckRange(i).len);
            }
            return true;
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算ACK帧的总大小
     * @return 帧的总字节数
     *
     * ACK帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 最大已确认数据包编号的变长整数编码长度
     * 3. 确认延迟时间的变长整数编码长度
     * 4. ACK块数量-1的变长整数编码长度
     * 5. 第一个ACK块长度的变长整数编码长度
     * 6. 其他ACK块的间隙和长度的变长整数编码长度
     */
    size_t QuicAckFrame::size() const
    {
        // 如果已有缓存的大小值，直接返回
        if (m_size) {
            return m_size;
        }
        // 计算基本部分长度：类型字节 + 最大确认号 + 延迟时间 + ACK块数量-1 + 第一个ACK块长度
        size_t pre_len = 1 + MBuffer::var_size(largestAcked()) + MBuffer::var_size(m_ack_delay)
                         + MBuffer::var_size(m_ack_ranges.size() - 1)
                         + MBuffer::var_size(encodeAckRange(0).len);
        // 计算其他ACK块的间隙和长度的变长整数编码长度
        for (size_t i = 1; i < m_ack_ranges.size(); i++) {
            pre_len += MBuffer::var_size(encodeAckRange(i).gap);
            pre_len += MBuffer::var_size(encodeAckRange(i).len);
        }
        return pre_len;
    }

    /**
     * @brief 生成ACK帧的可读字符串表示
     * @return ACK帧的字符串描述
     *
     * 包含帧大小、最大已确认数据包编号、确认延迟时间、ACK块数量以及各个ACK范围的信息
     */
    std::string QuicAckFrame::toString() const
    {
#if 0
            std::stringstream ss;
            ss << "[AckFrame size: " << size() << ", largest_ack: " << largestAcked()
               << ", delay: " << ack_delay() << ", block_count: " << m_ack_ranges.size()
               << ", first_block [" << encodeAckRange(0).gap << ": " << encodeAckRange(0).len << "]";
            ss << ", [";
            for (size_t i = 1; i < m_ack_ranges.size(); i++) {
                ss << << encodeAckRange(i).gap << ": " << encodeAckRange(i).len << ", ";
            }
            ss << "]]";
            return ss.str();
#else
        std::stringstream ss;
        ss << "AckFrame size: " << size() << ", largest_ack: " << largestAcked()
           << ", delay: " << ack_delay() << ", block_count: " << m_ack_ranges.size() << ": ";
        // 输出每个ACK范围的最大和最小数据包编号
        for (size_t i = 0; i < m_ack_ranges.size(); i++) {
            ss << "[" << m_ack_ranges[i]->m_largest << ": " << m_ack_ranges[i]->m_smallest << "], ";
        }
        return ss.str();
#endif
    }

    /**
     * @brief 编码指定索引的ACK范围为GapLenEntry结构
     * @param idx ACK范围的索引
     * @return 编码后的GapLenEntry结构，包含间隙和长度信息
     *
     * 对于第一个ACK范围，间隙为0，长度为最大和最小数据包编号之差
     * 对于后续ACK范围，计算与前一个范围的间隙和当前范围的长度
     */
    QuicAckFrame::GapLenEntry QuicAckFrame::encodeAckRange(size_t idx) const
    {
        // 第一个ACK范围特殊处理：间隙为0，长度为范围大小
        if (idx == 0) {
            return GapLenEntry{0,
                               uint64_t(m_ack_ranges[0]->m_largest - m_ack_ranges[0]->m_smallest)};
        }
        return GapLenEntry{
            uint64_t(m_ack_ranges[idx - 1]->m_smallest - m_ack_ranges[idx]->m_largest - 2),
            uint64_t(m_ack_ranges[idx]->m_largest - m_ack_ranges[idx]->m_smallest)};
    }

    /**
     * @brief 编码确认延迟时间
     * @param ack_delay 确认延迟时间
     * @return 编码后的延迟时间值
     *
     * 目前简单返回原始延迟值，未来可能会实现更复杂的编码逻辑
     */
    uint64_t QuicAckFrame::encodeAckDelay(uint64_t ack_delay)
    {
        return ack_delay;
    }

    /**
     * @brief 计算在指定大小限制下可编码的ACK范围数量
     * @return 可编码的ACK范围数量
     *
     * 根据帧大小限制（目前临时设为1024字节）计算可以包含在一个ACK帧中的ACK范围数量
     * 这个方法用于确保ACK帧不会超过最大传输单元(MTU)限制
     */
    int QuicAckFrame::numEncodableAckRanges()
    {
        // 计算基本部分长度：类型字节 + 最大确认号 + 延迟时间
        uint64_t length = 1 + MBuffer::var_size(largestAcked()) + MBuffer::var_size(m_ack_delay);
        // 预留空间（可能用于ACK块数量-1的编码）
        length += 2;
        // 逐个计算每个ACK范围的编码长度
        for (size_t i = 1; i < m_ack_ranges.size(); i++) {
            GapLenEntry entry = encodeAckRange(i);
            uint64_t range_len = MBuffer::var_size(entry.gap) + MBuffer::var_size(entry.len);
            // 如果添加当前范围会导致帧大小超过限制，返回之前的数量
            if (length + range_len > 1024) { // TODO: 替换为实际的MTU限制
                return i - 1;
            }
            length += range_len;
        }
        // 如果所有范围都可以编码，返回总数
        return m_ack_ranges.size();
    }

    /**
     * @brief 获取最低已确认的数据包编号
     * @return 最低已确认的数据包编号
     *
     * 返回所有ACK范围中最小的数据包编号，即最后一个ACK范围的最小值
     */
    QuicPacketNumber QuicAckFrame::lowestAcked()
    {
        return m_ack_ranges[m_ack_ranges.size() - 1]->m_smallest;
    }

    /**
     * @brief 检查指定数据包编号是否已被确认
     * @param pn 要检查的数据包编号
     * @return 如果数据包已被确认则返回true，否则返回false
     *
     * 检查过程：
     * 1. 首先检查数据包编号是否在整体范围内
     * 2. 然后在ACK范围列表中查找包含该数据包编号的范围
     * 3. 验证数据包编号是否在找到的范围内
     */
    bool QuicAckFrame::acksPacket(QuicPacketNumber pn)
    {
        // 快速排除：如果编号超出整体范围，直接返回false
        if (pn < lowestAcked() || pn > largestAcked()) {
            return false;
        }
        // 查找包含该编号的ACK范围
        size_t i = 0;
        for (; i < m_ack_ranges.size(); i++) {
            if (pn >= m_ack_ranges[i]->m_smallest) {
                break;
            }
        }
        // 验证编号是否小于等于找到范围的最大值
        return pn <= m_ack_ranges[i]->m_largest;
    }

    /// QuicRstStreamFrame
    /**
     * @brief 计算RESET_STREAM帧的总大小
     * @return 帧的总字节数
     *
     * RESET_STREAM帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 流标识符的变长整数编码长度
     * 3. 错误码的变长整数编码长度
     * 4. 最终偏移量的变长整数编码长度
     */
    size_t QuicRstStreamFrame::size() const
    {
        // 如果已有缓存的大小值，直接返回
        if (this->m_size) {
            return m_size;
        }
        // 计算帧的总大小
        return 1 + MBuffer::var_size(this->m_stream_id) + MBuffer::var_size(this->m_error_code)
               + MBuffer::var_size(this->m_final_offset);
    }

    /**
     * @brief 从缓冲区读取并解析RESET_STREAM帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * 解析流程：
     * 1. 读取流标识符(stream_id)
     * 2. 读取最终偏移量(final_offset)
     * 3. 读取错误码(error_code)
     * 4. 标记帧为有效并计算总大小
     */
    bool QuicRstStreamFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 读取流标识符
        size_t streamid_len = 0;
        if (!read_varint(buffer_block, m_stream_id, streamid_len)) {
            return false;
        }
        // 读取最终偏移量
        size_t offset_len = 0;
        if (!read_varint(buffer_block, m_final_offset, offset_len)) {
            return false;
        }
        // 读取错误码
        size_t error_code_len = 0;
        if (!read_varint(buffer_block, m_error_code, error_code_len)) {
            return false;
        }
        // 标记帧为有效并计算总大小
        m_valid = true;
        m_size = 1 + streamid_len + error_code_len + offset_len;
        return true;
    }

    /**
     * @brief 将RESET_STREAM帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(RESET_STREAM)
     * 2. 变长整数编码写入流标识符
     * 3. 变长整数编码写入最终偏移量
     * 4. 变长整数编码写入错误码
     */
    bool QuicRstStreamFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 写入帧类型字节
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::RESET_STREAM);
            buffer_block->writeFuint8(type_byte);
            // 写入流标识符
            buffer_block->var_encode(m_stream_id);
            // 写入最终偏移量
            buffer_block->var_encode(m_final_offset);
            // 写入错误码
            buffer_block->var_encode(m_error_code);
            return true;
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 生成RESET_STREAM帧的可读字符串表示
     * @return RESET_STREAM帧的字符串描述
     *
     * 包含帧大小、流标识符、错误码和最终偏移量的信息
     */
    std::string QuicRstStreamFrame::toString() const
    {
        std::stringstream ss;
        ss << "[RstFrame size: " << size() << ", stream_id: " << m_stream_id
           << ", error_code: " << m_error_code << ", final_offset: " << m_final_offset;
        return ss.str();
    }

    /// QuicPingFrame
    /**
     * @brief 从缓冲区读取并解析PING帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 总是返回true，因为PING帧只有类型字节，没有其他数据
     *
     * PING帧非常简单，只有一个类型字节，没有其他负载数据
     * 此方法标记帧为有效
     */
    bool QuicPingFrame::readFrom(MBuffer::ptr buffer_block)
    {
        return true;
    }

    /**
     * @brief 将PING帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * PING帧只包含一个类型字节(PING)
     */
    bool QuicPingFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 写入PING帧类型字节
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::PING);
            buffer_block->writeFuint8(type_byte);
            return true;
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 生成PING帧的可读字符串表示
     * @return PING帧的字符串描述
     */
    std::string QuicPingFrame::toString() const
    {
        std::stringstream ss;
        ss << "[PingFrame size: " << size() << "]";
        return ss.str();
    }

    /// PaddingFrame
    /**
     * @brief 从缓冲区读取并解析PADDING帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 总是返回true，因为PADDING帧只有类型字节，没有其他数据
     *
     * PADDING帧用于填充数据包，确保达到所需大小
     */
    bool QuicPaddingFrame::readFrom(MBuffer::ptr buffer_block)
    {
        return true;
    }

    /**
     * @brief 将PADDING帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * PADDING帧只包含一个类型字节(PADDING)
     * 注意：在实际使用中，PADDING帧通常会跟随多个额外的0字节来实现填充功能
     */
    bool QuicPaddingFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 写入PADDING帧类型字节
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::PADDING);
            buffer_block->writeFuint8(type_byte);
            return true;
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 生成PADDING帧的可读字符串表示
     * @return PADDING帧的字符串描述
     */
    std::string QuicPaddingFrame::toString() const
    {
        std::stringstream ss;
        ss << "[PADDING_STREAM size: " << this->size() << "]";
        return ss.str();
    }

    /// ConnectionCloseFrame
    /**
     * @brief 解析CONNECTION_CLOSE帧的类型字节
     * @param type_byte 帧类型字节
     * @return 总是返回true
     *
     * 根据类型字节判断错误类型：
     * - 0x1c: 传输错误（协议级错误）
     * - 0x1d: 应用错误
     */
    bool QuicConnectionCloseFrame::readTypeByte(uint8_t type_byte)
    {
        // 处理传输错误帧类型
        if (type_byte == 0x1c) {
            if (m_frame_type == QuicFrameType::PADDING) {
                m_frame_type = QuicFrameType::UNKNOWN;
            }
        }
        // 处理应用错误帧类型
        if (type_byte == 0x1d) {
            m_is_application_error = true;
        }
        return true;
    }

    /**
     * @brief 从缓冲区读取并解析CONNECTION_CLOSE帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * 解析流程：
     * 1. 读取错误码
     * 2. 如果是传输错误，读取触发错误的帧类型
     * 3. 读取原因短语长度和原因短语
     * 4. 标记帧为有效并计算总大小
     */
    bool QuicConnectionCloseFrame::readFrom(MBuffer::ptr buffer_block)
    {
        int ret = 0;
        // 读取错误码
        size_t error_code_len = 0;
        if (!read_varint(buffer_block, m_error_code, error_code_len)) {
            return false;
        }
        // 如果是传输错误，读取触发错误的帧类型
        if (!m_is_application_error) {
            size_t frame_type_len = 0;
            uint64_t frame_type = 0;
            if (!read_varint(buffer_block, frame_type, frame_type_len)) {
                return false;
            }
            m_frame_type = (QuicFrameType)frame_type;
        }
        // 读取原因短语长度
        size_t reason_phase_len = 0;
        if (!read_varint(buffer_block, m_reason_phrase_len, reason_phase_len)) {
            return false;
        }
        // 验证缓冲区中是否有足够的数据
        ret = stream_read_assert(buffer_block, reason_phase_len);
        if (ret < 0) {
            _LOG_INFO(g_logger) << "stream bufferRead failed, ret: " << ret << ", "
                                << strerror(errno);
            return false;
        }
        // 读取原因短语内容
        m_reason_phrase.resize(m_reason_phrase_len);
        buffer_block->copyOut(&m_reason_phrase[0], m_reason_phrase.size());
        buffer_block->consume(m_reason_phrase.size());
        // 标记帧为有效
        m_valid = true;
        // m_size = 1 + error_code_len + field_len + reason_phase_len + m_reason_phrase_len;
        return true;
    }

    /**
     * @brief 将CONNECTION_CLOSE帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 根据错误类型选择适当的帧类型字节
     * 2. 写入错误码
     * 3. 如果是传输错误，写入触发错误的帧类型
     * 4. 写入原因短语长度和原因短语内容
     */
    bool QuicConnectionCloseFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 根据错误类型设置帧类型字节
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::CONNECTION_CLOSE);
            if (m_is_application_error) {
                type_byte = 0x1d;
            }
            // 写入帧类型字节
            buffer_block->writeFuint8(type_byte);
            // 写入错误码
            buffer_block->var_encode(m_error_code);
            // 如果是传输错误，写入触发错误的帧类型
            if (!m_is_application_error) {
                buffer_block->var_encode(static_cast<uint64_t>(m_frame_type));
            }
            // 处理未知帧类型的情况
            if (m_frame_type == QuicFrameType::UNKNOWN) {
                m_frame_type = QuicFrameType::PADDING;
            }
            // 写入原因短语长度和内容
            buffer_block->var_encode(m_reason_phrase_len);
            buffer_block->write(m_reason_phrase.c_str(), m_reason_phrase.size());
            return true;
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算CONNECTION_CLOSE帧的总大小
     * @return 帧的总字节数
     *
     * CONNECTION_CLOSE帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 错误码的变长整数编码长度
     * 3. 原因短语长度的变长整数编码长度
     * 4. 原因短语内容的长度
     * 5. 如果是应用错误，还需要加上帧类型的变长整数编码长度
     *
     * 注意：计算中使用了sizeof()获取类型大小，这可能不准确，实际应使用var_size(error_code)
     * 但为了保持与现有实现一致，暂时保持不变
     */
    size_t QuicConnectionCloseFrame::size() const
    {
        // 使用缓存的大小值，避免重复计算
        if (this->m_size) {
            return this->m_size;
        }

        // 计算基本部分长度
        size_t length = 0;
        // 帧类型字节(1) + 错误码长度 + 原因短语长度字段长度 + 原因短语内容长度
        length = 1 + MBuffer::var_size(sizeof(QuicTransErrorCode))
                 + MBuffer::var_size(this->m_reason_phrase_len) + this->m_reason_phrase_len;

        // 如果是应用错误，添加帧类型的长度
        if (m_is_application_error) {
            length += MBuffer::var_size(sizeof(QuicFrameType));
        }

        return length;
    }

    /**
     * @brief 生成CONNECTION_CLOSE帧的可读字符串表示
     * @return CONNECTION_CLOSE帧的字符串描述
     *
     * 使用调试名称转换错误码和帧类型，使输出更具可读性
     * 格式: [ConnectionCloseFrame: size: XX, code: XX, frame_type: XX]
     *
     * 注意：当前实现没有包含原因短语信息，可以考虑在后续版本中添加
     */
    std::string QuicConnectionCloseFrame::toString() const
    {
        std::stringstream ss;
        // 构造包含帧类型、大小、错误码和帧类型的字符串表示
        // 使用QuicDebugNames工具类将数值转换为人类可读的名称
        ss << "[ConnectionCloseFrame: size: " << size()
           << ", code: " << QuicDebugNames::error_code(this->error_code())
           << ", frame_type: " << QuicDebugNames::frame_type(this->frame_type());
        return ss.str();
    }

    /// QuicMaxDataFrame
    /**
     * @brief 从缓冲区读取MAX_DATA帧数据
     * @param buffer_block 输入缓冲区，包含帧数据的剩余部分（不包括帧类型字节）
     * @return 如果读取和解析成功返回true，否则返回false
     *
     * 解析流程：
     * 1. 读取并解析最大数据限制值（变长整数）
     * 2. 标记帧为有效并计算总大小
     *
     * MAX_DATA帧用于控制连接级别的最大数据量，接收方通过此帧通知发送方
     * 可以发送的数据总量限制，是QUIC流控机制的重要组成部分
     */
    bool QuicMaxDataFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 读取并解析最大数据限制值（变长整数）
        size_t maximum_data_len = 0;
        if (!read_varint(buffer_block, m_maximum_data, maximum_data_len)) {
            return false; // 解析失败返回false
        }

        // 标记帧为有效并计算总大小
        m_valid = true; // 标记帧已成功解析
        // 帧大小 = 帧类型字节(1) + 最大数据限制值的长度
        m_size = 1 + maximum_data_len;
        return true;
    }

    bool QuicMaxDataFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::MAX_DATA);
            buffer_block->writeFuint8(type_byte);
            buffer_block->var_encode(m_maximum_data);
            return true;
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算MAX_DATA帧的大小
     * @return 帧的总字节数
     *
     * MAX_DATA帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 最大数据值的变长整数编码长度
     */
    size_t QuicMaxDataFrame::size() const
    {
        // 使用缓存的大小值，避免重复计算
        if (this->m_size) {
            return m_size; // 返回缓存的大小值
        }

        // 计算类型字节和最大数据值的变长整数编码长度之和
        // sizeof(QuicFrameType)通常为1字节
        return sizeof(QuicFrameType) + MBuffer::var_size(this->m_maximum_data);
    }

    /**
     * @brief 生成MAX_DATA帧的可读字符串表示
     * @return MAX_DATA帧的字符串描述
     *
     * 包含帧大小和最大数据值，便于调试和日志记录
     * 格式: [MAXDATA size: XX, maximum: XX]
     */
    std::string QuicMaxDataFrame::toString() const
    {
        std::stringstream ss;
        // 构造包含帧类型、大小和最大数据值的字符串表示
        ss << "[MAXDATA size: " << size() << ", maximum: " << m_maximum_data << "]";
        return ss.str();
    }

    /// MaxStreamDataFrame
    /**
     * @brief 从缓冲区读取并解析MAX_STREAM_DATA帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * MAX_STREAM_DATA帧用于限制特定流上可以发送的数据量
     * 解析流程：
     * 1. 读取流标识符(stream_id)
     * 2. 读取最大流数据值(maximum_stream_data)
     * 3. 标记帧为有效并计算总大小
     *
     * 该帧是QUIC流级流控机制的核心，允许接收方针对每个流单独设置数据量限制
     */
    bool QuicMaxStreamDataFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 1. 读取流标识符（变长整数编码）
        size_t streamid_len = 0;
        if (!read_varint(buffer_block, m_stream_id, streamid_len)) {
            return false; // 流ID解析失败，返回false
        }

        // 2. 读取最大流数据值（变长整数编码）
        // 该值表示允许发送方在指定流上发送的数据总量上限
        size_t maximum_data_len = 0;
        if (!read_varint(buffer_block, m_maximum_stream_data, maximum_data_len)) {
            return false; // 最大流数据值解析失败，返回false
        }

        // 3. 标记帧为有效并计算总大小
        m_valid = true; // 标记帧已成功解析并有效
        // 帧总大小 = 帧类型字节(1) + 流ID长度 + 最大流数据值长度
        m_size = 1 + streamid_len + maximum_data_len;
        return true; // 解析成功，返回true
    }

    /**
     * @brief 将MAX_STREAM_DATA帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(MAX_STREAM_DATA, 0x11)
     * 2. 变长整数编码写入流标识符
     * 3. 变长整数编码写入最大流数据值
     *
     * 该帧用于实现QUIC的流级流控，通知发送方特定流的当前接收窗口大小
     */
    bool QuicMaxStreamDataFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入帧类型字节(MAX_STREAM_DATA, 0x11)
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::MAX_STREAM_DATA);
            buffer_block->writeFuint8(type_byte);

            // 2. 使用变长整数编码写入流标识符
            // 流ID标识了此流控指令适用的特定QUIC流
            buffer_block->var_encode(m_stream_id);

            // 3. 使用变长整数编码写入最大流数据值
            // 此值告知发送方可以在该流上发送的最大数据量
            buffer_block->var_encode(m_maximum_stream_data);

            return true; // 写入成功，返回true
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算MAX_STREAM_DATA帧的大小
     * @return 帧的总字节数
     *
     * MAX_STREAM_DATA帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 流标识符的变长整数编码长度
     * 3. 最大流数据值的变长整数编码长度
     */
    size_t QuicMaxStreamDataFrame::size() const
    {
        // 如果已有缓存的大小值，直接返回
        if (this->m_size) {
            return this->m_size;
        }
        // 计算类型字节、流标识符和最大流数据值的变长整数编码长度之和
        return sizeof(QuicFrameType) + MBuffer::var_size(this->m_maximum_stream_data)
               + MBuffer::var_size(this->m_stream_id);
    }

    /**
     * @brief 生成MAX_STREAM_DATA帧的可读字符串表示
     * @return MAX_STREAM_DATA帧的字符串描述
     *
     * 包含帧大小、流标识符和最大流数据值
     */
    std::string QuicMaxStreamDataFrame::toString() const
    {
        std::stringstream ss;
        ss << "[MAX_STREAM_DATA size: " << size() << ", stream_id: " << m_stream_id
           << ", maximum: " << m_maximum_stream_data << "]";
        return ss.str();
    }

    /// MaxStreamFrame
    /**
     * @brief QuicMaxStreamsFrame构造函数
     * @param type 流类型(客户端流或服务器流)
     * @param max_num 最大流数量限制
     *
     * MAX_STREAMS帧用于限制对等方可以打开的流数量
     */
    QuicMaxStreamsFrame::QuicMaxStreamsFrame(QuicStreamType type, QuicStreamNum max_num)
        : m_type(type), m_maximum_streams(max_num)
    {
    }

    /**
     * @brief 从缓冲区读取并解析MAX_STREAMS帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * 解析流程：
     * 1. 读取最大流数量值
     * 2. 标记帧为有效并计算总大小
     *
     * 该帧是QUIC连接级流控机制的一部分，限制对等方可以打开的流数量
     * 注意：流类型(客户端流或服务器流)是由帧类型字节决定的，在parseFrame方法中设置
     */
    bool QuicMaxStreamsFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 1. 读取最大流数量值（变长整数编码）
        // 该值表示允许对等方打开的同类型流的最大数量
        size_t maximum_data_len = 0;
        if (!read_varint(buffer_block, m_maximum_streams, maximum_data_len)) {
            return false; // 最大流数量值解析失败，返回false
        }

        // 2. 标记帧为有效并计算总大小
        m_valid = true; // 标记帧已成功解析并有效
        // 帧总大小 = 帧类型字节(1) + 最大流数量值长度
        m_size = 1 + maximum_data_len;
        return true; // 解析成功，返回true
    }

    /**
     * @brief 将MAX_STREAMS帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(MAX_STREAMS_BIDI=0x12或MAX_STREAMS_UNI=0x13)
     * 2. 变长整数编码写入最大流数量值
     *
     * 该帧用于实现QUIC的连接级流控，限制对等方可以创建的流数量
     */
    bool QuicMaxStreamsFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 根据流类型写入相应的帧类型字节
            // 双向流使用MAX_STREAMS_BIDI(0x12)，单向流使用MAX_STREAMS_UNI(0x13)
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::MAX_STREAMS);
            buffer_block->writeFuint8(type_byte);

            // 2. 使用变长整数编码写入最大流数量值
            // 此值告知对等方可以打开的同类型流的最大数量
            buffer_block->var_encode(m_maximum_streams);

            return true; // 写入成功，返回true
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算MAX_STREAMS帧的大小
     * @return 帧的总字节数
     *
     * MAX_STREAMS帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 最大流数量值的变长整数编码长度
     *
     * 帧大小计算考虑了缓存优化，避免重复计算
     */
    size_t QuicMaxStreamsFrame::size() const
    {
        // 优先检查是否已有缓存的大小值，避免重复计算
        if (this->m_size) {
            return this->m_size; // 直接返回缓存的大小值
        }

        // 计算帧总大小：类型字节(1) + 最大流数量的变长整数编码长度
        // sizeof(QuicFrameType)通常为1字节，表示帧类型标识
        return sizeof(QuicFrameType) + MBuffer::var_size(this->m_maximum_streams);
    }

    /**
     * @brief 生成MAX_STREAMS帧的可读字符串表示
     * @return MAX_STREAMS帧的字符串描述
     *
     * 包含帧大小和最大流数量值
     */
    std::string QuicMaxStreamsFrame::toString() const
    {
        std::stringstream ss;
        ss << "[MAX_STREAMS size: " << size() << ", maximum: " << m_maximum_streams << "]";
        return ss.str();
    }

    /// QuicDataBlockFrame
    /**
     * @brief 从缓冲区读取并解析DATA_BLOCKED帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * DATA_BLOCKED帧用于通知对等方，由于连接级别的流量控制限制，无法发送更多数据
     * 解析流程：
     * 1. 读取数据偏移量(offset)
     * 2. 标记帧为有效并计算总大小
     */
    bool QuicDataBlockedFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 1. 读取数据偏移量（变长整数编码）
        // 该偏移量表示发送方希望发送但因流量控制被阻塞的数据位置
        size_t offset_len = 0;
        if (!read_varint(buffer_block, m_offset, offset_len)) {
            return false; // 数据偏移量解析失败，返回false
        }

        // 2. 标记帧为有效并计算总大小
        m_valid = true; // 标记帧已成功解析并有效
        // 帧总大小 = 帧类型字节(1) + 数据偏移量长度
        m_size = 1 + offset_len;
        return true; // 解析成功，返回true
    }

    /**
     * @brief 将DATA_BLOCKED帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(DATA_BLOCKED)
     * 2. 变长整数编码写入数据偏移量
     */
    bool QuicDataBlockedFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入帧类型字节(DATA_BLOCKED, 0x14)
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::DATA_BLOCKED);
            buffer_block->writeFuint8(type_byte);

            // 2. 使用变长整数编码写入数据偏移量
            // 此偏移量告知接收方发送方希望发送但被流量控制阻塞的数据位置
            buffer_block->var_encode(m_offset);

            return true; // 写入成功，返回true
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算DATA_BLOCKED帧的大小
     * @return 帧的总字节数
     *
     * DATA_BLOCKED帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 数据偏移量的变长整数编码长度
     */
    size_t QuicDataBlockedFrame::size() const
    {
        // 优先检查是否已有缓存的大小值，避免重复计算
        if (this->m_size) {
            return this->m_size; // 直接返回缓存的大小值
        }

        // 计算帧总大小：类型字节(1) + 数据偏移量的变长整数编码长度
        // sizeof(QuicFrameType)通常为1字节，表示帧类型标识
        return sizeof(QuicFrameType) + MBuffer::var_size(this->m_offset);
    }

    /**
     * @brief 生成DATA_BLOCKED帧的可读字符串表示
     * @return DATA_BLOCKED帧的字符串描述
     *
     * 包含帧大小和数据偏移量
     */
    std::string QuicDataBlockedFrame::toString() const
    {
        std::stringstream ss;
        // 构造包含帧类型、大小和数据偏移量的字符串表示
        // 格式: [DataBlocked size: XX, offset: XX]
        ss << "[DataBlocked size: " << size() << ", offset: " << m_offset << "]";
        return ss.str(); // 返回格式化的字符串，便于调试和日志记录
    }

    /// StreamDataBlockedFrame
    /**
     * @brief 从缓冲区读取并解析STREAM_DATA_BLOCKED帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * STREAM_DATA_BLOCKED帧用于通知对等方，由于特定流的流量控制限制，无法发送更多数据
     * 解析流程：
     * 1. 读取流标识符(stream_id)
     * 2. 读取数据偏移量(offset)
     * 3. 标记帧为有效并计算总大小
     *
     * 该帧是QUIC流级流控机制的一部分，用于流级别的流量控制反馈
     */
    bool QuicStreamDataBlockedFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 1. 读取流标识符（变长整数编码）
        // 标识被流量控制阻塞的特定流
        size_t streamid_len = 0;
        if (!read_varint(buffer_block, m_stream_id, streamid_len)) {
            return false; // 流ID解析失败，返回false
        }

        // 2. 读取数据偏移量（变长整数编码）
        // 表示发送方希望发送但因流量控制被阻塞的数据位置
        size_t offset_len = 0;
        if (!read_varint(buffer_block, m_offset, offset_len)) {
            return false; // 数据偏移量解析失败，返回false
        }

        // 3. 标记帧为有效并计算总大小
        m_valid = true; // 标记帧已成功解析并有效
        // 帧总大小 = 帧类型字节(1) + 流ID长度 + 数据偏移量长度
        m_size = 1 + streamid_len + offset_len;
        return true; // 解析成功，返回true
    }

    /**
     * @brief 将STREAM_DATA_BLOCKED帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(STREAM_DATA_BLOCKED, 0x15)
     * 2. 变长整数编码写入流标识符
     * 3. 变长整数编码写入数据偏移量
     *
     * 该帧用于实现QUIC的流级流控反馈，通知接收方特定流的流量控制限制
     */
    bool QuicStreamDataBlockedFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入帧类型字节(STREAM_DATA_BLOCKED, 0x15)
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::STREAM_DATA_BLOCKED);
            buffer_block->writeFuint8(type_byte);

            // 2. 使用变长整数编码写入流标识符
            // 标识被流量控制阻塞的特定流
            buffer_block->var_encode(m_stream_id);

            // 3. 使用变长整数编码写入数据偏移量
            // 此偏移量告知接收方发送方希望发送但被流量控制阻塞的数据位置
            buffer_block->var_encode(m_offset);

            return true; // 写入成功，返回true
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算STREAM_DATA_BLOCKED帧的大小
     * @return 帧的总字节数
     *
     * STREAM_DATA_BLOCKED帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 数据偏移量的变长整数编码长度
     * 3. 流标识符的变长整数编码长度
     */
    size_t QuicStreamDataBlockedFrame::size() const
    {
        // 优先检查是否已有缓存的大小值，避免重复计算
        if (this->m_size) {
            return this->m_size; // 直接返回缓存的大小值
        }

        // 计算帧总大小：类型字节(1) + 数据偏移量长度 + 流ID长度
        // 使用MBuffer::var_size计算变长整数的编码长度
        return sizeof(QuicFrameType) + MBuffer::var_size(this->m_offset)
               + MBuffer::var_size(this->m_stream_id);
    }

    /**
     * @brief 生成STREAM_DATA_BLOCKED帧的可读字符串表示
     * @return STREAM_DATA_BLOCKED帧的字符串描述
     *
     * 包含帧大小、流标识符和数据偏移量
     */
    std::string QuicStreamDataBlockedFrame::toString() const
    {
        std::stringstream ss;
        // 构造包含帧类型、大小、流ID和数据偏移量的字符串表示
        // 格式: [StreamDataBlocked size: XX, stream_id: XX, offset: XX]
        ss << "[StreamDataBlocked size: " << size() << ", stream_id: " << m_stream_id
           << ", offset: " << m_offset << "]";
        return ss.str(); // 返回格式化的字符串，便于调试和日志记录
    }

    /// StreamsBlockFrame
    /**
     * @brief QuicStreamsBlockedFrame构造函数
     * @param type 流类型(双向流或单向流)
     * @param num 流限制值
     *
     * STREAMS_BLOCKED帧用于通知对等方，由于流数量限制，无法创建更多流
     */
    QuicStreamsBlockedFrame::QuicStreamsBlockedFrame(QuicStreamType type, QuicStreamNum num)
        : m_stream_type(type), m_stream_limit(num)
    {
    }

    /**
     * @brief 根据帧类型字节确定流类型
     * @param type_byte 帧类型字节
     * @return 始终返回true，表示类型字节已成功解析
     *
     * 根据RFC 9000，流阻塞帧有两种类型：
     * - 0x16: 双向流阻塞
     * - 0x17: 单向流阻塞
     */
    bool QuicStreamsBlockedFrame::readTypeByte(uint8_t type_byte)
    {
        // 0x16表示双向流阻塞
        if (type_byte == 0x16) {
            m_stream_type = QuicStreamType::QuicStreamTypeBidi;
            return true;
        }
        // 其他情况(0x17)表示单向流阻塞
        m_stream_type = QuicStreamType::QuicStreamTypeUni;
        return true;
    }

    /**
     * @brief 从缓冲区读取并解析STREAMS_BLOCKED帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * 解析流程：
     * 1. 读取流限制值
     * 2. 标记帧为有效并计算总大小
     */
    bool QuicStreamsBlockedFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 1. 读取流限制值（变长整数编码）
        // 该值表示发送方希望创建但因流数量限制被阻塞的流ID
        size_t stream_limit_len = 0;
        if (!read_varint(buffer_block, m_stream_limit, stream_limit_len)) {
            return false; // 流限制值解析失败，返回false
        }

        // 2. 标记帧为有效并计算总大小
        m_valid = true; // 标记帧已成功解析并有效
        // 帧总大小 = 帧类型字节(1) + 流限制值长度
        m_size = 1 + stream_limit_len;
        return true; // 解析成功，返回true
    }

    /**
     * @brief 将STREAMS_BLOCKED帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 根据流类型确定帧类型字节
     *   - 双向流: STREAM_BLOCKED (0x16)
     *   - 单向流: STREAM_BLOCKED + 1 (0x17)
     * 2. 写入帧类型字节
     * 3. 变长整数编码写入流限制值
     */
    bool QuicStreamsBlockedFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 根据流类型确定帧类型字节
            // 双向流使用STREAM_BLOCKED(0x16)，单向流使用STREAM_BLOCKED+1(0x17)
            uint8_t type_byte;
            if (m_stream_type == QuicStreamType::QuicStreamTypeBidi) {
                type_byte = static_cast<uint8_t>(QuicFrameType::STREAM_BLOCKED); // 0x16
            } else {
                type_byte = static_cast<uint8_t>(QuicFrameType::STREAM_BLOCKED) + 1; // 0x17
            }

            // 2. 写入帧类型字节
            buffer_block->writeFuint8(type_byte);

            // 3. 使用变长整数编码写入流限制值
            // 此值告知接收方发送方希望创建但被流数量限制阻塞的流ID
            buffer_block->var_encode(m_stream_limit);

            return true; // 写入成功，返回true
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算STREAMS_BLOCKED帧的大小
     * @return 帧的总字节数
     *
     * STREAMS_BLOCKED帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 流限制值的变长整数编码长度
     */
    size_t QuicStreamsBlockedFrame::size() const
    {
        // 优先检查是否已有缓存的大小值，避免重复计算
        if (this->m_size) {
            return this->m_size; // 直接返回缓存的大小值
        }
        // 计算帧总大小：类型字节(1) + 流限制值的变长整数编码长度
        // sizeof(QuicFrameType)通常为1字节，表示帧类型标识
        return sizeof(QuicFrameType) + MBuffer::var_size(this->m_stream_limit);
    }

    /**
     * @brief 生成STREAMS_BLOCKED帧的可读字符串表示
     * @return STREAMS_BLOCKED帧的字符串描述
     *
     * 包含帧大小和流限制值
     */
    std::string QuicStreamsBlockedFrame::toString() const
    {
        std::stringstream ss;
        // 构造包含帧类型、大小和流限制值的字符串表示
        // 格式: [STREAMS_BLOCK_FRAME size: XX, stream_limit: XX]
        ss << "[STREAMS_BLOCK_FRAME size: " << size() << ", stream_limit: " << m_stream_limit
           << "]";
        return ss.str(); // 返回格式化的字符串，便于调试和日志记录
    }

    /// QuicNewConnectionIdFrame
    /**
     * @brief 从缓冲区读取并解析NEW_CONNECTION_ID帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * NEW_CONNECTION_ID帧用于提供新的连接标识符，支持QUIC的连接迁移功能
     * 解析流程：
     * 1. 读取序列号(sequence)
     * 2. 读取retire_prior_to值
     * 3. 读取连接ID长度和连接ID
     * 4. 读取无状态重置令牌
     * 5. 标记帧为有效并计算总大小
     *
     * 该帧是QUIC连接迁移机制的核心，允许在网络切换时保持连接
     */
    bool QuicNewConnectionIdFrame::readFrom(MBuffer::ptr buffer_block)
    {
        int ret = 0;

        // 1. 读取序列号（变长整数编码）
        // 序列号用于标识此连接ID的版本，必须单调递增
        size_t seq_len = 0;
        if (!read_varint(buffer_block, m_sequence, seq_len)) {
            return false; // 序列号解析失败，返回false
        }

        // 2. 读取retire_prior_to值（变长整数编码）
        // 指示接收方应撤销所有序列号小于此值的连接ID
        size_t retire_prior_len = 0;
        if (!read_varint(buffer_block, m_retire_prior_to, retire_prior_len)) {
            return false; // retire_prior_to解析失败，返回false
        }

        // 3. 读取连接ID长度（1字节）
        size_t cid_len = buffer_block->readFUint8();
        buffer_block->consume(1); // 消费已读取的长度字节

        // 4. 读取连接ID数据
        ret = stream_read_assert(buffer_block, cid_len);
        if (ret < 0) {
            return false; // 连接ID数据不足，返回false
        }
        m_connection_id = QuicConnectionId((uint8_t *)(buffer_block->toString().c_str()), cid_len);
        buffer_block->consume(cid_len); // 消费已读取的连接ID数据

        // 5. 读取无状态重置令牌
        ret = stream_read_assert(buffer_block, QuicStatelessResetToken::LEN);
        if (ret < 0) {
            return false; // 无状态重置令牌数据不足，返回false
        }
        m_stateless_reset_token =
            QuicStatelessResetToken((uint8_t *)(buffer_block->toString().c_str()));

        // 6. 标记帧为有效并计算总大小
        m_valid = true; // 标记帧已成功解析并有效
        // 帧总大小 = 帧类型(1) + 序列号长度 + retire_prior_to长度 + CID长度字段(1) + CID长度 +
        // 重置令牌长度
        m_size = 1 + seq_len + retire_prior_len + 1 + cid_len + QuicStatelessResetToken::LEN;
        return true; // 解析成功，返回true
    }

    /**
     * @brief 将NEW_CONNECTION_ID帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(NEW_CONNECTION_ID, 0x18)
     * 2. 变长整数编码写入序列号
     * 3. 变长整数编码写入retire_prior_to值
     * 4. 变长整数编码写入连接ID长度
     * 5. 写入连接ID数据
     * 6. 写入无状态重置令牌
     *
     * 该帧用于在QUIC连接中提供新的连接ID，支持连接迁移功能
     */
    bool QuicNewConnectionIdFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入帧类型字节(NEW_CONNECTION_ID, 0x18)
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::NEW_CONNECTION_ID);
            buffer_block->writeFuint8(type_byte);

            // 2. 使用变长整数编码写入序列号
            // 序列号用于标识此连接ID的版本，必须单调递增
            buffer_block->var_encode(m_sequence);

            // 3. 使用变长整数编码写入retire_prior_to值
            // 指示接收方应撤销所有序列号小于此值的连接ID
            buffer_block->var_encode(m_retire_prior_to);

            // 4. 使用变长整数编码写入连接ID长度
            buffer_block->var_encode(m_connection_id.length());

            // 5. 写入连接ID数据
            buffer_block->write(m_connection_id, m_connection_id.length());

            // 6. 写入无状态重置令牌
            // 用于无状态终止连接的安全验证
            buffer_block->write(m_stateless_reset_token.buf(), QuicStatelessResetToken::LEN);

            return true; // 写入成功，返回true
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 计算NEW_CONNECTION_ID帧的大小
     * @return 帧的总字节大小
     *
     * 帧大小计算规则：
     * 1. 帧类型字节(1字节)
     * 2. 序列号的变长整数编码长度
     * 3. retire_prior_to的变长整数编码长度
     * 4. 连接ID长度的变长整数编码长度
     * 5. 连接ID数据长度
     * 6. 无状态重置令牌长度(16字节)
     */
    size_t QuicNewConnectionIdFrame::size() const
    {
        // 优先检查是否已有缓存的大小值，避免重复计算
        if (m_size) {
            return m_size; // 直接返回缓存的大小值
        }
        // 计算帧总大小：
        // 1. 帧类型标识(通常为1字节) +
        // 2. 序列号的变长整数编码长度 +
        // 3. retire_prior_to的变长整数编码长度 +
        // 4. 连接ID长度(1字节) +
        // 5. 连接ID数据本身的长度 +
        // 6. 无状态重置令牌长度(固定16字节)
        return sizeof(QuicFrameType) +                // 帧类型字节(1字节)
               MBuffer::var_size(m_sequence) +        // 序列号的变长整数编码长度
               MBuffer::var_size(m_retire_prior_to) + // retire_prior_to的变长整数编码长度
               1 +                                    // 连接ID长度(1字节)
               m_connection_id.length() +             // 连接ID数据长度
               QuicStatelessResetToken::LEN;          // 无状态重置令牌长度(16字节)
    }

    /**
     * @brief 将NEW_CONNECTION_ID帧转换为字符串表示
     * @return 帧的字符串表示，用于调试和日志记录
     *
     * 字符串格式：[NEW_CONNECTION_ID size: 大小, seq: 序列号, rpt: retire_prior_to值, cid:
     * 连接ID(十六进制)] 该方法生成的字符串主要用于调试、日志记录和问题排查
     */
    std::string QuicNewConnectionIdFrame::toString() const
    {
        std::stringstream ss; // 创建字符串流用于构建格式化字符串

        // 构建包含帧类型、大小、序列号、retire_prior_to和连接ID的调试字符串
        ss << "[NEW_CONNECTION_ID size: " << size() << ", seq: " << sequence()
           << ", rpt: " << retire_prior_to() << ", cid: " << connection_id().toHexString().c_str()
           << "]";

        return ss.str(); // 返回构建好的字符串，用于调试和日志输出
    }

    /// StopSendingFrame
    /**
     * @brief 从缓冲区读取STOP_SENDING帧数据
     * @param buffer_block 输入缓冲区，包含帧数据的剩余部分（不包括帧类型字节）
     * @return 如果读取和解析成功返回true，否则返回false
     *
     * 解析流程：
     * 1. 读取并解析流标识符（变长整数）
     * 2. 读取并解析应用协议错误码（变长整数）
     * 3. 标记帧为有效并计算总大小
     *
     * STOP_SENDING帧用于通知对端停止在指定流上发送数据，通常是因为应用程序不再需要该流的数据
     */
    bool QuicStopSendingFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 1. 读取并解析流标识符（变长整数）
        size_t streamid_len = 0;
        if (!read_varint(buffer_block, m_stream_id, streamid_len)) {
            return false;
        }

        // 2. 读取并解析应用协议错误码（变长整数）
        size_t error_code_len = 0;
        if (!read_varint(buffer_block, m_error_code, error_code_len)) {
            return false;
        }

        // 3. 标记帧为有效并计算总大小
        m_valid = true; // 标记帧已成功解析
        // 帧大小 = 帧类型字节(1) + 流ID长度 + 错误码长度
        m_size = 1 + streamid_len + error_code_len;
        return true;
    }

    /**
     * @brief 将STOP_SENDING帧数据写入缓冲区
     * @param buffer_block 输出缓冲区，帧数据将被写入此缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(STOP_SENDING, 0x05)
     * 2. 变长整数编码写入流标识符
     * 3. 变长整数编码写入应用协议错误码
     */
    /**
     * @brief 将STOP_SENDING帧数据写入缓冲区
     * @param buffer_block 输出缓冲区，帧数据将被写入此缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(STOP_SENDING, 0x05)
     * 2. 变长整数编码写入流标识符
     * 3. 变长整数编码写入应用协议错误码
     *
     * STOP_SENDING帧用于通知对端停止在指定流上发送数据，通常是因为应用程序不再需要该流的数据
     */
    bool QuicStopSendingFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入帧类型字节(STOP_SENDING, 0x05)
            // STOP_SENDING帧的类型标识为0x05，用于指示接收方停止发送指定流的数据
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::STOP_SENDING);
            buffer_block->writeFuint8(type_byte);

            // 2. 使用变长整数编码写入流标识符
            // 流标识符指定了需要停止发送数据的流
            buffer_block->var_encode(m_stream_id);

            // 3. 使用变长整数编码写入应用协议错误码
            // 错误码用于指示停止发送的原因，由应用协议定义
            buffer_block->var_encode(m_error_code);

            return true; // 写入成功，返回true
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false;
    }

    /**
     * @brief 获取STOP_SENDING帧的大小
     * @return 帧的总字节大小
     *
     * 帧大小计算规则：
     * 1. 帧类型字节(1字节)
     * 2. 流标识符的变长整数编码长度
     * 3. 应用协议错误码的变长整数编码长度
     */
    size_t QuicStopSendingFrame::size() const
    {
        // 优先检查是否已有缓存的大小值，避免重复计算
        if (m_size) {
            return m_size; // 直接返回缓存的大小值
        }
        // 计算帧总大小：
        // 1. 帧类型标识(通常为1字节) +
        // 2. 流标识符的变长整数编码长度 +
        // 3. 应用协议错误码的变长整数编码长度
        return sizeof(QuicFrameType) +          // 帧类型字节(1字节)
               MBuffer::var_size(m_stream_id) + // 流标识符的变长整数编码长度
               MBuffer::var_size(m_error_code); // 应用协议错误码的变长整数编码长度
    }

    /**
     * @brief 生成STOP_SENDING帧的可读字符串表示
     * @return STOP_SENDING帧的字符串描述
     *
     * 包含帧大小、流标识符和错误码的详细信息，便于调试和日志记录
     * 格式: [STOP_SENDING size: XX, stream_id: XX, error_code: XX]
     * 该方法生成的字符串主要用于调试、日志记录和问题排查场景
     */
    std::string QuicStopSendingFrame::toString() const
    {
        std::stringstream ss; // 创建字符串流用于构建格式化字符串

        // 构建包含帧类型、大小、流标识符和错误码的调试字符串
        ss << "[STOP_SENDING size: " << size() << ", stream_id: " << stream_id()
           << ", error_code: " << error_code() << "]";

        return ss.str(); // 返回构建好的字符串，用于调试和日志输出
    }

    /// PathChallengeFrame
    /**
     * @brief 从缓冲区读取PATH_CHALLENGE帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * PATH_CHALLENGE帧用于路径验证，检测网络路径的双向连通性
     * 解析流程：
     * 1. 读取8字节的挑战数据
     * 2. 标记帧为有效并计算总大小
     *
     * 该帧是QUIC路径验证机制的一部分，接收方需要以PATH_RESPONSE帧响应
     */
    bool QuicPathChallengeFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 1. 检查并读取8字节的挑战数据
        int ret = stream_read_assert(buffer_block, QuicPathChallengeFrame::DATA_LEN);
        if (ret < 0) {
            return false; // 挑战数据不足，返回false
        }

        // 2. 保存挑战数据到成员变量
        m_data = std::string((char *)(buffer_block->toString().c_str()),
                             QuicPathChallengeFrame::DATA_LEN);

        // 3. 标记帧为有效并计算总大小
        m_valid = true; // 标记帧已成功解析
        // 帧总大小 = 帧类型字节(1) + 挑战数据长度(8)
        m_size = 1 + QuicPathChallengeFrame::DATA_LEN;

        return true; // 解析成功，返回true
    }

    /**
     * @brief 将PATH_CHALLENGE帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(PATH_CHALLENGE, 0x1A)
     * 2. 写入8字节的挑战数据
     *
     * PATH_CHALLENGE帧用于路径验证，检测网络路径的双向连通性
     */
    bool QuicPathChallengeFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入帧类型字节(PATH_CHALLENGE, 0x1A)
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::PATH_CHALLENGE);
            buffer_block->writeFuint8(type_byte);

            // 2. 写入8字节的挑战数据
            // 挑战数据用于唯一标识此路径验证请求
            buffer_block->write(m_data.c_str(), QuicPathChallengeFrame::DATA_LEN);

            return true; // 写入成功，返回true
        } catch (...) {
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false; // 发生异常，返回false
    }

    /**
     * @brief 计算PATH_CHALLENGE帧的大小
     * @return 帧的总字节大小
     *
     * 帧大小计算规则：
     * 1. 帧类型字节(1字节)
     * 2. 挑战数据长度(固定8字节)
     */
    size_t QuicPathChallengeFrame::size() const
    {
        // 优先检查是否已有缓存的大小值，避免重复计算
        if (m_size) {
            return m_size; // 直接返回缓存的大小值
        }
        // 计算帧总大小：帧类型字节(1) + 挑战数据长度(8)
        return sizeof(QuicFrameType) +           // 帧类型字节(1字节)
               QuicPathChallengeFrame::DATA_LEN; // 挑战数据长度(8字节)
    }

    /**
     * @brief 将PATH_CHALLENGE帧转换为字符串表示
     * @return 帧的字符串表示，用于调试和日志记录
     *
     * 字符串格式：[PathChallenge size: 大小, data: 挑战数据]
     * 该方法生成的字符串主要用于调试、日志记录和问题排查
     */
    std::string QuicPathChallengeFrame::toString() const
    {
        std::stringstream ss; // 创建字符串流用于构建格式化字符串

        // 构建包含帧类型、大小和挑战数据的调试字符串
        ss << "[PathChallenge size: " << size() << ", data: " << m_data << "]";

        return ss.str(); // 返回构建好的字符串，用于调试和日志输出
    }

    /// PathResponseFrame
    /**
     * @brief 从缓冲区读取PATH_RESPONSE帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * PATH_RESPONSE帧用于响应PATH_CHALLENGE帧，完成路径验证过程
     * 解析流程：
     * 1. 读取8字节的响应数据（应与对应的PATH_CHALLENGE帧数据相同）
     * 2. 标记帧为有效并计算总大小
     *
     * 该帧是QUIC路径验证机制的一部分，用于确认网络路径的双向连通性
     */
    bool QuicPathResponseFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 1. 检查并读取8字节的响应数据
        int ret = stream_read_assert(buffer_block, QuicPathResponseFrame::DATA_LEN);
        if (ret < 0) {
            return false; // 响应数据不足，返回false
        }

        // 2. 保存响应数据到成员变量
        m_data = std::string((char *)(buffer_block->toString().c_str()),
                             QuicPathResponseFrame::DATA_LEN);

        // 3. 标记帧为有效并计算总大小
        m_valid = true; // 标记帧已成功解析
        // 帧总大小 = 帧类型字节(1) + 响应数据长度(8)
        m_size = 1 + QuicPathResponseFrame::DATA_LEN;

        return true; // 解析成功，返回true
    }

    /**
     * @brief 将PATH_RESPONSE帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(PATH_RESPONSE, 0x1B)
     * 2. 写入8字节的响应数据（应与对应的PATH_CHALLENGE帧数据相同）
     *
     * PATH_RESPONSE帧用于响应PATH_CHALLENGE帧，完成路径验证过程
     */
    bool QuicPathResponseFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入帧类型字节(PATH_RESPONSE, 0x1B)
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::PATH_RESPONSE);
            buffer_block->writeFuint8(type_byte);
            // 2. 写入8字节的响应数据
            // 响应数据必须与接收到的PATH_CHALLENGE帧中的挑战数据完全相同
            buffer_block->write(m_data.c_str(), QuicPathResponseFrame::DATA_LEN);

            return true; // 写入成功，返回true
        } catch (...) {
            // 发生异常时记录错误日志
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false; // 发生异常，返回false
    }

    /**
     * @brief 计算PATH_RESPONSE帧的大小
     * @return 帧的总字节大小
     *
     * 帧大小计算规则：
     * 1. 帧类型字节(1字节)
     * 2. 响应数据长度(固定8字节)
     */
    size_t QuicPathResponseFrame::size() const
    {
        // 优先检查是否已有缓存的大小值，避免重复计算
        if (m_size) {
            return m_size; // 直接返回缓存的大小值
        }
        // 计算帧总大小：帧类型字节(1) + 响应数据长度(8)
        return sizeof(QuicFrameType) +          // 帧类型字节(1字节)
               QuicPathResponseFrame::DATA_LEN; // 响应数据长度(8字节)
    }

    /**
     * @brief 生成PATH_RESPONSE帧的可读字符串表示
     * @return PATH_RESPONSE帧的字符串描述，用于调试和日志记录
     *
     * 字符串格式：[PathResponse size: 大小, data: 响应数据]
     * 该方法生成的字符串主要用于调试、日志记录和问题排查
     */
    std::string QuicPathResponseFrame::toString() const
    {
        std::stringstream ss; // 创建字符串流用于构建格式化字符串

        // 构建包含帧类型、大小和响应数据的调试字符串
        ss << "[PathResponse size: " << size() << ", data: " << m_data << "]";

        return ss.str(); // 返回构建好的字符串，用于调试和日志输出
    }

    /// NewTokenFrame
    /**
     * @brief 从缓冲区读取并解析NEW_TOKEN帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * NEW_TOKEN帧用于提供一个新的连接令牌，用于连接迁移或0-RTT连接
     * 解析流程：
     * 1. 读取令牌长度
     * 2. 检查并读取令牌数据
     * 3. 标记帧为有效并计算总大小
     */
    bool QuicNewTokenFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 读取令牌长度
        size_t token_len = 0;
        if (!read_varint(buffer_block, m_token_len, token_len)) {
            return false;
        }
        // 检查并读取令牌数据
        int ret = stream_read_assert(buffer_block, m_token_len);
        if (ret < 0) {
            _LOG_INFO(g_logger) << "stream bufferRead failed, ret: " << ret << ", "
                                << strerror(errno);
            return false;
        }
        // 读取令牌内容
        m_token.resize(m_token_len);
        buffer_block->copyOut(&m_token[0], m_token.size());
        buffer_block->consume(m_token.size());
        // 标记帧为有效并计算总大小
        m_valid = true;
        m_size = 1 + token_len + m_token_len;
        return true;
    }

    /**
     * @brief 将NEW_TOKEN帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(NEW_TOKEN, 0x1C)
     * 2. 变长整数编码写入令牌长度
     * 3. 写入令牌数据
     *
     * NEW_TOKEN帧用于提供连接令牌，支持连接迁移和0-RTT连接建立
     */
    bool QuicNewTokenFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入帧类型字节：NEW_TOKEN (0x1C)
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::NEW_TOKEN);
            buffer_block->writeFuint8(type_byte);

            // 2. 使用变长整数编码写入令牌长度
            buffer_block->var_encode(m_token_len);

            // 3. 写入令牌数据
            buffer_block->write(&m_token[0], m_token.size());

            return true; // 写入成功
        } catch (...) {
            // 发生异常时记录错误日志
            _LOG_WARN(g_logger) << "write NewTokenFrame fail, " << toString();
        }
        return false; // 发生异常，返回false
    }

    /**
     * @brief 计算NEW_TOKEN帧的大小
     * @return 帧的总字节数
     *
     * NEW_TOKEN帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 令牌长度的变长整数编码长度
     * 3. 令牌的实际长度
     */
    size_t QuicNewTokenFrame::size() const
    {
        // 优先检查是否已有缓存的大小值，避免重复计算
        if (this->m_size) {
            return this->m_size; // 直接返回缓存的大小值
        }

        // 计算帧总大小：
        // 1. 帧类型字节(1字节)
        // 2. 变长整数编码的令牌长度 - 使用var_size计算变长整数编码需要的字节数
        // 3. 令牌数据本身的长度
        return sizeof(QuicFrameType) +          // 帧类型字节(1字节)
               MBuffer::var_size(m_token_len) + // 变长整数编码的令牌长度
               m_token.size();                  // 令牌数据长度
    }

    /**
     * @brief 生成NEW_TOKEN帧的可读字符串表示
     * @return NEW_TOKEN帧的字符串描述
     *
     * 包含帧大小和令牌内容
     */
    std::string QuicNewTokenFrame::toString() const
    {
        std::stringstream ss;
        ss << "[NEW_TOKEN size: " << size() << ", token: " << m_token << "]";
        return ss.str();
    }

    /// RetireConnectionIdFrame
    /**
     * @brief 从缓冲区读取并解析RETIRE_CONNECTION_ID帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * RETIRE_CONNECTION_ID帧用于通知对等方已丢弃特定的连接ID
     * 解析流程：
     * 1. 读取序列号
     * 2. 标记帧为有效并计算总大小
     */
    bool QuicRetireConnectionIdFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // 读取序列号
        size_t seq_num_len = 0;
        if (!read_varint(buffer_block, m_seq_num, seq_num_len)) {
            return false;
        }
        // 标记帧为有效并计算总大小
        m_valid = true;
        m_size = 1 + seq_num_len;
        return true;
    }

    /**
     * @brief 将RETIRE_CONNECTION_ID帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(RETIRE_CONNECTION_ID)
     * 2. 变长整数编码写入序列号
     */
    bool QuicRetireConnectionIdFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 1. 写入帧类型字节：RETIRE_CONNECTION_ID (0x1D)
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::RETIRE_CONNECTION_ID);
            buffer_block->writeFuint8(type_byte);

            // 2. 使用变长整数编码写入序列号
            // 序列号用于标识要丢弃的连接ID
            buffer_block->var_encode(m_seq_num);

            return true; // 写入成功，返回true
        } catch (...) {
            // 发生异常时记录错误日志
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false; // 发生异常，返回false
    }

    /**
     * @brief 计算RETIRE_CONNECTION_ID帧的大小
     * @return 帧的总字节数
     *
     * RETIRE_CONNECTION_ID帧大小计算规则：
     * 1. 类型字节(1字节)
     * 2. 序列号的变长整数编码长度
     */
    size_t QuicRetireConnectionIdFrame::size() const
    {
        // 优先检查是否已有缓存的大小值，避免重复计算
        if (this->m_size) {
            return this->m_size; // 直接返回缓存的大小值
        }

        // 计算帧总大小：
        // 1. 帧类型字节(1字节)
        // 2. 变长整数编码的序列号 - 使用var_size计算变长整数编码需要的字节数
        return sizeof(QuicFrameType) +             // 帧类型字节(1字节)
               MBuffer::var_size(this->m_seq_num); // 变长整数编码的序列号
    }

    /**
     * @brief 生成RETIRE_CONNECTION_ID帧的可读字符串表示
     * @return RETIRE_CONNECTION_ID帧的字符串描述
     *
     * 包含帧大小和序列号
     */
    std::string QuicRetireConnectionIdFrame::toString() const
    {
        std::stringstream ss; // 创建字符串流用于构建格式化字符串

        // 构建包含帧类型、大小和序列号的调试字符串
        // 字符串格式: [RETIRE_CONNECTION_ID size: 大小, seq num: 序列号]
        ss << "[RETIRE_CONNECTION_ID size: " << size() << ", seq num: " << m_seq_num << "]";

        return ss.str(); // 返回构建好的字符串，用于调试和日志输出
    }

    /// HandshakeDoneFrame
    /**
     * @brief 从缓冲区读取并解析HANDSHAKE_DONE帧
     * @param buffer_block 包含帧数据的缓冲区
     * @return 如果解析成功返回true，否则返回false
     *
     * HANDSHAKE_DONE帧表示握手已完成，不包含额外数据
     * 解析流程：
     * 1. 标记帧为有效
     * 2. 设置大小为1字节(仅包含帧类型字节)
     */
    bool QuicHandshakeDoneFrame::readFrom(MBuffer::ptr buffer_block)
    {
        // HANDSHAKE_DONE帧不包含额外数据，只需标记为有效
        m_valid = true;
        // 大小仅为类型字节(1字节)
        m_size = 1;
        return true;
    }

    /**
     * @brief 将HANDSHAKE_DONE帧写入缓冲区
     * @param buffer_block 目标缓冲区
     * @return 如果写入成功返回true，否则返回false
     *
     * 写入流程：
     * 1. 写入帧类型字节(HANDSHAKE_DONE)
     * HANDSHAKE_DONE帧不包含任何额外数据
     */
    bool QuicHandshakeDoneFrame::writeTo(MBuffer::ptr buffer_block)
    {
        try {
            // 写入帧类型字节：HANDSHAKE_DONE (0x1E)
            // HANDSHAKE_DONE帧是最小的QUIC帧，仅包含帧类型字节，不包含额外数据
            uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::HANDSHAKE_DONE);
            buffer_block->writeFuint8(type_byte);

            return true; // 写入成功，返回true
        } catch (...) {
            // 发生异常时记录错误日志
            _LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
        }
        return false; // 发生异常，返回false
    }

    /**
     * @brief 计算HANDSHAKE_DONE帧的大小
     * @return 帧的总字节数
     *
     * HANDSHAKE_DONE帧大小固定为1字节(仅包含帧类型字节)
     */
    size_t QuicHandshakeDoneFrame::size() const
    {
        // HANDSHAKE_DONE帧大小固定为1字节
        // 这是因为该帧只包含一个帧类型字节(0x1E)，不包含任何额外数据
        // 它是QUIC协议中最小的帧类型之一
        return 1; // 仅包含帧类型字节(1字节)
    }

    /**
     * @brief 生成HANDSHAKE_DONE帧的可读字符串表示
     * @return HANDSHAKE_DONE帧的字符串描述，用于调试和日志记录
     *
     * 字符串格式：[HANDSHAKE_DONE size: 1]
     * 该方法生成的字符串主要用于调试、日志记录和问题排查
     */
    std::string QuicHandshakeDoneFrame::toString() const
    {
        std::stringstream ss; // 创建字符串流用于构建格式化字符串

        // 构建包含帧类型和大小的调试字符串
        // 对于HANDSHAKE_DONE帧，大小总是1字节
        ss << "[HANDSHAKE_DONE size: " << size() << "]";

        return ss.str(); // 返回构建好的字符串，用于调试和日志输出
    }

    /// QuicFrameCodec类
    /// 负责QUIC协议帧的编解码工作，包括从字节流解析帧和将帧序列化为字节流
    /**
     * @brief 从缓冲区中解析下一个QUIC帧
     *
     * 该方法是QUIC帧解析的入口点，处理流程如下：
     * 1. 检查缓冲区中是否至少有一个字节可读（帧类型字节）
     * 2. 如果数据不足，返回nullptr表示需要更多数据
     * 3. 读取帧类型字节并消耗掉这个字节
     * 4. 如果是PADDING帧(0x0)，跳过并继续检查下一个帧
     * 5. 对于非PADDING帧，调用parseFrame方法进行实际解析并返回结果
     *
     * @param buffer_block 输入缓冲区，包含待解析的字节流数据
     * @param level 加密级别，用于确定帧解析的上下文和安全要求
     * @return 解析出的QUIC帧指针，如果解析失败或缓冲区数据不足则返回nullptr
     * @note 该方法会跳过所有PADDING帧，直到找到一个非PADDING帧或缓冲区耗尽
     * @note 此方法会修改输入缓冲区的位置指针，消耗已处理的数据
     */
    QuicFrame::ptr QuicFrameCodec::parseNext(const MBuffer::ptr &buffer_block,
                                             QuicEncryptionLevel level)
    {
        while (1) {
            // 确保缓冲区中至少有一个字节可读（帧类型字节）
            int ret = stream_read_assert(buffer_block, 1);
            if (ret < 0) {
                // 缓冲区数据不足，返回nullptr
                return nullptr;
            }

            // 读取并消耗第一个字节作为帧类型
            uint8_t type_byte = buffer_block->readFUint8();
            buffer_block->consume(1);

            // 跳过PADDING帧(类型0x0)，这些帧不包含有效信息，仅用于填充
            if (type_byte == 0x0) { // PADDING frame
                continue;
            }

            // 解析实际的帧内容
            return parseFrame(buffer_block, type_byte, level);
        }
        return nullptr;
    }

    /**
     * @brief 根据帧类型字节解析具体的QUIC帧
     *
     * 该方法是QUIC帧解析的核心实现，处理流程如下：
     * 1. 首先检查是否为STREAM帧(0x08-0x0f)，STREAM帧的高5位固定为0x08
     * 2. 对于STREAM帧，创建QuicStreamFrame对象并解析其内容，包括使用readTypeByte解析低3位控制信息
     * 3. 对于其他帧类型，使用switch语句根据type_byte的值分发到对应的处理逻辑
     * 4. 为每种帧类型创建相应的帧对象，并调用其readFrom方法解析帧内容
     * 5. 解析失败时记录日志并返回nullptr
     * 6. 解析成功后返回创建的帧对象
     *
     * 支持的主要帧类型包括：PING、ACK、RESET_STREAM、STOP_SENDING、CRYPTO、NEW_TOKEN、
     * MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS、DATA_BLOCKED、STREAM_DATA_BLOCKED、
     * STREAMS_BLOCKED、NEW_CONNECTION_ID、RETIRE_CONNECTION_ID、PATH_CHALLENGE、
     * PATH_RESPONSE、CONNECTION_CLOSE和HANDSHAKE_DONE等
     *
     * @param buffer_block 输入缓冲区，包含帧的剩余数据（帧类型字节之后的数据）
     * @param type_byte 帧类型字节，用于确定帧的具体类型
     * @param level 当前的加密级别，用于某些帧的上下文相关处理
     * @return 解析出的具体类型QUIC帧指针，如果解析失败则返回nullptr
     * @note 该方法是QUIC帧解析的核心，根据不同的帧类型创建不同的帧对象并解析其内容
     * @note 解析过程中会进行各种有效性检查，如缓冲区大小验证、必要字段存在性检查等
     */
    QuicFrame::ptr QuicFrameCodec::parseFrame(const MBuffer::ptr &buffer_block, uint8_t type_byte,
                                              QuicEncryptionLevel level)
    {
        QuicFrame::ptr frame = nullptr;

        // 首先处理STREAM帧 (0x08-0x0f)
        // STREAM帧的高5位固定为0x08
        if ((type_byte & 0xf8) == 0x8) {
            frame = std::make_shared<QuicStreamFrame>();
            // STREAM帧的低3位包含额外的控制信息，需要通过readTypeByte解析
            frame->readTypeByte(type_byte);
            if (!frame->readFrom(buffer_block)) {
                _LOG_INFO(g_logger) << "parse stream frame failed";
                return nullptr;
            }
            return frame;
        } else {
            // 根据帧类型字节的值，处理其他类型的帧
            switch (type_byte) {
                // PING帧 (0x01)：用于保活连接和测量往返时间
                case 0x1: {
                    frame = std::make_shared<QuicPingFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse ping frame failed";
                        return nullptr;
                    }
                    break;
                }
                // ACK帧 (0x02-0x03)：确认接收到的数据包
                // 0x02为普通ACK，0x03为带ECN信息的ACK
                case 0x2:
                case 0x3: {
                    frame = std::make_shared<QuicAckFrame>();
                    // 解析帧类型字节中的ECN标志
                    frame->readTypeByte(type_byte);
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse ack frame failed";
                        return nullptr;
                    }
                    break;
                }
                // RESET_STREAM帧 (0x04)：终止流并提供错误信息
                case 0x4: {
                    frame = std::make_shared<QuicRstStreamFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse reset stream frame failed";
                        return nullptr;
                    }
                    break;
                }
                // STOP_SENDING帧 (0x05)：通知对方停止发送数据
                case 0x5: {
                    frame = std::make_shared<QuicStopSendingFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse stop sending frame failed";
                        return nullptr;
                    }
                    break;
                }
                // CRYPTO帧 (0x06)：传输加密握手数据
                case 0x6: {
                    frame = std::make_shared<QuicCryptoFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse crypto frame failed";
                        return nullptr;
                    }
                    break;
                }
                // NEW_TOKEN帧 (0x07)：服务器向客户端提供新的令牌
                case 0x7: {
                    frame = std::make_shared<QuicNewTokenFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse new token frame failed";
                        return nullptr;
                    }
                    break;
                }
                // MAX_DATA帧 (0x10)：控制连接级别的最大数据量
                case 0x10: {
                    frame = std::make_shared<QuicMaxDataFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse max data frame failed";
                        return nullptr;
                    }
                    break;
                }
                // MAX_STREAM_DATA帧 (0x11)：控制单一流的最大数据量
                case 0x11: {
                    frame = std::make_shared<QuicMaxStreamDataFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse max stream data frame failed";
                        return nullptr;
                    }
                    break;
                }
                // MAX_STREAMS帧 (0x12-0x13)：控制最大流数量
                // 0x12为双向流，0x13为单向流
                case 0x12:
                case 0x13: {
                    frame = std::make_shared<QuicMaxStreamsFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse max streams frame failed";
                        return nullptr;
                    }
                    break;
                }
                // DATA_BLOCKED帧 (0x14)：指示已达到连接级别的数据限制
                case 0x14: {
                    frame = std::make_shared<QuicDataBlockedFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse data blocked frame failed";
                        return nullptr;
                    }
                    break;
                }
                // STREAM_DATA_BLOCKED帧 (0x15)：指示已达到流级别的数据限制
                case 0x15: {
                    frame = std::make_shared<QuicStreamDataBlockedFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse stream data blocked frame failed";
                        return nullptr;
                    }
                    break;
                }
                // STREAMS_BLOCKED帧 (0x16-0x17)：指示已达到流数量限制
                // 0x16为双向流，0x17为单向流
                case 0x16:
                case 0x17: {
                    frame = std::make_shared<QuicStreamsBlockedFrame>();
                    // 解析帧类型字节中的流类型信息
                    frame->readTypeByte(type_byte);
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse streams blocked frame failed";
                        return nullptr;
                    }
                    break;
                }
                // NEW_CONNECTION_ID帧 (0x18)：提供新的连接ID
                case 0x18: {
                    frame = std::make_shared<QuicNewConnectionIdFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse new connectionId frame failed";
                        return nullptr;
                    }
                    break;
                }
                // RETIRE_CONNECTION_ID帧 (0x19)：通知对方某个连接ID已不再使用
                case 0x19: {
                    frame = std::make_shared<QuicRetireConnectionIdFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse retire connectionId frame failed";
                        return nullptr;
                    }
                    break;
                }
                // PATH_CHALLENGE帧 (0x1a)：用于路径验证
                case 0x1a: {
                    frame = std::make_shared<QuicPathChallengeFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse path challenge frame failed";
                        return nullptr;
                    }
                    break;
                }
                // PATH_RESPONSE帧 (0x1b)：对PATH_CHALLENGE的响应
                case 0x1b: {
                    frame = std::make_shared<QuicPathResponseFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse path response frame failed";
                        return nullptr;
                    }
                    break;
                }
                // CONNECTION_CLOSE帧 (0x1c-0x1d)：关闭连接
                // 0x1c为传输层错误，0x1d为应用层错误
                case 0x1c:
                case 0x1d: {
                    frame = std::make_shared<QuicConnectionCloseFrame>();
                    // 解析帧类型字节中的错误类型信息
                    frame->readTypeByte(type_byte);
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse connection close frame failed";
                        return nullptr;
                    }
                    break;
                }
                // HANDSHAKE_DONE帧 (0x1e)：指示握手已完成
                case 0x1e: {
                    frame = std::make_shared<QuicHandshakeDoneFrame>();
                    if (!frame->readFrom(buffer_block)) {
                        _LOG_INFO(g_logger) << "parse handshake done frame failed";
                        return nullptr;
                    }
                    break;
                }
                // DATAGRAM帧 (0x30-0x31)：用于不可靠数据传输
                // 目前未实现
                case 0x30:
                case 0x31: {
                    /*
                    if (m_support_datagrams) {
                        // TODO frame = parseDataGramFrame()
                    }
                     */
                    break;
                }
                // 未知帧类型
                default:
                    break;
            }

            // 返回解析出的帧，如果没有匹配的帧类型或解析失败，可能返回nullptr
            return frame;
        }
    }

    /**
     * @brief 判断一个QUIC帧是否会触发ACK响应
     *
     * 在QUIC协议中，某些帧类型会触发接收方发送ACK帧来确认收到，这个函数用于确定一个帧
     * 是否属于这种需要被确认的类型。根据QUIC规范，大多数帧类型都需要被确认，但也有一些例外。
     *
     * @param frame 要检查的QUIC帧
     * @return 如果帧会触发ACK响应则返回true，否则返回false
     * @note ACK帧本身(0x2-0x3)不会触发ACK响应，因为它是对其他帧的确认
     * @note CONNECTION_CLOSE帧(0x1c-0x1d)也不会触发ACK响应，因为连接即将关闭
     * @note 其他所有帧类型都会触发ACK响应，包括STREAM、PING、CRYPTO等
     */
    bool isFrameAckEliciting(const QuicFrame::ptr &frame)
    {
        bool is_ack = false;
        bool is_conn_close = false;

        // 通过帧类型判断是否为ACK帧或CONNECTION_CLOSE帧
        switch ((int)frame->type()) {
            // ACK帧类型(0x2)和ACK_WITH_ECN帧类型(0x3)
            case 0x2:
            case 0x3: {
                is_ack = true; // 标记为ACK类型帧
                break;
            }
            // CONNECTION_CLOSE帧类型(0x1c)和APPLICATION_CLOSE帧类型(0x1d)
            case 0x1c:
            case 0x1d: {
                is_conn_close = true; // 标记为连接关闭类型帧
                break;
            }
            default:
                // 默认情况下is_ack和is_conn_close保持为false
                break;
        }

        // 只有当帧既不是ACK帧也不是CONNECTION_CLOSE帧时，才会触发ACK响应
        // 这是QUIC协议中的关键确认规则，确保了确认机制的高效性
        return !is_ack && !is_conn_close;
    }

    /**
     * @brief 检查一个帧列表中是否包含至少一个会触发ACK响应的帧
     *
     * 该函数用于判断一个QUIC数据包是否需要被确认。在QUIC协议中，包含触发ACK帧的数据包
     * 需要被接收方确认，这对于拥塞控制和可靠性保证非常重要。
     *
     * @param frames QUIC帧列表，通常代表一个数据包中的所有帧
     * @return 如果列表中包含至少一个会触发ACK响应的帧则返回true，否则返回false
     * @note 该函数会遍历整个帧列表，直到找到第一个触发ACK的帧或遍历完所有帧
     * @note 与isFrameAckEliciting函数配合使用，共同支持QUIC的确认机制
     */
    bool hasAckElicitingFrames(const std::list<QuicFrame::ptr> &frames)
    {
        // 遍历帧列表中的每个帧
        // 一旦找到第一个触发ACK的帧，立即返回true，避免不必要的遍历
        for (const auto &frame : frames) {
            // 调用isFrameAckEliciting函数检查当前帧是否会触发ACK响应
            if (isFrameAckEliciting(frame)) {
                return true; // 找到至少一个触发ACK的帧，返回true
            }
        }
        // 如果遍历完整个列表都没有找到触发ACK的帧，返回false
        // 这意味着该数据包可能只包含ACK帧或连接关闭帧
        return false;
    }
} // namespace quic
} // namespace base
