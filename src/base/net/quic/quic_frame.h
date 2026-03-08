#ifndef __QUIC_FRAME_HH__
#define __QUIC_FRAME_HH__

#include "base/bytearray.h"
#include "base/mbuffer.h"
#include "base/net/stream.h"
#include "quic_type.h"
#include <list>

namespace base
{
namespace quic
{

    /**
     * @class QuicFrame
     * @brief QUIC协议帧的基类
     *
     * 所有QUIC帧类型的抽象基类，定义了帧的通用接口和属性。
     * QUIC协议通过不同类型的帧来传输数据、控制信息和管理连接状态。
     */
    class QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicFrame> ptr;       ///< 智能指针类型定义
        constexpr static int MAX_INSTANCE_SIZE = 256; ///< 最大实例大小限制

        /**
         * @brief 通过字节数组判断帧类型
         * @param buf 包含帧数据的字节数组
         * @return 帧类型枚举值
         */
        static QuicFrameType type(const uint8_t *buf);

        virtual ~QuicFrame(){}; ///< 虚析构函数

        /**
         * @brief 读取并解析帧类型字节
         * @param type_byte 帧类型字节
         * @return 解析是否成功
         */
        virtual bool readTypeByte(uint8_t type_byte) { return true; }

        /**
         * @brief 从缓冲区读取帧数据
         * @param buffer_block 输入缓冲区
         * @return 读取是否成功
         */
        virtual bool readFrom(MBuffer::ptr buffer_block) = 0;

        /**
         * @brief 将帧数据写入缓冲区
         * @param buffer_block 输出缓冲区
         * @return 写入是否成功
         */
        virtual bool writeTo(MBuffer::ptr buffer_block) = 0;

        /**
         * @brief 获取帧类型
         * @return 帧类型枚举值
         */
        virtual QuicFrameType type() const = 0;

        /**
         * @brief 获取帧大小
         * @return 帧的字节大小
         */
        virtual size_t size() const = 0;

        /**
         * @brief 将帧转换为字符串表示
         * @return 帧的字符串描述
         */
        virtual std::string toString() const = 0;

        /**
         * @brief 判断是否为探测帧
         * @return 是否为探测帧
         */
        virtual bool is_probing_frame() const { return false; }

        /**
         * @brief 判断是否受流量控制
         * @return 是否受流量控制
         */
        virtual bool is_flow_controlled() const { return false; }

        /**
         * @brief 设置帧丢失回调函数
         * @param cb 帧丢失时的回调函数
         */
        void setOnLost(const std::function<void(QuicFrame::ptr)> &cb) { m_lost_cb = cb; }

        /**
         * @brief 设置帧被确认回调函数
         * @param cb 帧被确认时的回调函数
         */
        void setOnAcked(const std::function<void(QuicFrame::ptr)> &cb) { m_acked_cb = cb; }

        /**
         * @brief 触发帧丢失回调
         * @param frame 丢失的帧指针
         */
        void onLost(QuicFrame::ptr frame)
        {
            if (m_lost_cb)
                m_lost_cb(frame);
        }

        /**
         * @brief 触发帧被确认回调
         * @param frame 被确认的帧指针
         */
        void onAcked(QuicFrame::ptr frame)
        {
            if (m_acked_cb)
                m_acked_cb(frame);
        }

        /**
         * @brief 获取帧丢失回调函数
         * @return 帧丢失回调函数引用
         */
        const std::function<void(QuicFrame::ptr)> &lostCb() const { return m_lost_cb; }

        /**
         * @brief 判断帧是否有效
         * @return 帧是否有效
         */
        bool valid() const { return m_valid; }

        /**
         * @brief 获取流ID
         * @return 流ID
         */
        QuicStreamId stream_id() const { return m_stream_id; }

        /**
         * @brief 判断帧是否需要触发确认
         * @return 是否需要触发确认
         */
        bool ack_eliciting() const;

    protected:
        /**
         * @brief 构造函数
         * @param id 流ID
         */
        QuicFrame(QuicStreamId id = 0) : m_stream_id(id){};

        QuicStreamId m_stream_id;                                 ///< 流ID
        size_t m_size = 0;                                        ///< 帧大小
        bool m_valid = false;                                     ///< 帧有效性标志
        std::function<void(QuicFrame::ptr)> m_lost_cb = nullptr;  ///< 帧丢失回调函数
        std::function<void(QuicFrame::ptr)> m_acked_cb = nullptr; ///< 帧确认回调函数
    };

    /**
     * @class QuicStreamFrame
     * @brief QUIC流数据帧
     *
     * 用于在QUIC连接中传输流数据的帧类型。
     * 格式定义：
     * ```
     * STREAM Frame {
     *   Type (i) = 0x08..0x0f,
     *   Stream ID (i),
     *   [Offset (i)],
     *   [Length (i)],
     *   Stream Data (..),
     * }
     * ```
     * 其中Type字段的低3位用于控制标志：
     * - 0x01: FIN标志，表示流结束
     * - 0x02: 长度字段标志，表示存在长度字段
     * - 0x04: 偏移字段标志，表示存在偏移字段
     */
    class QuicStreamFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicStreamFrame> ptr;  ///< 智能指针类型定义
        static constexpr uint8_t MAX_HEADER_SIZE = 32; ///< 最大头部大小

        /**
         * @brief 构造函数
         * 创建一个空的流数据帧并初始化数据缓冲区
         */
        QuicStreamFrame() { m_data = std::make_shared<MBuffer>(); }

        /**
         * @brief 读取并解析帧类型字节，设置标志位
         * @param type_byte 帧类型字节
         * @return 解析是否成功
         */
        virtual bool readTypeByte(uint8_t type_byte) override;

        /**
         * @brief 从缓冲区读取流帧数据
         * @param buffer_block 输入缓冲区
         * @return 读取是否成功
         */
        virtual bool readFrom(MBuffer::ptr buffer_block) override;

        /**
         * @brief 将流帧数据写入缓冲区
         * @param buffer_block 输出缓冲区
         * @return 写入是否成功
         */
        virtual bool writeTo(MBuffer::ptr buffer_block) override;

        /**
         * @brief 获取帧类型
         * @return 返回QuicFrameType::STREAM
         */
        virtual QuicFrameType type() const override { return QuicFrameType::STREAM; }

        /**
         * @brief 获取帧大小
         * @return 帧的字节大小
         */
        virtual size_t size() const override;

        /**
         * @brief 将帧转换为字符串表示
         * @return 帧的字符串描述
         */
        virtual std::string toString() const override;

        /**
         * @brief 获取流ID
         * @return 流ID
         */
        QuicStreamId stream_id() const { return m_stream_id; }

        /**
         * @brief 获取数据偏移量
         * @return 数据在流中的偏移量
         */
        QuicOffset offset() const;

        /**
         * @brief 获取流数据缓冲区
         * @return 数据缓冲区的智能指针
         */
        const MBuffer::ptr &data() const { return m_data; }

        /**
         * @brief 设置流ID
         * @param stream_id 要设置的流ID
         */
        void set_stream_id(QuicStreamId stream_id) { m_stream_id = stream_id; }

        /**
         * @brief 设置数据偏移量并标记存在偏移字段
         * @param offset 数据在流中的偏移量
         */
        void set_offset(QuicOffset offset)
        {
            m_offset = offset;
            m_has_offset_field = true;
        }

        /**
         * @brief 设置流数据并标记存在长度字段
         * @param data 要设置的数据流缓冲区
         */
        void set_data(const MBuffer::ptr &data)
        {
            m_data = data;
            m_has_length_field = true;
        }

        /**
         * @brief 设置FIN标志，表示流结束
         */
        void set_fin_flag() { m_has_fin = true; }

        /**
         * @brief 如果数据量超过最大字节数，拆分帧
         * @param max_bytes 最大允许的字节数
         * @return 拆分出的新帧，如果不需要拆分则返回nullptr
         */
        QuicStreamFrame::ptr maybeSplitOffFrame(size_t max_bytes);

        /**
         * @brief 计算在最大帧大小限制下可以容纳的最大数据长度
         * @param max_size 最大帧大小
         * @return 可以容纳的最大数据长度
         */
        uint64_t maxDataLen(uint64_t max_size);

        /**
         * @brief 检查是否设置了FIN标志
         * @return 是否设置了FIN标志
         */
        bool has_fin_flag() const { return m_has_fin; }

        /**
         * @brief 检查是否存在偏移字段
         * @return 是否存在偏移字段
         */
        bool has_offset_field() const { return m_has_offset_field; }

        /**
         * @brief 检查是否存在长度字段
         * @return 是否存在长度字段
         */
        bool has_length_field() const { return m_has_length_field; }

    private:
        MBuffer::ptr m_data = nullptr;  ///< 流数据缓冲区
        QuicOffset m_offset = 0;        ///< 数据在流中的偏移量
        bool m_has_fin = false;         ///< FIN标志，表示流是否结束
        bool m_has_offset_field = true; ///< 偏移字段存在标志
        bool m_has_length_field = true; ///< 长度字段存在标志
    };

    /**
     * @class QuicCryptoFrame
     * @brief QUIC加密握手帧
     *
     * 用于在QUIC连接中传输加密握手数据的帧类型。
     * 格式定义：
     * ```
     * CRYPTO Frame {
     *   Type (i) = 0x06,
     *   Offset (i),
     *   Length (i),
     *   Crypto Data (..),
     * }
     * ```
     * 加密帧用于传输TLS握手消息，实现连接的安全建立。
     */
    class QuicCryptoFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicCryptoFrame> ptr;  ///< 智能指针类型定义
        static constexpr uint8_t MAX_HEADER_SIZE = 16; ///< 最大头部大小

        /**
         * @brief 构造函数
         * 创建一个空的加密帧并初始化数据
         */
        QuicCryptoFrame() = default;

        /**
         * @brief 从缓冲区读取加密帧数据
         * @param buffer_block 输入缓冲区
         * @return 读取是否成功
         */
        virtual bool readFrom(MBuffer::ptr buffer_block) override;

        /**
         * @brief 将加密帧数据写入缓冲区
         * @param buffer_block 输出缓冲区
         * @return 写入是否成功
         */
        virtual bool writeTo(MBuffer::ptr buffer_block) override;

        /**
         * @brief 获取帧类型
         * @return 返回QuicFrameType::CRYPTO
         */
        virtual QuicFrameType type() const override { return QuicFrameType::CRYPTO; }

        /**
         * @brief 获取帧大小
         * @return 帧的字节大小
         */
        virtual size_t size() const override;

        /**
         * @brief 将帧转换为字符串表示
         * @return 帧的字符串描述
         */
        virtual std::string toString() const override;

        /**
         * @brief 获取加密数据偏移量
         * @return 数据在加密流中的偏移量
         */
        QuicOffset offset() const { return m_offset; }

        /**
         * @brief 获取加密数据
         * @return 加密数据字符串
         */
        std::string data() const { return m_data; }

        /**
         * @brief 设置加密数据偏移量
         * @param offset 数据在加密流中的偏移量
         */
        void set_offset(QuicOffset offset) { m_offset = offset; }

        /**
         * @brief 设置加密数据
         * @param data 要设置的加密数据
         */
        void set_data(const std::string &data) { m_data = data; }

    private:
        QuicOffset m_offset = 0; ///< 数据在加密流中的偏移量
        std::string m_data = ""; ///< 加密数据内容
    };

    /**
     * @class QuicAckFrame
     * @brief QUIC确认帧
     *
     * 用于确认接收到的数据包的帧类型，实现可靠传输。
     * 格式定义：
     * ```
     * ACK Frame {
     *   Type (i) = 0x02..0x03,
     *   Largest Acknowledged (i),
     *   ACK Delay (i),
     *   ACK Range Count (i),
     *   First ACK Range (i),
     *   ACK Range (..) ...,
     *   [ECN Counts (..)],
     * }
     * ```
     * 确认帧包含最大确认包号和一系列确认范围，用于告知发送方哪些数据包已成功接收。
     */

    class QuicAckFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicAckFrame> ptr; ///< 智能指针类型定义
        /*ACK Range {
          Gap (i),
          ACK Range Length (i),
        }*/
        /**
         * @brief 表示ACK范围编码的结构，包含Gap和ACK Range Length
         */
        struct GapLenEntry {
            uint64_t gap; ///< 与前一个确认范围的间隔
            uint64_t len; ///< 确认范围的长度
        };

        /**
         * @brief ECN计数部分，用于报告ECN标记统计
         */
        struct EcnSection {
        public:
            typedef std::shared_ptr<QuicAckFrame::EcnSection> ptr;

            /**
             * @brief 获取ECN部分的大小
             * @return ECN部分的大小
             */
            size_t size() const { return m_size; }

            /**
             * @brief 检查ECN部分是否有效
             * @return ECN部分是否有效
             */
            bool vaild() const { return m_valid; }

            /**
             * @brief 获取ECT0标记的数据包数量
             * @return ECT0标记的数据包数量
             */
            uint64_t ect0_count() const { return m_ect0_count; }

            /**
             * @brief 获取ECT1标记的数据包数量
             * @return ECT1标记的数据包数量
             */
            uint64_t ect1_count() const { return m_ect1_count; }

            /**
             * @brief 获取CE标记的数据包数量
             * @return CE标记的数据包数量
             */
            uint64_t ecn_ce_count() const { return m_ecn_ce_count; }

            bool m_valid = false;        ///< ECN部分是否有效
            size_t m_size = 0;           ///< ECN部分的大小
            uint64_t m_ect0_count = 0;   ///< ECT0标记的数据包数量
            uint64_t m_ect1_count = 0;   ///< ECT1标记的数据包数量
            uint64_t m_ecn_ce_count = 0; ///< CE标记的数据包数量
        };

        /**
         * @brief 构造函数
         * 创建一个默认的确认帧
         */
        QuicAckFrame(){};
        /**
         * @brief 构造函数
         * @param ack_ranges 确认范围列表
         */
        QuicAckFrame(const std::vector<AckRange::ptr> &ack_ranges);

        /**
         * @brief 读取并验证帧类型字节
         * @param type_byte 帧类型字节
         * @return 验证是否成功
         */
        virtual bool readTypeByte(uint8_t type_byte) override;

        /**
         * @brief 从缓冲区读取确认帧数据
         * @param buffer_block 输入缓冲区
         * @return 读取是否成功
         */
        virtual bool readFrom(MBuffer::ptr buffer_block) override;

        /**
         * @brief 将确认帧数据写入缓冲区
         * @param buffer_block 输出缓冲区
         * @return 写入是否成功
         */
        virtual bool writeTo(MBuffer::ptr buffer_block) override;

        /**
         * @brief 获取帧类型
         * @return 返回QuicFrameType::ACK
         */
        virtual QuicFrameType type() const override { return QuicFrameType::ACK; }

        /**
         * @brief 获取帧大小
         * @return 帧的字节大小
         */
        virtual size_t size() const override;

        /**
         * @brief 将帧转换为字符串表示
         * @return 帧的字符串描述
         */
        virtual std::string toString() const override;

        /**
         * @brief 编码确认延迟时间
         * @param ack_delay 确认延迟时间
         * @return 编码后的延迟值
         */
        uint64_t encodeAckDelay(uint64_t ack_delay);

        /**
         * @brief 获取可编码的ACK范围数量
         * @return 可编码的ACK范围数量
         */
        int numEncodableAckRanges();

        /**
         * @brief 检查是否确认了指定的包号
         * @param pn 包号
         * @return 是否确认了该包号
         */
        bool acksPacket(QuicPacketNumber pn);

        /**
         * @brief 获取最低确认的包号
         * @return 最低确认的包号
         */
        QuicPacketNumber lowestAcked();

        /**
         * @brief 编码指定索引的ACK范围
         * @param idx ACK范围索引
         * @return 编码后的GapLenEntry结构
         */
        GapLenEntry encodeAckRange(size_t idx) const;

        /**
         * @brief 获取最大确认的包号
         * @return 最大确认的包号
         */
        QuicPacketNumber largestAcked() const { return m_ack_ranges[0]->m_largest; }

        /**
         * @brief 获取所有确认范围（只读）
         * @return 确认范围列表
         */
        const std::vector<AckRange::ptr> &ackRanges() const { return m_ack_ranges; }

        /**
         * @brief 获取所有确认范围（可修改）
         * @return 确认范围列表
         */
        std::vector<AckRange::ptr> &ackRanges() { return m_ack_ranges; }

        /**
         * @brief 检查是否存在丢失的范围（即非连续的确认）
         * @return 是否存在丢失的范围
         */
        bool hasMissingRanges() const { return m_ack_ranges.size() > 1; }

        /**
         * @brief 获取确认延迟时间
         * @return 确认延迟时间
         */
        uint64_t ack_delay() const { return m_ack_delay; }

        /**
         * @brief 获取ECN部分（只读）
         * @return ECN部分的智能指针
         */
        const EcnSection::ptr ecn_section() const { return m_ecn_section; }

        /**
         * @brief 获取ECN部分（可修改）
         * @return ECN部分的智能指针
         */
        EcnSection::ptr ecn_section() { return m_ecn_section; }

        /**
         * @brief 设置确认范围列表
         * @param ack_ranges 确认范围列表
         */
        void setAckRanges(const std::vector<AckRange::ptr> &ack_ranges)
        {
            m_ack_ranges = ack_ranges;
        }

        void setAckRanges(std::vector<AckRange::ptr> &&ack_ranges)
        {
            m_ack_ranges = std::move(ack_ranges);
        }

        /**
         * @brief 设置确认延迟时间
         * @param time 确认延迟时间
         */
        void setAckDelay(uint64_t time) { m_ack_delay = time; }

    private:
        std::vector<AckRange::ptr> m_ack_ranges; ///< 确认范围列表
        MBuffer::ptr m_block;                    ///< 缓冲区指针
        uint64_t m_ack_delay = 0;                ///< 确认延迟时间
        bool m_has_ecn = false;                  ///< 是否包含ECN计数
        EcnSection::ptr m_ecn_section = nullptr; ///< ECN计数部分
    };

    /**
     * @class QuicRstStreamFrame
     * @brief QUIC流重置帧
     *
     * 用于终止或重置流的帧类型，可以在任何时候发送。
     * 格式定义：
     * ```
     * RESET_STREAM Frame {
     *   Type (i) = 0x04,
     *   Stream ID (i),
     *   Application Protocol Error Code (i),
     *   Final Size (i),
     * }
     * ```
     * 流重置帧通知接收方流已被终止，携带错误码和最终大小信息。
     */
    class QuicRstStreamFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicRstStreamFrame> ptr; ///< 智能指针类型定义

        /**
         * @brief 默认构造函数
         */
        QuicRstStreamFrame() {}
        /**
         * @brief 带参数的构造函数
         * @param stream_id 要重置的流ID
         * @param offset 流的最终偏移量
         * @param err_code 应用层错误码，默认为0
         */
        QuicRstStreamFrame(QuicStreamId stream_id, QuicOffset offset, QuicAppErrCode err_code = 0)
            : QuicFrame(stream_id), m_final_offset(offset), m_error_code(err_code)
        {
        }

        /**
         * @brief 从缓冲区读取流重置帧数据
         * @param buffer_block 输入缓冲区
         * @return 读取是否成功
         */
        virtual bool readFrom(MBuffer::ptr buffer_block) override;

        /**
         * @brief 将流重置帧数据写入缓冲区
         * @param buffer_block 输出缓冲区
         * @return 写入是否成功
         */
        virtual bool writeTo(MBuffer::ptr buffer_block) override;

        /**
         * @brief 获取帧类型
         * @return 返回QuicFrameType::RESET_STREAM
         */
        virtual QuicFrameType type() const override { return QuicFrameType::RESET_STREAM; }

        /**
         * @brief 获取帧大小
         * @return 帧的字节大小
         */
        virtual size_t size() const override;

        /**
         * @brief 将帧转换为字符串表示
         * @return 帧的字符串描述
         */
        virtual std::string toString() const override;

        /**
         * @brief 获取应用层错误码
         * @return 错误码
         */
        QuicAppErrCode error_code() const { return m_error_code; }

        /**
         * @brief 获取流ID
         * @return 流ID
         */
        QuicStreamId stream_id() const { return m_stream_id; }

        /**
         * @brief 获取最终偏移量
         * @return 流的最终大小/偏移量
         */
        QuicOffset final_offset() const { return m_final_offset; }

    private:
        QuicOffset m_final_offset = 0;   ///< 流的最终大小/偏移量
        QuicAppErrCode m_error_code = 0; ///< 应用层错误码
    };

    /**
     * @class QuicPingFrame
     * @brief QUIC Ping帧
     *
     * 最小的帧类型，用于测量往返时间和保持连接活跃。
     * 格式定义：
     * ```
     * PING Frame {
     *   Type (i) = 0x01,
     * }
     * ```
     * Ping帧只包含一个类型字节，接收方必须立即发送响应。
     */
    class QuicPingFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicPingFrame> ptr; ///< 智能指针类型定义
        static constexpr uint8_t MAX_HEADER_SIZE = 1; ///< 最大头部大小（仅包含类型字节）

        /**
         * @brief 构造函数
         * 创建一个默认的Ping帧
         */
        QuicPingFrame() = default;

        /**
         * @brief 从缓冲区读取Ping帧（实际只验证类型字节）
         * @param buffer_block 输入缓冲区
         * @return 读取是否成功
         */
        virtual bool readFrom(MBuffer::ptr buffer_block) override;

        /**
         * @brief 将Ping帧写入缓冲区（仅写入类型字节）
         * @param buffer_block 输出缓冲区
         * @return 写入是否成功
         */
        virtual bool writeTo(MBuffer::ptr buffer_block) override;

        /**
         * @brief 获取帧类型
         * @return 返回QuicFrameType::PING
         */
        virtual QuicFrameType type() const override { return QuicFrameType::PING; }

        /**
         * @brief 获取帧大小
         * @return 帧的字节大小（始终为1）
         */
        virtual size_t size() const override { return 1; }

        /**
         * @brief 将帧转换为字符串表示
         * @return 帧的字符串描述
         */
        virtual std::string toString() const override;
    };

    /**
     * @class QuicPaddingFrame
     * @brief QUIC填充帧
     *
     * 用于填充数据包到特定大小的帧类型。
     * 格式定义：
     * ```
     * PADDING Frame {
     *   Type (i) = 0x00,
     * }
     * ```
     * 填充帧可以连续出现多个，用于长度填充或对齐。
     */
    class QuicPaddingFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicPaddingFrame> ptr; ///< 智能指针类型定义
        static constexpr uint8_t MAX_HEADER_SIZE = 1; ///< 最大头部大小（仅包含类型字节）

        /**
         * @brief 构造函数
         * 创建一个默认的填充帧
         */
        QuicPaddingFrame() = default;

        /**
         * @brief 从缓冲区读取填充帧（实际只验证类型字节）
         * @param buffer_block 输入缓冲区
         * @return 读取是否成功
         */
        virtual bool readFrom(MBuffer::ptr buffer_block) override;

        /**
         * @brief 将填充帧写入缓冲区（仅写入类型字节）
         * @param buffer_block 输出缓冲区
         * @return 写入是否成功
         */
        virtual bool writeTo(MBuffer::ptr buffer_block) override;

        /**
         * @brief 获取帧类型
         * @return 返回QuicFrameType::PADDING
         */
        virtual QuicFrameType type() const override { return QuicFrameType::PADDING; }

        /**
         * @brief 获取帧大小
         * @return 帧的字节大小
         */
        virtual size_t size() const override { return m_size; }

        /**
         * @brief 将帧转换为字符串表示
         * @return 帧的字符串描述
         */
        virtual std::string toString() const override;

    private:
        size_t m_size = 0; ///< 填充帧大小
    };

    /**
     * @class QuicConnectionCloseFrame
     * @brief QUIC连接关闭帧
     *
     * 用于通知对端关闭连接的帧类型，可以是加密握手层或应用层发起的关闭。
     * 格式定义：
     * ```
     * CONNECTION_CLOSE Frame {
     *   Type (i) = 0x1c..0x1d,
     *   Error Code (i),
     *   [Frame Type (i)],
     *   Reason Phrase Length (i),
     *   Reason Phrase (..),
     * }
     * ```
     * 连接关闭帧携带错误码和可选的原因短语，用于通知对端关闭的原因。
     */
    class QuicConnectionCloseFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicConnectionCloseFrame> ptr; ///< 智能指针类型定义

        /**
         * @brief 读取并验证帧类型字节
         * @param type_byte 帧类型字节
         * @return 验证是否成功
         */
        virtual bool readTypeByte(uint8_t type_byte) override;

        /**
         * @brief 从缓冲区读取连接关闭帧数据
         * @param buffer_block 输入缓冲区
         * @return 读取是否成功
         */
        virtual bool readFrom(MBuffer::ptr buffer_block) override;

        /**
         * @brief 将连接关闭帧数据写入缓冲区
         * @param buffer_block 输出缓冲区
         * @return 写入是否成功
         */
        virtual bool writeTo(MBuffer::ptr buffer_block) override;

        /**
         * @brief 获取帧类型
         * @return 返回QuicFrameType::CONNECTION_CLOSE
         */
        virtual QuicFrameType type() const override { return QuicFrameType::CONNECTION_CLOSE; }

        /**
         * @brief 获取帧大小
         * @return 帧的字节大小
         */
        virtual size_t size() const override;

        /**
         * @brief 将帧转换为字符串表示
         * @return 帧的字符串描述
         */
        virtual std::string toString() const override;

        /**
         * @brief 获取错误码
         * @return 错误码
         */
        uint16_t error_code() const { return m_error_code; }

        /**
         * @brief 获取帧类型
         * @return 帧类型
         */
        QuicFrameType frame_type() const { return m_frame_type; }

        /**
         * @brief 获取原因短语长度
         * @return 原因短语长度
         */
        uint64_t reason_phrase_length() const { return m_reason_phrase_len; }

        /**
         * @brief 获取原因短语
         * @return 原因短语
         */
        const char *reason_phrase() const { return m_reason_phrase.c_str(); }

        /**
         * @brief 设置是否为应用错误
         * @param err 是否为应用错误
         */
        void setAppErr(bool err) { m_is_application_error = err; }

        /**
         * @brief 判断是否为应用错误
         * @return 是否为应用错误
         */
        bool isAppErr() const { return m_is_application_error; }

    private:
        uint8_t m_type = 0;
        uint64_t m_error_code;
        QuicFrameType m_frame_type = QuicFrameType::UNKNOWN;
        uint64_t m_reason_phrase_len = 0;
        std::string m_reason_phrase = "";
        bool m_is_application_error = false;
    };

    /*MAX_DATA Frame {
      Type (i) = 0x10,
      Maximum Data (i),
    }*/
    class QuicMaxDataFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicMaxDataFrame> ptr;
        QuicMaxDataFrame(){};
        QuicMaxDataFrame(uint64_t maximum_data) : m_maximum_data(maximum_data) {}
        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::MAX_DATA; }
        virtual size_t size() const override;
        virtual std::string toString() const override;
        void setMaxData(uint64_t v) { m_maximum_data = v; }
        uint64_t maximum_stream_data() const { return m_maximum_data; }

    private:
        uint64_t m_maximum_data = 0;
    };

    /*MAX_STREAM_DATA Frame {
      Type (i) = 0x11,
      Stream ID (i),
      Maximum Stream Data (i),
    }*/
    class QuicMaxStreamDataFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicMaxStreamDataFrame> ptr;
        QuicMaxStreamDataFrame(){};
        QuicMaxStreamDataFrame(QuicStreamId id, uint64_t offset)
            : QuicFrame(id), m_maximum_stream_data(offset)
        {
        }
        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::MAX_STREAM_DATA; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

        QuicStreamId stream_id() const { return m_stream_id; }
        uint64_t maximum_stream_data() const { return m_maximum_stream_data; }

    private:
        uint64_t m_maximum_stream_data = 0;
    };

    /*MAX_STREAMS Frame {
      Type (i) = 0x12..0x13,
      Maximum Streams (i),
    }*/
    class QuicMaxStreamsFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicMaxStreamsFrame> ptr;

        QuicMaxStreamsFrame() {}
        QuicMaxStreamsFrame(QuicStreamType type, QuicStreamNum max_num);
        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::MAX_STREAMS; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

        uint64_t maximum_streams() const { return m_maximum_streams; }

    private:
        QuicStreamType m_type;
        uint64_t m_maximum_streams = 0;
    };

    /*DATA_BLOCKED Frame {
      Type (i) = 0x14,
      Maximum Data (i),
    }*/
    class QuicDataBlockedFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicDataBlockedFrame> ptr;
        QuicDataBlockedFrame(QuicOffset offset = 0) : m_offset(offset) {}
        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::DATA_BLOCKED; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

        QuicOffset offset() const { return m_offset; }

    private:
        QuicOffset m_offset = 0;
    };

    /*STREAM_DATA_BLOCKED Frame {
      Type (i) = 0x15,
      Stream ID (i),
      Maximum Stream Data (i),
    }*/
    class QuicStreamDataBlockedFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicStreamDataBlockedFrame> ptr;
        QuicStreamDataBlockedFrame() {}
        QuicStreamDataBlockedFrame(QuicStreamId stream_id, QuicOffset offset)
            : QuicFrame(stream_id), m_offset(offset)
        {
        }
        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::STREAM_DATA_BLOCKED; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

        QuicStreamId stream_id() const { return m_stream_id; }
        QuicOffset offset() const { return m_offset; }

    private:
        QuicOffset m_offset = 0;
    };

    /*STREAMS_BLOCKED Frame {
      Type (i) = 0x16..0x17,
      Maximum Streams (i),
    }*/
    class QuicStreamsBlockedFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicStreamsBlockedFrame> ptr;
        QuicStreamsBlockedFrame() {}
        QuicStreamsBlockedFrame(QuicStreamType type, QuicStreamNum num);
        virtual bool readTypeByte(uint8_t type_byte) override;
        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::STREAM_BLOCKED; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

    private:
        QuicStreamType m_stream_type;
        QuicStreamNum m_stream_limit;
    };

    /*NEW_CONNECTION_ID Frame {
      Type (i) = 0x18,
      Sequence Number (i),
      Retire Prior To (i),
      Length (8),
      Connection ID (8..160),
      Stateless Reset Token (128),
    }*/
    class QuicNewConnectionIdFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicNewConnectionIdFrame> ptr;

        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::NEW_CONNECTION_ID; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

        uint64_t sequence() const { return m_sequence; }
        uint64_t retire_prior_to() const { return m_retire_prior_to; }
        QuicConnectionId connection_id() const { return m_connection_id; }

    private:
        uint64_t m_sequence = 0;
        uint64_t m_retire_prior_to = 0;
        QuicConnectionId m_connection_id = QuicConnectionId::ZERO();
        QuicStatelessResetToken m_stateless_reset_token;
    };

    /*STOP_SENDING Frame {
      Type (i) = 0x05,
      Stream ID (i),
      Application Protocol Error Code (i),
    }*/
    class QuicStopSendingFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicStopSendingFrame> ptr;

        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::STOP_SENDING; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

        QuicStreamId stream_id() const { return m_stream_id; }
        QuicAppErrCode error_code() const { return m_error_code; }

    private:
        QuicAppErrCode m_error_code = 0;
    };

    /*PATH_CHALLENGE Frame {
      ype (i) = 0x1a,
      Data (64),
    }*/
    class QuicPathChallengeFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicPathChallengeFrame> ptr;
        static constexpr uint8_t DATA_LEN = 8;

        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::PATH_CHALLENGE; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

        const uint8_t *data() const { return (uint8_t *)m_data.c_str(); }

    private:
        std::string m_data = "";
    };

    /*PATH_RESPONSE Frame {
      Type (i) = 0x1b,
      Data (64),
    }*/
    class QuicPathResponseFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicPathResponseFrame> ptr;
        static constexpr uint8_t DATA_LEN = 8;

        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::PATH_RESPONSE; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

        const uint8_t *data() const { return (uint8_t *)m_data.c_str(); }

    private:
        std::string m_data = "";
    };

    /*NEW_TOKEN Frame {
      Type (i) = 0x07,
      Token Length (i),
      Token (..),
    }*/
    class QuicNewTokenFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicNewTokenFrame> ptr;

        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::NEW_TOKEN; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

        const uint8_t *token() const { return (uint8_t *)m_token.c_str(); }
        uint64_t token_length() const { return m_token_len; }

    private:
        std::string m_token = "";
        uint64_t m_token_len = 0;
    };

    /*RETIRE_CONNECTION_ID Frame {
      Type (i) = 0x19,
      Sequence Number (i),
    }*/
    class QuicRetireConnectionIdFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicRetireConnectionIdFrame> ptr;

        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::RETIRE_CONNECTION_ID; }
        virtual size_t size() const override;
        virtual std::string toString() const override;

        uint64_t seq_num() const { return m_seq_num; }

    private:
        uint64_t m_seq_num = 0;
    };

    /*HANDSHAKE_DONE Frame {
      Type (i) = 0x1e,
    }*/
    class QuicHandshakeDoneFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicHandshakeDoneFrame> ptr;

        virtual bool readFrom(MBuffer::ptr buffer_block) override;
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::HANDSHAKE_DONE; }
        virtual size_t size() const override;
        virtual std::string toString() const override;
    };

    class QuicUnknownFrame : public QuicFrame
    {
    public:
        typedef std::shared_ptr<QuicUnknownFrame> ptr;

        virtual bool readFrom(MBuffer::ptr buffer_block) override { return false; }
        virtual bool writeTo(MBuffer::ptr buffer_block) override;
        virtual QuicFrameType type() const override { return QuicFrameType::UNKNOWN; }
        virtual size_t size() const override { return 0; }
        virtual std::string toString() const override { return std::string(""); }
    };

    class QuicFrameFactory
    {
    public:
        static QuicFrame *create(uint8_t *buf, const uint8_t *src, size_t len);

    private:
    };

    /**
     * @class QuicFrameCodec
     * @brief QUIC协议帧的编解码器类
     *
     * 负责QUIC协议帧的编解码工作，提供以下核心功能：
     * 1. 从字节流中解析各种类型的QUIC帧
     * 2. 将QUIC帧序列化为字节流（目前未完全实现）
     * 3. 处理帧类型识别、数据有效性验证等工作
     *
     * 该类采用静态方法设计模式，无需创建实例即可使用。
     */
    class QuicFrameCodec
    {
    public:
        typedef std::shared_ptr<QuicFrameCodec> ptr;

        /**
         * @brief 从缓冲区中解析下一个QUIC帧
         * @param buffer_block 输入缓冲区，包含待解析的字节流数据
         * @param level 加密级别，用于确定帧解析的上下文和安全要求
         * @return 解析出的QUIC帧指针，如果解析失败或缓冲区数据不足则返回nullptr
         * @note 该方法会跳过所有PADDING帧，直到找到一个非PADDING帧或缓冲区耗尽
         */
        static QuicFrame::ptr parseNext(const MBuffer::ptr &buffer_block,
                                        QuicEncryptionLevel level = QuicEncryptionLevel::NONE);

        /**
         * @brief 根据帧类型字节解析具体的QUIC帧
         * @param buffer_block 输入缓冲区，包含帧的剩余数据
         * @param type_byte 帧类型字节，用于确定帧的具体类型
         * @param level 加密级别，影响某些帧的处理逻辑
         * @return 解析出的具体类型QUIC帧指针，如果解析失败则返回nullptr
         */
        static QuicFrame::ptr parseFrame(const MBuffer::ptr &buffer_block, uint8_t type_byte,
                                         QuicEncryptionLevel level = QuicEncryptionLevel::NONE);

        /**
         * @brief 将QUIC帧序列化为字节流
         * @param buffer_block 输出缓冲区，用于存储序列化后的字节流
         * @param frame 待序列化的QUIC帧
         * @return 序列化的字节数，如果序列化失败则返回负数
         * @note 当前为预留接口，实际序列化逻辑通过各帧类型自身的writeTo方法实现
         */
        static int32_t serializeTo(MBuffer::ptr buffer_block, QuicFrame::ptr frame) { return 0; }
    };

    bool isFrameAckEliciting(const QuicFrame::ptr &frame);
    bool hasAckElicitingFrames(const std::list<QuicFrame::ptr> &frames);

    struct QuicPacketPayload {
        typedef std::shared_ptr<QuicPacketPayload> ptr;
        std::list<QuicFrame::ptr> frames;
        QuicAckFrame::ptr ack;
        uint64_t length;
    };

    class StreamSender
    {
    public:
        typedef std::shared_ptr<StreamSender> ptr;
        virtual void onHasStreamData(QuicStreamId stream_id) = 0;
        virtual void onStreamCompleted(QuicStreamId stream_id) = 0;
        virtual void queueControlFrame(QuicFrame::ptr frame) = 0;

    private:
    };

} // namespace quic
} // namespace base
#endif
