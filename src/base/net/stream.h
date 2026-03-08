#pragma once

#include <memory>
#include "base/bytearray.h"
#include "base/net/address.h"
#include "base/mbuffer.h"

namespace base
{

/**
 * @brief 流结构
 */
class Stream
{
public:
    typedef std::shared_ptr<Stream> ptr;
    /**
     * @brief 析构函数
     */
    virtual ~Stream() {}

    /**
     * @brief 读数据
     * @param[out] buffer 接收数据的内存
     * @param[in] length 接收数据的内存大小
     * @return
     *      @retval >0 返回接收到的数据的实际大小
     *      @retval =0 被关闭
     *      @retval <0 出现流错误
     */
    virtual int read(void *buffer, size_t length) = 0;

    /**
     * @brief 读数据
     * @param[out] ba 接收数据的ByteArray
     * @param[in] length 接收数据的内存大小
     * @return
     *      @retval >0 返回接收到的数据的实际大小
     *      @retval =0 被关闭
     *      @retval <0 出现流错误
     */
    virtual int read(ByteArray::ptr ba, size_t length) = 0;

    /**
     * @brief 读固定长度的数据
     * @param[out] buffer 接收数据的内存
     * @param[in] length 接收数据的内存大小
     * @return
     *      @retval >0 返回接收到的数据的实际大小
     *      @retval =0 被关闭
     *      @retval <0 出现流错误
     */
    virtual int readFixSize(void *buffer, size_t length);

    /**
     * @brief 读固定长度的数据
     * @param[out] ba 接收数据的ByteArray
     * @param[in] length 接收数据的内存大小
     * @return
     *      @retval >0 返回接收到的数据的实际大小
     *      @retval =0 被关闭
     *      @retval <0 出现流错误
     */
    virtual int readFixSize(ByteArray::ptr ba, size_t length);

    /**
     * @brief 写数据
     * @param[in] buffer 写数据的内存
     * @param[in] length 写入数据的内存大小
     * @return
     *      @retval >0 返回写入到的数据的实际大小
     *      @retval =0 被关闭
     *      @retval <0 出现流错误
     */
    virtual int write(const void *buffer, size_t length) = 0;

    /**
     * @brief 写数据
     * @param[in] ba 写数据的ByteArray
     * @param[in] length 写入数据的内存大小
     * @return
     *      @retval >0 返回写入到的数据的实际大小
     *      @retval =0 被关闭
     *      @retval <0 出现流错误
     */
    virtual int write(ByteArray::ptr ba, size_t length) = 0;

    /**
     * @brief 写固定长度的数据
     * @param[in] buffer 写数据的内存
     * @param[in] length 写入数据的内存大小
     * @return
     *      @retval >0 返回写入到的数据的实际大小
     *      @retval =0 被关闭
     *      @retval <0 出现流错误
     */
    virtual int writeFixSize(const void *buffer, size_t length);

    /**
     * @brief 写固定长度的数据
     * @param[in] ba 写数据的ByteArray
     * @param[in] length 写入数据的内存大小
     * @return
     *      @retval >0 返回写入到的数据的实际大小
     *      @retval =0 被关闭
     *      @retval <0 出现流错误
     */
    virtual int writeFixSize(ByteArray::ptr ba, size_t length);

    virtual int sendTo(MBuffer::ptr buf, size_t length, Address::ptr addr) = 0;

    virtual int recvFrom(MBuffer::ptr buf, size_t length, Address::ptr addr) = 0;

    /**
     * @brief 关闭流
     */
    virtual void close() = 0;
};

} // namespace base
