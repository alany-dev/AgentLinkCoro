#include "base/log/log.h"
#include "base/net/address.h"
#include "base/coro/iomanager.h"
#include "base/net/stream.h"
#include "base/coro/fiber.h"
#include "base/util/hash_util.h"

#include "base/net/quic/quic_type.h"
#include "base/net/quic/quic_frame.h"
#include "base/net/quic/quic_session.h"
#include "base/net/quic/quic_frame_sorter.h"
#include "base/net/quic/quic_client.h"

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace base;
using namespace quic;
#define TMP_FILE "/tmp/1.log"

Logger::ptr g_logger = _LOG_ROOT();

std::string to_hex(const std::string &str)
{
    std::stringstream ss;
    for (size_t i = 0; i < str.size(); ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)(uint8_t)str[i];
    }
    return ss.str();
}

int file_size(const char *filePath)
{
    if (filePath == NULL)
        return 0;
    struct stat sb;
    if (stat(filePath, &sb) < 0) {
        return 0;
    }
    return sb.st_size;
}

int generate_file()
{
    int size = 0;
    FILE *f = fopen(TMP_FILE, "w+");
    if (f == nullptr) {
        _LOG_ERROR(g_logger) << "generate file failed";
        return -1;
    }
    std::string str = "1234567890abcdefghigklmnopqrstuvwxyz";
    for (int i = 0; i < 1000 * 100; i++) {
        int ret = fwrite(str.c_str(), 1, str.size(), f);
        if (ret != (int)str.size()) {
            _LOG_ERROR(g_logger) << "generate file fwrite failed";
            fclose(f);
            return -1;
        }
        size += ret;
    }
    fclose(f);
    return size;
}

void client_send_file(QuicClient::ptr client)
{
    int size = 0;
    auto stream = client->createStream();
    _LOG_ERROR(g_logger) << "session id: " << client->getSession()->getCid()->toHexString()
                         << ", stream id: " << stream->stream_id();

    size = file_size(TMP_FILE);
    if (size <= 0) {
        size = generate_file();
        if (size < 0) {
            return;
        }
    }
    FILE *f = fopen(TMP_FILE, "r");
    if (f == nullptr) {
        _LOG_ERROR(g_logger) << "open file faild";
        return;
    }
    uint64_t sum = 0;
    while (size) {
        std::string buffer("", 1024);
        int ret = fread(&buffer[0], 1, buffer.size(), f);
        size -= ret;
        auto buffer_block = std::make_shared<base::MBuffer>();
        buffer_block->write(buffer.c_str(), ret);
        _LOG_DEBUG(g_logger) << "send: " << buffer_block->toString();
        auto res = stream->write(buffer_block);
        if (res->bytes_rw() != ret || res->err_no() != 0) {
            _LOG_ERROR(g_logger) << "ret: " << ret << ", write ret: " << res->bytes_rw()
                                 << ", error: " << res->err_no() << ", strerr: " << res->strerr();
        }
        sum += res->bytes_rw();
    }
    _LOG_ERROR(g_logger) << "sum: " << sum << ", remain size: " << size << ", "
                         << stream->toSndStatisticsString();
    fclose(f);
    stream->close();
}

void quic_client(int idx)
{
    auto client_addr = base::IPv4Address::Create("127.0.0.1", 4242);
    auto client = std::make_shared<QuicClient>();
    client->connect(client_addr);
    IOManager::GetThis()->addTimer(5000, std::bind(&client_send_file, client), true);
    return;
}

int main()
{
    signal(SIGPIPE, SIG_IGN);
    base::IOManager iom(2, false, "io");
    srand(time(0));
    generate_file();
    for (int i = 0; i < 1; i++) {
        iom.schedule(std::bind(quic_client, i));
    }
    iom.stop();
    return 0;
}
