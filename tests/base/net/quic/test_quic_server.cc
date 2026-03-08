#include "base/log/log.h"
#include "base/net/address.h"
#include "base/coro/iomanager.h"
#include "base/net/stream.h"
#include "base/coro/fiber.h"
#include "base/macro.h"

#include "base/net/quic/quic_type.h"
#include "base/net/quic/quic_frame.h"
#include "base/net/quic/quic_session.h"
#include "base/net/quic/quic_frame_sorter.h"
#include "base/net/quic/quic_server.h"

#include <signal.h>

using namespace base;
using namespace quic;

Logger::ptr g_logger = _LOG_ROOT();
std::vector<QuicStream::ptr> g_streams;

std::string to_hex(const std::string &str)
{
    std::stringstream ss;
    for (size_t i = 0; i < str.size(); ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)(uint8_t)str[i];
    }
    return ss.str();
}

static void handle_session_stream(QuicStream::ptr stream)
{
    int sum_size = 0;
    _LOG_ERROR(g_logger) << ", accept stream_id: " << stream->stream_id();
    while (1) {
        auto buffer_block = std::make_shared<base::MBuffer>();
        auto ret = stream->read(buffer_block, 1500);
        sum_size += ret->bytes_rw();
        // _LOG_ERROR(g_logger) << "upper stream read ret: " << ret->bytes_rw()
        //             << ", sum_size: " << sum_size << ", err: " << ret->err_no();
        if (ret->isCompleted()) {
            break;
        }
    }
    stream->readStream()->cancelRead();
    _LOG_ERROR(g_logger) << "stream read completed: " << sum_size;
    stream->close();
}

static void handle_session(QuicSession::ptr session)
{
    while (1) {
        auto stream = session->acceptStream();
        if (stream) {
            _LOG_ERROR(g_logger) << "session accept stream ok ";
            IOManager::GetThis()->schedule(std::bind(&handle_session_stream, stream));
        }
    }
}

void quic_server()
{
    IPAddress::ptr server_addr = IPv4Address::Create("0.0.0.0", 4242);

    auto server = std::make_shared<QuicServer>();
    server->bind(server_addr);
    server->start();
    while (1) {
        auto session = server->accept(); // 每次获取session
        if (session) {
            _LOG_ERROR(g_logger) << "server accept session ok ";
            IOManager::GetThis()->schedule(std::bind(&handle_session, session));
        }
    }
    return;
}

int main()
{
    signal(SIGPIPE, SIG_IGN);
    base::IOManager iom(2, false, "io");
    srand(time(0));
    iom.schedule(quic_server);
    iom.stop();
    return 0;
}
