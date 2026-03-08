#include "base/net/udp_server.h"
#include "base/coro/iomanager.h"
#include "base/log/log.h"

base::Logger::ptr g_logger = _LOG_ROOT();

void run()
{
    auto addr = base::Address::LookupAny("0.0.0.0:8033");
    std::vector<base::Address::ptr> addrs;
    addrs.push_back(addr);

    base::UdpServer::ptr udp_server(new base::UdpServer);
    std::vector<base::Address::ptr> fails;
    while (!udp_server->bind(addrs, fails)) {
        _LOG_INFO(g_logger) << "bind failed, retrying...";
        sleep(2);
    }
    _LOG_INFO(g_logger) << "UDP server bound successfully";
    
    // 打印服务器信息
    _LOG_INFO(g_logger) << "Server info:\n" << udp_server->toString();
    
    udp_server->start();
    _LOG_INFO(g_logger) << "UDP server started successfully";
}

int main(int argc, char **argv)
{
    _LOG_INFO(g_logger) << "Starting UDP server test...";
    base::IOManager iom(2);
    iom.schedule(run);
    _LOG_INFO(g_logger) << "IOManager scheduled, waiting for events...";
    return 0;
}