#include "base/coro/iomanager.h"
#include "server.hpp"

int main(int argc, char *argv[])
{
    base::IOManager io_mgr(5, true);
    monitor::weaknet::WeakNetServer server(&io_mgr);
    server.start();
    io_mgr.start();
    return 0;
}
