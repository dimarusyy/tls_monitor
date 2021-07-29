#include "startup.h"
#include "trace_pipe.h"
#include "unix_socket_monitor.h"

#include <future>

int main(int argc, char *argv[])
{
    tlsm::startup_t startup(argc, argv);
    startup.check_pid();

    auto job_trace_unix_sock = std::async(std::launch::async, [pid = startup.pid()]()
                                          { tlsm::unix_socket_monitor_t unix_monitor{pid}; });

    return 0;
}
