#include "startup.h"
#include "trace_pipe.h"
#include "unix_socket_monitor.h"
#include "interface_monitor.h"

#include "bpf/tls_monitor.h"

#include <future>
#include <atomic>

std::atomic_bool stop{false};

void on_signal(int signal)
{
    stop = true;
}

int main(int argc, char *argv[])
{
    tlsm::startup_t startup(argc, argv);
    startup.check_pid();

    ebpf::BPF bpf;
    auto init_res = bpf.init(BPF_PROGRAM);
    if (init_res.code() != 0)
    {
        std::cerr << init_res.msg() << std::endl;
        exit(EXIT_FAILURE);
    }

    tlsm::unix_socket_monitor_t unix_monitor{bpf, startup.pid()};
    auto poll_unix_monitor = std::async(std::launch::async, [&]()
                                        {
                                            while (!stop)
                                                unix_monitor.poll();
                                        });

    signal(SIGINT, on_signal);

    return 0;
}
