#include "startup.h"
#include "trace_pipe.h"
#include "if_utils.h"
#include "monitor/unix_socket.h"
#include "monitor/interface.h"

// bpf program to compile
#include "bpf/tls_monitor.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

int main(int argc, char *argv[])
{
    ebpf::BPF bpf;
    bool stop{false};

    tlsm::startup_t startup(argc, argv);
    startup.check_pid();

    auto init_res = bpf.init(BPF_PROGRAM);
    if (init_res.code() != 0)
    {
        std::cerr << init_res.msg() << std::endl;
        exit(EXIT_FAILURE);
    }

    // asio ctx
    boost::asio::io_context ctx;

    // hanlde Ctrl+C
    boost::asio::signal_set signals(ctx, SIGINT);
    signals.async_wait([&](const boost::system::error_code &error,
                           int signal_number)
                       { boost::asio::post([&]()
                                           { stop = true; }); });

    /// init unix monitor
    tlsm::monitor::unix_socket_t usm{ctx, bpf, startup.pid()};
    usm.start([&]()
              { return stop; });

    std::vector<tlsm::monitor::interface_t> if_m;
    for (auto name : tlsm::get_inet_if())
    {
        std::cout << "interface [" << name << "]\n";
        if_m.emplace_back(ctx, bpf, name);
    }

    ctx.run();

    return 0;
}
