#include "startup.h"
#include "trace_pipe.h"
#include "unix_socket_monitor.h"
#include "interface_monitor.h"

#include "bpf/tls_monitor.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/high_resolution_timer.hpp>

using namespace std::chrono_literals;
#include <chrono>

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

    /// init unix monitor
    tlsm::unix_socket_monitor_t unix_monitor{bpf, startup.pid()};

    // asio ctx
    boost::asio::io_context ctx;

    // hanlde Ctrl+C
    boost::asio::signal_set signals(ctx, SIGINT);
    signals.async_wait([&](const boost::system::error_code &error, int signal_number)
                       { stop = true; });

    // trigger timer loop
    boost::asio::spawn(ctx, [&](auto yield)
                       {
                           boost::asio::high_resolution_timer timer(ctx);
                           boost::system::error_code ec;
                           while (!stop)
                           {
                               timer.expires_from_now(100ms, ec);
                               if(ec)
                               {
                                   std::cout << "Error : [" << ec.message() << "]\n";
                               }
                               timer.async_wait(yield[ec]);
                               if (!ec)
                               {
                                   unix_monitor.poll();
                               }
                           }
                       });
    ctx.run();

    return 0;
}
