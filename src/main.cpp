#include <unistd.h>
#include <fstream>
#include <iostream>
#include <exception>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fmt/core.h>

#include "bcc_version.h"

#include "attach_probe.h"
#include "startup.h"

// inline bpf code
#include "bpf/tls_monitor.h"


#define DEBUG_TRACE 0

struct accept_event_t
{
    struct sockaddr addr;
};

void on_tls_event_handler(void *cb_cookie, void *data, int data_size)
{

    auto event = static_cast<accept_event_t *>(data);
    struct sockaddr *peer = (struct sockaddr *)&event->addr;
    if(peer->sa_family == AF_INET)
    {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)peer;

        std::array<char, INET_ADDRSTRLEN>  buf;
        inet_ntop(AF_INET, &(addr_in->sin_addr), buf.data(), INET_ADDRSTRLEN);

        std::cout << fmt::format("TLS peer : {}:{}\n", buf.data(), ntohs(addr_in->sin_port));
    }
    else if(peer->sa_family == AF_INET6)
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)peer;

        std::array<char, INET6_ADDRSTRLEN>  buf;
        inet_ntop(AF_INET, &(addr_in6->sin6_addr), buf.data(), INET6_ADDRSTRLEN);

        std::cout << fmt::format("TLS peer : {}:{}\n", buf.data(), ntohs(addr_in6->sin6_port));
    }
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

    // set filterting pid
    uint32_t key{0};
    auto pid_table = bpf.get_array_table<uint32_t>("target_pid");
    auto rc = pid_table.update_value(key, startup.pid());
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << std::endl;
        exit(EXIT_FAILURE);
    }

    // read
    auto syscall_read_name = bpf.get_syscall_fnname("read");
    tlsm::attach_probe_t read_enter(bpf, syscall_read_name, "syscall__read_enter");
    tlsm::attach_probe_t read_exit(bpf, syscall_read_name, "syscall__read_exit", BPF_PROBE_RETURN);

    //close
    auto syscall_close_name = bpf.get_syscall_fnname("close");
    tlsm::attach_probe_t close_enter(bpf, syscall_close_name, "syscall__close_enter");

    //accept
    auto syscall_accept_name = bpf.get_syscall_fnname("accept");
    tlsm::attach_probe_t accept_enter(bpf, syscall_accept_name, "syscall__accept_enter");
    tlsm::attach_probe_t accept_exit(bpf, syscall_accept_name, "syscall__accept_exit", BPF_PROBE_RETURN);

    //connect
    auto syscall_connect_name = bpf.get_syscall_fnname("connect");
    tlsm::attach_probe_t connect_enter(bpf, syscall_connect_name, "syscall__connect_enter");
    tlsm::attach_probe_t connect_exit(bpf, syscall_connect_name, "syscall__connect_exit", BPF_PROBE_RETURN);

    rc = bpf.open_perf_buffer("tls_events", &on_tls_event_handler);
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << "\n";
        return EXIT_FAILURE;
    }

#if DEBUG_TRACE
    std::ifstream pipe("/sys/kernel/debug/tracing/trace_pipe");
    while (true)
    {
        std::string line;
        if (std::getline(pipe, line))
        {
            std::cout << "bpf log : [" << line << "]\n";
        }
    }
#else
    while (true)
        bpf.poll_perf_buffer("tls_events", 100);
#endif

    return 0;
}
