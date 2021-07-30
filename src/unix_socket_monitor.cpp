#include "unix_socket_monitor.h"

#include "bcc_version.h"

// inline bpf code
#include "bpf/tls_monitor.h"

#include <fmt/core.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <array>
#include <iostream>

namespace
{
    struct accept_event_t
    {
        struct sockaddr addr;
    };

    void on_tls_event_handler(void *cb_cookie, void *data, int data_size)
    {
        auto event = static_cast<accept_event_t *>(data);
        struct sockaddr *peer = (struct sockaddr *)&event->addr;
        if (peer->sa_family == AF_INET)
        {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)peer;

            std::array<char, INET_ADDRSTRLEN> buf;
            inet_ntop(AF_INET, &(addr_in->sin_addr), buf.data(), INET_ADDRSTRLEN);

            std::cout << fmt::format("TLS peer : {}:{}\n", buf.data(), ntohs(addr_in->sin_port));
        }
        else if (peer->sa_family == AF_INET6)
        {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)peer;

            std::array<char, INET6_ADDRSTRLEN> buf;
            inet_ntop(AF_INET, &(addr_in6->sin6_addr), buf.data(), INET6_ADDRSTRLEN);

            std::cout << fmt::format("TLS peer : {}:{}\n", buf.data(), ntohs(addr_in6->sin6_port));
        }
    }
}

namespace tlsm
{
    unix_socket_monitor_t::unix_socket_monitor_t(ebpf::BPF &bpf, pid_t pid)
        : _bpf(bpf)
        , _read_enter(_bpf, _bpf.get_syscall_fnname("read"), "syscall__read_enter")
        , _read_exit(_bpf, _bpf.get_syscall_fnname("read"), "syscall__read_exit", BPF_PROBE_RETURN)
        , _close_enter(_bpf, _bpf.get_syscall_fnname("close"), "syscall__close_enter")
        , _accept_enter(_bpf, _bpf.get_syscall_fnname("accept"), "syscall__accept_enter")
        , _accept_exit(_bpf, _bpf.get_syscall_fnname("accept"), "syscall__accept_exit", BPF_PROBE_RETURN)
        , _connect_enter(_bpf, _bpf.get_syscall_fnname("connect"), "syscall__connect_enter")
        , _connect_exit(_bpf, _bpf.get_syscall_fnname("connect"), "syscall__connect_exit", BPF_PROBE_RETURN)
    {
        // set filterting pid
        uint32_t key{0};
        auto pid_table = _bpf.get_array_table<uint32_t>("target_pid");
        auto rc = pid_table.update_value(key, pid);
        if (rc.code() != 0)
        {
            std::cerr << rc.msg() << std::endl;
            exit(EXIT_FAILURE);
        }

        rc = _bpf.open_perf_buffer("tls_events", &on_tls_event_handler);
        if (rc.code() != 0)
        {
            std::cerr << rc.msg() << "\n";
            exit(EXIT_FAILURE);
        }
    }

    void unix_socket_monitor_t::poll(int timeout_ms)
    {
        _bpf.poll_perf_buffer("tls_events", timeout_ms);
    }
}