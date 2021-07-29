#include "unix_socket_monitor.h"
#include "attach_probe.h"

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
    unix_socket_monitor_t::unix_socket_monitor_t(pid_t pid)
    {
        auto init_res = _bpf.init(BPF_PROGRAM);
        if (init_res.code() != 0)
        {
            std::cerr << init_res.msg() << std::endl;
            exit(EXIT_FAILURE);
        }

        // set filterting pid
        uint32_t key{0};
        auto pid_table = _bpf.get_array_table<uint32_t>("target_pid");
        auto rc = pid_table.update_value(key, pid);
        if (rc.code() != 0)
        {
            std::cerr << rc.msg() << std::endl;
            exit(EXIT_FAILURE);
        }

        // read
        auto syscall_read_name = _bpf.get_syscall_fnname("read");
        attach_probe_t read_enter(_bpf, syscall_read_name, "syscall__read_enter");
        attach_probe_t read_exit(_bpf, syscall_read_name, "syscall__read_exit", BPF_PROBE_RETURN);

        //close
        auto syscall_close_name = _bpf.get_syscall_fnname("close");
        attach_probe_t close_enter(_bpf, syscall_close_name, "syscall__close_enter");

        //accept
        auto syscall_accept_name = _bpf.get_syscall_fnname("accept");
        attach_probe_t accept_enter(_bpf, syscall_accept_name, "syscall__accept_enter");
        attach_probe_t accept_exit(_bpf, syscall_accept_name, "syscall__accept_exit", BPF_PROBE_RETURN);

        //connect
        auto syscall_connect_name = _bpf.get_syscall_fnname("connect");
        attach_probe_t connect_enter(_bpf, syscall_connect_name, "syscall__connect_enter");
        attach_probe_t connect_exit(_bpf, syscall_connect_name, "syscall__connect_exit", BPF_PROBE_RETURN);

        rc = _bpf.open_perf_buffer("tls_events", &on_tls_event_handler);
        if (rc.code() != 0)
        {
            std::cerr << rc.msg() << "\n";
            exit(EXIT_FAILURE);
        }

        while (!_stop.load(std::memory_order_acquire))
        {
            _bpf.poll_perf_buffer("tls_events", 100);
        }
    }

    void unix_socket_monitor_t::stop()
    {
        _stop.store(true, std::memory_order_release);
    }
}