#include <unistd.h>
#include <fstream>
#include <iostream>
#include <exception>
#include <assert.h>

#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fmt/core.h>

#include <bcc_version.h>
#include <BPF.h>

// inline bpf code
#include "bpf/tls_monitor.h"

/*

Note : TLS connection patterns:
----------------------------------------
| byte # | Value   | Description       |
----------------------------------------
| 0      | 22      | TLS id            |
----------------------------------------
| 1      | 3/2/1/0 | Minor TLS version |
----------------------------------------
| 2      | 1       | Major TLS version |
----------------------------------------

*/

struct attach_probe_t final
{
    attach_probe_t(ebpf::BPF &ebpf,
                   std::string fnname,
                   std::string probe_name,
                   bpf_probe_attach_type type = BPF_PROBE_ENTRY)
        : _ebpf(ebpf), _fnname(std::move(fnname)), _probe_name(std::move(probe_name))
    {
        std::cout << "Attaching probe=[" << _probe_name << "] to fnname=[" << _fnname << "]\n";
        auto rc = ebpf.attach_kprobe(_fnname, _probe_name, 0, type, 0);
        if (rc.code() != 0)
        {
            std::cerr << rc.msg() << std::endl;
            throw std::runtime_error("failed to attach probe [" + _probe_name + "]");
        }
    }

    ~attach_probe_t()
    {
        try
        {
            auto rc = _ebpf.detach_kprobe(_fnname);
            if (rc.code() != 0)
                std::cerr << "error :" << rc.msg() << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }
    }

private:
    ebpf::BPF &_ebpf;
    std::string _fnname;
    std::string _probe_name;
};

struct startup_t final
{
    startup_t(int argc, char **argv)
    {
        if (argc != 2)
        {
            std::cerr << argv[0] << "Usage: tls_monitor <pid>" << std::endl;
            exit(EXIT_FAILURE);
        }

        // handle passed arguments
        try
        {
            _pid = std::stoul(argv[1]);
            assert(_pid != 0U);
        }
        catch (const std::exception &ex)
        {
            std::cerr << "Error: expected <pid>, but [" << argv[1] << "] provided.\n";
            exit(EXIT_FAILURE);
        }
    }

    const unsigned long pid() const
    {
        return _pid;
    }

    void check_pid()
    {
        if (0 != kill((pid_t)_pid, 0))
        {
            std::cerr << "Error: process with pid [" << _pid << "] not found.\n";
            exit(EXIT_FAILURE);
        }
    }

private:
    unsigned long _pid{0};
};

struct accept_event_t
{
    struct sockaddr addr;
};

void on_tls_event_handler(void *cb_cookie, void *data, int data_size)
{
    auto event = static_cast<accept_event_t *>(data);
    struct sockaddr_in *peer = (struct sockaddr_in *)&event->addr;
    std::cout << fmt::format("address=[{}], port=[{}]\n", inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
}

int main(int argc, char *argv[])
{
    startup_t startup(argc, argv);
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
    else
    {
        std::cout << "started for pid [" << startup.pid() << "]\n";
    }

    // read
    auto syscall_read_name = bpf.get_syscall_fnname("read");
    attach_probe_t read_enter(bpf, syscall_read_name, "syscall__read_enter");
    attach_probe_t read_exit(bpf, syscall_read_name, "syscall__read_exit", BPF_PROBE_RETURN);

    //close
    auto syscall_close_name = bpf.get_syscall_fnname("close");
    attach_probe_t close_enter(bpf, syscall_close_name, "syscall__close_enter");

    //accept
    auto syscall_accept_name = bpf.get_syscall_fnname("accept");
    attach_probe_t accept_enter(bpf, syscall_accept_name, "syscall__accept_enter");
    attach_probe_t accept_exit(bpf, syscall_accept_name, "syscall__accept_exit", BPF_PROBE_RETURN);

    //connect
    auto syscall_connect_name = bpf.get_syscall_fnname("connect");
    attach_probe_t connect_enter(bpf, syscall_connect_name, "syscall__connect_enter");
    attach_probe_t connect_exit(bpf, syscall_connect_name, "syscall__connect_exit", BPF_PROBE_RETURN);

    rc = bpf.open_perf_buffer("tls_events", &on_tls_event_handler);
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << "\n";
        return EXIT_FAILURE;
    }

    std::ifstream pipe("/sys/kernel/debug/tracing/trace_pipe");
    while (true)
    {
#if 0
        std::string line;
        if (std::getline(pipe, line))
        {
            std::cout << "bpf log : [" << line << "]\n";
        }
#else
        bpf.poll_perf_buffer("tls_events");
#endif
    }

    return 0;
}
