#include "interface_monitor.h"

#include <sys/socket.h>
#include <iostream>

#include <boost/asio.hpp>

namespace tlsm
{
    interface_monitor_t::interface_monitor_t(ebpf::BPF &bpf, pid_t pid,
                                             const std::string &name)
        : _bpf(bpf)
    {
        int prog_fd;
        auto rc = _bpf.load_func("tls_filter", BPF_PROG_TYPE_SOCKET_FILTER, prog_fd);
        if (rc.code() != 0)
        {
            std::cerr << rc.msg() << std::endl;
            exit(EXIT_FAILURE);
        }

        _sockfd = bpf_open_raw_sock(name.c_str());
        if (_sockfd == -1)
        {
            std::cerr << "Failed to create bpf socket for [" << name << "]\n";
            exit(EXIT_FAILURE);
        }

        if (bpf_attach_socket(_sockfd, prog_fd) == -1)
        {
            std::cerr << "Error : setsockopt() failed [" << strerror(errno) << "]\n";
            exit(EXIT_FAILURE);
        }
    }
}