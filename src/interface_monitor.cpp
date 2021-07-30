#include "interface_monitor.h"

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <iostream>

#include <boost/asio.hpp>

namespace tlsm
{
    interface_monitor_t::interface_monitor_t(boost::asio::io_context &ctx,
                                             ebpf::BPF &bpf,
                                             pid_t pid,
                                             const std::string &ifname)
        : _bpf(bpf)
        , _socket(ctx, raw_protocol_t(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC))
    {
        int prog_fd;
        auto rc = _bpf.load_func("tls_filter", BPF_PROG_TYPE_SOCKET_FILTER, prog_fd);
        if (rc.code() != 0)
        {
            std::cerr << rc.msg() << std::endl;
            exit(EXIT_FAILURE);
        }

        struct sockaddr_ll addr = {0};
        addr.sll_family = PF_PACKET;
        addr.sll_protocol = htons(ETH_P_ALL);
        addr.sll_ifindex = if_nametoindex(ifname.c_str());
        if (addr.sll_ifindex == 0) {
            std::cerr << "if_nametoindex() failed for [" << ifname << "] : [" << strerror(errno) << "]\n";
            exit(EXIT_FAILURE);
        }
        addr.sll_hatype = 1;

        boost::system::error_code ec;
        _socket.bind(raw_endpoint_t(&addr, sizeof(addr)), ec);
        if(ec)
        {
            std::cerr << "Error : [" << ec.message() << "]\n";
            exit(EXIT_FAILURE);
        }

        if (bpf_attach_socket(_socket.native_handle(), prog_fd) == -1)
        {
            std::cerr << "Error : setsockopt() failed [" << strerror(errno) << "]\n";
            exit(EXIT_FAILURE);
        }
    }
}