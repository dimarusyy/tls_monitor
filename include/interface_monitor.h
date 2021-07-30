#include "BPF.h"
#include <sys/types.h>

#include <boost/asio/generic/raw_protocol.hpp>
namespace tlsm
{
    struct interface_monitor_t final
    {
        using raw_protocol_t = boost::asio::generic::raw_protocol;
        using raw_endpoint_t = boost::asio::generic::basic_endpoint<raw_protocol_t>;

        interface_monitor_t(boost::asio::io_context &,
                            ebpf::BPF &,
                            pid_t,
                            const std::string &);

    private:
        ebpf::BPF &_bpf;
        raw_protocol_t::socket _socket;
    };
}