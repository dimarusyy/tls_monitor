#include "BPF.h"
#include <sys/types.h>

#include <boost/asio/generic/raw_protocol.hpp>
namespace tlsm
{
    namespace monitor
    {
        struct interface_t final
        {
            using raw_protocol_t = boost::asio::generic::raw_protocol;
            using raw_endpoint_t = boost::asio::generic::basic_endpoint<raw_protocol_t>;

            interface_t(boost::asio::io_context &,
                                ebpf::BPF &,
                                const std::string &);

            void start(std::function<bool()> cancelation);

        private:
            boost::asio::io_context &_ctx;
            ebpf::BPF &_bpf;
            raw_protocol_t::socket _socket;
        };
    }
}