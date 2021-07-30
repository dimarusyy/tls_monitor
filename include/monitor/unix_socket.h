#include "BPF.h"
#include "attach_probe.h"

#include <boost/asio/io_context.hpp>
#include <sys/types.h>

namespace tlsm
{
    namespace monitor
    {
        struct unix_socket_t final
        {
            explicit unix_socket_t(boost::asio::io_context &ctx, ebpf::BPF &bpf, pid_t pid);

            void start(std::function<bool()>, int timeout_ms = 0);

        private:
            boost::asio::io_context &_ctx;
            ebpf::BPF &_bpf;

            tlsm::attach_probe_t _read_enter;
            tlsm::attach_probe_t _read_exit;

            tlsm::attach_probe_t _close_enter;

            tlsm::attach_probe_t _accept_enter;
            tlsm::attach_probe_t _accept_exit;

            tlsm::attach_probe_t _connect_enter;
            tlsm::attach_probe_t _connect_exit;
        };
    }
}