#include "BPF.h"
#include "attach_probe.h"

#include <sys/types.h>

namespace tlsm
{
    struct unix_socket_monitor_t final
    {
        explicit unix_socket_monitor_t(ebpf::BPF& bpf, pid_t pid);

        void poll();

    private:
        ebpf::BPF& _bpf;

        tlsm::attach_probe_t _read_enter;
        tlsm::attach_probe_t _read_exit;

        tlsm::attach_probe_t _close_enter;

        tlsm::attach_probe_t _accept_enter;
        tlsm::attach_probe_t _accept_exit;

        tlsm::attach_probe_t _connect_enter;
        tlsm::attach_probe_t _connect_exit;
    };
}