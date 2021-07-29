#include "BPF.h"

#include <sys/types.h>
#include <atomic>

namespace tlsm
{
    struct unix_socket_monitor_t final
    {
        explicit unix_socket_monitor_t(pid_t pid);
        void stop();

    private:
        ebpf::BPF _bpf;
        std::atomic_bool _stop{false};
    };
}