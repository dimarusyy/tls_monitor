#include "BPF.h"
#include <sys/types.h>

namespace tlsm
{
    struct interface_monitor_t final
    {
        interface_monitor_t(ebpf::BPF &, pid_t,
                            const std::string &);

    private:
        ebpf::BPF &_bpf;
        int _sockfd;
    };
}