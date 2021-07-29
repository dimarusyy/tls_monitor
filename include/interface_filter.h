#include "BPF.h"

namespace tlsm
{
    struct interface_filter_t final
    {
        interface_filter_t();

        private:
            ebpf::BPF _bpf;
    };
}