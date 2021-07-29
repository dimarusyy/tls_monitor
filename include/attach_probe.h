#include <iostream>
#include "BPF.h"

namespace tlsm
{
    struct attach_probe_t final
    {
        attach_probe_t(ebpf::BPF &ebpf,
                       std::string fnname,
                       std::string probe_name,
                       bpf_probe_attach_type type = BPF_PROBE_ENTRY)
            : _ebpf(ebpf), _fnname(std::move(fnname)), _probe_name(std::move(probe_name))
        {
            auto rc = ebpf.attach_kprobe(_fnname, _probe_name, 0, type, 0);
            if (rc.code() != 0)
            {
                std::cerr << rc.msg() << std::endl;
                throw std::runtime_error("failed to attach probe [" + _probe_name + "]");
            }
            else
            {
                std::cout << "Attched to kprobe[" << _fnname << "] with [" << _probe_name << "]\n";
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
}