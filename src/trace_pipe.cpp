#include "trace_pipe.h"

#include <iostream>
#include <fstream>
#include <string>

namespace tlsm
{
    trace_pipe_t::trace_pipe_t()
    {
        std::ifstream pipe("/sys/kernel/debug/tracing/trace_pipe");
        while (!_stop.load(std::memory_order_acquire))
        {
            std::string line;
            if (std::getline(pipe, line))
            {
                std::cout << "TRACE : [" << line << "]\n";
            }
        }
    }

    void trace_pipe_t::stop()
    {
        _stop.store(true, std::memory_order_release);
    }
}