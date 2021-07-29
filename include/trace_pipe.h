#include <atomic>
namespace tlsm
{
    struct trace_pipe_t final
    {
        trace_pipe_t();
        void stop();

    private:
        std::atomic_bool _stop{false};
    };
}