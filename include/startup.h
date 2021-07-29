#include <iostream>
#include <assert.h>
#include <signal.h>

namespace tlsm
{
    struct startup_t final
    {
        startup_t(int argc, char **argv)
        {
            if (argc != 2)
            {
                std::cerr << argv[0] << "Usage: tls_monitor <pid>" << std::endl;
                exit(EXIT_FAILURE);
            }

            // handle passed arguments
            try
            {
                _pid = std::stoul(argv[1]);
                assert(_pid != 0U);
            }
            catch (const std::exception &ex)
            {
                std::cerr << "Error: expected <pid>, but [" << argv[1] << "] provided.\n";
                exit(EXIT_FAILURE);
            }
        }

        const pid_t pid() const
        {
            return _pid;
        }

        void check_pid()
        {
            if (0 != kill(_pid, 0))
            {
                std::cerr << "Error: process with pid [" << _pid << "] not found.\n";
                exit(EXIT_FAILURE);
            }

            std::cout << "Attached to pid [" << _pid << "]\n";
        }

    private:
        pid_t _pid{0};
    };
}