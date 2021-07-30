#include "if_utils.h"

#include <sys/types.h>
#include <ifaddrs.h>
#include <algorithm>

namespace
{
    struct ifaddrs_finalizer_t
    {
        ifaddrs_finalizer_t(struct ifaddrs *addr)
            : _addr(addr)
        {
        }

        ~ifaddrs_finalizer_t()
        {
            freeifaddrs(_addr);
        }

        struct ifaddrs *_addr;
    };
}

namespace tlsm
{
    std::vector<std::string> get_inet_if()
    {
        std::vector<std::string> rc;

        struct ifaddrs *addrs, *tmp;

        getifaddrs(&addrs);
        ifaddrs_finalizer_t addrs_fin(addrs);

        tmp = addrs;
        while (tmp)
        {
            if (tmp->ifa_addr &&
                (tmp->ifa_addr->sa_family == AF_PACKET ||
                 tmp->ifa_addr->sa_family == AF_INET ||
                 tmp->ifa_addr->sa_family == AF_INET6))
            {
                rc.emplace_back(tmp->ifa_name);
            }

            tmp = tmp->ifa_next;
        }

        std::sort(rc.begin(), rc.end());
        auto last = std::unique(rc.begin(), rc.end());
        rc.erase(last, rc.end());
        return rc;
    }
}