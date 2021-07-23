#include "ip_convert.h"
#include <fmt/core.h>

std::string ip::ipv4_to_string(uint32_t ip)
{
    return fmt::format("{}.{}.{}.{}",
                       ((ip)&0xFF),
                       ((ip >> 8) & 0xFF),
                       ((ip >> 16) & 0xFF),
                       ((ip >> 24) & 0xFF));
}

std::string ip::ipv6_to_string(uint8_t (*addr)[16])
{
    return fmt::format(
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        *(addr[0]),
        *(addr[1]),
        *(addr[2]),
        *(addr[3]),
        *(addr[4]),
        *(addr[5]),
        *(addr[6]),
        *(addr[7]),
        *(addr[8]),
        *(addr[9]),
        *(addr[10]),
        *(addr[11]),
        *(addr[12]),
        *(addr[13]),
        *(addr[14]),
        *(addr[15])
    );
}