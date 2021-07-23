#include <string>

namespace ip
{
    std::string ipv4_to_string(uint32_t ip);
    std::string ipv6_to_string(uint8_t (*addr)[16]);
}
