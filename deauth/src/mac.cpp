#include "mac.h"
#include "pch.h"

Mac::Mac() {
    std::memset(addr, 0, 6);
}

Mac::Mac(const char* mac_str) {
    int values[6]; 
    int result = sscanf(mac_str, "%x:%x:%x:%x:%x:%x", 
                        &values[0], &values[1], &values[2], 
                        &values[3], &values[4], &values[5]);
    
    if (result == 6) {
        for(int i = 0; i < 6; ++i) {
            addr[i] = static_cast<uint8_t>(values[i]);
        }
    } else {
        std::memset(addr, 0, 6);
    }
}

Mac::Mac(const std::string& mac_str) : Mac(mac_str.c_str()) {}

Mac Mac::from_string(const std::string& mac_str) {
    return Mac(mac_str.c_str());
}

bool Mac::operator<(const Mac& other) const {
    return std::memcmp(addr, other.addr, 6) < 0;
}

void Mac::print_mac() const {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", \
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

std::string Mac::to_string() const {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", \
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return std::string(buf);
}
