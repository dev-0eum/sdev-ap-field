#pragma once
#include "pch.h"

#pragma pack(push, 1)
struct Mac {
    uint8_t addr[6];

    // 생성자 및 함수 선언
    Mac();
    Mac(const char* mac_str);
    Mac(const std::string& mac_str);

    static Mac from_string(const std::string& mac_str);

    // 연산자 오버로딩 및 유틸리티 함수 선언
    bool operator<(const Mac& other) const;
    void print_mac() const;
    std::string to_string() const;
};
#pragma pack(pop)