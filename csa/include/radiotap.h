#pragma once
#pragma pack(push, 1)

struct RadioTapHdr {
    uint8_t  version_;
    uint8_t  pad_;
    uint16_t len_; // 기본 Radiotap 헤더 길이 (8바이트 고정 + 4바이트 present 필드)
    uint32_t present_; // 0x00000000이면 안됨.
};

#pragma pack(pop)