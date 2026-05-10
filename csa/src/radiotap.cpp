#include "pch.h"
#include "radiotap.h"

// 패킷 바이트에서 Radiotap 헤더 길이를 읽어 반환 (little-endian)
uint16_t RadioTapHdr::get_len(const uint8_t* packet) {
    const RadioTapHdr* hdr = (const RadioTapHdr*)packet;
    return hdr->len_;
}
