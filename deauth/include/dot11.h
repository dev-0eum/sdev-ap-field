#pragma once

#include <pch.h>
#include <mac.h>
#include <radiotap.h> // RadioTapHdr 정의가 필요함

#pragma pack(push, 1)

// 802.11 공통 헤더
struct Dot11Hdr {
    uint8_t  subtype_ = 0x00;
    uint8_t  ver_type_ = 0x00;
    uint16_t duration_id_ = 0x0000;
    Mac      addr_1; 
    Mac      addr_2; 
    Mac      addr_3; 
    uint16_t seq_control_ = 0x0000;

    bool is_deauth() const;
};

// Deauth 프레임 구조체
struct DeauthFrame : public Dot11Hdr {
    uint16_t reason_code_ = 0x0007;

    // 생성자 선언
    DeauthFrame(Mac dest, Mac src, Mac bssid);
};

// 최종 패킷 구조체
struct DeauthPacket {
    RadioTapHdr rtap;
    DeauthFrame deauth;

    // 생성자 선언
    DeauthPacket(Mac dest, Mac src, Mac bssid);
};

#pragma pack(pop)
