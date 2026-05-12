#pragma once

#include <pch.h>
#include <mac.h>
#include <radiotap.h> // RadioTapHdr 정의가 필요함

#pragma pack(push, 1)

// 802.11 공통 헤더
struct Dot11Hdr {
    uint8_t  subtype_;
    uint8_t  ver_type_;
    uint16_t duration_id_;
    Mac      addr_1; 
    Mac      addr_2; 
    Mac      addr_3; 
    uint16_t seq_control_;

    Dot11Hdr(Mac dest, Mac src, Mac bssid);

    bool is_data() const;
};

struct BeaconHdr : public Dot11Hdr {
    Mac dest() const { return addr_1; }
    Mac src() const { return addr_2; }
    Mac bssid() const { return addr_3; }
    
    struct Fix {
        uint64_t timestamp;
        uint16_t beaconInterval;
        uint16_t capabilityInfo;
    } fix_;

    struct Tag {
        uint8_t number;
        uint8_t length;

        // 짧은 함수들은 헤더에 두어도 무방합니다.
        void print_tag_info() const;
        void value(const uint8_t* data) const;

        Tag* next() const {
            return (Tag*)((uint8_t*)this + sizeof(Tag) + length);
        }
    };

    struct csa : Tag {
        uint8_t csa_mode;
        uint8_t new_ch;
        uint8_t sw_count;
    } csa_;

    // 태그 시작 위치 계산 함수
    Tag* first_tag() const;
    bool is_beacon() const { return (subtype_ == 0x80) && (ver_type_ == 0x00); }
};
typedef BeaconHdr* PBeaconHdr;
#pragma pack(pop)
