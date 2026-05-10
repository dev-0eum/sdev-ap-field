#include "pch.h"
#include "dot11.h"

// Dot11Hdr 생성자
Dot11Hdr::Dot11Hdr(Mac dest, Mac src, Mac bssid) : 
    subtype_(0), ver_type_(0), duration_id_(0), 
    addr_1(dest), addr_2(src), addr_3(bssid), seq_control_(0) {}

// Dot11Hdr 멤버 함수 구현
bool Dot11Hdr::is_data() const {
    return (subtype_ == 0x08) && (ver_type_ == 0x00);
}

/* BeaconHdr */
// tag_param의 멤버 함수 구현
void BeaconHdr::tag_param::print_tag_info() const {
    printf("Tag Number: %d, Tag Length: %d\n", number, length);
}

void BeaconHdr::tag_param::value(const uint8_t* data) const {
    printf("Tag[%d] Data: ", number);
    for (int i = 0; i < length; i++) {
        printf("%c", data[i]);
    }
    printf("\n");
}

// BeaconHdr의 멤버 함수 구현
BeaconHdr::tag_param* BeaconHdr::first_tag() const {
    // 부모 클래스와 fixed_param 이후의 위치를 계산하여 반환
    return (tag_param*)((uint8_t*)this + sizeof(BeaconHdr) + sizeof(fixed_param));
}
