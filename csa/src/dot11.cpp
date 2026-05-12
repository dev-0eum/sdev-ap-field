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
// Tag의 멤버 함수 구현
void BeaconHdr::Tag::print_tag_info() const {
    printf("Tag Number: %d, Tag Length: %d\n", number, length);
}

void BeaconHdr::Tag::value(const uint8_t* data) const {
    printf("Tag[%d] Data: ", number);
    for (int i = 0; i < length; i++) {
        printf("%c", data[i]);
    }
    printf("\n");
}

// BeaconHdr의 멤버 함수 구현
// Fix가 이제 BeaconHdr의 멤버(fix_)이므로, tagged params 시작 위치는
// Dot11Hdr 크기 + Fix 크기만큼 이동한 위치
BeaconHdr::Tag* BeaconHdr::first_tag() const {
    return (Tag*)((uint8_t*)this + sizeof(Dot11Hdr) + sizeof(Fix));
}
