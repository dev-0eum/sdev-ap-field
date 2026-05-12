#include "pch.h"
#include "radiotap.h"

void RadioTapHdr::init() {
    version_ = 0;
    pad_ = 0;
    len_ = sizeof(RadioTapHdr);
    present_.val_ = 0;
}

size_t RadioTapHdr::get_fcs() {
    // Present 필드에서 FCS 비트가 켜져 있는지 확인
    if ((present_.val_ & (1 << FCS)) == 0) {
        return 0; // FCS 필드가 없으면 0 반환
    } else {
        // FCS 필드가 존재하는 경우, RadioTap 헤더 끝에서 4바이트를 읽어 반환
        return *(uint32_t*)((uint8_t*)this + len_ - 4);
    }
}
