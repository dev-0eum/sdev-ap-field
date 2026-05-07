#include <dot11.h>

// Dot11Hdr 멤버 함수 구현
bool Dot11Hdr::is_deauth() const {
    return (subtype_ == 0xc0) && (ver_type_ == 0x00);
}

// DeauthFrame 생성자 구현
DeauthFrame::DeauthFrame(Mac dest, Mac src, Mac bssid) {
    subtype_ = 0xc0;        
    ver_type_ = 0x00;       
    duration_id_ = 0x013a;  
    
    addr_1 = dest;
    addr_2 = src;
    addr_3 = bssid;
    seq_control_ = 0x0000;
    reason_code_ = 0x0007; // 헤더 초기화값이 있지만 명시적 설정 가능
}

// DeauthPacket 생성자 구현
DeauthPacket::DeauthPacket(Mac dest, Mac src, Mac bssid) 
    : deauth(dest, src, bssid) {
    // rtap은 RadioTapHdr의 기본 생성자에 의해 초기화됨
}
