#include "pch.h"
#include "radiotap.h"

bool RadioTapHdr::has_fcs() const {
    // Step 1: present_ 워드에서 FLAGS 필드(bit 1)가 포함됐는지 확인
    // FLAGS bit가 없으면 FLAGS 바이트 자체가 없으므로 FCS 정보 불명 → false
    if (!(present_.val_ & (1 << FLAGS))) return false;

    // Step 2: extended present 워드를 건너뛰어 필드 데이터 시작 오프셋 계산
    // present 워드의 bit 31이 설정되면 다음 4바이트도 present 워드
    const uint8_t* base = (const uint8_t*)this;
    const uint32_t* pw = &present_.val_;
    size_t offset = (const uint8_t*)(pw + 1) - base; // 첫 present 워드 다음
    while (*pw & 0x80000000) {
        pw++;
        offset += sizeof(uint32_t);
    }

    // Step 3: FLAGS 앞에 오는 TSFT 필드(bit 0) 건너뜀
    // TSFT: size=8, align=8
    if (present_.val_ & (1 << TSFT)) {
        size_t align = RT_FIELD_INFO[TSFT].align;
        offset = (offset + align - 1) & ~(align - 1);
        offset += RT_FIELD_INFO[TSFT].size;
    }

    // Step 4: FLAGS 바이트 위치 정렬 (align=1 이므로 실질적 변화 없음)
    size_t align = RT_FIELD_INFO[FLAGS].align;
    offset = (offset + align - 1) & ~(align - 1);

    // Step 5: FLAGS 바이트에서 FCS_AT_END 비트 확인
    return (base[offset] & FCS_AT_END) != 0;
}

void RadioTapHdr::init() {
    version_ = 0;
    pad_ = 0;
    len_ = sizeof(RadioTapHdr);
    present_.val_ = 0;
}

size_t RadioTapHdr::get_fcs() {
    size_t fcs_size = 0;
    // Present 필드에서 FCS 비트가 켜져 있는지 확인
    if (has_fcs()) {
        fcs_size += sizeof(uint32_t); // FCS는 4바이트
    }
    
    return fcs_size;

}
