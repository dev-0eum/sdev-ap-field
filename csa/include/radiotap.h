#pragma once
#pragma pack(push, 1)

struct RadioTapHdr {
    enum PresentBit {
        TSFT = 0,
        FLAGS = 1,
        RATE = 2,
        CHANNEL = 3,
        FHSS = 4,
        DBM_ANTSIGNAL = 5,
        DBM_ANTNOISE = 6,
        LOCK_QUALITY = 7,
        TX_ATTENUATION = 8,
        DB_TX_ATTENUATION = 9,
        DBM_TX_POWER = 10,
        ANTENNA = 11,
        DB_ANTSIGNAL = 12,
        DB_ANTNOISE = 13,
    };
    
    struct FieldInfo {
        size_t size;
        size_t align;
    };
    // 인스턴스 레이아웃 제거 목적으로 static constexpr로 정의
    static constexpr FieldInfo RT_FIELD_INFO[14] = {
        {8, 8}, // TSFT
        {1, 1}, // FLAGS
        {1, 1}, // RATE
        {4, 2}, // CHANNEL
        {2, 2}, // FHSS
        {1, 1}, // DBM_ANTSIGNAL
        {1, 1}, // DBM_ANTNOISE
        {2, 2}, // LOCK_QUALITY
        {2, 2}, // TX_ATTENUATION
        {2, 2}, // DB_TX_ATTENUATION
        {1, 1}, // DBM_TX_POWER
        {1, 1}, // ANTENNA
        {1, 1}, // DB_ANTSIGNAL
        {1, 1}  // DB_ANTNOISE
    };

    enum Flag {
        FCS = 0x01,
        WEP = 0x02,
        FRAGMENT = 0x04,
        FCS_AT_END = 0x08,
    };

    struct Present{
        uint32_t val_;
        Present* next(){
            // 현재 Present 구조체의 다음 위치 계산
            if(val_ & 0x80000000){
                return (Present*)((uint8_t*)this + sizeof(Present));
            }
            return nullptr;
        }
    };

    uint8_t  version_;
    uint8_t  pad_;
    uint16_t len_; 
    Present present_; // init

    void init();
    uint16_t get_len(){ return len_; };
    bool has_fcs() const;
    size_t get_fcs();
};
typedef RadioTapHdr* PRadioTapHdr;
#pragma pack(pop)