#include <cstdint>
#include <cstddef>
#include <iostream>

// 1. Radiotap 필드의 비트 인덱스를 정의하는 Enum
enum RadiotapField : int {
    RT_TSFT = 0,
    RT_FLAGS = 1,
    RT_RATE = 2,
    RT_CHANNEL = 3,
    RT_FHSS = 4,
    RT_ANTENNA_SIGNAL = 5,
    RT_ANTENNA_NOISE = 6,
    RT_RX_FLAGS = 7,
    RT_TX_FLAGS = 8,
    RT_RTS_RETRIES = 9,
    RT_DATA_RETRIES = 10,
    // 필요시 규격서를 보고 추가...
};

// 2. 각 필드의 크기(Size)와 정렬(Alignment) 정보를 담은 구조체
struct RadiotapFieldInfo {
    size_t size;
    size_t align;
};

// 3. 인덱스(비트 번호)에 매핑되는 필드 스펙 배열
// 주의: 인덱스 순서가 위 Enum의 값(0, 1, 2...)과 정확히 일치해야 합니다.
const RadiotapFieldInfo RT_FIELD_INFO[] = {
    {8, 8}, // 0: TSFT
    {1, 1}, // 1: Flags
    {1, 1}, // 2: Rate
    {4, 2}, // 3: Channel
    {2, 2}, // 4: FHSS
    {1, 1}, // 5: Antenna signal
    {1, 1}, // 6: Antenna noise
    {2, 2}, // 7: RX flags
    {2, 2}, // 8: TX flags
    {1, 1}, // 9: RTS retries
    {1, 1}, // 10: Data retries
};