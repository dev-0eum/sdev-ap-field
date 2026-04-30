extern "C" {
    #include <pcap.h>
}
#include <stdbool.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <cstring>
#include <time.h>
#include "radiohdr-field.h"

using namespace std;

void usage() {
	printf("syntax: ./airodump-test <interface>\n");
	printf("sample: ./airodump-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

#pragma pack(push, 1)
struct RadioTapHdr {
    uint8_t  version_;
    uint8_t  pad_;
    uint16_t len_;
    uint32_t present_;

    int8_t get_pwr() const {
        // 1. MSB(Ext 비트) 확인 및 초기 오프셋 계산
        size_t offset = 8; 
        const uint32_t* next_present = &present_;
        
        while ((*next_present & 0x80000000) != 0) {
            offset += 4;
            next_present++;
        }

        // 2. Antenna Signal 필드가 존재하는지 비트 마스크로 확인
        // (1 << RT_ANTENNA_SIGNAL) 은 0x20과 동일합니다.
        if ((present_ & (1 << RT_ANTENNA_SIGNAL)) == 0) {
            return 0; 
        }

        // 3. 0번 비트부터 타겟 비트(Antenna Signal) '직전'까지 반복하며 오프셋 누적
        for (int i = 0; i < RT_ANTENNA_SIGNAL; ++i) {
            // 현재 검사 중인 비트(i)가 켜져 있다면
            if (present_ & (1 << i)) {
                size_t align = RT_FIELD_INFO[i].align;
                size_t size  = RT_FIELD_INFO[i].size;

                // 정렬(Alignment) 맞추기 공식
                offset = (offset + (align - 1)) & ~(align - 1);
                
                // 크기(Size) 더하기
                offset += size;
            }
        }

        // 4. 타겟(Antenna Signal)을 읽기 직전, 해당 필드의 정렬 수행
        size_t target_align = RT_FIELD_INFO[RT_ANTENNA_SIGNAL].align;
        offset = (offset + (target_align - 1)) & ~(target_align - 1);

        // 5. signal 값 반환
        const uint8_t* base_ptr = reinterpret_cast<const uint8_t*>(this);
        return static_cast<int8_t>(base_ptr[offset]);
    }
};

struct MAC{
    uint8_t addr[6];

    bool operator<(const MAC& other) const {
        return memcmp(addr, other.addr, 6) < 0; // BSSID 비교를 위한 연산자 오버로딩
    }
};

typedef struct Dot11Hdr {
    uint8_t subtype_; // 패킷 종류와 플래그 (길이 변화의 핵심)
	uint8_t  ver_type_; // 패킷 종류와 플래그 (길이 변화의 핵심)
    uint16_t duration_id_;
    MAC  dest_;
    MAC  src_;
    MAC  bssid_;
    uint16_t seq_control_;

    public:
    // 802.11 프레임이 Beacon인지 확인하는 멤버 함수
    bool is_beacon() const {
        return (subtype_ == 0x80) && (ver_type_ == 0x00);
    }

    // bssid와 ssid를 출력하는 함수
    void print_info() const {
        printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n", bssid_.addr[0], bssid_.addr[1], bssid_.addr[2], bssid_.addr[3], bssid_.addr[4], bssid_.addr[5]);
    }
} Dot11Hdr;

struct BeaconHdr : public Dot11Hdr {
    MAC dest() const { return dest_; }
    MAC src() const { return src_; }
    MAC bssid() const { return bssid_; }
    
    struct fixed_param {
        uint64_t timestamp; // 타임스탬프
        uint16_t beaconInterval; // 비콘 인터벌
        uint16_t capabilityInfo; // 기능 정보
    };

    struct tag_param {
        uint8_t number;
        uint8_t length;

        void print_tag_info() const {
            printf("Tag Number: %d, Tag Length: %d\n", number, length);
        }

        void value(const uint8_t* data) const {
            printf("Tag[%d] Data: ", number);
            for (int i = 0; i < length; i++) {
                printf("%c", data[i]);
            }
            printf("\n");
        }
        tag_param* next() const {
            return (tag_param*)((uint8_t*)this + sizeof(tag_param) + length);
        }
    };

    // 첫 번째 태그 파라미터의 포인터를 반환하는 멤버 함수
    tag_param* first_tag() const {
        return (tag_param*)((uint8_t*)this + sizeof(BeaconHdr) + sizeof(fixed_param));
    }

};
#pragma pack(pop)

struct ap_node {
    string ssid_; // station이 연결된 AP의 BSSID
    int8_t pwr_;
    int beaconCount_;
};

map<MAC, ap_node> ap_list; // BSSID를 key로, ap_node를 value로 하는 맵
void process_beacon(MAC current_bssid, string current_ssid, int8_t current_pwr) {
    // 1. 맵에서 현재 BSSID가 이미 존재하는지 검색
    auto it = ap_list.find(current_bssid);

    if (it != ap_list.end()) {
        // [기존에 존재하는 AP인 경우] -> 데이터 업데이트
        it->second.pwr_ = current_pwr;         // 최신 신호 세기로 갱신
        it->second.beaconCount_++;             // 비콘 카운트 1 증가
        
        // (선택) 처음에 Hidden SSID였다가 나중에 이름이 파악된 경우 이름 갱신
        if (it->second.ssid_.empty() && !current_ssid.empty()) {
            it->second.ssid_ = current_ssid;
        }
    } else {
        // [처음 발견한 새로운 AP인 경우] -> 맵에 새로 추가
        ap_node new_ap;
        new_ap.ssid_ = current_ssid;
        new_ap.pwr_ = current_pwr;
        new_ap.beaconCount_ = 1;

        // ap_list[current_bssid] = new_ap; 
        ap_list.insert({current_bssid, new_ap});
    }
}

void print_ap_list() {
    // 화면을 지우고 맨 위로 커서 이동 (리눅스/맥 환경 ANSI 이스케이프 시퀀스)
    // 실제 airodump처럼 보이게 해줍니다.
    printf("\033[2J\033[1;1H"); 

    printf(" BSSID              PWR   Beacons    ESSID\n");
    printf(" --------------------------------------------------------\n");

    // 맵을 순회 (Key는 pair.first, Value는 pair.second로 접근)
    for (const auto& pair : ap_list) {
        const MAC& bssid = pair.first;
        const ap_node& info = pair.second;

        // BSSID 출력 (MAC 주소 포맷팅)
        printf(" %02X:%02X:%02X:%02X:%02X:%02X  ", 
            bssid.addr[0], bssid.addr[1], bssid.addr[2], 
            bssid.addr[3], bssid.addr[4], bssid.addr[5]);

        // Power, Beacon, SSID 출력
        printf("%4d  %8d    %s\n", 
            info.pwr_, 
            info.beaconCount_, 
            info.ssid_.c_str());
    }
}

int main(int argc, char *argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live() return null - %s\n", errbuf);
		return -1;
	}

    // 화면 갱신을 위한 시간 체크 변수
    time_t last_print_time = time(NULL);
    while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			// 에러 또는 파일 끝에 도달한 경우 루프 종료
			break;
		}

        // Header Prasing
		RadioTapHdr *rtap = (struct RadioTapHdr *)packet; // Radiotap Header
        BeaconHdr *beacon = (BeaconHdr *)(packet + rtap->len_);  // BeaconHdr Casting
        if (!beacon->is_beacon()) continue; // Check if it's a beacon frame

        // 수동 계산 대신 깔끔하게 메서드 호출!
        BeaconHdr::tag_param *tag = beacon->first_tag(); 

        // 안전한 루프 탈출 조건 (pcap 헤더의 caplen 등 패킷의 끝 위치를 반드시 활용)
        const uint8_t* packet_end = packet + header->caplen; 

        // 패킷 끝을 넘지 않고, 원하는 태그(예: SSID인 0번)를 찾을 때까지 반복
        while ((uint8_t*)tag < packet_end && tag->number != 0) { 
            tag = tag->next();
        }

        process_beacon(beacon->bssid(), tag->number == 0 ? string((char*)(tag + 1), tag->length) : "", rtap->get_pwr()); // pwr는 예시로 0, 실제로는 Radiotap에서 읽어와야 함

        // 화면 갱신 로직 추가
        time_t current_time = time(NULL);
        if (current_time - last_print_time >= 1) { // 1초가 경과했으면
            print_ap_list(); // 맵 출력
            last_print_time = current_time; // 마지막 출력 시간 갱신
        }
    }
    pcap_close(pcap);
	return 0;
}