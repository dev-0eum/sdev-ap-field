#include <pcap.h>
#include <string>
#include <cstring>

#include <stdbool.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>
#include <time.h>
#include <mutex>
#include <thread>
#include <chrono>
#include "radiohdr-field.h"



using namespace std;

void usage() {
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

typedef struct {
	char* dev_;          // 인터페이스 (wlan0, mon0 등)
    char* ap_mac_;       // AP의 MAC 주소
    char* station_mac_;  // Station(단말기)의 MAC 주소 (선택)
    bool auth_flag_;     // -auth 옵션 활성화 여부
} Param;

Param param = {
	.dev_ = NULL,
    .ap_mac_ = NULL,
    .station_mac_ = NULL,
    .auth_flag_ = false
};

bool parse(Param* param, int argc, char* argv[]) {
    // 최소 실행 파일(argv[0]), 인터페이스(argv[1]), AP MAC(argv[2])이 필요하므로 argc는 최소 3이어야 함
    if (argc < 3 || argc > 5) {
        usage();
        return false;
    }

    // 필수 인자 저장
    param->dev_ = argv[1];
    param->ap_mac_ = argv[2];

    // 선택 인자 1: Station MAC이 입력된 경우 (argc >= 4)
    if (argc >= 4) {
        // 사용자가 실수로 station mac 자리에 -auth를 먼저 적었는지 방어 (usage 규칙 엄수)
        if (strncmp(argv[3], "-auth", 5) == 0) {
            printf("[Error] -auth 옵션은 <station mac> 뒤에 와야 합니다.\n");
            usage();
            return false; 
        }
        param->station_mac_ = argv[3];
    }

    // 선택 인자 2: -auth 옵션이 입력된 경우 (argc == 5)
    if (argc == 5) {
        if (strncmp(argv[4], "-auth", 5) == 0) {
            param->auth_flag_ = true;
        } else {
            printf("[Error] 알 수 없는 옵션입니다: %s\n", argv[4]);
            usage();
            return false;
        }
    }

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

struct Mac{
    uint8_t addr[6];

    Mac() {
        memset(addr, 0, 6);
    }

    Mac(const char* mac_str) {
        int values[6]; 
        int result = sscanf(mac_str, "%x:%x:%x:%x:%x:%x", 
                            &values[0], &values[1], &values[2], 
                            &values[3], &values[4], &values[5]);
        
        if (result == 6) {
            for(int i = 0; i < 6; ++i) {
                addr[i] = static_cast<uint8_t>(values[i]);
            }
        } else {
            memset(addr, 0, 6);
        }
    }

    Mac(const std::string& mac_str) : Mac(mac_str.c_str()) {}
    static Mac from_string(const string& mac_str) {
        return Mac(mac_str.c_str());
    }

    bool operator<(const Mac& other) const {
        return memcmp(addr, other.addr, 6) < 0; // BSSID 비교를 위한 연산자 오버로딩
    }

    // bssid와 ssid를 출력하는 함수
    void print_bssid() const {
        printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    }
};

typedef struct Dot11Hdr {
    uint8_t subtype_; // 패킷 종류와 플래그 (길이 변화의 핵심)
	uint8_t  ver_type_; // 패킷 종류와 플래그 (길이 변화의 핵심)
    uint16_t duration_id_;
    Mac  addr_1; // receiver
    Mac  addr_2; // transmitter
    Mac  addr_3; // 프로토콜마다 다르다
    uint16_t seq_control_;

    public:
    // 802.11 프레임이 Beacon인지 확인하는 멤버 함수
    bool is_beacon() const {
        return (subtype_ == 0x80) && (ver_type_ == 0x00);
    }

    
} Dot11Hdr;

struct BeaconHdr : public Dot11Hdr {
    Mac dest() const { return addr_1; }
    Mac src() const { return addr_2; }
    Mac bssid() const { return addr_3; }
    
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

mutex m_lock;
map<Mac, ap_node> ap_list; // BSSID를 key로, ap_node를 value로 하는 맵
void process_beacon(Mac current_bssid, string current_ssid, int8_t current_pwr) {
    m_lock.lock(); // 맵을 수정하기 전에 자물쇠 잠금

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

    m_lock.unlock(); // 수정이 끝났으니 자물쇠 풀기
}

void print_ap_list() {
    // 화면을 지우고 맨 위로 커서 이동 (리눅스/맥 환경 ANSI 이스케이프 시퀀스)
    // 실제 airodump처럼 보이게 해줍니다.
    printf("\033[2J\033[1;1H"); 

    printf(" BSSID              PWR   Beacons    ESSID\n");
    printf(" --------------------------------------------------------\n");

    // 맵을 순회 (Key는 pair.first, Value는 pair.second로 접근)
    for (const auto& pair : ap_list) {
        const Mac& bssid = pair.first;
        const ap_node& info = pair.second;

        // BSSID 출력 (MAC 주소 포맷팅)
        bssid.print_bssid();

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
	pcap_t* pcap = pcap_open_offline("./2026-05-03-Deauth_S24U-AP_N105G-ST.pcapng", errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_offline() return null - %s\n", errbuf);
		return -1;
	}

    // 1. MAC 객체 생성 (문자열 -> 바이트 배열 변환)
    Mac ap_mac(param.ap_mac_);
    Mac station_mac;
    
    if (param.station_mac_ != NULL) {
        station_mac = Mac(param.station_mac_);
    } else {
        // 단말기가 지정되지 않으면 브로드캐스트 주소로 설정
        station_mac = Mac("ff:ff:ff:ff:ff:ff");
    }

    // 디버깅: 변환된 MAC 주소 확인
    printf("[Target Info]\n");
    printf("Interface   : %s\n", param.dev_);
    printf("AP MAC      : %02x:%02x:%02x:%02x:%02x:%02x\n", 
            ap_mac.addr[0], ap_mac.addr[1], ap_mac.addr[2], 
            ap_mac.addr[3], ap_mac.addr[4], ap_mac.addr[5]);
    printf("Station MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", 
            station_mac.addr[0], station_mac.addr[1], station_mac.addr[2], 
            station_mac.addr[3], station_mac.addr[4], station_mac.addr[5]);
    printf("Auth Attack : %s\n", param.auth_flag_ ? "ON" : "OFF");

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
        // time_t current_time = time(NULL);
        // if (current_time - last_print_time >= 1) { // 1초가 경과했으면
        //     print_ap_list(); // 맵 출력
        //     last_print_time = current_time; // 마지막 출력 시간 갱신
        // }

    }
    pcap_close(pcap);
	return 0;
}