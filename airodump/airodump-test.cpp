extern "C" {
    #include <pcap.h>
}
#include <stdbool.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>
#include <string>

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
typedef struct RadioTapHdr {
    uint8_t  version_;  // Header revision (항상 0)
    uint8_t  pad_;      // Header pad
    uint16_t len_;      // 전체 Radiotap 헤더 길이
    uint32_t present_;  // 뒤에 어떤 필드가 오는지 알려주는 비트마스크 (Present flags) // MSB 값으로 다음 있는지 판단
} RadioTapHdr;

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
	pcap_t* pcap = pcap_open_offline("./pcapfile/mon0_wlan.pcapng", errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_offline() return null - %s\n", errbuf);
		return -1;
	}

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
        beacon->print_info(); // BSSID 출력

        // 수동 계산 대신 깔끔하게 메서드 호출!
        BeaconHdr::tag_param *tag = beacon->first_tag(); 

        // 안전한 루프 탈출 조건 (pcap 헤더의 caplen 등 패킷의 끝 위치를 반드시 활용)
        const uint8_t* packet_end = packet + header->caplen; 

        // 패킷 끝을 넘지 않고, 원하는 태그(예: SSID인 0번)를 찾을 때까지 반복
        while ((uint8_t*)tag < packet_end && tag->number != 0) { 
            tag = tag->next();
        }

        // 루프를 무사히 빠져나왔고, 그것이 우리가 찾는 태그라면 출력
        if ((uint8_t*)tag < packet_end && tag->number == 0) {
            tag->print_tag_info();
            tag->value((uint8_t*)tag + sizeof(BeaconHdr::tag_param));
        }

        process_beacon(beacon->bssid(), tag->number == 0 ? string((char*)(tag + 1), tag->length) : "", /*pwr*/0); // pwr는 예시로 0, 실제로는 Radiotap에서 읽어와야 함

        cout << endl;
    }

    print_ap_list(); // AP 리스트 출력

	cout << "End Program" << endl;
	return 0;
}