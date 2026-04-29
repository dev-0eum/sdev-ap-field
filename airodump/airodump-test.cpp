extern "C" {
    #include <pcap.h>
}
#include <stdbool.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>

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

    // present 비트 확인
    // std::vector<uint32_t> get_present_flags() const {
    //     std::vector<uint32_t> flags;
        
    //     // // 1. 구조체에 명시된 첫 번째 present_ 값 추가
    //     // uint32_t current_flag = present_;
    //     // flags.push_back(current_flag);

    //     // // 2. present_ 필드 바로 뒤의 메모리를 가리키도록 포인터 설정
    //     // // (이 구조체가 패킷 원본 버퍼에 캐스팅되어 있다고 가정하므로 안전하게 동작합니다)
    //     // const uint32_t* next_flag_ptr = &present_ + 1;

    //     // // 3. 최상위 비트(0x80000000)가 1인지 비트 AND 연산으로 검사
    //     // while ((current_flag & 0x80000000) != 0) {
    //     //     // 다음 4바이트(확장 present 플래그)를 읽어옵니다.
    //     //     current_flag = *next_flag_ptr; 
    //     //     flags.push_back(current_flag);
            
    //     //     // 포인터를 다음 4바이트 위치로 이동시킵니다.
    //     //     next_flag_ptr++; 
    //     // }
    //     return flags;
    // }
} RadioTapHdr;

struct MAC{
    uint8_t addr[6];

    bool operator<(const MAC& other) const {
        return memcmp(addr, other.addr, 6) < 0; // BSSID 비교를 위한 연산자 오버로딩
    }
};

typedef struct _80211Hdr {
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
} _80211Hdr;

struct BeaconHdr : public _80211Hdr {
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
    MAC bssid;
    string ssid_;
    int8_t pwr_;
    int beaconCount_;
};


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

        // Radiotap Header
		RadioTapHdr *rtap = (struct RadioTapHdr *)packet;

        // // 802.11 Header
		// _80211Hdr *wifi = (struct _80211Hdr *)(packet + rtap->len_);
		// // 802.11 프레임이 Beacon인지 확인
        // if (!wifi->is_beacon()) continue;
        // wifi->print_info();

        // // CHECK How to use the inherited struct
        // // tagged parameter에서 SSID 정보 추출
        // BeaconHdr::fixed_param *fixed = (struct BeaconHdr::fixed_param *)(packet + rtap->len_ + sizeof(BeaconHdr));
        // cout << "Timestamp: " << fixed->timestamp << endl; // 타임스탬프
        // BeaconHdr::tag_param *tag = (struct BeaconHdr::tag_param *)(packet + rtap->len_ + sizeof(BeaconHdr) + sizeof(BeaconHdr::fixed_param));
        // // BeaconHdr::tag_param *tag = beacon->first_tag();
        // tag->print_tag_info();

        // while (tag->number != 5) { // SSID 태그가 나올 때까지 반복
        //     tag->print_tag_info();
        //     tag->value((uint8_t*)tag + sizeof(BeaconHdr::tag_param)); // 태그 데이터 출력
        //     tag = tag->next();
        // }

        // 1. 단번에 BeaconHdr로 캐스팅 (부모, 자식 함수 모두 사용 가능)
        BeaconHdr *beacon = (BeaconHdr *)(packet + rtap->len_);

        if (!beacon->is_beacon()) continue;
        beacon->print_info();

        // 수동 계산 대신 깔끔하게 메서드 호출!
        BeaconHdr::tag_param *tag = beacon->first_tag(); 

        // 3. 안전한 루프 탈출 조건 (pcap 헤더의 caplen 등 패킷의 끝 위치를 반드시 활용)
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


        // SSID 태그의 데이터 추출

        // map에서 BSSID로 검색해서 SSID추출 -> SSID가 다르면 업데이트, 같으면 패스
        cout << endl;
    }

    map<MAC, ap_node> ap_list; // BSSID를 key로, ap_node를 value로 하는 맵

	cout << "End Program" << endl;
	return 0;
}