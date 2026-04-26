#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define MAX_APS 1000       // 추적할 최대 AP 개수
#define MAC_LEN 6          // BSSID (MAC 주소) 길이
#define MAX_SSID_LEN 32    // 802.11 규격상 최대 SSID 길이

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
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
struct RadioTapHeader {
    uint8_t  version;  // Header revision (항상 0)
    uint8_t  pad;      // Header pad
    uint16_t len;      // 전체 Radiotap 헤더 길이
    uint32_t present[3];  // 뒤에 어떤 필드가 오는지 알려주는 비트마스크 (Present flags)

	uint64_t timestamp;
	uint8_t  flags;
	uint8_t  rate;
	uint16_t channel_freq;
	uint16_t channel_flags;
	uint8_t  pwr;
};

struct _80211Header {
    uint8_t subtype; // 패킷 종류와 플래그 (길이 변화의 핵심)
	uint8_t  ver_type; // 패킷 종류와 플래그 (길이 변화의 핵심)
    uint16_t duration_id;
    uint8_t  dest[6];
    uint8_t  src[6];
    uint8_t  bssid[6];
    uint16_t seq_control;
};

struct fixed_param {
	uint64_t timestamp; // 타임스탬프
	uint16_t beacon_interval; // 비콘 인터벌
	uint16_t capability_info; // 기능 정보
};

struct tag_param {
	uint8_t number;
	uint8_t length;
};

struct ap_node {
    uint8_t bssid[MAC_LEN];
    char ssid[MAX_SSID_LEN + 1]; // 문자열 출력을 위한 NULL 문자 공간 포함
	int8_t pwr;
    int beacon_count;
};
#pragma pack(pop)


struct ap_node ap_list[MAX_APS];
int ap_count = 0;

void process_ap(const uint8_t *bssid, const uint8_t *ssid_data, uint8_t ssid_len, int8_t pwr) {
    char temp_ssid[MAX_SSID_LEN + 1] = {0};

    // 데이터 안전성 확보: SSID 복사 및 제어 문자 필터링
    int len = (ssid_len > MAX_SSID_LEN) ? MAX_SSID_LEN : ssid_len;
    for (int i = 0; i < len; i++) {
        if (ssid_data[i] >= 32 && ssid_data[i] <= 126) {
            temp_ssid[i] = ssid_data[i];
        } else {
            temp_ssid[i] = '.';
        }
    }
    temp_ssid[len] = '\0'; // 문자열 끝 지정

    // 3. 기존 리스트에서 (BSSID, SSID) 쌍 검색
    for (int i = 0; i < ap_count; i++) {
        // BSSID가 일치하고 SSID도 일치하는지 확인
        if (memcmp(ap_list[i].bssid, bssid, MAC_LEN) == 0 &&
            strcmp(ap_list[i].ssid, temp_ssid) == 0) {
            
            // 기존 쌍을 찾은 경우 카운트 증가
            ap_list[i].beacon_count++;
			ap_list[i].pwr = pwr; // 들어온 최신 패킷의 신호 세기로 갱신
            
            // 화면 갱신을 위해 캐리지 리턴(\r) 사용 (한 줄에서 업데이트)
            printf("\r[Update] BSSID: %02x:%02x:%02x:%02x:%02x:%02x | SSID: %-20s | Power: %4d dBm | Beacons: %4d\n",\
				bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],\
				temp_ssid, ap_list[i].pwr, ap_list[i].beacon_count);
            
            // 버퍼 강제 출력
            fflush(stdout); 
            return;
        }
    }

    // 4. 리스트에 없는 새로운 쌍인 경우 새로 추가
    if (ap_count < MAX_APS) {
        // 데이터 복사
        memcpy(ap_list[ap_count].bssid, bssid, MAC_LEN);
        strncpy(ap_list[ap_count].ssid, temp_ssid, MAX_SSID_LEN);
        ap_list[ap_count].beacon_count = 1; // 초기 카운트 1
        ap_list[ap_count].pwr = pwr; // 들어온 최신 패킷의 신호 세기로 갱신
        
        printf("[New AP] BSSID: %02x:%02x:%02x:%02x:%02x:%02x | SSID: %-20s | Power: %4d dBm | Beacons: %4d\n", \
			bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], temp_ssid, ap_list[ap_count].pwr, 1);

        ap_count++;
    } else {
        printf("\n[Warning] AP List is full! (%d max)\n", MAX_APS);
    }
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	int packet_count = 0; // 패킷 번호를 세기 위한 변수
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
		struct RadioTapHeader *rtap = (struct RadioTapHeader *)packet;

		// 802.11 Header
		struct _80211Header *wifi = (struct _80211Header *)(packet + rtap->len);
		if (wifi->subtype == 0x80 && wifi->ver_type == 0x00) { // 프레임 타입과 서브타입이 beacon인지 확인
		} else { 
			continue; // 다음 패킷으로 넘어감
		}
		
		// Fixed Parameters와 Tagged Parameters
		struct fixed_param *fixed = (struct fixed_param *)(packet + rtap->len + sizeof(struct _80211Header));
		struct tag_param *tag = (struct tag_param *)(packet + rtap->len + sizeof(struct _80211Header) + sizeof(struct fixed_param));
		uint8_t *data = (uint8_t *)(packet + rtap->len + sizeof(struct _80211Header) + sizeof(struct fixed_param) + sizeof(struct tag_param)); // 태그 번호(1바이트) + 태그 길이(1바이트) 이후부터 데이터 시작
		
		if (tag->number == 0) { // SSID 발견
			// 리스트 업데이트 함수 호출
			process_ap(wifi->bssid, data, tag->length, rtap->pwr);
		}
	}
	pcap_close(pcap);
}
