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

    // 5. 공격 루프 (aireplay-ng 로직 모방)
    int count = 0;
    while (true) {
        
    }
    pcap_close(pcap);
	return 0;
}
