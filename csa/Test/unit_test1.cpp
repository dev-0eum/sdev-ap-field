#include <pcap.h>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <cassert>

// ── 테스트 대상 구조체 인라인 정의 ──────────────────────────────
// (include/ 헤더를 그대로 재사용)
#include "../include/pch.h"
#include "../include/radiotap.h"
#include "../include/mac.h"
#include "../include/dot11.h"

using namespace std;

// ── 헬퍼: tag number 순 정렬 여부 확인 ─────────────────────────
static bool tags_are_sorted(const uint8_t* tags_start, const uint8_t* tags_end) {
    const uint8_t* p = tags_start;
    int prev = -1;
    while (p + 2 <= tags_end) {
        int num = p[0];
        int len = p[1];
        if (num < prev) return false;
        prev = num;
        if (p + 2 + len > tags_end) break;
        p += 2 + len;
    }
    return true;
}

// ── 헬퍼: CSA IE (tag 37) 존재 여부 + 값 확인 ──────────────────
static bool has_csa_tag(const uint8_t* tags_start, const uint8_t* tags_end,
                        uint8_t expected_channel) {
    const uint8_t* p = tags_start;
    while (p + 2 <= tags_end) {
        uint8_t num = p[0];
        uint8_t len = p[1];
        if (num == 37 && len == 3) {
            // p[2]=mode, p[3]=new_channel, p[4]=count
            if (p + 2 + len <= tags_end && p[3] == expected_channel) return true;
        }
        if (p + 2 + (int)len > tags_end) break;
        p += 2 + len;
    }
    return false;
}

// ── CSA IE 삽입 함수 (main.cpp 로직 동일) ───────────────────────
static vector<uint8_t> build_csa_packet(const uint8_t* packet, int caplen,
                                        const Mac& station_mac) {
    uint16_t rt_len = RadioTapHdr::get_len(packet);
    int min_len = rt_len + (int)sizeof(BeaconHdr) + (int)sizeof(BeaconHdr::fixed_param);
    if (caplen < min_len) return {};

    const BeaconHdr* beacon = (const BeaconHdr*)(packet + rt_len);
    const uint8_t* tags_start = (const uint8_t*)beacon->first_tag();
    const uint8_t* tags_end_ptr = packet + caplen - 4;  // FCS 제외

    uint8_t csa_ie[] = {37, 3, 1, 14, 1};
    bool csa_inserted = false;
    vector<uint8_t> new_tags;
    const uint8_t* p = tags_start;

    while (p < tags_end_ptr && p + 2 <= tags_end_ptr) {
        uint8_t tag_num = p[0];
        uint8_t tag_len = p[1];

        if (!csa_inserted && tag_num >= 37) {
            if (tag_num == 37) {
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
    if (!csa_inserted)
        new_tags.insert(new_tags.end(), csa_ie, csa_ie + sizeof(csa_ie));

    int fixed_hdr_len = (int)(tags_start - (packet + rt_len));
    vector<uint8_t> new_packet;
    new_packet.insert(new_packet.end(), packet, packet + rt_len + fixed_hdr_len);
    new_packet.insert(new_packet.end(), new_tags.begin(), new_tags.end());

    // addr_1 교체
    int addr1_offset = rt_len + 4;
    memcpy(new_packet.data() + addr1_offset, station_mac.addr, 6);

    return new_packet;
}

// ── 테스트 케이스 ────────────────────────────────────────────────
static int pass_count = 0;
static int fail_count = 0;

#define CHECK(cond, msg) \
    do { \
        if (cond) { printf("[PASS] %s\n", msg); pass_count++; } \
        else      { printf("[FAIL] %s\n", msg); fail_count++; } \
    } while(0)

int main() {
    const char* pcap_path =
        "../pcapfile/2026-05-05-CSA_selfcapture.pcapng";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(pcap_path, errbuf);
    if (!pcap) {
        fprintf(stderr, "[ERROR] pcap_open_offline failed: %s\n", errbuf);
        return 1;
    }
    printf("=== unit_test1: CSA IE 삽입 검증 ===\n");
    printf("pcap file: %s\n\n", pcap_path);

    struct pcap_pkthdr* hdr;
    const uint8_t* pkt;
    int beacon_count = 0;
    int processed = 0;

    while (pcap_next_ex(pcap, &hdr, &pkt) == 1) {
        uint16_t rt_len = RadioTapHdr::get_len(pkt);
        int min_len = rt_len + (int)sizeof(BeaconHdr) + (int)sizeof(BeaconHdr::fixed_param);
        if ((int)hdr->caplen < min_len) continue;

        const BeaconHdr* beacon = (const BeaconHdr*)(pkt + rt_len);
        // Beacon: subtype=0x80, ver_type=0x00
        if (beacon->subtype_ != 0x80 || beacon->ver_type_ != 0x00) continue;

        beacon_count++;

        // ── TEST 1: Radiotap 헤더 길이 > 0 ───────────────────
        CHECK(rt_len > 0, "T1: Radiotap len > 0");

        // ── TEST 2: 원본에 CSA 태그 없는지 (선택적) ──────────
        const uint8_t* tags_s = (const uint8_t*)beacon->first_tag();
        const uint8_t* tags_e = pkt + hdr->caplen - 4;

        // ── TEST 3: CSA 패킷 조립 성공 ───────────────────────
        Mac bcast("ff:ff:ff:ff:ff:ff");
        vector<uint8_t> new_pkt = build_csa_packet(pkt, hdr->caplen, bcast);
        CHECK(!new_pkt.empty(), "T3: CSA packet built (non-empty)");
        if (new_pkt.empty()) { processed++; continue; }

        // ── TEST 4: 조립 패킷 최소 크기 ──────────────────────
        CHECK((int)new_pkt.size() >= min_len + 5,
              "T4: new packet size >= original header + CSA IE (5 bytes)");

        // ── TEST 5: CSA IE (tag 37) 존재 + channel=14 ────────
        uint16_t new_rt_len = RadioTapHdr::get_len(new_pkt.data());
        const BeaconHdr* new_beacon = (const BeaconHdr*)(new_pkt.data() + new_rt_len);
        const uint8_t* new_tags_s = (const uint8_t*)new_beacon->first_tag();
        const uint8_t* new_tags_e = new_pkt.data() + new_pkt.size();
        CHECK(has_csa_tag(new_tags_s, new_tags_e, 14),
              "T5: CSA tag(37) present with channel=14");

        // ── TEST 6: tag number 정렬 유지 ─────────────────────
        CHECK(tags_are_sorted(new_tags_s, new_tags_e),
              "T6: tagged params are sorted by tag number");

        // ── TEST 7: Destination addr_1 = broadcast ────────────
        int addr1_off = new_rt_len + 4;
        uint8_t expected_bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
        CHECK(memcmp(new_pkt.data() + addr1_off, expected_bcast, 6) == 0,
              "T7: addr_1 set to broadcast ff:ff:ff:ff:ff:ff");

        // ── TEST 8: unicast 대상 addr_1 교체 ─────────────────
        Mac uni("11:22:33:44:55:66");
        vector<uint8_t> uni_pkt = build_csa_packet(pkt, hdr->caplen, uni);
        uint8_t expected_uni[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
        CHECK(!uni_pkt.empty() &&
              memcmp(uni_pkt.data() + addr1_off, expected_uni, 6) == 0,
              "T8: addr_1 set to unicast 11:22:33:44:55:66");

        processed++;
        if (processed >= 5) break;  // 최대 5개 Beacon만 검사
    }

    pcap_close(pcap);

    printf("\n=== 결과: Beacon %d개 처리, PASS %d / FAIL %d ===\n",
           processed, pass_count, fail_count);
    if (beacon_count == 0)
        printf("[WARN] pcap 파일에서 Beacon 프레임을 찾지 못했습니다.\n");

    return (fail_count == 0) ? 0 : 1;
}
