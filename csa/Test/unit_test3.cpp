#include <pcap.h>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>

#include "../include/pch.h"
#include "../include/radiotap.h"
#include "../include/mac.h"
#include "../include/dot11.h"

using namespace std;

// ── 카운터 ────────────────────────────────────────────────────────
static int pass_count = 0;
static int fail_count = 0;
static int warn_count = 0;

#define CHECK(cond, msg) \
    do { \
        if (cond) { printf("[PASS] %s\n", msg); pass_count++; } \
        else      { printf("[FAIL] %s\n", msg); fail_count++; } \
    } while(0)

#define WARN_IF_NOT(cond, msg) \
    do { \
        if (cond) { printf("[PASS] %s\n", msg); pass_count++; } \
        else      { printf("[WARN] %s\n", msg); warn_count++; } \
    } while(0)

// ── 패킷 구조 검증 (malformed 체크) ──────────────────────────────
// 반환값: true = 정상, false = malformed
struct MalformResult {
    bool ok;
    int  step;        // 실패한 단계 번호 (1~7), 정상이면 0
    const char* reason;
};

static MalformResult check_malformed(const uint8_t* packet, int caplen) {
    // Step 1. 최소 Radiotap 헤더 크기
    if (caplen < (int)sizeof(RadioTapHdr))
        return {false, 1, "packet too short for RadioTapHdr"};

    RadioTapHdr* rt = (RadioTapHdr*)packet;
    uint16_t rt_len = rt->get_len();

    // Step 2. Radiotap 길이가 패킷 안에 있는지
    if (rt_len == 0 || rt_len > caplen)
        return {false, 2, "radiotap len out of bounds"};

    // Step 3. 최소 Dot11Hdr + Fix 크기
    int min_dot11 = rt_len + (int)sizeof(Dot11Hdr) + (int)sizeof(BeaconHdr::Fix);
    if (caplen < min_dot11)
        return {false, 3, "packet too short for Dot11Hdr+Fix"};

    const BeaconHdr* beacon = (const BeaconHdr*)(packet + rt_len);

    // Step 4. Beacon 프레임인지
    if (!beacon->is_beacon())
        return {false, 4, "not a beacon frame"};

    // Step 5. FCS 크기가 0 또는 4인지
    size_t fcs_size = rt->get_fcs();
    if (fcs_size != 0 && fcs_size != 4)
        return {false, 5, "invalid FCS size (expected 0 or 4)"};

    // Step 6. FCS 제외 후 태그 영역 유효성
    const uint8_t* tags_start = (const uint8_t*)beacon->first_tag();
    const uint8_t* tags_end   = packet + caplen - fcs_size;

    if (tags_start > tags_end)
        return {false, 6, "tags_start exceeds tags_end (FCS overlap)"};

    // Step 7. 각 태그의 length가 경계 안에 있는지 순회
    const BeaconHdr::Tag* t = (const BeaconHdr::Tag*)tags_start;
    while ((const uint8_t*)t + 2 <= tags_end) {
        if ((const uint8_t*)t + 2 + t->length > tags_end)
            return {false, 7, "tag length exceeds packet boundary"};
        t = t->next();
    }

    return {true, 0, "ok"};
}

// ── CSA IE 삽입 (csa.cpp 로직 동일) ──────────────────────────────
static vector<uint8_t> build_csa_packet(const uint8_t* packet, int caplen,
                                        const Mac& station_mac,
                                        bool is_broadcast) {
    RadioTapHdr* rt = (RadioTapHdr*)packet;
    uint16_t rt_len = rt->get_len();
    size_t fcs_size = rt->get_fcs();

    int min_len = rt_len + (int)sizeof(Dot11Hdr) + (int)sizeof(BeaconHdr::Fix);
    if (caplen < min_len) return {};

    const BeaconHdr* beacon = (const BeaconHdr*)(packet + rt_len);
    const uint8_t* tags_start   = (const uint8_t*)beacon->first_tag();
    const uint8_t* tags_end_ptr = packet + caplen - fcs_size;

    uint8_t csa_ie[] = {37, 3, 1, 14, 1};
    bool csa_inserted = false;
    vector<uint8_t> new_tags;

    BeaconHdr::Tag* t = (BeaconHdr::Tag*)tags_start;
    while ((uint8_t*)t + 2 <= tags_end_ptr) {
        if (t->number == 37) {
            // 기존 tag 37: new_ch만 변경하여 복사
            if (t->length == 3 && (uint8_t*)t + 5 <= tags_end_ptr) {
                uint8_t mod[5];
                memcpy(mod, (uint8_t*)t, 5);
                mod[3] = csa_ie[3]; // new_ch 덮어쓰기
                new_tags.insert(new_tags.end(), mod, mod + 5);
            }
            csa_inserted = true;
            t = t->next();
            continue;
        }
        if (!csa_inserted && t->number > 37) {
            new_tags.insert(new_tags.end(), csa_ie, csa_ie + sizeof(csa_ie));
            csa_inserted = true;
        }
        if ((uint8_t*)t + 2 + t->length > tags_end_ptr) break;
        new_tags.insert(new_tags.end(), (uint8_t*)t, (uint8_t*)t + 2 + t->length);
        t = t->next();
    }
    if (!csa_inserted)
        new_tags.insert(new_tags.end(), csa_ie, csa_ie + sizeof(csa_ie));

    int fixed_hdr_len = (int)(tags_start - (packet + rt_len));
    vector<uint8_t> new_packet;
    new_packet.insert(new_packet.end(), packet, packet + rt_len + fixed_hdr_len);
    new_packet.insert(new_packet.end(), new_tags.begin(), new_tags.end());

    if (!is_broadcast) {
        int addr1_offset = rt_len + 4;
        memcpy(new_packet.data() + addr1_offset, station_mac.get_addr(), 6);
    }

    return new_packet;
}

// ── Goal.md Result 조건 검증 ──────────────────────────────────────
// "The difference of new packet from captured packet is only CSA tag and FCS bytes"
//
// 검증 방법:
//   orig_body  = orig[rt_len .. caplen - fcs_size)  (태그 포함 802.11 프레임, FCS 제거)
//   new_body   = new_pkt[rt_len .. new_pkt.size())
//
//   orig_body를 태그 단위로 순회하면서 new_body와 1:1 비교.
//   tag 37 구간만 건너뛰고(또는 삽입 위치만 다름) 나머지 모든 바이트가 동일해야 PASS.
static bool check_result_condition(const uint8_t* orig, int orig_caplen,
                                   const vector<uint8_t>& newpkt) {
    RadioTapHdr* rt = (RadioTapHdr*)orig;
    uint16_t rt_len   = rt->get_len();
    size_t fcs_size   = rt->get_fcs();

    // 원본 FCS 제외 범위
    int orig_end = orig_caplen - (int)fcs_size;

    // Radiotap + Dot11Hdr+Fix 구간은 동일해야 함
    int tags_offset = rt_len + (int)sizeof(Dot11Hdr) + (int)sizeof(BeaconHdr::Fix);
    if ((int)newpkt.size() < tags_offset) return false;
    if (memcmp(orig, newpkt.data(), tags_offset) != 0) return false;

    // 태그 영역 비교: orig 태그를 순회하며 new에 동일하게 존재하는지 확인
    // CSA IE(tag 37) 제외하고 나머지 태그 바이트열이 완전히 동일해야 함
    const uint8_t* op = orig + tags_offset;
    const uint8_t* op_end = orig + orig_end;
    const uint8_t* np = newpkt.data() + tags_offset;
    const uint8_t* np_end = newpkt.data() + newpkt.size();

    while (op + 2 <= op_end) {
        uint8_t num = op[0];
        uint8_t len = op[1];

        if (num == 37) {
            // 원본에 tag 37이 있으면 그냥 건너뜀 (새 패킷에서 교체됨)
            op += 2 + len;
            continue;
        }

        // new 패킷에서 tag 37은 건너뜀
        while (np + 2 <= np_end && np[0] == 37) {
            np += 2 + np[1];
        }

        // 바이트 단위 비교
        int chunk = 2 + (int)len;
        if (np + chunk > np_end) return false;
        if (memcmp(op, np, chunk) != 0) return false;

        op += chunk;
        np += chunk;
    }

    return true;
}

// ── main ─────────────────────────────────────────────────────────
int main() {
    const char* pcap_path = "../pcapfile/2026-05-05-CSA_selfcapture.pcapng";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(pcap_path, errbuf);
    if (!pcap) {
        fprintf(stderr, "[ERROR] pcap_open_offline failed: %s\n", errbuf);
        return 1;
    }
    printf("=== unit_test3: Malformed Check + Goal Result Condition ===\n");
    printf("pcap file: %s\n\n", pcap_path);

    struct pcap_pkthdr* hdr;
    const uint8_t* pkt;
    int beacon_count = 0;
    int processed    = 0;

    while (pcap_next_ex(pcap, &hdr, &pkt) == 1) {
        // ── Malformed 사전 필터 ───────────────────────────────────
        MalformResult mf = check_malformed(pkt, hdr->caplen);
        if (!mf.ok) {
            printf("[SKIP] Malformed packet (%s)\n", mf.reason);
            continue;
        }

        const BeaconHdr* beacon = (const BeaconHdr*)
            (pkt + ((RadioTapHdr*)pkt)->get_len());
        if (!beacon->is_beacon()) continue;

        beacon_count++;

        // ── CSA 패킷 조립 ─────────────────────────────────────────
        uint16_t rt_len = ((RadioTapHdr*)pkt)->get_len();
        size_t fcs_size = ((RadioTapHdr*)pkt)->get_fcs();
        Mac dummy;
        vector<uint8_t> new_pkt = build_csa_packet(pkt, hdr->caplen, dummy, true);

        printf("──────────────────────────────────────\n");
        printf("[Beacon #%d] orig=%d new=%d fcs=%zu\n",
               beacon_count, hdr->caplen, (int)new_pkt.size(), fcs_size);

        CHECK(!new_pkt.empty(), "T0: CSA packet built successfully");
        if (new_pkt.empty()) { processed++; continue; }

        // ── 새 패킷 malformed 체크 (T1~T5) ───────────────────────
        MalformResult new_mf = check_malformed(new_pkt.data(), (int)new_pkt.size());

        // T1: 새 패킷 전체 구조 정상 여부
        if (new_mf.ok) {
            printf("[PASS] T1: new packet is well-formed (not malformed)\n");
            pass_count++;
        } else {
            printf("[FAIL] T1: new packet is well-formed (not malformed)\n");
            printf("       └─ Step %d failed: %s\n", new_mf.step, new_mf.reason);
            fail_count++;
        }

        // T2: 새 패킷 Radiotap 길이 유효
        uint16_t new_rt_len = ((RadioTapHdr*)new_pkt.data())->get_len();
        CHECK(new_rt_len > 0 && new_rt_len < (int)new_pkt.size(),
              "T2: new packet radiotap len within bounds");

        // T3: 새 패킷 FCS = 0 (전송 패킷에는 FCS 없음)
        size_t new_fcs = ((RadioTapHdr*)new_pkt.data())->get_fcs();
        CHECK(new_fcs == 0,
              "T3: new packet has no FCS (FCS stripped)");

        // T4: 새 패킷 태그 영역 경계 초과 없음
        const BeaconHdr* new_beacon = (const BeaconHdr*)(new_pkt.data() + new_rt_len);
        const uint8_t* new_tags_s = (const uint8_t*)new_beacon->first_tag();
        const uint8_t* new_tags_e = new_pkt.data() + new_pkt.size();
        bool boundary_ok = true;
        const BeaconHdr::Tag* t = (const BeaconHdr::Tag*)new_tags_s;
        while ((const uint8_t*)t + 2 <= new_tags_e) {
            if ((const uint8_t*)t + 2 + t->length > new_tags_e) {
                boundary_ok = false; break;
            }
            t = t->next();
        }
        CHECK(boundary_ok, "T4: new packet all tag lengths within boundary");

        // T5: 새 패킷에 tag 37 존재하며 new_ch == 14
        bool has_csa = false;
        t = (const BeaconHdr::Tag*)new_tags_s;
        while ((const uint8_t*)t + 2 <= new_tags_e) {
            if (t->number == 37 && t->length == 3) {
                const uint8_t* val = (const uint8_t*)t + 2;
                has_csa = (val[1] == 14); // new_ch == 14
                break;
            }
            if ((const uint8_t*)t + 2 + t->length > new_tags_e) break;
            t = t->next();
        }
        CHECK(has_csa, "T5: new packet has tag 37 with new_ch=14");

        // ── T6: Goal.md Result 조건 ───────────────────────────────
        bool result_ok = check_result_condition(pkt, hdr->caplen, new_pkt);
        CHECK(result_ok,
              "T6: diff between orig and new is ONLY CSA IE + FCS removal");

        // ── T7: 크기 검증 ─────────────────────────────────────────
        int size_diff = (int)new_pkt.size() - (int)(hdr->caplen - fcs_size);
        printf("     size diff (new - orig_no_fcs): %+d bytes\n", size_diff);
        CHECK(size_diff >= 5,
              "T7: new packet >= FCS-stripped original + 5 bytes");

        // ── T8: 새 패킷에 FCS 없음 (원본과 마지막 4바이트 다름) ──
        if (fcs_size > 0) {
            bool no_fcs_in_new = (memcmp(new_pkt.data() + new_pkt.size() - 4,
                                         pkt + hdr->caplen - 4, 4) != 0);
            CHECK(no_fcs_in_new, "T8: new packet does not end with original FCS bytes");
        } else {
            printf("[PASS] T8: no FCS in original, skipped\n");
            pass_count++;
        }

        processed++;
        if (processed >= 5) break;
    }

    pcap_close(pcap);

    printf("\n══════════════════════════════════════\n");
    printf("총 Beacon %d개 처리\n", processed);
    printf("PASS: %d  FAIL: %d  WARN: %d\n", pass_count, fail_count, warn_count);
    if (beacon_count == 0)
        printf("[WARN] pcap 파일에서 Beacon 프레임을 찾지 못했습니다.\n");

    return (fail_count == 0) ? 0 : 1;
}
