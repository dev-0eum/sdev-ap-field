#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

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

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		break; // temp break
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		// printf("%u bytes captured\n", header->caplen);
		pcap_close(pcap);
	}

	// My code
	struct pcap_pkthdr* header;
    const u_char* packet;
    int res;
    int packet_count = 0;

	printf("Packet Programming\n");
	pcap_t* handle = pcap_open_offline("../pcapfiles/http-filtered-packet.pcap", errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open pcap file: %s\n", errbuf);
		return -1;
	}
	printf("Packet Started\n");
	while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;

        printf("\n[Packet #%d] Length: %u bytes\n", ++packet_count, header->caplen);
        
        // --- 여기서부터 1바이트씩 읽고 출력하는 핵심 로직 ---
        for (u_int i = 0; i < header->caplen; i++) {
            // 1바이트씩 16진수로 출력
            printf("%02x ", packet[i]);

            // 가독성을 위해 16바이트마다 줄바꿈
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n------------------------------------------\n");
		if (packet_count >= 1) break; // 예시로 1개 패킷만 출력하도록 제한
    }


	pcap_close(handle);
}
