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

	struct EthHeader {
		u_char dest_mac[6];
		u_char src_mac[6];
		u_short type;
	} __attribute__((packed)); // 메모리 최적화 위한 패딩 제거

	struct IPv4Header {
		u_char ver_ihl;			// Version + Internet Header Length
		u_char  tos;            // Type of Service
		u_short tlen;           // Total Length
		u_short id;             // Identification
		u_short flags_off;       // Flags (3 bits) + Fragment Offset (13 bits)
		u_char  ttl;            // Time to Live
		u_char  proto;          // Protocol (TCP=6, UDP=17, ICMP=1 등)
		u_short checksum;            // Header Checksum
		u_char  src_ip[4];         // Source IP Address
		u_char  dest_ip[4];        // Destination IP Address
	} __attribute__((packed));

	struct TCPHeader {
		u_short src_port;        // Source Port
		u_short dest_port;       // Destination Port
		u_int seq_num;          // Sequence Number
		u_int ack_num;          // Acknowledgment Number
		u_char data_offset;     // Data Offset (4 bits) + Reserved (3 bits) + NS flag (1 bit)
		u_char flags;           // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN (8 bits)
		u_short window;         // Window Size
		u_short checksum;       // Checksum
		u_short urgent_ptr;     // Urgent Pointer
	} __attribute__((packed));

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
		printf("[Ethernet Header]\n");

		// 패킷 데이터를 담고 있는 버퍼가 있다고 가정 (unsigned char *packet)
		struct EthHeader *eth = (struct EthHeader *)packet;

		printf("Source MAC: ");
		for (int i = 0; i < 6; i++) {
			printf("%02x", eth->src_mac[i]);
			if (i < 5) printf(":");
		}

		printf("\nDestination MAC: ");
		for (int i = 0; i < 6; i++) {
			printf("%02x", eth->dest_mac[i]);
			if (i < 5) printf(":");
		}
		printf("\nEtherType: 0x%04x\n", ntohs(eth->type));

		// 타입 확인 (0x0800이면 IPv4, 0x0806이면 ARP 등)
		// 네트워크 바이트 순서(Big-endian)이므로 ntohs()로 변환 필요
		if (ntohs(eth->type) == 0x0800) {
			printf("이 패킷은 IPv4 패킷입니다.\n");
		} else if (ntohs(eth->type) == 0x0806){
			printf("이 패킷은 ARP 패킷입니다.\n");
		}

		printf("\n[IPv4 Header]\n");
		// Ethernet 헤더 바로 뒤에 IPv4 헤더가 위치하기에 offset 계산
		struct IPv4Header *ip = (struct IPv4Header *)(packet + sizeof(struct EthHeader));
		printf("Source IP: %d.%d.%d.%d\n", ip->src_ip[0], ip->src_ip[1], ip->src_ip[2], ip->src_ip[3]);
		printf("Destination IP: %d.%d.%d.%d\n", ip->dest_ip[0], ip->dest_ip[1], ip->dest_ip[2], ip->dest_ip[3]);
		printf("Protocol: %d\n", ip->proto); // TCP=6, UDP=17, ICMP=1 등

		// Wellknown Protocol only now
		if (ip->proto == 6) {
			printf("이 패킷은 TCP 패킷입니다.\n");
		} else if (ip->proto == 17) {
			printf("이 패킷은 UDP 패킷입니다.\n");
		} else if (ip->proto == 1) {
			printf("이 패킷은 ICMP 패킷입니다.\n");
		}

		printf("\n[TCP Header]\n");
		// IPv4 헤더 뒤에 TCP 헤더가 위치하기에 offset 계산
		struct TCPHeader *tcp = (struct TCPHeader *)(packet + sizeof(struct EthHeader) + sizeof(struct IPv4Header));
		printf("Source Port: %d\n", ntohs(tcp->src_port));
		printf("Destination Port: %d\n", ntohs(tcp->dest_port));

		


        printf("\n------------------------------------------\n");
		printf("%lu", sizeof(u_short));
		printf("%lu", sizeof(u_char));
		printf("%lu", sizeof(u_int8_t));
		printf("%lu", sizeof(u_int16_t));
		if (packet_count >= 1) break; // 예시로 1개 패킷만 출력하도록 제한
    }


	pcap_close(handle);
}
