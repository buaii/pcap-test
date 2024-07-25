#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pcap-test.h"

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

void print_mac_address(const uint8_t *addr) {
	for (int i = 0; i < ETHER_ADDR_LEN; i++) {
		printf("%02x",addr[i]);
		if (i < ETHER_ADDR_LEN -1) printf(":");
	}
}

void print_ip_address(struct in_addr addr) {
	printf("%s", inet_ntoa(addr));

}

void packet_handler(u_int8_t *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    struct eth_header *eth_hdr = (struct eth_header *)packet;
    struct ip_header *ip_hdr = (struct ip_header *)(packet + sizeof(struct eth_header));
    struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + sizeof(struct eth_header) + (ip_hdr->ip_ver_ihl & 0x0F) * 4);
    
    printf("Ethernet Header\n");
    printf("   Source MAC: ");
    print_mac_address(eth_hdr->src_mac);
    printf("\n");
    printf("   Destination MAC: ");
    print_mac_address(eth_hdr->dest_mac);
    printf("\n");
    
    printf("IP Header\n");
    printf("   Source IP: ");
    print_ip_address(ip_hdr->ip_src);
    printf("\n");
    printf("   Destination IP: ");
    print_ip_address(ip_hdr->ip_dst);
    printf("\n");
    
    printf("TCP Header\n");
    printf("   Source Port: %d\n", ntohs(tcp_hdr->src_port));
    printf("   Destination Port: %d\n", ntohs(tcp_hdr->dst_port));
    
    printf("Payload (Hex): ");
    int ip_hdr_len = (ip_hdr->ip_ver_ihl & 0x0F) * 4;
    int tcp_hdr_len = (tcp_hdr->data_offset >> 4) * 4;
    int payload_len = header->caplen - (sizeof(struct eth_header) + ip_hdr_len + tcp_hdr_len);
    
    if (payload_len > 20) {
        payload_len = 20;
    }
    
    for (int i = 0; i < payload_len; i++) {
        printf("%02x ", packet[sizeof(struct eth_header) + ip_hdr_len + tcp_hdr_len + i]);
    }
    printf("\n\n");
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
		const uint8_t* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		packet_handler(NULL, header, packet);
	}

	pcap_close(pcap);
}
