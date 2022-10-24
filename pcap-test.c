#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>


void usage() {

    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");

}


int main(int argc, char* argv[]) {

    if (argc != 2) {
        usage();
        return -1;
    }
    char* interface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE]; //pcap에서 문제가 생기면 여기에

    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf); //인터페이스, 이만큼의 사이즈..

    if (pcap == NULL) { //pcap이 없으면
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        
        for(int i=0; i<header->caplen; i++) {
            printf("0x%02X ",packet[i]);
        }

        printf("%u bytes captured\n", header->caplen);
    }
    pcap_close(pcap);
}
