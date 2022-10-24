#include<pcap.h>
#include<stdbool.h>
#include<stdio.h>
#include<stdlib.h>
#include<libnet.h>

void usage() {
    printf("systax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
} //use error message

int main(int argc, char *argv[]) {
    if(argc != 2)
    {
        usage();
        return -1;
    }// 인자 잘못 입력시
    char *interface = argv[1]; //interface를 인자로 준다.
    char errbuf[PCAP_ERRBUF_SIZE]; //error buffer

    pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    
    if(pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n",interface, errbuf);
        return -1;
    } // error

    while (true) {
        struct pcap_pkthdr *header;
        struct libnet_ethernet_hdr *ethernet;
        struct libnet_ipv4_hdr *ipv4;
        struct libnet_tcp_hdr *tcp;

        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n",res,pcap_geterr(pcap));
            break;
        } // error 처리
        //header->caplen은 byte 단위

        ethernet = (struct libnet_ethernet_hdr *)packet;
        ipv4 = (struct libnet_ipv4_hdr *) (packet+sizeof(*ethernet));
        tcp = (struct libnet_tcp_hdr *) (packet+sizeof(*ethernet)+sizeof(*ipv4));

        //print scr mac, dst mac
        printf("<Ethernet>\n");
        printf("Soruce MAC address : ");
        for(int i=0; i<ETHER_ADDR_LEN; i++) {
            if(i == ETHER_ADDR_LEN-1) {
                printf("%02X\n",ethernet->ether_shost[i]);
            }
            else {
                printf("%02X:",ethernet->ether_shost[i]);
            }
        }
        printf("Destination MAC address : ");
        for(int i=0; i<ETHER_ADDR_LEN; i++) {
            if(i == ETHER_ADDR_LEN-1) {
                printf("%02X\n",ethernet->ether_dhost[i]);
            }
            else {
                printf("%02X:",ethernet->ether_dhost[i]);
            }
        }

        // if(ethernet->ether_type == 0x0800) // if next is ip protocol
        printf("<IPv4>\n");
        u_int8_t ip1, ip2, ip3, ip4;
        uint32_t sip = ntohl(ipv4->ip_src.s_addr);
        uint32_t dip = ntohl(ipv4->ip_dst.s_addr);

        printf("Source IP address : ");

        ip1 = (sip & 0xff000000) >> 24;
        ip2 = (sip & 0x00ff0000) >> 16;
        ip3 = (sip & 0x0000ff00) >> 8;
        ip4 = (sip & 0x000000ff);
        printf("%d.%d.%d.%d\n",ip1,ip2,ip3,ip4);

        printf("Destination IP address : ");
        ip1 = (dip & 0xff000000) >> 24;
        ip2 = (dip & 0x00ff0000) >> 16;
        ip3 = (dip & 0x0000ff00) >> 8;
        ip4 = (dip & 0x000000ff);
        printf("%d.%d.%d.%d\n",ip1,ip2,ip3,ip4);

        printf("<TCP>\n");
        printf("Source PORT : ");
        printf("%d\n",ntohs(tcp->th_sport));
        printf("Destination PORT : ");
        printf("%d\n",ntohs(tcp->th_dport));

        uint32_t hsize = 14+(ipv4->ip_hl)*4+(tcp->th_off)*4;

        printf("Payload(Data) : ");
        for(int i=hsize; i<hsize+8 && i<header->caplen; i++) {
            printf("0x%02X ",packet[i]);
        }
        printf("\n\n");

    }

    pcap_close(pcap);
}