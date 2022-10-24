#include<stdio.h>
#include<stdlib.h>
#include<libnet.h>
#include<pcap.h>
#include<unistd.h>
#include<fcntl.h>

void usage(); //error message with usage
uint32_t make_random();
int three_way_handshaking();

int main(int argc, char *argv[])
{
    if(argc != 4) //argument error
    {
        usage();
        return -1;
    }

    char *interface = argv[1]; //initialize interface
    char *dip = argv[2];
    char *dport = argv[3];
    char errbuf[PCAP_ERRBUF_SIZE]; //declare errbuf

    pcap_t *outhandle = pcap_open_live(interface, 0, 0, 0, errbuf);
    if(outhandle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s (%s)\n",interface, errbuf);
        return -1;
    }
    
    pcap_t *inhandle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(inhandle == nullptr)
    {
        fprintf(stderr, "pcap_open_live(%s) reuturn null - %s\n", interface, errbuf);
        return -1;
    } // check null ptr outhandle, inhandle
    
    three_way_handshaking(); //tr   ying connection

    while(true)
    {
        
    }





    return 0;
}

void usage()
{
    printf("syntax: ./client <my interface> <destination ip> <destination port>\n");
    printf("sample: ./client wlan0 1.1.1.1 1337\n");
    return;
}

uint32_t make_random()
{
    int fd;
    uint32_t ret;
    fd = open("/dev/urandom", O_RDONLY);

    if(fd == -1)
    {
        perror("urandom open error!\n");
        exit(-1);
    }

    read(fd, &ret, 4);

    close(fd);
    
    return ret;

}


int three_way_handshaking() // tcp connecton
{
    u_char *packet;
    uint32_t raw_syn = make_random();
    struct libnet_ethernet_hdr *ethernet;
    struct libnet_ipv4_hdr *ipv4;
    struct libnet_tcp_hdr *tcp;

    ethernet = (struct libnet_ethernet_hdr *) packet;
    ipv4 = (struct libnet_ipv4_hdr *) (packet + sizeof(*ethernet));
    tcp = (struct libnet_tcp_hdr *) (packet + sizeof(*ethernet) + sizeof(*ipv4));

    

}