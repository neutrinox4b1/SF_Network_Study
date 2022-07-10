#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include<libnet.h> //libnet을 이용하여 패킷 의미 찾기
#include <libnetfilter_queue/libnetfilter_queue.h>

int is_tcp = 0;

void dump(unsigned char* buf, int size) { // data와 ret를 확인하는 함수.패킷 데이터가 출력되는 것을 볼 수 있음. ip 헤더부터 시작
	struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *) (buf); //libent 사용
    struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *) (buf + sizeof(*ipv4));
    
    uint32_t sip = htonl(ipv4->ip_src.s_addr);
    uint32_t dip = htonl(ipv4->ip_dst.s_addr);

    uint8_t ip1, ip2, ip3, ip4;
	printf("===========================\n");
    printf("Source IP: ");
    ip1 = (sip & 0xff000000) >> 24;
    ip2 = (sip & 0x00ff0000) >> 16;
    ip3 = (sip & 0x0000ff00) >> 8;
    ip4 = (sip & 0x000000ff);
    printf("%d.%d.%d.%d\n",ip1, ip2, ip3, ip4);

    printf("Destination IP: ");
    ip1 = (dip & 0xff000000) >> 24;
    ip2 = (dip & 0x00ff0000) >> 16;
    ip3 = (dip & 0x0000ff00) >> 8;
    ip4 = (dip & 0x000000ff);
    printf("%d.%d.%d.%d\n",ip1, ip2, ip3, ip4);

    if(ipv4->ip_p == 0x06)
    {
        printf("tcp\n");
        is_tcp = 1;
        
        printf("Source Port: ");
        printf("%d\n",ntohs(tcp->th_sport));
        printf("Destination Port: ");
        printf("%d\n",ntohs(tcp->th_dport));
    }
	printf("===========================\n");
	/*
    int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}*/
	printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb) //패킷 정보를print 하는 함수
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		// printf("hw_protocol=0x%04x hook=%u id=%u ",
			// ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		// printf("hw_src_addr=");
		// for (i = 0; i < hlen-1; i++)
			// printf("%02x:", hwph->hw_addr[i]);
		// printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	// if (mark)
	// 	printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	// if (ifi)
	// 	printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	// if (ifi)
	// 	printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	// if (ifi)
	// 	printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	// if (ifi)
	// 	printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data); //중요한 함수, 패킷에 대한 시작 위치가 data에 들어가고 그 길이가 ret에 들어간다.
	if (ret >= 0)
	{
		dump(data, ret);
	}
		// printf("payload_len=%d\n", ret);// ret는 패킷의 길이
	// fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)// call back fucntion
{
    is_tcp = 0;
	u_int32_t id = print_pkt(nfa);// 패킷 정보를 춫력하고 id를 넣어서 
	printf("entering callback\n");
    if(is_tcp) // tcp : DROP
    {
		printf("DROP!\n\n");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    else
    {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

int main(int argc, char **argv) //main function
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) { //h error
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL); //패킷이 queue에 들어오면 callback함수(cb) 호출
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n"); //qh error
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) { //뭔가 패킷을 받으면 에러나는듯(큐 벗어나서?)
			printf("\n\npkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
