/*
 ============================================================================
 Name        : testPcap.c
 Author      : xiao Wang
 Version     :
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>




/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


static void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int main(int argc,char* argv[]) {
    char * dev =argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handler;
    dev = pcap_lookupdev(errbuf);
    struct bpf_program pf;
    char filter_exp[] = "port 80";

    if(dev == NULL){
            fprintf(stderr,"Couldn't find default device: %s\n", errbuf);
            return(2);
    }
    printf("Device:%s\n",dev);

    handler = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);

    if(!handler){
    	fprintf(stderr,"Couldn't open device: %s\n",dev);
    	return(2);
    }

    if(pcap_datalink(handler) != DLT_EN10MB){
    	fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
    	return(2);
    }

    if(pcap_compile(handler,&pf,filter_exp,0,PCAP_NETMASK_UNKNOWN)){
    	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handler));
    	return(2);
    }

	 if (pcap_setfilter(handler, &pf) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handler));
		 return(2);
	 }

	 pcap_loop(handler,-1,callback, NULL);

	 pcap_freecode(&pf);
	 pcap_close(handler);

	 return(0);
}
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

void print_IP(char* IP){

}
static void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
	 printf("Jacked a packet at %ds %dus with length of [%d]\n", h->ts.tv_sec, h->ts.tv_usec,h->len);
	 struct sniff_ethernet * ether = (struct sniff_ethernet*) bytes;
	 printf("Ether SRC:");
	 print_hex_ascii_line(ether->ether_shost,ETHER_ADDR_LEN,0);
	 printf("Ether SRC:");
	 print_hex_ascii_line(ether->ether_dhost,ETHER_ADDR_LEN,0);

	 struct sniff_ip * IP = (struct sniff_ip *) (bytes+sizeof(struct sniff_ethernet));
	 printf("IP SRC:%s\n",inet_ntoa(IP->ip_src));
	 printf("IP DST:%s\n",inet_ntoa(IP->ip_dst));
	 printf("IP length:%d\n",ntohs(IP->ip_len));

	 struct sniff_tcp*  tcp = (struct sniff_tcp*) (bytes+sizeof(struct sniff_ethernet)+sizeof(struct sniff_ip));

	 printf("TCP PORT SRC:%d\n", ntohs(tcp->th_sport));
	 printf("TCP PORT DST:%d\n", ntohs(tcp->th_dport));




}
