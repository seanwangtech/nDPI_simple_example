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
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "libndpi-2.1.0/libndpi/ndpi_api.h"



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



struct ndpi_detection_module_struct * ndpi_module;
struct ndpi_flow_struct * ndpi_flow;

static void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int main(int argc,char* argv[]) {
    char * dev =argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handler;
    dev = pcap_lookupdev(errbuf);
    struct bpf_program pf;
    char filter_exp[] = "port 80";


    ndpi_module = ndpi_init_detection_module();
    if(ndpi_module == NULL) {
    	fprintf(stderr,"Couldn't initialize nDPI module\n");
    	exit(-2);
    }
    // enable all protocols
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_module, &all);
    ndpi_flow = malloc(SIZEOF_FLOW_STRUCT);
    if(ndpi_module == NULL) {
    	fprintf(stderr,"Couldn't initialize ndpi_flow\n");
    	exit(-2);
    }
    memset(ndpi_flow,0,SIZEOF_FLOW_STRUCT);



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

static void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
	 struct tm tm = *localtime(&h->ts.tv_sec);
	 printf("Jacked a packet at %d:%d:%d %dus with length of [%d]\n", tm.tm_hour,tm.tm_min,tm.tm_sec,(unsigned int) h->ts.tv_usec,h->caplen);

	 struct sniff_ip * IP = (struct sniff_ip *) (bytes+sizeof(struct sniff_ethernet));
	 printf("IP SRC:%s and DST:%s\n",inet_ntoa(IP->ip_src),inet_ntoa(IP->ip_dst));

	 int ipsize = h->len - sizeof(struct sniff_ethernet);
	 ndpi_protocol detected_protocol = ndpi_detection_process_packet(ndpi_module, ndpi_flow,
	 							  (unsigned char *)IP,
	 							  ipsize, time(NULL), NULL, NULL);

	 printf("Application Protocol type is:%d\n",detected_protocol.master_protocol);
	 printf("Application Protocol type is:%d\n",detected_protocol.app_protocol);

}
