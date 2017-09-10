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

static void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
	 printf("Jacked a packet at %ds %dus with length of [%d]\n", h->ts.tv_sec, h->ts.tv_usec,h->len);
}
