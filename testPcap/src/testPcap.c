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
int main(int argc,char* argv[]) {
    char * dev =argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
            fprintf(stderr,"Couldn't find default device: %s\n", errbuf);
            return(2);
    }
    printf("Device:%s\n",dev);
    return(0);
}
