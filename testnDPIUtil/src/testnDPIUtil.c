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
#include "ndpi_util.h"


// flow preferences
ndpi_workflow_prefs_t flow_prefs = {
		.decode_tunnels=0,
		.quiet_mode=1,
		.num_roots=NUM_ROOTS,
		.max_ndpi_flows = MAX_NDPI_FLOWS
};

struct ndpi_workflow * workflow;
static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
static void on_protocol_discovered(struct ndpi_workflow * workflow, struct ndpi_flow_info * flow, void * udata);


int main(int argc, char* argv[]) {
	char * dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handler;
	dev = pcap_lookupdev(errbuf);
	//Initialize pcap to capture packet.
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return (2);
	}
	printf("Using network Interface:%s\n", dev);

	handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (!handler) {
		fprintf(stderr, "Couldn't open device: %s\n", dev);
		return (2);
	}

	//initialize ndpi_util workflow
	workflow = ndpi_workflow_init(&flow_prefs, handler);

	ndpi_workflow_set_flow_detected_callback(workflow, on_protocol_discovered,
			NULL);

	// enable all protocols
	NDPI_PROTOCOL_BITMASK all;
	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &all);

	// clear memory for results
	memset(workflow->stats.protocol_counter, 0,
			sizeof(workflow->stats.protocol_counter));
	memset(workflow->stats.protocol_counter_bytes, 0,
			sizeof(workflow->stats.protocol_counter_bytes));
	memset(workflow->stats.protocol_flows, 0,
			sizeof(workflow->stats.protocol_flows));

	//start capturing
	pcap_loop(handler,-1,pcap_callback, NULL);

	ndpi_workflow_free( workflow);
	pcap_close(handler);

	return (0);
}

static void pcap_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){

	ndpi_workflow_process_packet(workflow, header, packet);

	/* Idle flows cleanup algorithm can be written here. This is just for demo purpose, thus we ignored the cleanup algorithm*/

}


static int num_flows = 0;
static void printFlow(struct ndpi_flow_info *flow) {
	FILE *out = stdout;
	fprintf(out, "\t%u", ++num_flows);

	if (flow->vlan_id > 0)
		fprintf(out, "[VLAN: %u]", flow->vlan_id);

	if (flow->detected_protocol.master_protocol) {
		char buf[64];

		fprintf(out, "[proto: %u.%u/%s]",
				flow->detected_protocol.master_protocol,
				flow->detected_protocol.app_protocol,
				ndpi_protocol2name(workflow->ndpi_struct,
						flow->detected_protocol, buf, sizeof(buf)));
	} else
		fprintf(out, "[proto: %u/%s]", flow->detected_protocol.app_protocol,
				ndpi_get_proto_name(workflow->ndpi_struct,
						flow->detected_protocol.app_protocol));

	if (flow->host_server_name[0] != '\0')
		fprintf(out, "[Host: %s]", flow->host_server_name);
	if (flow->info[0] != '\0')
		fprintf(out, "[%s]", flow->info);

	if (flow->ssh_ssl.client_info[0] != '\0')
		fprintf(out, "[client: %s]", flow->ssh_ssl.client_info);
	if (flow->ssh_ssl.server_info[0] != '\0')
		fprintf(out, "[server: %s]", flow->ssh_ssl.server_info);
	if (flow->bittorent_hash[0] != '\0')
		fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);

	fprintf(out, "\n");
}
static void on_protocol_discovered(struct ndpi_workflow * workflow, struct ndpi_flow_info * flow, void * udata) {
	printFlow( flow);
}
