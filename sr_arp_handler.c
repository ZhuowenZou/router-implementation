#include <stdlib.h>

#include "sr_router.h"
#include "sr_utils.h"
#include "sr_arp_handler.h"

//Entry method for handling arp packet
void sr_arp_handler(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *curr_if){

	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);

	if (!arp_check_size(len)){
		Debug("ARP min size check FAILED. Packet Dropped.\n");
		return;
	}

	switch (ntohs(arp_hdr->ar_op)){
		case arp_op_request:
			Debug("Detect ARP Request.\n");
			sr_arpreq_handler(sr, eth_hdr, arp_hdr, curr_if);
			break;
		case arp_op_request:
			Debug("Detect ARP Reply.\n");
			sr_arprep_handler(sr, arp_hdr, curr_if);
			break;
		default
			Debug("GET ARP non-req-nor-rep type, dropping.\n");
	}
}

//Handle request packet
//TODO when should I send reply???
void sr_arpreq_handler(struct sr_instance* sr, sr_ethernet_hdr_t *from_eth_hdr, sr_arp_hdr_t *from_arp_hdr, struct sr_if *curr_if){

	sr_arpcache_insert(&(sr->cache), from_arp_hdr->ar_sha, from_arp_hdr->ar_sip);
	sr_send_arprep(sr, from_eth_hdr, req_arp_hdr, curr_if);

	// hit
	if (from_arp_hdr->ar_tip == curr_if->ip){
		Debug("Received ARP Request at interface $s, replying", curr_if->name);
	}
}

//Handle reply packet
void sr_arprep_handler(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr, struct sr_if *curr_if){

	// hit, caching results
	if (srp_hdr->ar_tip == curr_if->ip){
		Debug("Received ARP Reply at interface $s./n", curr_if->name);

		pthread_mutex_lock(&(sr->cache.lock));

		struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
		if (req){
			struct sr_packet *packet = req->packets;
			while (packet){
				Debug("Forwarding ARP-stalled packet\n");
				sr_forward_packet(sr, packet->buf, packet->len, arp_hdr->ar_sha, curr_if);
				packet = packet->next;
			}
			sr_arpreq_destroy(&(sr->cache), req);
		}
		pthread_mutex_unlock(&(sr->cache.lock));
	}
}
