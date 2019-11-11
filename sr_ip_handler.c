#include <stdlib.h>

#include "sr_router.h"
#include "sr_utils.h"
#include "sr_ip_handler.h"


//IP sanity check (min size + checksum)
uint8_t ip_check_sanity(sr_ip_hdr_t *ip_hdr, unsigned int len) {
	uint8_t valid = 1;
	// Check min size limit
	if (!ip_check_size(len)){
		Debug("IP min size check FAILED. Packet Dropped.\n");
		valid = 0;
	}
	if (!ip_check_sum(ip_hdr)){
		Debug("IP checksum FAILED. Packet Dropped.\n");
		valid = 0;
	}
	return valid;
}

//ICMP sanity check (min size + checksum)
uint8_t icmp_check_sanity(sr_ip_hdr_t *ip_hdr, sr_icmp_t11_hdr_t *icmp_hdr, unsigned int len) {
	uint8_t valid = 1;
	// Check min size limit
	if (!icmp_check_size(len)){
		Debug("ICMP min size check FAILED. Packet Dropped.\n");
		valid = 0;
	}
	if (!icmp_check_sum(ip_hdr->ip_len, icmp_hdr)){
		Debug("ICMP checksum FAILED. Packet Dropped.\n");
		valid = 0;
	}
	return valid;
}

void sr_ip_handler(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* curr_if){

	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);

	//Sanity check
	if (!ip_check_sanity(ip_hdr, len))
		return;

	// Check if it's my packet
	struct sr_if *if_iter = sr->if_list;
	while (if_iter){
		if (if_iter->ip == ip_hdr->ip_dst){
			Debug("Receive my packet at interface %s.\n", if_iter->name);
			sr_my_ip_handler(sr, packet, len, if_iter);
			return;
		}
		if_iter = if_iter->next;
	}

	// Not my packets
	Debug("Received not-my packet.\n");

	ip_hdr->ip_ttl--;

	// TTL expire, reply ICMP
	if (ip_hdr->ip_ttl == 0){
		Debug("IP Packet TTL expired, sending ICMP.\n");
		sr_send_icmp(sr, packet, icmp_type_time_exceed, icmp_code_ttl_expired, curr_if);
		return;
	}

	// Forward packet
	sr_forward_ip(sr, packet, len, curr_if);


}

void sr_my_ip_handler(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *curr_if){

	sr_ip_hdr_t* ip_hdr = get_ip_hdr(packet);
	uint8_t ip_protocol = ip_hdr->ip_p;

	switch (ip_protocol){
		// Hanlde icmp
		case ip_protocol_icmp:
			sr_icmp_t11_hdr_t* icmp_hdr = get_icmp_hdr(packet);

			// Check sanity
			if (!icmp_check_sanity(ip_hdr, icmp_hdr, len))
				return;

			//Handle echo
			if (icmp_hdr->icmp_type == icmp_type_echo_req && icmp_hdr->icmp_code == icmp_code_empty){
				sr_icmp_echo(sr, icmp_type_echo_rep, icmp_code_empty, packet, len, curr_if);
			}
			break;
		// KILL TCP/UDP and send ICMP
		case ip_protocol_tcp:
		case ip_protocol_udp:
			Debug("Why is there a TCP/UDP here? Dropped and replying ICMP.\n");
			sr_send_icmp(sr, packet, icmp_type_dest_unreach, icmp_code_port_unreach, curr_if);
			break;
		default:
			Debug("Protocol %d unknown.\n", ip_protocol);
	}
}

void sr_forward_ip(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *curr_if){

	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	struct sr_if *out_if = sr_dst_if(sr, ip_hdr->ip_dst);

	if (out_if){
		struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
		if (entry){
			Debug("Forwarding packet with ARP table\n");
			sr_forward_packet(sr, packet, len, entry->mac, out_if);
			free(entry);
		}
		else{
			Debug("No entry in ARP table. Sending ARP request\n");
			struct sr_arpreq * request = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, out_if->name);
			sr_arpcache_handlereq(sr, request);
		}
	}
	else {
		Debug("Packet's ip_dst's interface not found on routing table.\n");
		sr_send_icmp(sr, packet, icmp_type_dest_unreach, icmp_code_net_unreach, curr_if);
	}
}




