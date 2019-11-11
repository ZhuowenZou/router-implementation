#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"

//TODO CHECK htons and ntohs again

uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += 4;
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

// Header getters
sr_ethernet_hdr_t *get_eth_hdr(uint8_t *packet){
	return (sr_ethernet_hdr_t *)packet;
}
sr_arp_hdr_t *get_arp_hdr(uint8_t *packet){
	return (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}
sr_ip_hdr_t *get_ip_hdr(uint8_t *packet){
	return (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}
sr_icmp_t11_hdr_t *get_icmp_hdr(uint8_t *packet){
	return (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

// Router Table Lookup
struct sr_if* sr_dst_if(struct sr_instance *sr, uint32_t dst){

	struct sr_rt* rt_iter = sr->routing_table;
	uint32_t masked = 0; //the after-mask
	while (rt_iter){
		mask = rt_iter->mask.s_addr & dst;
		if (masked == rt_iter->dest.s_addr)
			return sr_get_interface(sr, rt_iter->interface);
		rt_iter = rt_iter->next;
	}
	//not found
	return NULL;
}

// Populators: handle populating the headers and actually send them out via sr_send_packet
void sr_forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t* dst_mac, struct sr_if *out_if){

	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	memcpy(eth_hdr->ether_dhost, dst_mac, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum((void*)ip_hdr, sizeof(sr_ip_hdr_t));
	sr_send_packet(sr, packet, len, out_if->name);
}

void sr_icmp_echo(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint8_t* packet, int len, struct sr_if *curr_if){

	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	sr_icmp_t11_hdr_t *icmp_hdr = get_icmp_hdr(packet);
	struct sr_if *out_if = sr_dst_if(sr, ip_hdr->ip_src);

	//eth hdr
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);

	//ip hdr: going back
	ip_hdr->ip_dst = ip_hdr->ip_src;
	ip_hdr->ip_src = curr_if->ip;

	//icmp hdr
	icmp_hdr->icmp_type = icmp_type;
	icmp_hdr->icmp_code = icmp_code;
	icmp_hdr->sum = 0;
	icmp_hdr->sum =cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

	sr_send_packet(sr, packet, len, out_if->name);
}

void sr_send_icmp(struct sr_instance *sr, uint8_t *recv, uint8_t icmp_type, uint8_t icmp_code, uint8_t* packet, struct sr_if *curr_if){

	unsigned int pac_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
	uint8_t *packet = (uint8_t *)malloc(pac_len);
	memset(packet, 0, pac_len);

	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	sr_icmp_t11_hdr_t *icmp_hdr = get_icmp_hdr(packet);
	sr_ethernet_hdr_t *recv_eth_hdr = get_eth_hdr(recv);
	sr_ip_hdr_t *recv_ip_hdr = get_icmp_hdr(recv);

	struct sr_if *out_if = sr_dst_if(sr, curr_ip_hdr->ip_src);

	//eth hdr
	memcpy(eth_hdr->ether_dhost, recv_eth_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(erthertype_ip);

	//ip hdr: jesus this is gonna hurt TODO: what's IP ID
	ip_hdr->ip_hl = recv_ip_hdr->ip_hl;
	ip_hdr->ip_v = recv_ip_hdr->ip_v;
	ip_hdr->ip_tos = recv_ip_hdr->ip_tos;
	ip_hdr->ip_len = htons(pac_len - sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = htons(IP_DF);			/* fragment offset field */
	ip_hdr->ip_ttl = INIT_TTL;			/* time to live */
	ip_hdr->ip_p = ip_protocol_icmp;			/* protocol */
	ip_hdr->ip_dst = recv_ip_hdr->ip_src;
	ip_hdr->ip_src = curr_if->ip;
	ip_hdr->ip_sum = 0;			/* checksum */
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));			/* checksum */

	//icmp hdr
	icmp_hdr->icmp_type = icmp_type;
	icmp_hdr->icmp_code = icmp_code;
	memcpy(icmp_hdr->data, recv_ip_hdr, ICMP_DATA_SIZE);
	icmp_hdr->sum = 0;
	icmp_hdr->sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

	sr_send_packet(sr, packet, len, out_if->name);
}

void sr_send_arpreq(struct sr_instance *sr, uint32_t q_ip){

	unsigned int pac_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *packet = (uint8_t *)malloc(pac_len);
	memset(packet, 0, pac_len);

	struct sr_if *out_if =sr_dst_if(sr, q_ip);
	struct sr_ethernet_hdr *eth_hdr  = get_eth_hdr(packet);
	struct sr_arp_hdr *arp_hdr  = get_arp_hdr(packet);

	memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
	eth_hdr->ether_type =htons(ethertype_arp);

	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
	arp_hdr->ar_pro = htons(ethertype_ip);
	arp_hdr->ar_hln = ETHER_ARRD_LEN;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(arp_op_request);
	memcpy(arp_hdr->ar_sha, out_if->addr, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = out_if->ip;
	memset(arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN);
	arp_hdr->ar_tip = q_ip;

	sr_send_packet(sr, packet, pac_len, out_if->name);
}

void sr_send_arprep(struct sr_instance *sr, sr_ethernet_hdr_t *from_eth_hdr,
		sr_arp_hdr_t *from_arp_hdr, struct sr_if* curr_if) {

	unsigned int pac_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *packet = (uint8_t *)malloc(pac_len);
	memset(packet, 0, pac_len);

	struct sr_ethernet_hdr *eth_hdr  = get_eth_hdr(packet);
	struct sr_arp_hdr *arp_hdr  = get_arp_hdr(packet);

	memcpy(eth_hdr->ether_dhost, from_eth_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, curr_if->addr, ETHER_ADDR_LEN);
	eth_hdr->ether_type =htons(ethertype_arp);

	arp_hdr->ar_hrd = from_arp_hdr->ar_hrd;
	arp_hdr->ar_pro = from_arp_hdr->ar_pro;
	arp_hdr->ar_hln = from_arp_hdr->ar_hln;
	arp_hdr->ar_pln = from_arp_hdr->ar_pln;
	arp_hdr->ar_op = htons(arp_op_reply);
	memcpy(arp_hdr->ar_sha, curr_if->addr, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = curr_if->ip;
	memcpy(arp_hdr->ar_tha, from_arp_hdr->sha, ETHER_ADDR_LEN);
	arp_hdr->ar_tip = from_arp_hdr->ar_sip;

	sr_send_packet(sr, packet, pac_len, curr_if->name);
}


// Sanity checks
uint8_t ip_check_size(unsigned int len){
	return (len >= (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
}
uint8_t ip_check_sum(sr_ip_hdr_t *ip_hdr){

	uint8_t valid = 0;
	uint16_t temp = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) == temp){
		valid = 1;
	}
	ip_hdr->ip_sum = temp;
	return valid;
}

uint8_t icmp_check_size(unsigned int len){
	return (len >= (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t)));
}

uint8_t icmp_check_sum(sr_icmp_t11_hdr_t *icmp_hdr){

	uint8_t valid = 0;
	uint16_t temp = icmp_hdr->icmp_sum;
	icmp_hdr->icmp_sum = 0;
	if (cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t)) == temp){
		valid = 1;
	}
	icmp_hdr->icmp_sum = temp;
	return valid;
}

uint8_t arp_check_size(unsigned int len){
	return (len >= (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)));
}




