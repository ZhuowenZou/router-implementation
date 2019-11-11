/*
 *  Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef SR_UTILS_H
#define SR_UTILS_H

uint16_t cksum(const void *_data, int len);

uint16_t ethertype(uint8_t *buf);
uint8_t ip_protocol(uint8_t *buf);

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);

//header - getters
sr_ethernet_hdr_t *get_eth_hdr(uint8_t *packet);
sr_arp_hdr_t *get_arp_hdr(uint8_t *packet);
sr_ip_hdr_t *get_ip_hdr(uint8_t *packet);
sr_icmp_t11_hdr_t *get_icmp_hdr(uint8_t *packet);

struct sr_if* sr_dst_if(struct sr_instance *sr, uint32_t dst);
void sr_forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t* dst_mac, struct sr_if *out_if);
void sr_icmp_echo(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint8_t* packet, int len, struct sr_if *curr_if);
void sr_send_icmp(struct sr_instance *sr, uint8_t *recv, uint8_t icmp_type, uint8_t icmp_code, uint8_t* packet, struct sr_if *curr_if);
void sr_send_arpreq(struct sr_instance *sr, uint32_t q_ip);
void sr_send_arprep(struct sr_instance *sr, sr_ethernet_hdr_t *from_eth_hdr,
		sr_arp_hdr_t *from_srp_hdr, struct sr_if* curr_if);
uint8_t ip_check_size(unsigned int len);
uint8_t ip_check_sum(sr_ip_hdr_t *ip_hdr);
uint8_t icmp_check_size(unsigned int len);
uint8_t icmp_check_sum(sr_ip_hdr_t *icmp_hdr);
uint8_t arp_check_size(unsigned int len);

#endif /* -- SR_UTILS_H -- */
