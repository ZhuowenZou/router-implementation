#ifndef SR_ARP_HANDLER_H
#define SR_ARP_HANDLER_H

//Entry method for handling arp packet
void sr_arp_handler(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *curr_if);

//Handle request packet
void sr_arpreq_handler(struct sr_instance* sr, sr_ethernet_hdr_t *from_eth_hdr, sr_arp_hdr_t *from_arp_hdr, struct sr_if *curr_if);

//Handle reply packet
void sr_arprep_handler(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr, struct sr_if *curr_if);

#endif
