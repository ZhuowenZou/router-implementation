#ifndef SR_IP_HANDLER_H
#define SR_IP_HANDLER_H

//Entry method for handling ip packet
void sr_ip_handler(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *curr_if);

//Handle packet destined for the router
void sr_my_ip_handler(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *curr_if);

//Forward packet destined for the others
void sr_forward_ip(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *curr_if);

#endif
