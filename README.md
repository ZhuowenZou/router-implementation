Name: Zhuowen Zou
PID: A14554030

This is the submission for CSE 123 Project 2.It is a simple router capable of handling ip packets, arp request/reply, and ICMP messages. I am not entering the espresso prize.

The description for each file is below.

 
sha1.h/c: Provided code for implementing SHA1 algorithm. Nothing is modified.

arp_handler.h/c: The source code for router to handling any arp-related packets, including arp request and reply. It delegates all arp cache manipulation to arp_cache.h/c

arp_cache.h/c: Implemnets handler for arp cache manipulation. It also loop through the requests list and handles time-out requests.

sr_dumper.h/c: dump pcap infos. 

sr_if.h/c: code related to interface. 

ip_handler.h/c: The source code for router to handling any ip-related forwarding through others' packets and taking its own packet.

sr_protocol.h/c: the protocols are define here.

sr_router.h/c: the code for router. Most of the work are delegated to arp_handler and ip_handler.

sr_rt.h/c: the code related to the routing table.

sr_utils.h/c: Utility functions for the router, including computing checksum, retrieving protocol header pointers, printing headers, router tbale lookup, and populating headers.  



 


 
