/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include <time.h>

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) {
    /* REQUIRES */
    assert(sr);

    memset(&(sr->hosts[0]),0,sizeof(Host) * MAX_HOSTS);
    memset(&(sr->cache[0]),0,sizeof(mPacket) * MAX_CACHE);
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);
    
    

    struct sr_ethernet_hdr* ethr_hdr;

    ethr_hdr = get_ethernet_hdr(packet);

    switch (ntohs(ethr_hdr->ether_type)) {
        case ETHERTYPE_IP:
            assert(ethr_hdr);
            struct ip* ip_hdr;
            ip_hdr = get_ip_hdr(packet);
            sr_cache_host(sr,ip_hdr,interface);
            struct sr_if * iface = sr->if_list;
            while (iface) {
            	if (ip_hdr->ip_dst.s_addr == iface->ip) break;
            	iface = iface->next;
            }
            if (iface) {/*(ip_hdr->ip_dst.s_addr == sr_get_interface(sr, interface)->ip) {*/
                printf("RECIEVED IP PACKET TO ETHERNET INTERFACE (no routing required)\n");
                if (ip_hdr->ip_p == IPPROTO_ICMP && ((struct sr_icmphdr *)(packet + sizeof(struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4))->icmp_type == ICMP_TYPE_ECHO_REQUEST) {
		            struct sr_icmphdr* icmphdr = get_icmp_hdr(packet, ip_hdr);
		            sr_handle_icmp_packet(sr, len, interface, icmphdr, packet, ip_hdr, (struct sr_ethernet_hdr *) packet);
                } else {
                	send_icmp_message(sr, len, interface, packet, ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_DEST_PORT_UNREACHABLE);
                }
            } else {
            	if (ip_hdr->ip_ttl > 1) {
                	sr_route_packet(sr,packet,len,interface);
            	} else {
            		send_icmp_message(sr, len, interface, packet, ICMP_TYPE_TIME_EXCEEDED, 0);
            	}
            }
            
            break;
        case ETHERTYPE_ARP:
            sr_handle_arp_packet(sr, len, interface, packet);
            break;
    }

	
}

void sr_handle_icmp_packet(struct sr_instance* sr, unsigned int len, char* interface, struct sr_icmphdr* icmphdr, uint8_t* packet, struct ip* ip_hdr, struct sr_ethernet_hdr* ethr_hdr) {
    if (icmphdr->icmp_type == ICMP_TYPE_ECHO_REQUEST) { /*echo request*/
        printf("Recieved echo request from %s to ", inet_ntoa(ip_hdr->ip_src));
        printf("%s.\n", inet_ntoa(ip_hdr->ip_dst));
        if (1) { /*(iface->ip)==((ip_hdr->ip_dst.s_addr))) { echo request to router*/
            int i;
            int tmp;
            for (i = 0; i < ETHER_ADDR_LEN; i++) {
                tmp = ethr_hdr->ether_dhost[i];
                ethr_hdr->ether_dhost[i] = ethr_hdr->ether_shost[i];
                ethr_hdr->ether_shost[i] = tmp;
            }
            ethr_hdr->ether_type = htons(ETHERTYPE_IP);
            in_addr_t* dest = malloc(sizeof (in_addr_t));
            *dest = (ip_hdr->ip_src.s_addr);
            ip_hdr->ip_src.s_addr = (ip_hdr->ip_dst.s_addr);
            ip_hdr->ip_dst.s_addr = *dest;
            free(dest);
            struct sr_icmphdr* icmphdr = get_icmp_hdr(packet, ip_hdr);
            icmphdr->icmp_type = ICMP_TYPE_ECHO_REPLY;
            setICMPchecksum(icmphdr, packet + sizeof (struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4, len - sizeof (struct sr_ethernet_hdr) - ip_hdr->ip_hl * 4);

            sr_send_packet(sr, packet, len, interface);
        } else { /*echo request to app server or other interface */

        }
    }
}

void sr_handle_udp_packet(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet) {
    struct ip* ip_hdr = get_ip_hdr(packet);


    if (ip_hdr->ip_dst.s_addr == sr_get_interface(sr, interface)->ip) {
        uint8_t * outpack = malloc(sizeof (struct sr_ethernet_hdr) + 64);
        struct sr_ethernet_hdr * out_eth_hdr = (struct sr_ethernet_hdr *) outpack;
        memcpy(out_eth_hdr, packet, sizeof (struct sr_ethernet_hdr));
        out_eth_hdr->ether_type = ntohs(ETHERTYPE_IP);
        int i;
        char tmp;
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            tmp = out_eth_hdr->ether_dhost[i];
            out_eth_hdr->ether_dhost[i] = out_eth_hdr->ether_shost[i];
            out_eth_hdr->ether_shost[i] = tmp;
        }
        struct ip* in_ip_hdr = get_ip_hdr(packet);
        struct in_addr src;
        src.s_addr = sr_get_interface(sr, interface)->ip;
        struct ip* tmp_ip = create_ip_hdr(0, 20, IPPROTO_ICMP, in_ip_hdr->ip_dst, in_ip_hdr->ip_src);
        struct ip* out_ip_hdr = (struct ip *) (outpack + sizeof (struct sr_ethernet_hdr));
        memcpy(outpack + sizeof (struct sr_ethernet_hdr), tmp_ip, 20);
        out_ip_hdr->ip_id = in_ip_hdr->ip_id;

        /* create and fill an icmp header */
        struct sr_icmphdr * out_icmp = (struct sr_icmphdr *) (outpack + sizeof (struct sr_ethernet_hdr) + 20);
        struct sr_icmphdr * tmpicmp = create_icmp_hdr(ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_DEST_PORT_UNREACHABLE, 0, 0);
        memcpy(out_icmp, tmpicmp, 8);
        free(tmpicmp);
        memcpy(((uint8_t *) out_icmp) + 8, in_ip_hdr, 28);
        out_ip_hdr->ip_len = ntohs(56);

        /* calculate checksums for DEST PORT UNREACHABLE message */
        setICMPchecksum(out_icmp, outpack + sizeof (struct sr_ethernet_hdr) + 20, 36);
        setIPchecksum(out_ip_hdr);
        
        /* send DEST PORT UNREACHABLE message*/
        sr_send_packet(sr, outpack, sizeof (struct sr_ethernet_hdr) + 56, interface);
    } else if (ip_hdr->ip_ttl < 2) {
        /* allocate space for new ICMP packet */
        uint8_t * outpack = malloc(sizeof (struct sr_ethernet_hdr) + 56);

        /* copy ethernet header and switch source and destination addresses */
        struct sr_ethernet_hdr * out_eth_hdr = (struct sr_ethernet_hdr *) outpack;
        memcpy(out_eth_hdr, packet, sizeof (struct sr_ethernet_hdr));
        out_eth_hdr->ether_type = ntohs(ETHERTYPE_IP);
        int i;
        char tmp;
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            tmp = out_eth_hdr->ether_dhost[i];
            out_eth_hdr->ether_dhost[i] = out_eth_hdr->ether_shost[i];
            out_eth_hdr->ether_shost[i] = tmp;
        }


        /* copy over ip header */
        struct ip* in_ip_hdr = ip_hdr;
        struct ip* tmp_ip = create_ip_hdr(0, 255, IPPROTO_ICMP, in_ip_hdr->ip_dst, in_ip_hdr->ip_src);
        struct ip* out_ip_hdr = (struct ip *) (outpack + sizeof (struct sr_ethernet_hdr));
        memcpy(outpack + sizeof (struct sr_ethernet_hdr), tmp_ip, 20);


        /* create and fill an icmp header */
        struct sr_icmphdr * out_icmp = (struct sr_icmphdr *) (outpack + sizeof (struct sr_ethernet_hdr) + 20);
        struct sr_icmphdr * tmpicmp = create_icmp_hdr(ICMP_TYPE_TIME_EXCEEDED, 0, 0, 0);
        memcpy(out_icmp, tmpicmp, 8);
        free(tmpicmp);
        memcpy(((uint8_t *) out_icmp) + 8, in_ip_hdr, 28);
        out_ip_hdr->ip_len = ntohs(56);


        /* calculate checksums for TIME EXCEEDED message */
        setICMPchecksum(out_icmp, outpack + sizeof (struct sr_ethernet_hdr) + 20, 36);
        setIPchecksum(out_ip_hdr);

        /* send TIME EXCEEDED message */
        sr_send_packet(sr, outpack, sizeof (struct sr_ethernet_hdr) + 56, interface);
    }
}

void send_icmp_message(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet, uint8_t type, uint8_t code) {
	uint8_t * outpack = malloc(sizeof (struct sr_ethernet_hdr) + 64);
    struct sr_ethernet_hdr * out_eth_hdr = (struct sr_ethernet_hdr *) outpack;
    memcpy(out_eth_hdr, packet, sizeof (struct sr_ethernet_hdr));
    out_eth_hdr->ether_type = ntohs(ETHERTYPE_IP);
    int i;
    char tmp;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        tmp = out_eth_hdr->ether_dhost[i];
        out_eth_hdr->ether_dhost[i] = out_eth_hdr->ether_shost[i];
        out_eth_hdr->ether_shost[i] = tmp;
    }
    struct ip* in_ip_hdr = get_ip_hdr(packet);
    struct in_addr src;
    src.s_addr = sr_get_interface(sr, interface)->ip;
    struct ip* tmp_ip = create_ip_hdr(0, 20, IPPROTO_ICMP, in_ip_hdr->ip_dst, in_ip_hdr->ip_src);
    struct ip* out_ip_hdr = (struct ip *) (outpack + sizeof (struct sr_ethernet_hdr));
    memcpy(outpack + sizeof (struct sr_ethernet_hdr), tmp_ip, 20);
    out_ip_hdr->ip_id = in_ip_hdr->ip_id;

    /* create and fill an icmp header */
    struct sr_icmphdr * out_icmp = (struct sr_icmphdr *) (outpack + sizeof (struct sr_ethernet_hdr) + 20);
    struct sr_icmphdr * tmpicmp = create_icmp_hdr(type, code, 0, 0);
    memcpy(out_icmp, tmpicmp, 8);
    free(tmpicmp);
    memcpy(((uint8_t *) out_icmp) + 8, in_ip_hdr, in_ip_hdr->ip_hl * 4 + 8);
    out_ip_hdr->ip_len = ntohs(28 + in_ip_hdr->ip_hl * 4 + 8);

    /* calculate checksums for message */
    setICMPchecksum(out_icmp, outpack + sizeof (struct sr_ethernet_hdr) + 20, 16 + in_ip_hdr->ip_hl * 4);
    setIPchecksum(out_ip_hdr);
    
    /* send message*/
    sr_send_packet(sr, outpack, sizeof (struct sr_ethernet_hdr) + 36 + in_ip_hdr->ip_hl * 4, interface);
    free(outpack);
    
    free(tmp_ip);
}

void sr_handle_arp_packet(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet) {
    struct sr_ethernet_hdr* ethr_hd = (struct sr_ethernet_hdr *) packet;
    struct sr_arphdr* arp_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

    if (arp_hdr->ar_op == ntohs(ARP_REQUEST)) {
        struct sr_if * iface = sr->if_list;
        while (iface) {
        	if (iface->ip == arp_hdr->ar_tip) break;
        	iface = iface->next;
        }
        int j;
        for (j = 0; j < MAX_HOSTS; j++) {
            if (sr->hosts[j].ip == arp_hdr->ar_tip &&  sr->hosts[j].iface && strcmp((char *)ethr_hd->ether_dhost, (char *)sr->hosts[j].iface->addr)) {
                break;
            }
        }
        if (iface || j < MAX_HOSTS) {
            struct sr_arphdr* arp_reply = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

            memcpy(ethr_hd->ether_dhost, ethr_hd->ether_shost, sizeof (ethr_hd->ether_dhost));
            memcpy(ethr_hd->ether_shost, sr->if_list->addr, sizeof (ethr_hd->ether_shost));
            ethr_hd->ether_type = htons(ETHERTYPE_ARP);

            arp_reply->ar_hrd = htons(ARPHDR_ETHER);
            arp_reply->ar_pro = htons(ETHERTYPE_IP);
            arp_reply->ar_hln = 06;
            arp_reply->ar_pln = 04;
            arp_reply->ar_op = htons(ARP_REPLY);
            memcpy(arp_reply->ar_sha, sr_get_interface(sr,interface)->addr, sizeof (ethr_hd->ether_dhost));

            memcpy(arp_reply->ar_tha, ethr_hd->ether_shost, sizeof (ethr_hd->ether_shost));
            uint32_t tmp = arp_reply->ar_tip;
            arp_reply->ar_tip = arp_reply->ar_sip;
            arp_reply->ar_sip = tmp;
            

            printf("--->Sending ARP REPLY!!\n");
            sr_send_packet(sr, packet, len, interface);
        }
    } else if (arp_hdr->ar_op == ntohs(ARP_REPLY)) {
    	printf("got ARP reply\n");
    	uint32_t naddr = arp_hdr->ar_sip;
    	int i;
    	int j;
    	for (i = 0; i < MAX_HOSTS; i++) {
    		if (sr->hosts[i].ip == naddr) {
    			for (j = 0; j < ETHER_ADDR_LEN; j++) {
    				sr->hosts[i].daddr[j] = arp_hdr->ar_sha[j];
    			}
    			sr->hosts[i].age = time(0);
    			sr->hosts[i].queue = 0;
    			sr->hosts[i].iface = sr_get_interface(sr,interface);
    			break;
    		} 
    	}
    	if (i < MAX_HOSTS) {
    		for (j = 0; j < MAX_CACHE; j++) {
	    		if (sr->cache[j].len > 0 && sr->cache[j].ip == naddr) {
	    			sr_route_packet(sr,sr->cache[j].packet,sr->cache[j].len,"");
	    			sr->cache[j].len = 0;
	    			free(sr->cache[j].packet);
	    		}
	    	}
    	}
    }
}

struct sr_ethernet_hdr *get_ethernet_hdr(uint8_t *packet) {
    return (struct sr_ethernet_hdr *) packet;
}

struct ip *get_ip_hdr(uint8_t *packet) {
    return (struct ip *) (packet + sizeof (struct sr_ethernet_hdr));
}

struct sr_icmphdr *get_icmp_hdr(uint8_t *packet, struct ip* ip_hdr) {
    return (struct sr_icmphdr *) (packet + sizeof (struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4);
}

struct sr_ethernet_hdr* create_ether_hdr(uint8_t dest[ETHER_ADDR_LEN], uint8_t src[ETHER_ADDR_LEN], uint16_t type) {
    struct sr_ethernet_hdr* returnable = malloc(sizeof (struct sr_ethernet_hdr));
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        returnable->ether_dhost[i] = dest[i];
        returnable->ether_shost[i] = src[i];
    }
    returnable->ether_type = ntohs(type);
    return returnable;
}

struct ip* create_ip_hdr(uint8_t type, uint8_t ttl, uint8_t protocol, struct in_addr src, struct in_addr dest) {
    struct ip* ip_hdr = malloc(20);
    ip_hdr->ip_v = 4;
    ip_hdr->ip_ttl = ttl;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_p = protocol;
    ip_hdr->ip_src = src;
    ip_hdr->ip_dst = dest;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_tos = type;
    return ip_hdr;
}

struct sr_icmphdr* create_icmp_hdr(uint8_t type, uint8_t code, uint16_t id, uint16_t seq) {
    struct sr_icmphdr* icmp_hdr = malloc(sizeof (struct sr_icmphdr));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_id = id;
    icmp_hdr->icmp_seq = seq;

    uint16_t sum = 0;
    sum = ((type << 8)&0xFF00) + code;
    sum = sum + id + seq;

    return icmp_hdr;
}

void setICMPchecksum(struct sr_icmphdr* icmphdr, uint8_t * packet, int len) {
    uint32_t sum = 0;
    icmphdr->icmp_sum = 0;
    uint16_t* tmp = (uint16_t *) packet;

    int i;
    for (i = 0; i < len / 2; i++) {
        sum = sum + tmp[i];
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = sum + (sum >> 16);

    icmphdr->icmp_sum = ~sum;
}

void setIPchecksum(struct ip* ip_hdr) {
    uint32_t sum = 0;
    ip_hdr->ip_sum = 0;

    uint16_t* tmp = (uint16_t *) ip_hdr;

    int i;
    for (i = 0; i < ip_hdr->ip_hl * 2; i++) {
        sum = sum + tmp[i];
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = sum + (sum >> 16);

    ip_hdr->ip_sum = ~sum;
}

void send_arp_request(struct sr_instance * sr, uint32_t dst_ip, char* interface) {
    printf("sending arp request\n");
    uint8_t * packet = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));

    struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) packet;
    struct sr_arphdr * arp_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

    eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);
    eth_hdr->ether_dhost[0] = 255;
    eth_hdr->ether_dhost[1] = 255;
    eth_hdr->ether_dhost[2] = 255;
    eth_hdr->ether_dhost[3] = 255;
    eth_hdr->ether_dhost[4] = 255;
    eth_hdr->ether_dhost[5] = 255;

    arp_hdr->ar_hrd = ntohs(1);
    arp_hdr->ar_op = ntohs(ARP_REQUEST);
    arp_hdr->ar_pro = ntohs(ETHERTYPE_IP);
    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_tip = dst_ip;

    struct sr_if * iface = sr->if_list;
    while (iface) {
        if (strcmp(iface->name, interface)) {
	        int j;
	        for (j = 0; j < ETHER_ADDR_LEN; j++) {
	            arp_hdr->ar_sha[j] = iface->addr[j];
	            eth_hdr->ether_shost[j] = arp_hdr->ar_sha[j];
	        }
	        arp_hdr->ar_sip = iface->ip;
	        sr_send_packet(sr, packet, sizeof (struct sr_ethernet_hdr) + sizeof (struct sr_arphdr), iface->name);
        }
        iface = iface->next;
    }
    free(packet);
}

void free_old_cache(struct sr_instance * sr) {
	int i;
	for (i = 0; i < MAX_HOSTS; i++) {
		if (sr->hosts[i].iface && timediff(time(NULL),sr->hosts[i].age) > 14) {
			printf("erasing host record, %ld\n",timediff(time(NULL),sr->hosts[i].age));
			sr->hosts[i].iface = NULL;
			sr->hosts[i].queue = 0;
		}
	}
	int j;
	for (j = 0; j < MAX_CACHE; j++) {
		if (sr->cache[j].len && timediff(sr->cache[j].age,time(NULL)) > 5) {
			printf("erasing cached packet size %d, %ld\n", sr->cache[j].len, timediff(sr->cache[j].age,time(NULL)));
			sr->cache[j].len = 0;
			free(sr->cache[j].packet);
		}
	}
}

void sr_route_packet(struct sr_instance * sr, uint8_t * packet, int len, char* interface) {
	struct ip* ip_hdr = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));
	uint32_t dst_ip = ip_hdr->ip_dst.s_addr;
	
	int i;
	uint8_t to_cache = 1;
	for (i = 0; i < MAX_HOSTS; i ++) {
		if (sr->hosts[i].ip == dst_ip) {
			if (sr->hosts[i].queue == 0 && strcmp(sr->hosts[i].iface->name,interface)) {
				to_cache = 0;
			} else {
				send_arp_request(sr, dst_ip, interface);
				sr->hosts[i].queue += 1;
			}
            printf("host number %d\n",i);
			break;
		}
	}
	if (i < MAX_HOSTS) {
		if (to_cache == 0) {
			ip_hdr->ip_ttl -= 1;
			setIPchecksum(ip_hdr);
			struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) packet;
			int j;
			for (j = 0; j < ETHER_ADDR_LEN; j++) {
				eth_hdr->ether_dhost[j] = sr->hosts[i].daddr[j];
				eth_hdr->ether_shost[j] = sr->hosts[i].iface->addr[j];
			}
            printf("routing a packet\n");
			sr_send_packet(sr,packet,len,sr->hosts[i].iface->name);
		} else {
            printf("caching an old host packet\n");
			for (i = 0; i < MAX_CACHE; i++) {
				if (sr->cache[i].len == 0) {
					uint8_t * npacket = malloc(len + 1);
					memcpy(npacket,packet,len);
					sr->cache[i].packet = npacket;
					sr->cache[i].len = len;
					sr->cache[i].age = time(0);
					sr->cache[i].ip = dst_ip;
					break;
				}
			}
		}
	} else {
        int k;
        printf("caching a new host packet\n");
        for (k = 0; k < MAX_CACHE; k++) {
            if (sr->cache[k].len == 0) {
                uint8_t * npacket = malloc(len + 1);
                memcpy(npacket, packet, len);
                sr->cache[k].packet = npacket;
                sr->cache[k].len = len;
                sr->cache[k].age = time(0);
                sr->cache[k].ip = dst_ip;
                break;
            }
        }   
        printf("cached, trying to obtain host address\n");
        for (k = 0; k < MAX_HOSTS; k++) {
            printf("looking at host %d\n",k);
			if (sr->hosts[k].ip == 0) {
                printf("find empty at host %d\n",k);
				sr->hosts[k].ip = dst_ip;
				sr->hosts[k].queue = 1;
                printf("find going at host %d\n",k);
				send_arp_request(sr,dst_ip,interface);
                break;
			}
		}
	}
}

void sr_cache_host(struct sr_instance * sr, struct ip* ip_hdr, char * interface) {
    uint32_t ip = ip_hdr->ip_src.s_addr;
    struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) (((uint8_t *)ip_hdr) - sizeof(struct sr_ethernet_hdr));
    
    int i;
    for (i = 0; i < MAX_HOSTS; i++) {
        if (sr->hosts[i].ip == ip) {
            sr->hosts[i].iface = sr_get_interface(sr,interface);
            sr->hosts[i].queue = 0;
            sr->hosts[i].age = time(0);
            int j;
            for (j = 0; j < ETHER_ADDR_LEN; j++) {
                sr->hosts[i].daddr[j] = eth_hdr->ether_shost[j];
            }
            break;
        }
    }
    if (i == MAX_HOSTS) {
        for (i = 0; i < MAX_HOSTS; i++) {
            if (sr->hosts[i].ip == 0) {
                sr->hosts[i].ip = ip;
                sr->hosts[i].iface = sr_get_interface(sr,interface);
                sr->hosts[i].queue = 0;
                sr->hosts[i].age = time(0);
                int j;
                for (j = 0; j < ETHER_ADDR_LEN; j++) {
                    sr->hosts[i].daddr[j] = eth_hdr->ether_shost[j];
                }
                break;
            }
        }
    }
}

unsigned long int timediff(time_t t1, time_t t2) {
	if (t1 > t2) return t1 - t2;
	if (t2 > t1) return t2 - t1;
	return 0;
}
