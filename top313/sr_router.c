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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"


#ifndef WORD_BYTELEN
#define WORD_BYTELEN 4
#endif

#ifndef BCAST_IP
#define BCAST_IP 0xff
#endif

#ifndef TCP_NUM
#define TCP_NUM 6
#endif

#ifndef UDP_NUM
#define UDP_NUM 17
#endif

#ifndef ARP_MAXREQS
#define ARP_MAXREQS 5
#endif

#ifndef ARPCACHE_TIMEOUT
#define ARPCACHE_TIMEOUT 15
#endif

#ifndef ICMPHDR_LEN
#define ICMPHDR_LEN 8
#endif

/* for ICMP unreach only */
#ifndef ICMPDAT_LEN
#define ICMPDAT_LEN 8
#endif

#ifndef ICMPHDR_16BITLEN
#define ICMPHDR_16BITLEN 4
#endif

#ifndef ICMP_ECHOREQ
#define ICMP_ECHOREQ 8
#endif

#ifndef ICMP_TTL
#define ICMP_TTL 11
#endif

#ifndef ICMP_UNREACH
#define ICMP_UNREACH 3
#endif

#ifndef ICMP_HOST_UNREACH
#define ICMP_HOST_UNREACH 1
#endif

#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif


/* For some reason, using ntohl on the (destination) IP address of a received packet
 * converts it into the opposite byte order from the one interface IPs are stored in
 * - I guess those are stored in network order?
 */

/* even though ICMP messages aren't described as having "headers" */
struct icmp_hdr {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_sum;
    uint32_t icmp_unused;
} __attribute__ ((packed));

struct icmp_echoreply_hdr {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_sum;
    uint16_t icmp_id;
    uint16_t icmp_seqnum;
} __attribute__ ((packed));

/* arpc_ip in NETWORK byte order */
struct arpc_entry {	// ARP cache entry
    uint32_t arpc_ip;
    unsigned char arpc_mac[ETHER_ADDR_LEN];
    time_t arpc_timeout;
    struct arpc_entry *prev;
    struct arpc_entry *next;
};

/* stuff in packet in NETWORK byte order */
struct queued_packet {
    uint8_t *packet;
    unsigned len;
    char icmp_ifname[sr_IFACE_NAMELEN];	// to use if/when sending host unreachable ICMP to source
    struct queued_packet *next;
};

struct packetq {
    struct queued_packet *first;
    struct queued_packet *last;	// REMOVE?
};

/* arpq_ip in NETWORK byte order */
struct arpq_entry {
    uint32_t arpq_ip;
    struct sr_if *arpq_if;
    struct packetq arpq_packets;
    time_t arpq_lastreq;
    uint8_t arpq_numreqs;
    struct arpq_entry *next;
    struct arpq_entry *prev;
};

struct arp_cache {
    struct arpc_entry *first;
    struct arpc_entry *last;
};

struct arp_queue {
    struct arpq_entry *first;
    struct arpq_entry *last;
};

static struct arp_cache sr_arpcache = {0, 0};

static struct arp_queue sr_arpqueue = {0, 0};


/*---------------------------------------------------------------------
 * Signature provided in stub code, but doesn't seem to serve any essential function
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance *sr) {
    assert(sr);
}


/*---------------------------------------------------------------------
 * Prints an IP address in period-separated bytes
 * Not used, but left around for possible debugging purposes
 *---------------------------------------------------------------------*/
static void ip_print(uint32_t *ip) {
    assert(ip);
    uint8_t *ipbyte = (uint8_t*) ip;
    int i;
    for (i = 0; i < 3; ++i)
        printf("%u.", ipbyte[i]);
    printf("%u\n", ipbyte[i]);
}


/*---------------------------------------------------------------------
 * Determines whether a packet is destined for any of the router's interfaces
 *---------------------------------------------------------------------*/
static struct sr_if *isdst_check(struct sr_instance *sr, uint32_t packetip) {
    struct sr_if *curr_if = sr->if_list;
    assert(curr_if);
    while (curr_if && packetip != curr_if->ip)
        curr_if = curr_if->next;
    if (curr_if)
        return curr_if;
    return 0;
}


/*---------------------------------------------------------------------
 * Search for interface with given IP address in interface list
 *---------------------------------------------------------------------*/
struct sr_if *if_list_search_ip(struct sr_if *iface, uint32_t ip) {
    while (iface) {
        if (iface->ip == ip)
            return iface;
        iface = iface->next;
    }
    return 0;
}


/*---------------------------------------------------------------------
 * Computes checksum over given data
 * Assumes all multiple-byte fields in network byte order
 *---------------------------------------------------------------------*/
static uint16_t checksum_compute(uint16_t *dat, size_t dat_len) {
    assert(dat);
    uint32_t sum = 0;
    size_t dat_16bitlen = dat_len / 2;
    
    while (dat_16bitlen--)
        sum += *dat++;
    if (dat_len % 2)
        sum += *((uint8_t*) dat);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ((uint16_t) ~sum);
}


/*---------------------------------------------------------------------
 * Swaps ethernet addresses
 *---------------------------------------------------------------------*/
static void ether_addr_swap(struct sr_ethernet_hdr *hdr) {
    assert(hdr);
    uint8_t temp1[ETHER_ADDR_LEN];
    memcpy(temp1, hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(hdr->ether_shost, hdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(hdr->ether_dhost, temp1, ETHER_ADDR_LEN);
}


/*---------------------------------------------------------------------
 * Modifies received packet to make ICMP echo reply
 *---------------------------------------------------------------------*/
// Q: WHAT IF DATA IS TOO LONG (EXCEEDS MAX LEN WHEN ADDED TO ICMP HEADER)?
static void icmp_echoreply_fill(uint8_t *packet, size_t icmp_len) {
    assert(packet);
    ether_addr_swap((struct sr_ethernet_hdr*) packet);
    
    struct ip *iphdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
    struct in_addr temp2 = iphdr->ip_src;
    iphdr->ip_src = iphdr->ip_dst;
    iphdr->ip_dst = temp2;
    
    struct icmp_echoreply_hdr *icmphdr = (struct icmp_echoreply_hdr*)
    (packet + sizeof(struct sr_ethernet_hdr) + iphdr->ip_hl * WORD_BYTELEN);
    icmphdr->icmp_type = 0;
    icmphdr->icmp_sum = 0;
    icmphdr->icmp_sum = checksum_compute((uint16_t *) icmphdr, icmp_len);
    iphdr->ip_sum = 0;
    iphdr->ip_sum = checksum_compute((uint16_t *) iphdr, iphdr->ip_hl * WORD_BYTELEN);
}


/*---------------------------------------------------------------------
 * Fills in fields with (mostly) predetermined values in IP packets containing
 * ICMP destination unreachable and time exceeded messages
 *---------------------------------------------------------------------*/
static void icmp_prefill(struct ip *iphdr, struct icmp_hdr *icmphdr,
                         uint8_t type, uint8_t code) {
    assert(iphdr);
    iphdr->ip_v = 4;
    iphdr->ip_hl = 5;
    iphdr->ip_tos = 0;
    iphdr->ip_id = 0;
    iphdr->ip_off = 0;
    iphdr->ip_ttl = 64;
    iphdr->ip_p = IPPROTO_ICMP;
    
    assert(icmphdr);
    icmphdr->icmp_type = type;
    icmphdr->icmp_code = code;
    icmphdr->icmp_unused = 0;
}


/*---------------------------------------------------------------------
 * Fills in IP packets containing ICMP destination unreachable and
 * time exceeded messages
 * icmpdat: the header plus 64 bits of data of the original IP
 *---------------------------------------------------------------------*/
static void icmp_specfill(struct ip *iphdr, struct icmp_hdr *icmphdr, uint32_t sip,
                          uint32_t dip, uint8_t *icmpdat, size_t icmpdat_len) {
    assert(iphdr);	assert(icmphdr);  	assert(icmpdat);
    iphdr->ip_len = htons(iphdr->ip_hl * WORD_BYTELEN + ICMPHDR_LEN + icmpdat_len);
    (iphdr->ip_src).s_addr = sip;
    (iphdr->ip_dst).s_addr = dip;
    iphdr->ip_sum = 0;
    iphdr->ip_sum = checksum_compute((uint16_t*) iphdr, iphdr->ip_hl * WORD_BYTELEN);
    
    memcpy(icmphdr + 1, icmpdat, icmpdat_len);
    icmphdr->icmp_sum = 0;
    icmphdr->icmp_sum = checksum_compute((uint16_t*) icmphdr, ICMPHDR_LEN + icmpdat_len);
}



/*---------------------------------------------------------------------
 * Returns pointer to entry corresponding to the longest prefix match
 * in the routing table for a given IP address. Assumes:
 * 1. 1s in netmasks are contiguous
 * 2. addr can have more than one prefix match (of different lengths)
 *---------------------------------------------------------------------*/
static struct sr_rt *rt_findmatch(struct sr_instance *sr, uint8_t *addr) {
    assert(addr);
    struct sr_rt *curr, *defaultr = 0, *bestmatch = 0;
    uint8_t *addrbyte, *rtbyte, *maskbyte;
    uint8_t tomatch, mismatch = 0, count = 0, longest = 0;
    
    for (curr = sr->routing_table; curr; curr = curr->next) {
        if (!defaultr) {
            if ((curr->dest).s_addr == 0)
                defaultr = curr;
        }
        addrbyte = addr;
        rtbyte = (uint8_t*) &((curr->dest).s_addr);
        maskbyte = (uint8_t*) &((curr->mask).s_addr);
        for (; addrbyte < addr + WORD_BYTELEN; ++addrbyte, ++rtbyte, ++maskbyte) {
            if (!(tomatch = (*addrbyte) & (*maskbyte)))
                break;
            if (tomatch != *rtbyte) {
                mismatch = 1;
                break;
            }
            count += 1;
        }
        if (mismatch) {
            mismatch = 0;
        }
        else if (count > longest) {
            longest = count;
            bestmatch = curr;
        }
        count = 0;
    }
	printf("~~ Best match ip : %s\n", inet_ntoa(*(struct in_addr*)&(bestmatch->gw).s_addr));
    if (bestmatch)
        return bestmatch;
    return defaultr;
}


/*---------------------------------------------------------------------
 * Add new entry to ARP cache
 *---------------------------------------------------------------------*/
static struct arpc_entry *arp_cache_add(struct arp_cache *cache, uint32_t ip, unsigned char *mac) {
    assert(cache); 	assert(mac);
    time_t temp;
    struct arpc_entry *new;
    if (new = (struct arpc_entry*) malloc(sizeof(struct arpc_entry))) {
        new->arpc_ip = ip;
        memcpy(new->arpc_mac, mac, ETHER_ADDR_LEN);
        new->arpc_timeout = time(&temp) + ARPCACHE_TIMEOUT;
        new->next = 0;
        new->prev = cache->last;
        if (cache->first)
            cache->last->next = new;
        else
            cache->first = new;
        cache->last = new;
    }
    return new;
}


/*---------------------------------------------------------------------
 * Add new packet to ARP queue entry
 *---------------------------------------------------------------------*/
static struct queued_packet *arpq_packet_add(struct arpq_entry *arp, uint8_t *packet,
                                             unsigned packetlen, char *ifname) {
    assert(arp); 	assert(packet);	 assert(ifname);
    struct queued_packet *add;
    if (add = (struct queued_packet*) malloc(sizeof(struct queued_packet))) {
        add->packet = (uint8_t*) malloc(packetlen);
        add->len = packetlen;
        memcpy(add->icmp_ifname, ifname, sr_IFACE_NAMELEN);
        memcpy(add->packet, packet, packetlen);
        add->next = 0;
        if ((arp->arpq_packets).first)
            ((arp->arpq_packets).last)->next = add;
        else
            (arp->arpq_packets).first = add;
        (arp->arpq_packets).last = add;
    }
    return add;
}


/*---------------------------------------------------------------------
 * Add new entry (ARP request) to ARP queue
 * lastreq (and numreqs) always set after sending req
 *---------------------------------------------------------------------*/
static struct arpq_entry *arpq_add_entry(struct arp_queue *queue, uint32_t ip, struct sr_if *iface,
                                         char *icmp_if, uint8_t *packet, unsigned len) {
    assert(queue);	assert(iface);
    struct arpq_entry *add;
    if (add = (struct arpq_entry*) malloc(sizeof(struct arpq_entry))) {
        add->arpq_ip = ip;
        add->arpq_if = iface;
        (add->arpq_packets).last = (add->arpq_packets).first = 0;
        if (arpq_packet_add(add, packet, len, icmp_if)) {
            add->arpq_numreqs = 1;
            add->next = 0;
            add->prev = queue->last;
            if (queue->first)
                queue->last->next = add;
            else
                queue->first = add;
            queue->last = add;
            return add;
        }
    }
    return 0;
}


/*---------------------------------------------------------------------
 * Update/refresh ARP cache entry
 *---------------------------------------------------------------------*/
static void arp_cache_update(struct arpc_entry *update, unsigned char *mac) {
    time_t temp;
    assert(update);	assert(mac);
    memcpy(update->arpc_mac, mac, ETHER_ADDR_LEN);
    update->arpc_timeout = time(&temp) + ARPCACHE_TIMEOUT;
}


/*---------------------------------------------------------------------
 * Clean ARP cache of timed-out (>= 15 seconds old) entries
 *---------------------------------------------------------------------*/
static void arp_cache_clear_invalids(struct arp_cache *cache) {
    assert(cache);
    struct arpc_entry *curr = cache->first;
    struct arpc_entry *temp = 0;
    time_t now;
    while (curr) {
        if (time(&now) >= curr->arpc_timeout) {
            if (curr->prev)
                curr->prev->next = curr->next;
            else
                cache->first = curr->next;
            if (curr->next)
                curr->next->prev = curr->prev;
            else
                cache->last = curr->prev;
            temp = curr;
        }
        curr = curr->next;
        if (temp) {
            free(temp);
            temp = 0;
        }
    }
}


/*---------------------------------------------------------------------
 * Fills in a request ARP header
 *---------------------------------------------------------------------*/
static void arpreq_fill(struct sr_arphdr *hdr, unsigned char *sha,
                        uint32_t sip, uint32_t tip) {
    assert(hdr);		assert(sha);
    hdr->ar_hrd = htons(1);
    hdr->ar_pro = htons(ETHERTYPE_IP);
    hdr->ar_hln = 6;
    hdr->ar_pln = WORD_BYTELEN;
    hdr->ar_op = htons(ARP_REQUEST);
    memcpy(hdr->ar_sha, sha, ETHER_ADDR_LEN);
    memset(hdr->ar_tha, 0, ETHER_ADDR_LEN);
    hdr->ar_sip = sip;
    hdr->ar_tip = tip;
}


/*---------------------------------------------------------------------
 * Fills in ethernet header fields for an ARP request
 * no error-checking for null pointers, like in much of the rest of this code
 *---------------------------------------------------------------------*/
static void arpreq_etherhdr_fill(struct sr_ethernet_hdr* hdr, uint8_t *saddr) {
    assert(hdr);		assert(saddr);
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; ++i)
        hdr->ether_dhost[i] = BCAST_IP;
    memcpy(hdr->ether_shost, saddr, ETHER_ADDR_LEN);
    hdr->ether_type = htons(ETHERTYPE_ARP);
}


/*---------------------------------------------------------------------
 * Generate and send ARP request
 *---------------------------------------------------------------------*/
static int arpreq_gen_send(struct sr_instance *sr, struct arpq_entry *arp,
                           struct sr_if *send_if, uint32_t dip) {
    assert(arp);		assert(send_if);
	printf(" ~ the ip destination is : %x\n",dip);
    unsigned len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
    uint8_t *sendpacket;
    if (sendpacket = (uint8_t*) malloc(len)) {	// padding added by OS apparently
        arpreq_fill((struct sr_arphdr*) (sendpacket + sizeof(struct sr_ethernet_hdr)),
                    send_if->addr, send_if->ip, dip);
        arpreq_etherhdr_fill((struct sr_ethernet_hdr*) sendpacket, send_if->addr);
        time(&(arp->arpq_lastreq));
        arp->arpq_numreqs += 1;		// queues with too many outstanding requests already discarded
        return sr_send_packet(sr, sendpacket, len, send_if->name);
    }
    else {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
}


/*---------------------------------------------------------------------
 * Allocates memory for an ICMP ethernet packet, and assigns values
 * to pointers pointing to various headers in it based on that address.
 * Attempted to use a struct holding the information for that purpose,
 * but that caused bus errors, probably due to memory alignment issues.
 *---------------------------------------------------------------------*/
static void icmp_ether_info_fill(unsigned old_hdrlen, unsigned *lenptr,
                                 uint8_t **packetptr, struct sr_ethernet_hdr **etherptr,
                                 struct ip **ipptr, struct icmp_hdr **icmpptr) {
    assert(lenptr); 	assert(packetptr);
    *lenptr = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)
    + ICMPHDR_LEN + old_hdrlen + ICMPDAT_LEN;
    if (*packetptr = (uint8_t*) malloc(*lenptr)) {
        *etherptr = (struct sr_ethernet_hdr*) *packetptr;
        *ipptr = (struct ip*) (*packetptr + sizeof(struct sr_ethernet_hdr));
        *icmpptr = (struct icmp_hdr*) (*packetptr + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    }
    else {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
}


/*---------------------------------------------------------------------
 * Sends destination unreachable or time exceeded ICMP for one packet
 *---------------------------------------------------------------------*/
static void packet_icmp_send(struct sr_instance *sr, struct sr_ethernet_hdr *etherhdr,
                             struct ip *iphdr, struct icmp_hdr *icmphdr, uint8_t *dha,
                             char *ifname, uint32_t dip, uint8_t *icmpdat,
                             size_t icmpdat_len, unsigned tot_len) {
    assert(ifname);	assert(etherhdr);	assert(dha);
    struct sr_if *send_if = sr_get_interface(sr, ifname);
    memcpy(etherhdr->ether_dhost, dha, ETHER_ADDR_LEN);
    memcpy(etherhdr->ether_shost, send_if->addr, ETHER_ADDR_LEN);
    icmp_specfill(iphdr, icmphdr, send_if->ip, dip, icmpdat, icmpdat_len);
    if (sr_send_packet(sr, (uint8_t*) etherhdr, tot_len, ifname)) {
        fprintf(stderr, "Error sending ICMP host unreachable\n");
    }
}


/*---------------------------------------------------------------------
 * Frees packet queue, sending necessary ICMPs
 *---------------------------------------------------------------------*/
static void arpq_packets_icmpsend(struct sr_instance *sr, struct packetq *queue) {
    assert(queue);
    unsigned int packetlen; uint8_t *packetptr; struct sr_ethernet_hdr *etherptr;
    struct ip *ipptr; struct icmp_hdr *icmpptr;
    icmp_ether_info_fill(sizeof(struct ip), &packetlen, &packetptr, &etherptr, &ipptr, &icmpptr);
    // initialize fields that all packets in this queue have common values for
    etherptr->ether_type = htons(ETHERTYPE_IP);
    icmp_prefill(ipptr, icmpptr, ICMP_UNREACH, ICMP_HOST_UNREACH);
    icmpptr->icmp_unused = 0;
    
    unsigned prev_iphdrlen = sizeof(struct ip);
    unsigned diff, iphdr_bytelen;
    struct sr_if *send_if;
    struct queued_packet *currp;
    /* (curr->arpq_packets).first should be non-null, but I suppose there will be no
     * consequences at this point if a null value is not detected...  */
    while (currp = queue->first) {
        struct ip *tempip = (struct ip*) (currp->packet + sizeof(struct sr_ethernet_hdr));
        iphdr_bytelen = tempip->ip_hl * WORD_BYTELEN;
        if (tempip->ip_p == IPPROTO_ICMP) {
            struct icmp_hdr *icmphdr = (struct icmp_hdr*) (currp->packet + sizeof(struct sr_ethernet_hdr) + iphdr_bytelen);
            if (icmphdr->icmp_type == ICMP_UNREACH || icmphdr->icmp_type == ICMP_TTL)
                return;
        }
        if (iphdr_bytelen != prev_iphdrlen) {
            diff = iphdr_bytelen - prev_iphdrlen;
            packetlen += diff;
            prev_iphdrlen = iphdr_bytelen;
            if (realloc(packetptr, packetlen)) {
                perror("realloc failed");
                exit(EXIT_FAILURE);		// not exiting could cause problems with inaccurate packet sizes
            }
        }
        packet_icmp_send(sr, etherptr, ipptr, icmpptr,
                         ((struct sr_ethernet_hdr*) (currp->packet))->ether_shost,
                         currp->icmp_ifname, (tempip->ip_src).s_addr,
                         (uint8_t*) tempip, iphdr_bytelen + ICMPDAT_LEN, packetlen);
        if (!(queue->first = currp->next))	// packet queue now empty
            queue->last = 0;
        free(currp);
    }
    free(packetptr);
}


/*---------------------------------------------------------------------
 * Clean ARP queue of entries with five or more requests
 * with the last made over a second ago
 *---------------------------------------------------------------------*/
static void arpq_clear_invalids(struct sr_instance *sr, struct arp_queue *queue) {
    assert(queue);
    struct arpq_entry *curr = queue->first;
    struct arpq_entry *temp = 0;
    time_t now;
    
    while (curr) {
        temp = 0;
        if (time(&now) - 1 > curr->arpq_lastreq) {
            if (curr->arpq_numreqs >= ARP_MAXREQS) {	// should be ==...
                temp = curr;
                arpq_packets_icmpsend(sr, &curr->arpq_packets);
            }
            else if (arpreq_gen_send(sr, curr, curr->arpq_if, curr->arpq_ip)) {
                fprintf(stderr, "Packet (ARP request) send failed\n");
            }
        }
        curr = curr->next;
        if (temp) {
            if (temp->prev)
                temp->prev->next = temp->next;
            else
                queue->first = temp->next;
            if (temp->next)
                temp->next->prev = temp->prev;
            else
                queue->last = temp->prev;
            free(temp);
            temp = 0;
        }
    }
}


/*---------------------------------------------------------------------
 * Search ARP cache for entry corresponding to given IP address
 *---------------------------------------------------------------------*/
static struct arpc_entry *arp_cache_search(struct arpc_entry *ar, uint32_t ip) {
    while (ar) {
        if (ip == ar->arpc_ip)
            return ar;
        ar = ar->next;
    }
    return 0;
}


/*---------------------------------------------------------------------
 * Search ARP queue for ARP request(s) for given IP
 *---------------------------------------------------------------------*/
static struct arpq_entry *arp_queue_search(struct arpq_entry *ar, uint32_t ip) {
    while (ar) {
        if (ip == ar->arpq_ip)
            return ar;
        ar = ar->next;
    }
    return 0;
}


/*---------------------------------------------------------------------
 * Clear ARP queue entry, sending queued packets (upon receipt of ARP reply)
 *---------------------------------------------------------------------*/
static void arpq_entry_clear(struct sr_instance *sr, struct arp_queue *queue,
                             struct arpq_entry *rm, unsigned char *dha) {
    struct queued_packet *currp;
    assert(dha);	assert(rm);	assert(queue);
    while (currp = (rm->arpq_packets).first) {
        memcpy(((struct sr_ethernet_hdr*) (currp->packet))->ether_shost, rm->arpq_if->addr, ETHER_ADDR_LEN);
        memcpy(((struct sr_ethernet_hdr*) (currp->packet))->ether_dhost, dha, ETHER_ADDR_LEN);
        struct ip *send_ip = (struct ip*) ((currp->packet) + sizeof(struct sr_ethernet_hdr));
        send_ip->ip_sum = 0;
        send_ip->ip_sum = checksum_compute((uint16_t *) send_ip, send_ip->ip_hl * WORD_BYTELEN);
        if (sr_send_packet(sr, currp->packet, currp->len, rm->arpq_if->name))
            fprintf(stderr, "Packet send (from ARP queue) failed.\n");
        if (!((rm->arpq_packets).first = currp->next))
            (rm->arpq_packets).last = 0;			// no more packets
        free(currp);
    }
    if (rm->prev)
        rm->prev->next = rm->next;
    else
        queue->first = rm->next;
    if (rm->next)
        rm->next->prev = rm->prev;
    else
        queue->last = rm->prev;
    free(rm);
}


/*---------------------------------------------------------------------
 * Form ARP reply from ARP request (including ethernet header)
 *---------------------------------------------------------------------*/
static void arp_reply_fill(struct sr_ethernet_hdr *etherhdr,
                           struct sr_arphdr *arphdr, struct sr_if *sif) {
    assert(etherhdr);	assert(arphdr);		assert(sif);
    memcpy(etherhdr->ether_dhost, etherhdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(etherhdr->ether_shost, sif->addr, ETHER_ADDR_LEN);
    memcpy(arphdr->ar_tha, arphdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(arphdr->ar_sha, sif->addr, ETHER_ADDR_LEN);
    arphdr->ar_tip = arphdr->ar_sip;
    arphdr->ar_sip = sif->ip;
    arphdr->ar_op = htons(ARP_REPLY);
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */,
                     unsigned len, char* interface/* lent */) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    
    printf("*** -> Received packet of length %d \n",len);
    
    // check ARP cache and queue for timeouts or number of requests exceeded
    arp_cache_clear_invalids(&sr_arpcache);
    arpq_clear_invalids(sr, &sr_arpqueue);
    
    uint16_t ethertype = ntohs(((struct sr_ethernet_hdr *) packet)->ether_type);
    
    if (ethertype == ETHERTYPE_IP) {

	printf(" SENDING IP 1\n");
        struct ip *ippacket = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
        size_t iphdr_bytelen = ippacket->ip_hl * WORD_BYTELEN;
        uint16_t sum_recvd = ippacket->ip_sum;
        ippacket->ip_sum = 0;
        
        if (checksum_compute((uint16_t*) ippacket, iphdr_bytelen) != sum_recvd) {
            fprintf(stderr, "IP checksum incorrect; packet dropped\n");
            return;
        }
        
        if ((ippacket->ip_ttl -= 1) == 0) {
	printf(" SENDING IP 2\n");
            if (ippacket->ip_p == IPPROTO_ICMP) {
                struct icmp_hdr *icmphdr = (struct icmp_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + iphdr_bytelen);
                if (icmphdr->icmp_type == ICMP_UNREACH || icmphdr->icmp_type == ICMP_TTL)
                    return;
            }
		printf(" SENDING IP 3\n");
            //struct icmp_ether_info *icmpinfo;
            unsigned int packetlen; uint8_t *packetptr; struct sr_ethernet_hdr *etherptr;
            struct ip *ipptr; struct icmp_hdr *icmpptr;
            icmp_ether_info_fill(iphdr_bytelen, &packetlen, &packetptr, &etherptr, &ipptr, &icmpptr);
            etherptr->ether_type = htons(ETHERTYPE_IP);
            ippacket->ip_ttl += 1;
            icmp_prefill(ipptr, icmpptr, ICMP_TTL, 0);
		printf(" CAME HERE  dest: %s\n", inet_ntoa(*(struct in_addr*)&(ippacket->ip_src).s_addr));
            packet_icmp_send(sr, etherptr, ipptr, icmpptr, ((struct sr_ethernet_hdr*) packet)->ether_shost,
                             interface, (ippacket->ip_src).s_addr, (uint8_t*) ippacket,
                             iphdr_bytelen + ICMPDAT_LEN, packetlen);
            free(packetptr);
            return;
        }
        
        if (isdst_check(sr, (ippacket->ip_dst).s_addr)) {	// addressed to a router iface
		printf(" SENDING IP 4\n");           
	 if (ippacket->ip_p == IPPROTO_ICMP) {
                struct icmp_hdr *packet_icmp = (struct icmp_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + iphdr_bytelen);
                if (packet_icmp->icmp_type == ICMP_ECHOREQ) {
                    uint16_t sum_recvd = packet_icmp->icmp_sum;
                    packet_icmp->icmp_sum = 0;
                    if (checksum_compute((uint16_t *) packet_icmp, ntohs(ippacket->ip_len) - iphdr_bytelen) != sum_recvd) {
                        fprintf(stderr, "ICMP checksum incorrect; packet dropped\n");
                        return;
                    }
                    icmp_echoreply_fill(packet, ntohs(ippacket->ip_len) - iphdr_bytelen);
                    if (sr_send_packet(sr, packet, len, interface))
                        fprintf(stderr, "Packet sending (in response to packet addressed to interface %s) failed\n", interface);
                }
            }
            else if (ippacket->ip_p == UDP_NUM || ippacket->ip_p == TCP_NUM) {
		printf(" SENDING IP 5\n");
                unsigned sendlen = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + ICMPHDR_LEN + iphdr_bytelen + ICMPDAT_LEN;
                uint8_t *sendpacket = (uint8_t*) malloc(sendlen);
                struct ip *sendip = (struct ip*) (sendpacket + sizeof(struct sr_ethernet_hdr));
                struct icmp_hdr *sendicmp = (struct icmp_hdr*) (sendip + 1);
                memcpy(sendpacket, packet, sizeof(struct sr_ethernet_hdr));
                ether_addr_swap((struct sr_ethernet_hdr*) sendpacket);
                ippacket->ip_ttl += 1;		// set back to original value; to be included in data portion of ICMP message
                icmp_prefill(sendip, sendicmp, ICMP_UNREACH, ICMP_PORT_UNREACH);
                icmp_specfill(sendip, sendicmp, (ippacket->ip_dst).s_addr, (ippacket->ip_src).s_addr,
                              (uint8_t*) ippacket, iphdr_bytelen + ICMPDAT_LEN);
                if (sr_send_packet(sr, sendpacket, sendlen, interface))
                    fprintf(stderr, "Packet sending (in response to packet addressed to interface %s) failed\n", interface);
                free(sendpacket);
            }
        }
        
        else {				// to be forwarded
	printf(" SENDING IP 6\n");
            uint32_t dstip = (ippacket->ip_dst).s_addr;
	printf("~~ before findmatchthe right ip : %s\n", inet_ntoa(*(struct in_addr*)&(ippacket->ip_dst).s_addr));
	printf("~~ SAME before findmatchthe right ip : %x\n", (ippacket->ip_dst).s_addr);
            struct sr_rt *nexthop_rt = rt_findmatch(sr, (uint8_t*) &dstip);
		//struct sr_rt *nexthop_rt = arp_mapping(sr, (uint8_t*) &dstip, interface);
            uint32_t nexthop = (nexthop_rt->gw).s_addr;
		//uint32_t nexthop = (nexthop_rt);
            printf("~~ getting the right ip : %s\n", inet_ntoa(*(struct in_addr*)&(nexthop_rt->gw).s_addr));
            unsigned char *dstmac_ptr;
            struct sr_if *send_if;
            struct arpc_entry *cacheresult;
            if (!(send_if = sr_get_interface(sr, nexthop_rt->interface))) {
                fprintf(stderr, "interface not found!?!");
                return;
            }
            
            if (cacheresult = arp_cache_search(sr_arpcache.first, nexthop)) { 				// IP in ARP cache
		printf(" SENDING IP 7\n");
                dstmac_ptr = cacheresult->arpc_mac;
                // only overwrite ethernet header contents (addresses) in this case
                memcpy(((struct sr_ethernet_hdr *) packet)->ether_shost, send_if->addr, ETHER_ADDR_LEN);
                memcpy(((struct sr_ethernet_hdr *) packet)->ether_dhost, dstmac_ptr, ETHER_ADDR_LEN);
                ippacket->ip_sum = checksum_compute((uint16_t *) ippacket, ippacket->ip_hl * WORD_BYTELEN);
                if (sr_send_packet(sr, packet, len, send_if->name))
                    fprintf(stderr, "Packet forwarding failed\n");
            }
            else {									// not in ARP cache: check if ARP request has been sent (ever; in last second)
		printf(" SENDING IP 8\n");
                struct arpq_entry *ent;
                if (ent = arp_queue_search(sr_arpqueue.first, nexthop)) {		// there are outstanding ARP request(s) for this IP
			printf(" SENDING IP 9\n");
		printf(" ~ passing this ip for arp req : %s", inet_ntoa(*(struct in_addr*)&ent->arpq_ip));
                    time_t now;
                    if (time(&now) - 1 > ent->arpq_lastreq) {
                        if (ent->arpq_numreqs >= ARP_MAXREQS) {	// should be ==...
                            arpq_packets_icmpsend(sr, &ent->arpq_packets);
                            free(ent);
                            unsigned int packetlen; uint8_t *packetptr; struct sr_ethernet_hdr *etherptr;
                            struct ip *ipptr; struct icmp_hdr *icmpptr;
                            icmp_ether_info_fill(iphdr_bytelen, &packetlen, &packetptr, &etherptr, &ipptr, &icmpptr);
                            etherptr->ether_type = htons(ETHERTYPE_IP);
                            icmp_prefill(ipptr, icmpptr, ICMP_UNREACH, ICMP_HOST_UNREACH);
                            icmpptr->icmp_unused = 0;
                            packet_icmp_send(sr, etherptr, ipptr, icmpptr, ((struct sr_ethernet_hdr*) packet)->ether_shost, 
                                             interface, (ippacket->ip_src).s_addr, (uint8_t*) ippacket, 
                                             iphdr_bytelen + ICMPDAT_LEN, packetlen);
                            free(packetptr);
                            return;
                        }
                        else if (arpreq_gen_send(sr, ent, ent->arpq_if, ent->arpq_ip)) {
                           
				fprintf(stderr, "ARP request send failed\n");
                        }
			
                    }
                    assert((ent->arpq_packets).first);					// arpq_packets should be non-empty
                    // leave ethernet header contents alone so source hw addr can be put in dest hw addr if ICMP needs to be sent
                    if (!arpq_packet_add(ent, packet, len, interface)) 
                        fprintf(stderr, "Failed to add packet to ARP queue entry for next hop\n");
                }
                else {									// no outstanding ARP requests for this IP
                    // add new entry (for this IP) to ARP queue
		printf(" SENDING IP 10\n");
                    if (ent = arpq_add_entry(&sr_arpqueue, nexthop, send_if, interface, packet, len)) {	
                        if (arpreq_gen_send(sr, ent, send_if, nexthop)) {
                            fprintf(stderr, "Packet (ARP request) send failed\n");
                            return;
                        }
                    }
                    else {  	
                        fprintf(stderr, "Failed to add new entry (IP of next hop) to ARP queue\n");
                    }
                }
            }
        }
    }
    
    else if (ethertype == ETHERTYPE_ARP) {
        struct sr_arphdr *arphdr = (struct sr_arphdr*) (packet + sizeof(struct sr_ethernet_hdr));
        if (ntohs(arphdr->ar_hrd) != ARPHDR_ETHER || ntohs(arphdr->ar_pro) != ETHERTYPE_IP) 
            return;
        uint8_t incache = 0;
        struct arpc_entry *arpc_info;
	printf(" SOME ARP PACKET FROM IP : %s\n", inet_ntoa(*(struct in_addr*)&arphdr->ar_sip));
        if (arpc_info = arp_cache_search(sr_arpcache.first, arphdr->ar_sip)) {	// IP in ARP cache
            arp_cache_update(arpc_info, arphdr->ar_sha);
            incache = 1;
        }
	else{
	printf(" IP not in ARP cache \n");
	}
        struct sr_if *tif; 
	//printf(" TARGET IP MOTHAFUCKA : %s", inet_ntoa(*(struct in_addr*)&arphdr->ar_tip));
        if (tif = isdst_check(sr, arphdr->ar_tip)) {		// I am the target IP	
		//printf(" the ip i got now as target is : %s\n", inet_ntoa(*(struct in_addr*)tif));            
		if (!incache) {
                if (arp_cache_add(&sr_arpcache, arphdr->ar_sip, arphdr->ar_sha)) {
		//printf(" this ip is going to cache : %s", inet_ntoa(*(struct in_addr*)&arphdr->ar_tip));                   
	struct arpq_entry *rm;
			printf(" inside arp_cache add\n");
                    if (rm = arp_queue_search(sr_arpqueue.first, arphdr->ar_sip)) {
                        arpq_entry_clear(sr, &sr_arpqueue, rm, arphdr->ar_sha);		// also forwards queued packets
                    printf("ANY LUCK MY MAN?\n");
			}
                }
                else
                    fprintf(stderr, "Error adding new entry to ARP cache: invalid hardware address used.\n");
            }
            if (ntohs(arphdr->ar_op) == ARP_REQUEST) {
		printf("Got an ARP REQ from %s \n", inet_ntoa(*(struct in_addr*)&arphdr->ar_sip));
                arp_reply_fill((struct sr_ethernet_hdr*) packet, arphdr, tif); 
                sr_send_packet(sr, packet, len, interface);
            }
	    if (ntohs(arphdr->ar_op) == ARP_REPLY) {
		//printf(" NOW I HAVE TO CODE HERE\n");	

		uint32_t naddr = arphdr->ar_sip;
		printf(" Kadavule ip: %s \n", inet_ntoa(*(struct in_addr*)&arphdr->ar_sip));	
		}
        }
    }
}/* end sr_ForwardPacket */
