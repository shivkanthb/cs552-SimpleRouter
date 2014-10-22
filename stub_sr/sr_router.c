/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



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

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
    
   struct sr_ethernet_hdr* ethr_hdr = (struct sr_ethernet_hdr*)packet;
    
    switch (htons(ethr_hdr->ether_type))
    {
        case ETHERTYPE_ARP:
            {printf("packet heuleuela");
            handle_arp_packet(sr, len, interface, packet);
            break;}

        case ETHERTYPE_IP:
        {
            printf("IP packet recieved. Not bad.\n");

            assert(ethr_hdr);
            struct ip* ip_hdr;
            ip_hdr = get_ip_hdr(packet);
            struct sr_if * iface = sr->if_list;
            struct in_addr ip_address;
        
            //printf(" the dest IP is : %s",inet_ntoa(*(struct in_addr*)&ip_hdr->ip_dst.s_addr));
            if (iface) {/*(ip_hdr->ip_dst.s_addr == sr_get_interface(sr, interface)->ip) {*/
                printf("RECIEVED IP PACKET TO ETHERNET INTERFACE (no routing required)\n");
                if (ip_hdr->ip_p == IPPROTO_ICMP && ((struct sr_icmphdr *)(packet + sizeof(struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4))->icmp_type == ICMP_TYPE_ECHO_REQUEST) {
		            struct sr_icmphdr* icmphdr = get_icmp_hdr(packet, ip_hdr);
                    printf("before getting into shashwat");
		            sr_handle_icmp_packet(sr, len, interface, icmphdr, packet, ip_hdr, (struct sr_ethernet_hdr *) packet);
                } else {
                    printf("have to send rthe icmp message npow");
                	send_icmp_message(sr, len, interface, packet, ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_DEST_PORT_UNREACHABLE);
                }
            }
            
            
            
            break;


        }
    }
 
    


}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method: handle_arp_packet
 *
 *---------------------------------------------------------------------*/
void handle_arp_packet(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet) {
    
    /*struct sr_ethernet_hdr* tx_e_hdr = ((struct sr_ethernet_hdr*)(malloc(sizeof(struct sr_ethernet_hdr))));  // for swapping.
    uint8_t* tx_packet;

    struct sr_ethernet_hdr* ethr_hd = (struct sr_ethernet_hdr *) packet;
    struct sr_arphdr* arp_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr)); // recieved
    
    struct sr_if * iface = sr->if_list; */

    struct sr_ethernet_hdr* ethr_hd = (struct sr_ethernet_hdr *) packet;
    struct sr_arphdr* arp_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

    switch (htons(arp_hdr->ar_op))
    {
        case ARP_REQUEST:

            printf("\nReceived ARP REQuest with length = %d\n", len);
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
            break;
    }



}

// end of handle_arp_packet

struct ip *get_ip_hdr(uint8_t *packet) {
    return (struct ip *) (packet + sizeof (struct sr_ethernet_hdr));
}

struct sr_icmphdr *get_icmp_hdr(uint8_t *packet, struct ip* ip_hdr) {
    return (struct sr_icmphdr *) (packet + sizeof (struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4);
}

// sr_handle_icmp

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
           // setICMPchecksum(icmphdr, packet + sizeof (struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4, len - sizeof (struct sr_ethernet_hdr) - ip_hdr->ip_hl * 4);
            
            sr_send_packet(sr, packet, len, interface);
        } else { /*echo request to app server or other interface */
            
        }
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
    //setICMPchecksum(out_icmp, outpack + sizeof (struct sr_ethernet_hdr) + 20, 16 + in_ip_hdr->ip_hl * 4);
    //setIPchecksum(out_ip_hdr);
    printf("going inside shashwat");
    /* send message*/
    sr_send_packet(sr, outpack, sizeof (struct sr_ethernet_hdr) + 36 + in_ip_hdr->ip_hl * 4, interface);
    free(outpack);
    
    free(tmp_ip);
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
