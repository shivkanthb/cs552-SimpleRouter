/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 * 90904102 
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

struct sr_icmphdr
{
	uint8_t icmp_type; 					/* type of icmp message */
	uint8_t icmp_code; 					/* code of icmp message */
    uint16_t icmp_sum;					/* icmp checksum */
    uint16_t icmp_id;					/* icmp ID */
    uint16_t icmp_seq;					/* icmp sequence number */
    uint16_t icmp_ohc;					/* icmp outbound count */
    uint16_t icmp_rhc;					/* icmp return count */
} __attribute__ ((packed));

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_TRACE_ROUTE 30
#define ICMP_CODE_ECHO_REPLY 0

#define ICMP_CODE_DEST_HOST_UNREACHABLE 1
#define ICMP_CODE_DEST_PORT_UNREACHABLE 3
#define ICMP_CODE_DEST_PROTOCOL_UNREACHABLE 2
#define ICMP_CODE_DEST_HOST_UNKNOWN 7
#define ICMP_CODE_TRACE_CODE 0

#define ICMP_CODE_ECHO_REQUEST 0

#define ICMP_CODE_TTL_EXPIRED 0

#define MAX_HOSTS 32
#define MAX_CACHE 32

typedef struct host {
    struct sr_if * iface;
    uint8_t daddr[ETHER_ADDR_LEN];
    uint32_t ip;
    time_t age;
    uint8_t queue;
} Host;

typedef struct mcpacket {
	uint8_t* packet;
	uint16_t len;
	time_t age;
	uint32_t ip;
} mPacket;




/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
void handle_arp_packet(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet);
struct ip *get_ip_hdr(uint8_t *packet);
struct sr_icmphdr *get_icmp_hdr(uint8_t *packet, struct ip* ip_hdr);
void sr_handle_icmp_packet(struct sr_instance* sr, unsigned int len, char* interface, struct sr_icmphdr* icmphdr, uint8_t* packet, struct ip* ip_hdr, struct sr_ethernet_hdr* ethr_hdr);

void send_icmp_message(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet, uint8_t type, uint8_t code);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
