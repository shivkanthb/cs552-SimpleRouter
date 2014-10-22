/*-----------------------------------------------------------------------------
 * File: sr_main.c
 * Date: Spring 2002
 * Authors: Guido Apanzeller, Vikram Vijayaraghaven, Martin Casado
 * Contact: casado@stanford.edu
 *
 * Based on many generations of sr clients including the original c client
 * and bert.
 *
 * Description:
 *
 * Driver file for sr
 *
 *---------------------------------------------------------------------------*/

#ifdef _SOLARIS_
#define __EXTENSIONS__
#endif /* _SOLARIS_ */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

#ifdef _LINUX_
#include <getopt.h>
#endif /* _LINUX_ */

#include "sr_dumper.h"
#include "sr_router.h"
#include "sr_rt.h"

extern char* optarg;

/*-----------------------------------------------------------------------------
 *---------------------------------------------------------------------------*/

#define DEFAULT_PORT 12345
#define DEFAULT_HOST "vrhost"
#define DEFAULT_SERVER "171.67.71.18"
#define DEFAULT_RTABLE "rtable"
#define DEFAULT_TOPO 0

static void usage(char* );
static void sr_init_instance(struct sr_instance* );
static void sr_destroy_instance(struct sr_instance* );
static void sr_set_user(struct sr_instance* );

/*-----------------------------------------------------------------------------
 *---------------------------------------------------------------------------*/

int main(int argc, char **argv)
{
    int c;
    char *host   = DEFAULT_HOST;
    char *client = 0;
    char *server = DEFAULT_SERVER;
    char *rtable = DEFAULT_RTABLE;
    unsigned int port = DEFAULT_PORT;
    unsigned int topo = DEFAULT_TOPO;
    char *logfile = 0;
    struct sr_instance sr;
    
    while ((c = getopt(argc, argv, "hs:v:p:c:t:r:l:")) != EOF)
    {
        switch (c)
        {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'p':
                port = atoi((char *) optarg);
                break;
            case 't':
                topo = atoi((char *) optarg);
                break;
            case 'v':
                host = optarg;
                break;
            case 'c':
                client = optarg;
                break;
            case 's':
                server = optarg;
                break;
            case 'l':
                logfile = optarg;
                break;
            case 'r':
                rtable = optarg;
                break;
        } /* switch */
    } /* -- while -- */
    
    /* -- zero out sr instance -- */
    sr_init_instance(&sr);
    
    /* -- set up routing table from file -- */
    if(sr_load_rt(&sr, rtable) != 0)
    {
        fprintf(stderr,"Error setting up routing table from file %s\n",
                rtable);
        exit(1);
    }
    
    
    printf("Loading routing table\n");
    printf("---------------------------------------------\n");
    sr_print_routing_table(&sr);
    printf("---------------------------------------------\n");
    
    sr.topo_id = topo;
    strncpy(sr.host,host,32);
    
    if(! client )
    { sr_set_user(&sr); }
    else
    { strncpy(sr.user, client, 32); }
    
    /* -- set up file pointer for logging of raw packets -- */
    if(logfile != 0)
    {
        sr.logfile = sr_dump_open(logfile,0,PACKET_DUMP_SIZE);
        if(!sr.logfile)
        {
            fprintf(stderr,"Error opening up dump file %s\n",
                    logfile);
            exit(1);
        }
    }
    
    Debug("Client %s connecting to Server %s:%d\n", sr.user, server, port);
    Debug("Requesting topology %d\n", topo);
    
    /* connect to server and negotiate session */
    if(sr_connect_to_server(&sr,port,server) == -1)
    {
        return 1;
    }
    
    /* call router init (for arp subsystem etc.) */
    sr_init(&sr);
    
    /* -- whizbang main loop ;-) */
    while( sr_read_from_server(&sr) == 1);
    
    sr_destroy_instance(&sr);
    
    return 0;
}/* -- main -- */

/*-----------------------------------------------------------------------------
 * Method: usage(..)
 * Scope: local
 *---------------------------------------------------------------------------*/

static void usage(char* argv0)
{
    printf("Simple Router Client\n");
    printf("Format: %s [-h] [-v host] [-s server] [-p port] \n",argv0);
    printf("           [-t topo id] [-r routing table] \n");
    printf("           [-l log file] \n");
    printf("   defaults server=%s port=%d host=%s  \n",
           DEFAULT_SERVER, DEFAULT_PORT, DEFAULT_HOST );
} /* -- usage -- */

/*-----------------------------------------------------------------------------
 * Method: sr_set_user(..)
 * Scope: local
 *---------------------------------------------------------------------------*/

void sr_set_user(struct sr_instance* sr)
{
    uid_t uid = getuid();
    struct passwd* pw = 0;
    
    /* REQUIRES */
    assert(sr);
    
    if(( pw = getpwuid(uid) ) == 0)
    {
        fprintf (stderr, "Error getting username, using something silly\n");
        strncpy(sr->user, "something_silly", 32);
    }
    else
    {
        strncpy(sr->user, pw->pw_name, 32);
    }
    
} /* -- sr_set_user -- */

/*-----------------------------------------------------------------------------
 * Method: sr_destroy_instance(..)
 * Scope: Local
 *
 *
 *----------------------------------------------------------------------------*/

static void sr_destroy_instance(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);
    
    if(sr->logfile)
    {
        sr_dump_close(sr->logfile);
    }
    
    /*
     fprintf(stderr,"sr_destroy_instance leaking memory\n");
     */
} /* -- sr_destroy_instance -- */

/*-----------------------------------------------------------------------------
 * Method: sr_init_instance(..)
 * Scope: Local
 *
 *
 *----------------------------------------------------------------------------*/

static void sr_init_instance(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);
    
    sr->sockfd = -1;
    sr->user[0] = 0;
    sr->host[0] = 0;
    sr->topo_id = 0;
    sr->if_list = 0;
    sr->routing_table = 0;
    sr->logfile = 0;
} /* -- sr_init_instance -- */

/*-----------------------------------------------------------------------------
 * Method: sr_verify_routing_table()
 * Scope: Global
 *
 * make sure the routing table is consistent with the interface list by
 * verifying that all interfaces used in the routing table actually exist
 * in the hardware.
 *
 * RETURN VALUES:
 *
 *  0 on success
 *  something other than zero on error
 *
 *---------------------------------------------------------------------------*/

int sr_verify_routing_table(struct sr_instance* sr)
{
    struct sr_rt* rt_walker = 0;
    struct sr_if* if_walker = 0;
    int ret = 0;
    
    /* -- REQUIRES --*/
    assert(sr);
    
    if( (sr->if_list == 0) || (sr->routing_table == 0))
    {
        return 999; /* doh! */
    }
    
    rt_walker = sr->routing_table;
    
    while(rt_walker)
    {
        /* -- check to see if interface exists -- */
        if_walker = sr->if_list;
        while(if_walker)
        {
            if( strncmp(if_walker->name,rt_walker->interface,sr_IFACE_NAMELEN)
               == 0)
            { break; }
            if_walker = if_walker->next;
        }
        if(if_walker == 0)
        { ret++; } /* -- interface not found! -- */
        
        rt_walker = rt_walker->next;
    } /* -- while -- */
    
    return ret;
} /* -- sr_verify_routing_table -- */