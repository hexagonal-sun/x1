#include <string.h>
#include <lib/macros.h>
#include <src/mem.h>
#include <src/panic.h>
#include <src/mutex.h>
#include <src/condvar.h>
#include <stdio.h>
#include <stdbool.h>

#include "arp.h"
#include "packet.h"
#include "protocol.h"
#include "emac.h"
#include "ethernet.h"
#include "ipv4.h"
#include "udp.h"
#include "tcp.h"
#include "netshell.h"

static LIST(protocol_head);
static LIST(pkt_q);
static struct mutex pkt_q_mutex;
static struct condvar pkt_q_condvar;

#define NO_PROTO_WORKERS 3


void protocol_rx_packet(struct packet_t *pkt)
{
    mutex_lock(&pkt_q_mutex);

    list_insert_head(&pkt_q, &pkt->node);
    condvar_signal(&pkt_q_condvar);

    mutex_unlock(&pkt_q_mutex);
}

void protocol_print_stats()
{
    struct protocol_t *proto;

    for_each_protocol(proto)
        if (proto->print_statistics) {
            printf("Stats for protocol: %s\n", proto->name);

            proto->print_statistics();

            putchar('\n');
        }
}

void protocol_inject_tx(struct packet_t *pkt, enum protocol_type type)
{
    pkt->dir = TX;
    pkt->handler = type;

    mutex_lock(&pkt_q_mutex);
    list_insert_head(&pkt_q, &pkt->node);
    condvar_signal(&pkt_q_condvar);
    mutex_unlock(&pkt_q_mutex);
}

void protocol_register(struct protocol_t *protocol)
{
    list_insert_head(&protocol_head, &protocol->next_protocol);
}

static struct protocol_t *resolve_pkt_protocol(struct packet_t *pkt)
{
    struct protocol_t *proto;

    for_each_protocol(proto) {
        if (proto->type == pkt->handler)
            return proto;
    }

    return NULL;
}

static void protocol_task(void *arg __unused)
{
    while (1) {
        struct packet_t *pkt;

        mutex_lock(&pkt_q_mutex);

        while (list_empty(&pkt_q))
            condvar_wait(&pkt_q_condvar, &pkt_q_mutex);

        pkt = list_first_entry(&pkt_q, typeof(*pkt), node);
        list_remove(&pkt->node);

        mutex_unlock(&pkt_q_mutex);

        while (pkt) {
            struct protocol_t *proto = resolve_pkt_protocol(pkt);

            if (!proto) {
                /* We couldn't find a protocol handler for this packet.
                 * Drop it. */
                panic("Could not resolve protocol %d", pkt->handler);
                pkt->handler = DROP;
            }
            else
                if (pkt->dir == RX)
                    proto->rx_pkt(pkt);
                else if (pkt->dir == TX)
                    proto->tx_pkt(pkt);

            if (pkt->handler == DROP) {
                packet_destroy(pkt);
                pkt = NULL;
            }
        }
    }
}

void protocol_setup(void)
{
    mutex_init(&pkt_q_mutex);
    condvar_init(&pkt_q_condvar);
    ethernet_init();
    emac_init();
    arp_init();
    ipv4_init();
    udp_init();
    tcp_init();
    net_shell_init();
    netinf_init();

    for (size_t i = 0; i < NO_PROTO_WORKERS; i++)
        thread_create(NULL, protocol_task, NULL,
                      "Protocol worker thread", 1024, THREAD_MIN_PRIORITY);
}
