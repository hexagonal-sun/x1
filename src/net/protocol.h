#pragma once
#include <stdint.h>
#include <lib/list.h>
#include <lib/cbuf.h>
#include "constants.h"

struct packet_t;

enum protocol_type {
    EMAC,
    ETHERNET,
    IPV4,
    UDP,
    TCP,
    ARP,

    /* None indicates that this packet should be destroyed and
     * dropped. */
    DROP
};

typedef void (*protocol_func_t)(struct packet_t *pkt);

struct protocol_t
{
    enum protocol_type type;
    protocol_func_t rx_pkt;
    protocol_func_t tx_pkt;
    struct list next_protocol;
};

#define for_each_protocol(pos)                                  \
    list_for_each_entry(&protocol_head, (pos), next_protocol)

void protocol_inject_rx(struct cbuf *cbuf);
void protocol_inject_tx(struct packet_t *pkt, enum protocol_type type);
void protocol_register(struct protocol_t *protocol);
void protocol_setup(void);
