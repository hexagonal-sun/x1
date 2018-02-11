#pragma once
#include <stdint.h>
#include <lib/list.h>
#include <lib/cbuf.h>
#include "constants.h"

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

struct ipv4_pkt_info {
    uint32_t src_ip;
    uint32_t dst_ip;
};

union tx_data {
    struct {
        uint8_t dhost[ETHER_ADDR_LEN];
        uint16_t ether_type;
    } ethernet;

    struct {
        uint8_t protocol;
        uint32_t dst_ip;
    } ipv4;

    struct {
        unsigned int tick_count;
        int TPA;
        int timed_out;
    } arp_pending;
};

struct packet_t
{
    void *data;
    void *cur_data;
    size_t data_length;
    size_t cur_data_length;
    enum protocol_type handler;
    struct ipv4_pkt_info ip4_info;
    union tx_data tx_data;
    struct list node;
    enum {
        TX,
        RX
    } dir;
};

typedef void (*pkt_func_t)(struct packet_t *pkt);

struct protocol_t
{
    enum protocol_type type;
    pkt_func_t rx_pkt;
    pkt_func_t tx_pkt;
    struct list next_protocol;
};

#define for_each_protocol(pos)                                  \
    list_for_each_entry(&protocol_head, (pos), next_protocol)

struct packet_t *packet_create(void *frame, size_t frame_len);
struct packet_t *packet_empty(void);
void packet_push_header(struct packet_t *pkt, void *header_data,
                        size_t header_len);
void packet_destroy(struct packet_t *pkt);
void packet_inject_rx(struct cbuf *cbuf);
void packet_inject_tx(struct packet_t *pkt, enum protocol_type type);
void protocol_register(struct protocol_t *protocol);
void protocol_setup(void);
