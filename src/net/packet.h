#pragma once

#include "protocol.h"

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

union rx_data {
    uint16_t ipv4_payload_len;
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
    union rx_data rx_data;
    struct list node;
    enum {
        TX,
        RX
    } dir;
};

struct packet_t *packet_create(void *frame, size_t frame_len);
struct packet_t *packet_empty(void);
void packet_push_header(struct packet_t *pkt, void *header_data,
                        size_t header_len);
void packet_destroy(struct packet_t *pkt);
