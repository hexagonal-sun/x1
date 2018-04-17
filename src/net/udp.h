#pragma once
#include <stdint.h>

#include "packet.h"

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header;

void *udp_listen(uint16_t port);
void udp_free(void *udp);

int udp_rx_data(void *udp, void *dst_buf, uint16_t buf_len);

void udp_xmit_packet(uint16_t src_port, uint16_t dst_port, uint32_t dst_ip,
                     void *payload, int payload_len);

void udp_xmit_packet_paylaod(uint16_t src_port, uint16_t dst_port,
                             uint32_t dst_ip, struct packet_t *payload);

void udp_init(void);
