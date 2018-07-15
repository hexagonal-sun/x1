#pragma once
#include <stdint.h>

#include "packet.h"

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header;

void udp_xmit_packet_paylaod(uint16_t src_port, uint16_t dst_port,
                             uint32_t dst_ip, struct packet_t *payload);

void udp_init(void);
