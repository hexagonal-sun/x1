#pragma once
#include <stdint.h>

#define IP_PROTO_TCP 0x6
#define IP_PROTO_UDP 0x11

typedef struct {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t __reserved_0;
    uint16_t tot_length;
    uint16_t identification;
    uint16_t __reserverd_1;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed)) ipv4_header;

void ipv4_init(void);
