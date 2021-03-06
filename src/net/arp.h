#include <stdint.h>
#include "ethernet.h"

/* ARP protocol. */
typedef struct
{
    uint16_t HTYPE;
    uint16_t PTYPE;
    uint8_t  HLEN;
    uint8_t  PLEN;
    uint16_t OPER;
    uint8_t  SHA[ETHER_ADDR_LEN];
    uint32_t SPA;
    uint8_t  THA[ETHER_ADDR_LEN];
    uint32_t TPA;
} __attribute__((packed)) arp_packet;

#define HTYPE_ETHERNET 1
#define OPER_REQUEST 1
#define OPER_REPLY 2

const uint8_t * resolve_address(uint32_t IpAddress);
void arp_process_packet(void *payload, int payload_len);
void arp_init(void);
