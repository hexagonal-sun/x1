#pragma once
#include <stdint.h>

#define ETHER_ADDR_LEN 6

/* Ethernet protocol. */
typedef struct
{
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
} __attribute__((packed)) ethernet_header;

#define	ETHERTYPE_IP		0x0800
#define ETHERTYPE_ARP		0x0806

/*
 * Compare two MAC addresses for equality.
 *
 * @returns 0 if the addresses do not match, 1 otherwise.
 */
int ethernet_mac_equal(const uint8_t *a, const uint8_t *b);

/*
 * Copy a MAC address from `src' into `dst'.  `dst' must already be
 * allocated.
 */
void ethernet_mac_copy(uint8_t *dst, const uint8_t *src);


/*
 * Setup the Ethernet layer.
 */
void ethernet_init(void);
