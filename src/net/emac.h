#pragma once

#define DESC_LEN 4
#define RX_FRAG_BUF_SZ 127
#define PHY_ADDR 1
#define IRQ_EMAC 28

/* Return a pointer to our assigned mac address */
const uint8_t *emac_get_mac_address(void);

void emac_init(void);
