#include <string.h>
#include <lpc17xx.h>
#include <src/mem.h>
#include <src/cpu.h>
#include <src/mutex.h>
#include <lib/cbuf.h>
#include <assert.h>
#include <stdio.h>
#include "constants.h"
#include "packet.h"
#include "protocol.h"
#include "emac.h"

#define FRAG_BUF_SIZE 4096
static struct cbuf fragment_cbuf;
static uint8_t fragment_buf[FRAG_BUF_SIZE];

static uint8_t mac_address[ETHER_ADDR_LEN] = {0, 1, 2, 3, 4, 5};
static struct mutex emac_mutex;

typedef struct
{
    void *packet;
    uint32_t control;
} txrx_descriptor;

typedef struct
{
    uint32_t status_info;
    uint32_t status_hash_crc;
} rx_status_t;

/* txrx descriptor arrays. */
static volatile txrx_descriptor __attribute__((aligned(4))) tx_desc[DESC_LEN];
static volatile txrx_descriptor __attribute__((aligned(4))) rx_desc[DESC_LEN];
static volatile uint32_t        __attribute__((aligned(4))) tx_status[DESC_LEN];
static volatile rx_status_t     __attribute__((aligned(8))) rx_status[DESC_LEN];

static void phy_write(int reg, int writeval)
{
    LPC_EMAC->MCMD = 0;
    LPC_EMAC->MADR = reg | (PHY_ADDR << 8);
    LPC_EMAC->MWTD = writeval;
    while (LPC_EMAC->MIND & 0x1) {};
}

static unsigned short phy_read(unsigned char reg)
{
    LPC_EMAC->MCMD = 0x1;
    LPC_EMAC->MADR = reg | (PHY_ADDR << 8);
    while  (LPC_EMAC->MIND & 0x1) {};
    LPC_EMAC->MCMD = 0;
    return (LPC_EMAC->MRDD);
}

static void emac_irq(void *arg __unused)
{
    while (LPC_EMAC->RxConsumeIndex != LPC_EMAC->RxProduceIndex) {
        int desc_idx = LPC_EMAC->RxConsumeIndex,
            frag_len = (rx_status[desc_idx].status_info & 0x7FF) + 1;
        void *frag = rx_desc[desc_idx].packet;
        int error;

        /* Gather the new fragment out of DMA memory. */
        error = cbuf_push(&fragment_cbuf, frag, frag_len, false);

        if (error) {
            printf("emac: Warning: fragment dropped\n");
            cbuf_clear(&fragment_cbuf);
        }

        /* Do we have a full frame? */
        if (rx_status[desc_idx].status_info & (1 << 30))
            protocol_inject_rx(&fragment_cbuf);

        desc_idx += 1;
        desc_idx %= DESC_LEN;
        LPC_EMAC->RxConsumeIndex = desc_idx;
    }

    LPC_EMAC->IntClear = (1 << 3);
}


/*
 * In section 3.4 of the LPC176x errata sheet
 * (https://www.nxp.com/docs/en/errata/ES_LPC176X.pdf) it is
 * documented that the ethernet mac will not update the TxConsumeIndex
 * register when the first packet has been transmitted, i.e. this will
 * update to the value two, skipping one.  Since we block, waiting for
 * a packet to be transmitted, this menas we block all TX.
 *
 * Work around this by sending two dummy frames so the TxProduceIndex
 * and TxConsumeIndex begin at 2.
 */
static void send_dummy_frames(void)
{
    const char *buf = "foobar";
    tx_desc[0].packet = (void *)buf;
    tx_desc[0].control = strlen(buf) - 1;
    tx_desc[1].packet = (void *)buf;
    tx_desc[1].control = strlen(buf) - 1;
    tx_desc[1].control |= (1 << 30);

    LPC_EMAC->TxProduceIndex = 2;

    while (LPC_EMAC->TxProduceIndex != LPC_EMAC->TxConsumeIndex) {};
}

static void emac_tx_frame(struct packet_t *pkt)
{
    size_t desc_idx, i;

    assert(pkt->handler == EMAC);
    assert(pkt->dir == TX);
    assert(pkt->tx.header_ptr < DESC_LEN);

    mutex_lock(&emac_mutex);

    desc_idx = LPC_EMAC->TxProduceIndex;

    i = pkt->tx.header_ptr;

    while (i--) {
        tx_desc[desc_idx].packet = pkt->tx.headers[i].data;
        tx_desc[desc_idx].control = pkt->tx.headers[i].size - 1;

        if (i == 0)
            tx_desc[desc_idx].control |= (1 << 30); /* set the LAST bit. */

        desc_idx = (desc_idx + 1) % (DESC_LEN);
    }

    /* Increment the TX produce index. */
    LPC_EMAC->TxProduceIndex = desc_idx;

    /* Wait for xmit to complete. */
    while (LPC_EMAC->TxProduceIndex != LPC_EMAC->TxConsumeIndex) {};

    mutex_unlock(&emac_mutex);

    pkt->handler = DROP;
}

static struct protocol_t emac_protocol = {
    .type = EMAC,
    .tx_pkt = emac_tx_frame,
};

const uint8_t *emac_get_mac_address(void)
{
    return mac_address;
}

void emac_init(void)
{
    int i;
    uint16_t link_params;

    cbuf_init(&fragment_cbuf, fragment_buf, sizeof(fragment_buf));
    mutex_init(&emac_mutex);

    /* Enable ethernet power. */
    LPC_SC->PCONP |= (1 << 30);

    /* Enable ethernet pins. */
    LPC_PINCON->PINSEL2 = 0x50150105;
    LPC_PINCON->PINSEL3 = 0x5;

    /* Bring the MAC out of SOFT RESET */
    LPC_EMAC->MAC1 = 0;

    /* Enable automatic CRC, PADding.  */
    LPC_EMAC->MAC2 |= 1 | (1 << 4) | (1 << 5);

    /* Set the interframe gap time */
    LPC_EMAC->IPGT = 0x15;
    LPC_EMAC->IPGR = 0x12 | (0xC << 8);

    /* Enable RMII. */
    LPC_EMAC->Command |= (1 << 9);

    /* Reset the PHY. */
    phy_write(0, (1 << 15));

    /* Wait for the PHY to come out of reset. */
    while(phy_read(0) & (1 << 15)) {};

    /* Enable auto negotiation */
    phy_write(0, (1 << 12));

    /* Wait for link to become ready and auto negotiation to
     * complete. */
    while (!(phy_read(0x10) & ((1 << 0) | (1 << 4)))) {};

    /* Get link parameters */
    link_params = phy_read(0x10);

    if (!(link_params & (1 << 1)))
        /* Link speed is 100 Mbps. */
        LPC_EMAC->SUPP = (1 << 8);
    else
        /* Link speed is 10 Mbps. */
        LPC_EMAC->SUPP = 0;

    if (link_params & (1 << 2))
        /* Link is full-duplex. */
        LPC_EMAC->Command |= (1 << 10);
    else
        LPC_EMAC->Command &= ~(1 << 10);

    /* Set the station address. */
    LPC_EMAC->SA0 = (mac_address[0] << 8) | mac_address[1];
    LPC_EMAC->SA1 = (mac_address[2] << 8) | mac_address[3];
    LPC_EMAC->SA2 = (mac_address[4] << 8) | mac_address[5];

    /* Allocate the receive fragment buffers. */
    for (i = 0; i < DESC_LEN; i++) {
        rx_desc[i].packet = mem_alloc(RX_FRAG_BUF_SZ);
        rx_desc[i].control = (RX_FRAG_BUF_SZ - 1) | (1 << 31);
    }

    /* Set the txrx desc base address. */
    LPC_EMAC->RxDescriptor = (uint32_t)rx_desc;
    LPC_EMAC->TxDescriptor = (uint32_t)tx_desc;
    LPC_EMAC->TxStatus = (uint32_t)tx_status;
    LPC_EMAC->RxStatus = (uint32_t)rx_status;

    /* Set the txrx desc array length. */
    LPC_EMAC->RxDescriptorNumber = DESC_LEN - 1;
    LPC_EMAC->TxDescriptorNumber = DESC_LEN - 1;

    /* Zero the indices. */
    LPC_EMAC->RxConsumeIndex = 0;
    LPC_EMAC->TxProduceIndex = 0;

    /* Set RECEIVE_ENABLE */
    LPC_EMAC->MAC1 |= 1;

    /* Enable interrupts on rx. */
    LPC_EMAC->IntEnable |= (1 << 3);

    /* Enable Tx & Rx! */
    LPC_EMAC->Command |= 3 | (1 << 9) | (1 << 7);

    send_dummy_frames();

    cpu_irq_register(IRQ_EMAC, emac_irq, NULL);

    protocol_register(&emac_protocol);
}
