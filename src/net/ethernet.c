#include <lib/byteswap.h>
#include <string.h>
#include <stdio.h>

#include "ethernet.h"
#include "packet.h"
#include "protocol.h"
#include "emac.h"

int ethernet_mac_equal(const uint8_t *a, const uint8_t *b)
{
    if (memcmp(a, b, ETHER_ADDR_LEN))
        return 0;
    else
        return 1;
}

void ethernet_mac_copy(uint8_t *dst, const uint8_t *src)
{
    memcpy(dst, src, ETHER_ADDR_LEN);
}

static void ethernet_tx_pkt(struct packet_t *pkt)
{
    int i;
    ethernet_header header;
    const uint8_t *ether_addr = pkt->interface->ether_addr;

    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        header.ether_dhost[i] = pkt->tx.meta.ethernet.dhost[i];
        header.ether_shost[i] = ether_addr[i];
    }

    header.ether_type = pkt->tx.meta.ethernet.ether_type;
    swap_endian16(&header.ether_type);

    packet_tx_push_header(pkt, &header, sizeof(header));

    pkt->handler = INTERFACE;
}

static void ethernet_rx_pkt(struct packet_t *pkt)
{
    static int no_dropped_packets;
    ethernet_header *header = (ethernet_header *)pkt->rx.cur_data;
    pkt->rx.cur_data += sizeof(*header);
    pkt->rx.cur_data_length -= sizeof(*header);

    swap_endian16(&header->ether_type);

    switch (header->ether_type)
    {
    case ETHERTYPE_ARP:
        pkt->handler = ARP;
        break;
    case ETHERTYPE_IP:
        pkt->handler = IPV4;
        break;
    default:
        /* Drop the packet. */
        printf("Ethernet: Unknown ether type: 0x%X; Packet dropped.\n",
               header->ether_type);
        pkt->handler = DROP;
        no_dropped_packets++;
        break;
    }
}

struct protocol_t ethernet_protocol = {
    .type = ETHERNET,
    .rx_pkt = ethernet_rx_pkt,
    .tx_pkt = ethernet_tx_pkt,
    .name = "Ethernet"
};

void ethernet_init(void)
{
    protocol_register(&ethernet_protocol);
}
