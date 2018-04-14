#include <string.h>
#include <stdio.h>
#include <lib/byteswap.h>

#include "arp.h"
#include "ipv4.h"
#include "packet.h"
#include "protocol.h"
#include "ethernet.h"

#define DEFAULT_TTL 10

static void ipv4_swap_endian(ipv4_header *iphdr)
{
    swap_endian16(&iphdr->tot_length);
    swap_endian16(&iphdr->identification);
    swap_endian32(&iphdr->src_ip);
    swap_endian32(&iphdr->dst_ip);
}

static void ipv4_compute_checksum(ipv4_header *header)
{
    uint16_t *x = (uint16_t *)header;
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i < sizeof(ipv4_header) / 2; i++)
        sum += x[i];

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    header->header_checksum = ~sum;
}

static void ipv4_rx_packet(struct packet_t *pkt)
{
    ipv4_header *header = (ipv4_header *)pkt->rx.cur_data;
    size_t header_len;

    ipv4_swap_endian(header);

    /* TODO: checksum checking. */

    header_len = header->ihl * 4;
    pkt->rx.cur_data += header_len;
    pkt->rx.cur_data_length -= header_len;
    pkt->rx.meta.ipv4_payload_len = header->tot_length - header_len;

    /* Drop packet if ttl is zero. */
    if (!header->ttl) {
        pkt->handler = DROP;
        return;
    }

    /* Drop packet if it is not addressed to us. */
    if (header->dst_ip != OUR_IP_ADDRESS) {
        pkt->handler = DROP;
        return;
    }

    pkt->ip4_info.dst_ip = header->dst_ip;
    pkt->ip4_info.src_ip = header->src_ip;

    switch (header->protocol)
    {
    case IP_PROTO_TCP:
        pkt->handler = TCP;
        break;
    case IP_PROTO_UDP:
        pkt->handler = UDP;
        break;
    default:
        printf("IPv4: Unknown protocol type: 0x%X; packet dropped\n",
               header->protocol);
        pkt->handler = DROP;
        return;
    }
}

static uint32_t ipv4_get_pkt_dst(uint32_t dst_ip)
{
    if ((dst_ip & NET_MASK) == (OUR_IP_ADDRESS & NET_MASK))
        return dst_ip;

    return IP_GATEWAY;
}

static void ipv4_tx_packet(struct packet_t *pkt)
{
    ipv4_header header;
    size_t packet_buf_len = sizeof(header) + pkt->tx.total_len;
    uint32_t pkt_dst_ip = ipv4_get_pkt_dst(pkt->tx.meta.ipv4.dst_ip);
    const uint8_t *dst_hw_addr = resolve_address(pkt_dst_ip);

    memset(&header, 0, sizeof(header));

    if (!dst_hw_addr) {
        pkt->handler = DROP;
        return;
    }

    header.version = 4;
    header.ihl = 5;
    header.tot_length = packet_buf_len;
    header.ttl = DEFAULT_TTL;
    header.protocol = pkt->tx.meta.ipv4.protocol;
    header.src_ip = OUR_IP_ADDRESS;
    header.dst_ip = pkt->tx.meta.ipv4.dst_ip;

    ipv4_swap_endian(&header);

    ipv4_compute_checksum(&header);

    packet_tx_push_header(pkt, &header, sizeof(header));
    ethernet_mac_copy(pkt->tx.meta.ethernet.dhost, dst_hw_addr);
    pkt->tx.meta.ethernet.ether_type = ETHERTYPE_IP;
    pkt->handler = ETHERNET;
}


static struct protocol_t ipv4_protocol = {
    .rx_pkt = ipv4_rx_packet,
    .tx_pkt = ipv4_tx_packet,
    .type = IPV4,
    .name = "IPv4"
};

void ipv4_init(void)
{
    protocol_register(&ipv4_protocol);
}
