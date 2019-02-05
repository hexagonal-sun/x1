#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <lib/list.h>
#include <lib/byteswap.h>
#include <src/mutex.h>
#include <src/condvar.h>

#include "arp.h"
#include "emac.h"
#include "packet.h"
#include "protocol.h"

#define ARP_TIMEOUT 250

struct arp_entry
{
    uint8_t ether_addr[ETHER_ADDR_LEN];
    uint32_t ipaddr;
    struct list node;
};

struct arp_pending_request
{
    int tick_count;
    uint32_t TPA;
    int timed_out;
    int finished;
    struct arp_entry *answer;
    struct list node;
};

static LIST(arp_pending_requests);
static LIST(arp_table_head);
static struct condvar arp_condvar;
static struct mutex arp_mutex;

static void arp_swap_endian(arp_packet *packet)
{
    swap_endian16(&packet->HTYPE);
    swap_endian16(&packet->PTYPE);
    swap_endian16(&packet->OPER);
    swap_endian32(&packet->SPA);
    swap_endian32(&packet->TPA);
}

const uint8_t *resolve_address(uint32_t ip_address)
{
    struct arp_entry *cur;
    struct arp_pending_request arp_p_req;
    const uint8_t broadcast_addr[ETHER_ADDR_LEN] =
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    mutex_lock(&arp_mutex);

    list_for_each_entry(&arp_table_head, cur, node) {
        if (cur->ipaddr == ip_address) {
            mutex_unlock(&arp_mutex);
            return cur->ether_addr;
        }
    }
    mutex_unlock(&arp_mutex);

    /*
     * We couldn't find an entry in the ARP table.  We need to send
     * out ARP packet to resolve address.
     */
    struct netinf *interface = netinf_get_for_ipv4_addr(ip_address);
    struct packet_t *pkt;
    const uint8_t *our_mac_address = interface->ether_addr;
    arp_packet arp_request;

    if (!interface)
        return NULL;

    pkt = packet_tx_create(interface);

    if (!pkt)
        return NULL;

    memset(&arp_request, 0, sizeof(arp_request));

    /* Fill in ARP request fields. */
    arp_request.HTYPE = HTYPE_ETHERNET;
    arp_request.PTYPE = ETHERTYPE_IP;
    arp_request.HLEN  = 6;
    arp_request.PLEN  = 4;
    arp_request.OPER  = OPER_REQUEST;
    ethernet_mac_copy(arp_request.SHA, our_mac_address);
    ethernet_mac_copy(arp_request.THA, broadcast_addr);
    arp_request.SPA = OUR_IP_ADDRESS;
    arp_request.TPA = ip_address;

    memset(&arp_p_req, 0, sizeof(arp_p_req));
    arp_p_req.TPA = ip_address;

    arp_swap_endian(&arp_request);

    packet_tx_push_header(pkt, &arp_request, sizeof(arp_request));

    ethernet_mac_copy(pkt->tx.meta.ethernet.dhost, broadcast_addr);

    pkt->tx.meta.ethernet.ether_type = ETHERTYPE_ARP;

    mutex_lock(&arp_mutex);
    list_insert_head(&arp_pending_requests, &arp_p_req.node);

    protocol_inject_tx(pkt, ETHERNET);

    while (!arp_p_req.finished)
        condvar_wait(&arp_condvar,
                     &arp_mutex);

    list_remove(&arp_p_req.node);

    mutex_unlock(&arp_mutex);

    if (arp_p_req.timed_out)
        return 0;

    return arp_p_req.answer->ether_addr;
}

static void arp_rx_packet(struct packet_t *pkt)
{
    arp_packet *packet = (arp_packet *)pkt->rx.cur_data;
    const uint8_t *our_mac_address = emac_get_mac_address();

    /* This function will process any arp packets; they're not passed
     * to any other prtocol layers.  Therefore, we can drop this
     * packet once we have finished processing it. */
    pkt->handler = DROP;

    arp_swap_endian(packet);

    /* We are only interested in Ethernet type ARP packets. */
    if (packet->HTYPE != HTYPE_ETHERNET)
        return;

    switch (packet->OPER)
    {
    case OPER_REQUEST:
    {
        struct packet_t *resp_packet = packet_tx_create(interface);
        arp_packet resp;

        memset(&resp, 0, sizeof(resp));

        if (packet->TPA != OUR_IP_ADDRESS)
            return;

        resp.HTYPE = HTYPE_ETHERNET;
        resp.PTYPE = ETHERTYPE_IP;
        resp.HLEN  = 6;
        resp.PLEN  = 4;
        resp.OPER  = OPER_REPLY;
        ethernet_mac_copy(resp.SHA, our_mac_address);
        ethernet_mac_copy(resp.THA, packet->SHA);
        resp.SPA = OUR_IP_ADDRESS;
        resp.TPA = packet->SPA;

        arp_swap_endian(&resp);

        packet_tx_push_header(resp_packet, &resp, sizeof(resp));
        ethernet_mac_copy(resp_packet->tx.meta.ethernet.dhost, packet->SHA);
        resp_packet->tx.meta.ethernet.ether_type = ETHERTYPE_ARP;
        protocol_inject_tx(resp_packet, ETHERNET);
        break;
    }
    case OPER_REPLY:
    {
        struct arp_entry *new_arp_entry;
        struct arp_pending_request *i;

        /* Ensure this packet is for us. */
        if (!ethernet_mac_equal(our_mac_address, packet->THA)) {
            pkt->handler = DROP;
            return;
        }

        mutex_lock(&arp_mutex);

        /* Find the request that this packet fulfils */
        list_for_each_entry(&arp_pending_requests, i, node)
            if (i->TPA == packet->SPA) {

                new_arp_entry = malloc(sizeof(*new_arp_entry));

                ethernet_mac_copy(new_arp_entry->ether_addr, packet->SHA);
                new_arp_entry->ipaddr = packet->SPA;

                list_insert_head(&arp_table_head, &new_arp_entry->node);

                /* We have fulfilled the request, set the reply and remove
                 * from the list of pending requests. */
                i->answer = new_arp_entry;
                i->finished = 1;
                condvar_signal(&arp_condvar);
                break;
            }

        mutex_unlock(&arp_mutex);
    }
    default:
        return;
    }
}

struct protocol_t arp_protocol = {
    .type = ARP,
    .rx_pkt = arp_rx_packet,
    .name = "ARP"
};

void arp_init(void)
{
    protocol_register(&arp_protocol);
    mutex_init(&arp_mutex);
    condvar_init(&arp_condvar);
}
