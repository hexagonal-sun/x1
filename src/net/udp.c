#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <lib/byteswap.h>
#include <lib/cbuf.h>
#include <src/mutex.h>
#include <src/condvar.h>
#include <network/udp.h>

#include "ipv4.h"
#include "packet.h"
#include "protocol.h"
#include "udp.h"

static const size_t RX_BUF_SZ = 256;

typedef struct
{
    uint16_t port;
    struct list node;
    struct cbuf rx_buf;
    void *rx_buf_buffer;
} udp_listener;

static LIST(udp_listeners);
static struct mutex udp_mutex;
static struct condvar udp_condvar;

static void udp_swap_endian(udp_header *header)
{
    swap_endian16(&header->dst_port);
    swap_endian16(&header->src_port);
    swap_endian16(&header->length);
}

void *udp_listen(uint16_t port)
{
    udp_listener *i;
    udp_listener *newListener;
    void *rx_buf;

    mutex_lock(&udp_mutex);

    list_for_each_entry(&udp_listeners, i, node)
        if (i->port == port)
            return NULL;

    newListener = malloc(sizeof(*newListener));

    if (!newListener)
        return NULL;

    rx_buf = malloc(RX_BUF_SZ);

    if (!rx_buf) {
        free(newListener);
        return NULL;
    }

    newListener->port = port;
    newListener->rx_buf_buffer = rx_buf;
    cbuf_init(&newListener->rx_buf, rx_buf, RX_BUF_SZ);

    list_insert_head(&udp_listeners, &newListener->node);

    mutex_unlock(&udp_mutex);

    return (void *)newListener;
}

void udp_free(void *udp)
{
    udp_listener *listerner = (udp_listener *)udp;

    mutex_lock(&udp_mutex);

    list_remove(&listerner->node);

    mutex_unlock(&udp_mutex);

    free(listerner->rx_buf_buffer);
    free(listerner);
}

int udp_rx_data(void *udp, void *dst_buf, uint16_t buf_len)
{
    udp_listener *listener = (udp_listener *)udp;
    size_t bytes_copied = 0;
    mutex_lock(&udp_mutex);

    while (buf_len) {
        size_t no_bytes_to_copy, bytes_in_buf;

        while (cbuf_size(&listener->rx_buf) == 0)
            condvar_wait(&udp_condvar, &udp_mutex);

        bytes_in_buf = cbuf_size(&listener->rx_buf);
        no_bytes_to_copy = bytes_in_buf > buf_len ? buf_len : bytes_in_buf;

        cbuf_pop(&listener->rx_buf, dst_buf, &no_bytes_to_copy);

        buf_len      -= no_bytes_to_copy;
        dst_buf      += no_bytes_to_copy;
        bytes_copied += no_bytes_to_copy;
    }

    mutex_unlock(&udp_mutex);

    return bytes_copied;
}

static void udp_rx_packet(struct packet_t *pkt)
{
    udp_listener *i;
    udp_header *header = (udp_header *)pkt->rx.cur_data;
    uint8_t *udp_payload;
    size_t udp_payload_sz;

    pkt->rx.cur_data += sizeof(*header);
    pkt->rx.cur_data_length -= sizeof(*header);

    udp_payload = pkt->rx.cur_data;
    udp_payload_sz = pkt->rx.cur_data_length;

    udp_swap_endian(header);

    /* Drop the packet as it will either not be found, or the udp
     * payload contents will be copied to the user supplied buffer. */
    pkt->handler = DROP;

    mutex_lock(&udp_mutex);
    list_for_each_entry(&udp_listeners, i, node) {
        if (i->port == header->dst_port) {
            cbuf_push(&i->rx_buf, udp_payload, udp_payload_sz, 0);

            condvar_signal(&udp_condvar);
            break;
        }
    }
    mutex_unlock(&udp_mutex);
}

void udp_xmit_packet_paylaod(uint16_t src_port, uint16_t dst_port,
                             uint32_t dst_ip, struct packet_t *payload)
{
    udp_header header;

    memset(&header, 0, sizeof(header));

    header.src_port = src_port;
    header.dst_port = dst_port;
    header.length = sizeof(header) + payload->tx.total_len;
    header.checksum = 0;

    udp_swap_endian(&header);

    packet_tx_push_header(payload, &header, sizeof(header));

    payload->tx.meta.ipv4.dst_ip = dst_ip;
    payload->tx.meta.ipv4.protocol = IP_PROTO_UDP;

    protocol_inject_tx(payload, IPV4);
}

void udp_xmit_packet(uint16_t src_port, uint16_t dst_port, uint32_t dst_ip,
                     void *payload, int payload_len)
{
    struct packet_t *pkt = packet_tx_create();

    if (!pkt)
        return;

    packet_tx_push_header(pkt, payload, payload_len);

    udp_xmit_packet_paylaod(src_port, dst_port, dst_ip, pkt);
}

static struct protocol_t udp_procotol = {
    .rx_pkt = udp_rx_packet,
    .type = UDP,
    .name = "UDP"
};

void udp_init(void)
{
    mutex_init(&udp_mutex);
    condvar_init(&udp_condvar);
    protocol_register(&udp_procotol);
}
