#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <lib/byteswap.h>
#include <src/mutex.h>
#include <src/condvar.h>

#include "ipv4.h"
#include "packet.h"
#include "protocol.h"
#include "udp.h"

typedef struct
{
    uint8_t *dst_buf;
    size_t dst_buf_sz;
    size_t dst_buf_ptr;
    uint16_t port;
    struct list node;
} udp_listener;

static LIST(udp_listeners);
static struct mutex udp_mutex;
static struct condvar udp_condvar;

static void udp_swap_endian(udp_header *header)
{
    swap_endian16(&header->dst_port);
    swap_endian16(&header->length);
}

int udp_rx(uint16_t port, void *dst_buf, uint16_t dst_buf_sz)
{
    udp_listener *i;
    udp_listener newListener;

    mutex_lock(&udp_mutex);

    list_for_each_entry(&udp_listeners, i, node)
        if (i->port == port)
            return EINUSE;

    newListener.port = port;
    newListener.dst_buf = dst_buf;
    newListener.dst_buf_sz = dst_buf_sz;
    newListener.dst_buf_ptr = 0;

    list_insert_head(&udp_listeners, &newListener.node);

    while (newListener.dst_buf_ptr !=
           newListener.dst_buf_sz)
        condvar_wait(&udp_condvar, &udp_mutex);


    list_remove(&newListener.node);
    mutex_unlock(&udp_mutex);

    return newListener.dst_buf_ptr;
}

static void udp_rx_packet(struct packet_t *pkt)
{
    udp_listener *i;
    udp_header *header = (udp_header *)pkt->cur_data;
    uint8_t *udp_payload;
    size_t udp_payload_sz;

    pkt->cur_data += sizeof(*header);
    pkt->cur_data_length -= sizeof(*header);

    udp_payload = pkt->cur_data;
    udp_payload_sz = pkt->cur_data_length;

    udp_swap_endian(header);

    /* Drop the packet as it will either not be found, or the udp
     * payload contents will be copied to the user supplied buffer. */
    pkt->handler = DROP;

    mutex_lock(&udp_mutex);
    list_for_each_entry(&udp_listeners, i, node) {
        if (i->port == header->dst_port) {
            size_t user_buf_sz = i->dst_buf_sz - i->dst_buf_ptr,
                   no_bytes_to_copy = user_buf_sz;


            if (udp_payload_sz < no_bytes_to_copy)
                no_bytes_to_copy = udp_payload_sz;

            memcpy(i->dst_buf + i->dst_buf_ptr, udp_payload, no_bytes_to_copy);

            i->dst_buf_ptr += no_bytes_to_copy;
            condvar_signal(&udp_condvar);
            break;
        }
    }
    mutex_unlock(&udp_mutex);
}

void udp_xmit_packet(uint16_t dst_port, uint32_t dst_ip, void *payload,
                     int payload_len)
{
    struct packet_t *pkt = packet_create(payload, payload_len);
    udp_header header;

    memset(&header, 0, sizeof(header));

    header.src_port = 0;
    header.dst_port = dst_port;
    header.length = sizeof(header) + payload_len;
    header.checksum = 0;

    udp_swap_endian(&header);

    packet_push_header(pkt, &header, sizeof(header));
    pkt->tx_data.ipv4.dst_ip = dst_ip;
    pkt->tx_data.ipv4.protocol = IP_PROTO_UDP;

    protocol_inject_tx(pkt, IPV4);
}

static struct protocol_t udp_procotol = {
    .rx_pkt = udp_rx_packet,
    .type = UDP
};

void udp_init(void)
{
    mutex_init(&udp_mutex);
    condvar_init(&udp_condvar);
    protocol_register(&udp_procotol);
}
