#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "packet.h"

static struct packet_t *packet_empty()
{
    struct packet_t *ret = malloc(sizeof(*ret));

    if (!ret)
        return NULL;

    memset(ret, 0, sizeof(*ret));

    return ret;
}

struct packet_t *packet_tx_create()
{
    struct packet_t *ret = packet_empty();

    ret->dir = TX;

    return ret;
}

struct packet_t *packet_rx_create(void *frame, size_t frame_len)
{
    if (!frame || !frame_len)
        return NULL;

    struct packet_t *ret = packet_empty();

    if (!ret)
        return NULL;

    ret->rx.data = ret->rx.cur_data = malloc(frame_len);

    if (!ret->rx.data) {
        free(ret);
        return NULL;
    }

    memcpy(ret->rx.data, frame, frame_len);
    ret->rx.data_length = ret->rx.cur_data_length = frame_len;

    ret->dir = RX;

    return ret;
}

static bool is_tx_packet_full(struct packet_t *pkt)
{
    return pkt->tx.header_ptr == NO_PACKET_HEADERS - 1;
}

int packet_tx_push_header(struct packet_t *pkt, void *header, size_t header_len)
{
    void *new_buf;

    assert(pkt->dir == TX);

    if (is_tx_packet_full(pkt))
        panic("Packet: Number of packet headers exhausted\n");

    new_buf = malloc(header_len);

    memcpy(new_buf, header, header_len);

    if (!new_buf)
        return ENOMEM;

    pkt->tx.headers[pkt->tx.header_ptr].data = new_buf;
    pkt->tx.headers[pkt->tx.header_ptr].size = header_len;

    pkt->tx.header_ptr++;
    pkt->tx.total_len += header_len;

    return 0;
}

static void tx_shift_headers(struct packet_t *pkt)
{
    size_t i;

    if (is_tx_packet_full(pkt))
        panic("Packet: Could not shift full packet\n");

    for (i = pkt->tx.header_ptr; i > 0; i--)
        pkt->tx.headers[i] = pkt->tx.headers[i - 1];

    pkt->tx.header_ptr++;

    pkt->tx.headers[0].data = NULL;
    pkt->tx.headers[0].size = 0;
}

int packet_tx_push_header_end(struct packet_t *pkt, void *header,
                              size_t header_len)
{
    assert(pkt->dir == TX);

    void *new_buf = malloc(header_len);

    if (!new_buf)
        return ENOMEM;

    memcpy(new_buf, header, header_len);

    tx_shift_headers(pkt);

    pkt->tx.headers[0].data = new_buf;
    pkt->tx.headers[0].size = header_len;

    pkt->tx.total_len += header_len;

    return 0;
}

void packet_destroy(struct packet_t *pkt)
{
    if (pkt->rx.data)
        free(pkt->rx.data);

    for (size_t i = 0; i < pkt->tx.header_ptr; i++)
        if (pkt->tx.headers[i].data)
            free(pkt->tx.headers[i].data);

    free(pkt);
}
