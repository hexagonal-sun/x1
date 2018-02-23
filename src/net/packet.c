#include "packet.h"
#include <stdlib.h>
#include <string.h>

struct packet_t *packet_empty()
{
    struct packet_t *ret = malloc(sizeof(*ret));

    if (!ret)
        return NULL;

    ret->data = ret->cur_data = NULL;
    ret->data_length = ret->cur_data_length = 0;

    return ret;
}

struct packet_t *packet_create(void *frame, size_t frame_len)
{
    if (!frame || !frame_len)
        return NULL;

    struct packet_t *ret = packet_empty();

    if (!ret)
        return NULL;

    ret->data = ret->cur_data = malloc(frame_len);

    if (!ret->data) {
        free(ret);
        return NULL;
    }

    memcpy(ret->data, frame, frame_len);
    ret->data_length = ret->cur_data_length = frame_len;

    return ret;
}

void packet_push_header(struct packet_t *pkt, void *header, size_t header_len)
{
    size_t new_data_sz = pkt->data_length + header_len;
    void *old_buf = pkt->data;
    void *new_buf = malloc(new_data_sz);

    if (pkt->data)
        memcpy(new_buf + header_len, pkt->data, pkt->data_length);

    memcpy(new_buf, header, header_len);

    pkt->cur_data = pkt->data = new_buf;
    pkt->cur_data_length = pkt->data_length = new_data_sz;

    if (old_buf)
        free(old_buf);
}

void packet_destroy(struct packet_t *pkt)
{
    if (pkt->data)
        free(pkt->data);

    free(pkt);
}
