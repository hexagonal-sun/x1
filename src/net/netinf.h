#pragma once

#include <src/mutex.h>
#include <lib/cbuf.h>

#include "packet.h"

typedef void (*tx_callback_t)(struct packet_t *pkt);

#define FRAME_DATA_SIZE 1700
#define FRAME_BUF_ELMS 4

struct frame
{
    uint8_t data[FRAME_DATA_SIZE];
    size_t frame_sz;
};

struct ipv4_data_t {
    uint32_t addr, netmask, gateway;
};

struct netinf {
    unsigned int frame_buf_prod_idx;
    unsigned int frame_buf_cons_idx;
    struct frame frame_buf[FRAME_BUF_ELMS];
    struct thread *frame_gatherer_task;
    enum protocol_type rx_frame_protocol;
    tx_callback_t tx_callback;
    const char *name;
    struct list next_interface;
    struct ipv4_data_t ipv4_data;
};

/* Take all data in `frag_buf' and insert it into the networking
 * stack.
 *
 * This function assumes that all data in `frag_buf' is a single
 * frame.
 *
 * This function should be called in an interrupt context.
 */
void netinf_rx_frame(struct netinf *interface,
                     struct cbuf *frag_buf);

struct netinf *netinf_create(const char *name,
                             tx_callback_t tx_callback,
                             enum protocol_type rx_frame_protocol);

void netinf_init(void);
