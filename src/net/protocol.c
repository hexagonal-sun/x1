#include <string.h>
#include <lib/macros.h>
#include <src/mem.h>
#include <src/panic.h>
#include <src/mutex.h>
#include <src/condvar.h>
#include <stdio.h>
#include <stdbool.h>

#include "arp.h"
#include "packet.h"
#include "protocol.h"
#include "emac.h"
#include "ethernet.h"
#include "ipv4.h"
#include "udp.h"
#include "tcp.h"

static LIST(protocol_head);
static LIST(pkt_q);
static LIST(rx_pkt_q);
static struct mutex pkt_q_mutex;
static struct condvar pkt_q_condvar;
struct thread *pkt_waiter;

#define RX_PACKET_BUF_SIZE 4
#define FRAME_DATA_SIZE 1700

struct frame
{
    uint8_t data[FRAME_DATA_SIZE];
    size_t frame_sz;
};

static unsigned int rx_frame_prod_idx;
static unsigned int rx_frame_cons_idx;
static struct frame rx_frames[RX_PACKET_BUF_SIZE];


#define NO_PROTO_WORKERS 3


static bool is_rx_buf_full(void)
{
    if ((rx_frame_prod_idx + 1) % RX_PACKET_BUF_SIZE == rx_frame_cons_idx)
        return true;
    else
        return false;
}

static bool rx_buf_empty(void)
{
    return rx_frame_prod_idx == rx_frame_cons_idx;
}

void protocol_inject_rx(struct cbuf *cbuf)
{
    struct frame *f;
    size_t frame_sz = cbuf_size(cbuf);

    if (is_rx_buf_full()) {
        printf("Protocol: RX buffer full; frame dropped.\n");
        cbuf_clear(cbuf);
        return;
    }

    if (frame_sz > FRAME_DATA_SIZE) {
        printf("Protocol: Frame size greater than RX frame buffer; "
               "frame dropped\n");
        cbuf_clear(cbuf);
        return;
    }

    f = &rx_frames[rx_frame_prod_idx];
    rx_frame_prod_idx++;
    rx_frame_prod_idx %= RX_PACKET_BUF_SIZE;

    cbuf_pop(cbuf, f->data, &frame_sz);
    f->frame_sz = frame_sz;

    thread_wakeup(pkt_waiter);
}

void protocol_inject_tx(struct packet_t *pkt, enum protocol_type type)
{
    pkt->dir = TX;
    pkt->handler = type;

    mutex_lock(&pkt_q_mutex);
    list_insert_head(&pkt_q, &pkt->node);
    condvar_signal(&pkt_q_condvar);
    mutex_unlock(&pkt_q_mutex);
}

void protocol_register(struct protocol_t *protocol)
{
    list_insert_head(&protocol_head, &protocol->next_protocol);
}

static struct protocol_t *resolve_pkt_protocol(struct packet_t *pkt)
{
    struct protocol_t *proto;

    for_each_protocol(proto) {
        if (proto->type == pkt->handler)
            return proto;
    }

    return NULL;
}

static void protocol_task(void *arg __unused)
{
    while (1) {
        struct packet_t *pkt;

        mutex_lock(&pkt_q_mutex);

        while (list_empty(&pkt_q))
            condvar_wait(&pkt_q_condvar, &pkt_q_mutex);

        pkt = list_first_entry(&pkt_q, typeof(*pkt), node);
        list_remove(&pkt->node);

        mutex_unlock(&pkt_q_mutex);

        while (pkt) {
            struct protocol_t *proto = resolve_pkt_protocol(pkt);

            if (!proto) {
                /* We couldn't find a protocol handler for this packet.
                 * Drop it. */
                panic("Could not resolve protocol %d", pkt->handler);
                pkt->handler = DROP;
            }
            else
                if (pkt->dir == RX)
                    proto->rx_pkt(pkt);
                else if (pkt->dir == TX)
                    proto->tx_pkt(pkt);

            if (pkt->handler == DROP) {
                packet_destroy(pkt);
                pkt = NULL;
            }
        }
    }
}

static void protocol_gatherer_task(void *arg __unused)
{
    for (;;)
    {
        uint32_t primask = thread_preempt_disable_intr_save();
        struct packet_t *pkt;
        struct frame *f;

        while (rx_buf_empty()) {
            pkt_waiter = thread_self();
            thread_sleep();
            pkt_waiter = NULL;
        }

        f = &rx_frames[rx_frame_cons_idx];
        rx_frame_cons_idx++;
        rx_frame_cons_idx %= RX_PACKET_BUF_SIZE;

        thread_preempt_enable_intr_restore(primask);

        pkt = packet_create(f->data, f->frame_sz);

        if (!pkt) {
            printf("Protocol: Warning: Could not allocate packet\n");
            continue;
        }

        pkt->handler = ETHERNET;
        pkt->dir = RX;

        mutex_lock(&pkt_q_mutex);

        list_insert_head(&pkt_q, &pkt->node);
        condvar_signal(&pkt_q_condvar);

        mutex_unlock(&pkt_q_mutex);
    }
}

void protocol_setup(void)
{
    mutex_init(&pkt_q_mutex);
    condvar_init(&pkt_q_condvar);
    ethernet_init();
    emac_init();
    arp_init();
    ipv4_init();
    udp_init();

    for (size_t i = 0; i < NO_PROTO_WORKERS; i++)
        thread_create(NULL, protocol_task, NULL,
                      "Protocol worker thread", 1024, 0);

    thread_create(NULL, protocol_gatherer_task, NULL,
                  "Protocol Gatherer Task", 1024, 0);
}
