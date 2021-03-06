#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netinf.h"

static LIST(interface_head);
static struct mutex interface_list_mutex;

#define for_each_interface(pos)                                 \
    list_for_each_entry(&interface_head, (pos), next_interface)

static bool is_frame_buf_full(struct netinf *interface)
{
    if ((interface->frame_buf_prod_idx + 1) %
        FRAME_BUF_ELMS == interface->frame_buf_cons_idx)
        return true;
    else
        return false;
}

static bool is_frame_buf_empty(struct netinf *interface)
{
    return interface->frame_buf_prod_idx ==
           interface->frame_buf_cons_idx;
}

static void frame_gatherer_task(void *data)
{
    struct netinf *inf = (struct netinf *)data;

    for (;;)
    {
        uint32_t primask = thread_preempt_disable_intr_save();
        struct packet_t *pkt;
        struct frame *f;

        while (is_frame_buf_empty(inf))
            thread_sleep();

        f = &inf->frame_buf[inf->frame_buf_cons_idx];
        inf->frame_buf_cons_idx++;
        inf->frame_buf_cons_idx %= FRAME_BUF_ELMS;

        thread_preempt_enable_intr_restore(primask);

        pkt = packet_rx_create(f->data, f->frame_sz);

        pkt->interface = inf;

        if (!pkt) {
            printf("Protocol: Warning: Could not allocate packet\n");
            continue;
        }

        pkt->handler = inf->rx_frame_protocol;
        pkt->dir = RX;

        protocol_rx_packet(pkt);
    }
}

void netinf_rx_frame(struct netinf *interface,
                     struct cbuf *frag_buf)
{
    struct frame *f;
    size_t frame_sz = cbuf_size(frag_buf);

    if (is_frame_buf_full(interface)) {
        printf("Interface: %s: RX buffer full; frame dropped.\n",
               interface->name);
        cbuf_clear(frag_buf);
        return;
    }

    if (frame_sz > FRAME_DATA_SIZE) {
        printf("Interface: %s: Fragments greater than RX frame buffer size; "
               "frame dropped\n",
               interface->name);
        cbuf_clear(frag_buf);
        return;
    }

    f = &interface->frame_buf[interface->frame_buf_prod_idx];
    interface->frame_buf_prod_idx++;
    interface->frame_buf_prod_idx %= FRAME_BUF_ELMS;

    cbuf_pop(frag_buf, f->data, &frame_sz);
    f->frame_sz = frame_sz;

    thread_wakeup(interface->frame_gatherer_task);
}

struct netinf *netinf_create(const char *name,
                             tx_callback_t tx_callback,
                             enum protocol_type rx_frame_protocol)
{
    struct netinf *ret = malloc(sizeof(*ret));

    if (!ret)
        return NULL;

    memset(ret, 0, sizeof(*ret));

    ret->name = name;
    ret->tx_callback = tx_callback;
    ret->rx_frame_protocol = rx_frame_protocol;

    thread_create(&ret->frame_gatherer_task, frame_gatherer_task, ret,
                  "Frame Gatherer Task", 1024, THREAD_MIN_PRIORITY);

    mutex_lock(&interface_list_mutex);
    list_insert_head(&interface_head, &ret->next_interface);
    mutex_unlock(&interface_list_mutex);

    return ret;
}

static bool has_valid_gateway(struct netinf *interface)
{
    uint32_t netmask = interface->ipv4_data.netmask;

    if (!interface->ipv4_data.gateway)
        return false;

    if ((interface->ipv4_data.addr & netmask) ==
        (interface->ipv4_data.gateway & netmask))
        return true;

    return false;
}

struct netinf *netinf_get_for_ipv4_addr(uint32_t dst_addr)
{
    struct netinf *interface, *ret = NULL;

    mutex_lock(&interface_list_mutex);

    /* First, see if there are any interfaces that are on the subnet
     * requested. */
    for_each_interface(interface) {
        uint32_t netmask = interface->ipv4_data.netmask;
        uint32_t dst_subnet = dst_addr & netmask;
        uint32_t src_subnet = interface->ipv4_data.addr & netmask;

        if (dst_subnet == src_subnet) {
            ret = interface;
            goto out;
        }
    }

    /* If we couldn't find an interface that is on the same subnet as
     * `dst_addr', find one that has a default gateway set. */
    for_each_interface(interface)
        if (has_valid_gateway(interface)) {
            ret = interface;
            goto out;
        }

out:
    mutex_unlock(&interface_list_mutex);
    return ret;
}

struct netinf *netinf_get_for_name(const char *name)
{
    struct netinf *interface, *ret = NULL;

    mutex_lock(&interface_list_mutex);

    for_each_interface(interface) {
        if (strcmp(name, interface->name) == 0) {
            ret = interface;
            break;
        }
    }

    mutex_unlock(&interface_list_mutex);
    return ret;
}

void netinf_for_each_interface(netinf_iter_callback_t callback)
{
    struct netinf *i;
    mutex_lock(&interface_list_mutex);

    for_each_interface(i)
        callback(i);

    mutex_unlock(&interface_list_mutex);
}

void netinf_init(void)
{
    mutex_init(&interface_list_mutex);
}
