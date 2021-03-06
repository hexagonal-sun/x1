#include <lib/byteswap.h>
#include <src/mutex.h>
#include <src/condvar.h>
#include <src/panic.h>
#include <network/tcp.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "tcp.h"
#include "packet.h"
#include "protocol.h"
#include "ethernet.h"
#include "ipv4.h"

#define TCP_TIMEOUT 250
#define TCP_BUF_SZ 128

typedef struct
{
    uint32_t src;
    uint32_t dst;
    uint8_t __reserved_0;
    uint8_t proto;
    uint16_t length;
} tcp_pseudo;

static LIST(tcb_head);
static struct mutex tcp_mutex;
static struct condvar tcp_condvar;

static void tcp_swap_endian(tcp_header *header)
{
    swap_endian16(&header->source_port);
    swap_endian16(&header->dest_port);
    swap_endian32(&header->seq_n);
    swap_endian32(&header->ack_n);
    swap_endian16(&header->window_sz);
    swap_endian16(&header->checksum);
    swap_endian16(&header->urg_ptr);
}

static void tcp_swap_pseudo_endian(tcp_pseudo *pheader)
{
    swap_endian32(&pheader->src);
    swap_endian32(&pheader->dst);
    swap_endian16(&pheader->length);
}

static void tcp_compute_checksum(tcp_header *header, tcp_pseudo *pheader,
                                 void *payload_data, size_t payload_len)
{
    void *buf;
    uint16_t *x;
    size_t buf_sz = sizeof(*header) + sizeof(*pheader) + payload_len;
    uint32_t sum = 0;
    size_t i;

    if (buf_sz % 2)
        buf_sz += 1;

    buf = malloc(buf_sz);
    memset(buf, 0, buf_sz);

    memcpy(buf, pheader, sizeof(*pheader));
    memcpy(buf + sizeof(*pheader), header, sizeof(*header));
    memcpy(buf + sizeof(*pheader) + sizeof(*header), payload_data, payload_len);

    x = buf;

    for (i = 0; i < buf_sz / 2; i++)
        sum += x[i];

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    header->checksum = ~sum;

    free(buf);
}

static void tcp_header_prepopulate(tcb *t, tcp_header *header)
{
    header->source_port = t->src_port;
    header->dest_port = t->dst_port;
    header->seq_n = t->cur_seq_n;
    header->ack_n = t->cur_ack_n;
    header->data_offset = 5;

    header->window_sz = cbuf_capacity(&t->rx_buf) - cbuf_size(&t->rx_buf);
}

static void tcp_tx(tcp_header header, uint32_t dest_ip,
                   void *payload, size_t payload_len)
{
    struct netinf *interface = netinf_get_for_ipv4_addr(dest_ip);
    struct packet_t *pkt;
    tcp_pseudo pheader;

    if (!interface)
        return;

    pkt = packet_tx_create(interface);

    if (!pkt)
        return;

    if (payload)
        packet_tx_push_header(pkt, payload, payload_len);

    memset(&pheader, 0, sizeof(pheader));

    pheader.src = interface->ipv4_data.addr;
    pheader.dst = dest_ip;
    pheader.proto = IP_PROTO_TCP;
    pheader.length = sizeof(header) + payload_len;

    tcp_swap_endian(&header);
    tcp_swap_pseudo_endian(&pheader);

    tcp_compute_checksum(&header, &pheader, payload, payload_len);

    packet_tx_push_header(pkt, &header, sizeof(header));
    pkt->tx.meta.ipv4.dst_ip = dest_ip;
    pkt->tx.meta.ipv4.protocol = IP_PROTO_TCP;
    protocol_inject_tx(pkt, IPV4);
}

static void tcp_rx_packet(struct packet_t *pkt)
{
    tcb *i, *referenced_tcb = NULL;
    tcp_header *incoming = (tcp_header *)pkt->rx.cur_data;
    size_t tcp_header_sz = incoming->data_offset * 4;
    size_t data_len;
    int send_ack = 0;

    pkt->rx.cur_data += tcp_header_sz;
    pkt->rx.cur_data_length -= tcp_header_sz;
    data_len = pkt->rx.meta.ipv4_payload_len - tcp_header_sz;
    tcp_swap_endian(incoming);

    /* Once we return, drop the packet as this is an terminus
     * protocol. */
    pkt->handler = DROP;

    mutex_lock(&tcp_mutex);

    /* Find the TCB that this packet was for. */
    for_each_tcb(i) {
        if (incoming->dest_port == i->src_port &&
            incoming->source_port == i->dst_port &&
            i->dst_ip == pkt->ip4_info.src_ip) {
            referenced_tcb = i;
            break;
        }
    }

    /* If we didn't find a TCB, see if there are any TCBs that are in
     * the listening state that can accept this packet as it may be
     * the start of a new connection. */
    if (!referenced_tcb) {
        for_each_tcb(i) {
            if (i->state == LISTEN &&
                incoming->dest_port == i->src_port) {
                referenced_tcb = i;
                break;
            }
        }
    }

    if (referenced_tcb == NULL) {
        tcp_header response;

        /* We couldn't find a TCB for the referenced connection.
         * which is equivalent to the connection being in a CLOSED
         * state. */
        mutex_unlock(&tcp_mutex);

        if (incoming->rst)
            return;

        memset(&response, 0, sizeof(response));

        response.rst = 1;
        response.data_offset = 5;
        response.dest_port = incoming->source_port;
        response.source_port = incoming->dest_port;
        response.ack = 1;
        response.ack_n = incoming->seq_n + 1;

        tcp_tx(response, pkt->ip4_info.src_ip, NULL, 0);
        return;
    }

    /* We've received a packet for this tcb, stop any timeout
     * counters. */
    referenced_tcb->decrement_timeout = 0;
    referenced_tcb->timed_out = 0;
    referenced_tcb->timeout = 0;

    switch(referenced_tcb->state)
    {
    case SYN_SENT:
        /* At this point the client could refuse the connection [RST,
         * ACK] or accept the connection [SYN, ACK]. */
        if (incoming->syn && incoming->ack) {
            tcp_header response;

            referenced_tcb->cur_seq_n++;
            referenced_tcb->cur_ack_n = incoming->seq_n + 1;
            referenced_tcb->host_window_sz = incoming->window_sz;

            memset(&response, 0, sizeof(response));

            tcp_header_prepopulate(referenced_tcb, &response);

            response.ack = 1;

            tcp_tx(response, referenced_tcb->dst_ip, NULL, 0);

            referenced_tcb->state = ESTABLISHED;
            break;
        }

        referenced_tcb->state = CLOSED;
        break;

    case LISTEN:
        if (incoming->syn) {
            referenced_tcb->dst_ip = pkt->ip4_info.src_ip;
            referenced_tcb->cur_ack_n = incoming->seq_n + 1;
            referenced_tcb->dst_port = incoming->source_port;
            referenced_tcb->state = SYN_RECEIVED;
        }
        break;

    case SYN_RECEIVED:
        if (incoming->ack) {
            referenced_tcb->cur_seq_n = incoming->ack_n;
            referenced_tcb->state = ESTABLISHED;
        }
        break;
    case ESTABLISHED:
    {
        int no_acked_bytes = 0;

        if (incoming->ack) {
            no_acked_bytes = incoming->ack_n -
                referenced_tcb->cur_seq_n;

            if (no_acked_bytes > 0)
                referenced_tcb->unacked_byte_count -= no_acked_bytes;

            referenced_tcb->cur_seq_n = incoming->ack_n;
        }

        if (incoming->fin) {
            referenced_tcb->state = CLOSE_WAIT;
            referenced_tcb->cur_ack_n++;
            send_ack = 1;
        }

        if (data_len) {
            cbuf_push(&referenced_tcb->rx_buf, pkt->rx.cur_data, data_len, false);
            referenced_tcb->cur_ack_n += data_len;
            send_ack = 1;
        }

        if (!data_len && !no_acked_bytes)
            send_ack = 1;
        break;
    }
    case CLOSE_WAIT:
    {
        if (incoming->ack &&
            incoming->ack_n == referenced_tcb->cur_ack_n + 1) {
            free(referenced_tcb->rx_buf_buffer);
            list_remove(&referenced_tcb->node);
            free(referenced_tcb);
            mutex_unlock(&tcp_mutex);
            return;
        }

        break;
    }
    case FIN_WAIT1:
    {
        if (incoming->fin &&
            incoming->ack &&
            incoming->ack_n == referenced_tcb->cur_seq_n) {
            referenced_tcb->cur_ack_n = incoming->seq_n + 1;
            send_ack = 1;
            referenced_tcb->state = TIME_WAIT;
            referenced_tcb->timeout = TCP_TIMEOUT;
            referenced_tcb->decrement_timeout = 1;
            break;
        }

        if (incoming->ack &&
            incoming->ack_n == referenced_tcb->cur_seq_n) {
            referenced_tcb->cur_ack_n = incoming->seq_n;
            referenced_tcb->state = FIN_WAIT2;
            break;
        }

        if (incoming->fin) {
            referenced_tcb->cur_ack_n++;
            send_ack = 1;
            referenced_tcb->state = CLOSING;
        }

        break;
    }
    case FIN_WAIT2:
    {

        if (incoming->fin &&
            incoming->ack) {
            referenced_tcb->cur_ack_n = incoming->ack_n;
            send_ack = 1;
            referenced_tcb->state = TIME_WAIT;
            referenced_tcb->timeout = TCP_TIMEOUT;
            referenced_tcb->decrement_timeout = 1;
        }
        break;
    }
    case CLOSING:
    {
        if (incoming->ack)
            referenced_tcb->cur_ack_n = incoming->ack;

        referenced_tcb->state = TIME_WAIT;
        referenced_tcb->timeout = TCP_TIMEOUT;
        referenced_tcb->decrement_timeout = 1;
        break;
    }
    default:
    {
        panic("TCP packet recieved for TCB in unknown state\n");
    }
    }

    if (send_ack)
    {
        tcp_header resp;

        memset(&resp, 0, sizeof(resp));

        tcp_header_prepopulate(referenced_tcb, &resp);

        resp.ack = 1;

        tcp_tx(resp, pkt->ip4_info.src_ip, NULL, 0);
    }

    condvar_broadcast(&tcp_condvar);
    mutex_unlock(&tcp_mutex);
}

/* Perform a 3-way handshake and establish a TCP connection. */
void *tcp_connect(uint16_t port, uint32_t ip)
{
    tcp_header header;
    tcb *new_tcb = malloc(sizeof(*new_tcb));

    if (!new_tcb)
        return NULL;

    memset(&header, 0, sizeof(header));
    memset(new_tcb, 0, sizeof(*new_tcb));

    new_tcb->rx_buf_buffer = malloc(TCP_BUF_SZ);

    if (!new_tcb->rx_buf_buffer) {
        free(new_tcb);
        return NULL;
    }

    cbuf_init(&new_tcb->rx_buf, new_tcb->rx_buf_buffer, TCP_BUF_SZ);

    new_tcb->cur_seq_n = 1024;
    new_tcb->state = SYN_SENT;
    new_tcb->timeout = TCP_TIMEOUT;
    new_tcb->decrement_timeout = 1;
    new_tcb->src_port = 65355;
    new_tcb->dst_port = port;
    new_tcb->last_msg = &header;
    new_tcb->dst_ip = ip;

    tcp_header_prepopulate(new_tcb, &header);

    header.syn = 1;

    mutex_lock(&tcp_mutex);
    list_insert_head(&tcb_head, &new_tcb->node);

    tcp_tx(header, ip, NULL, 0);

    while (new_tcb->state == SYN_SENT)
        condvar_wait(&tcp_condvar, &tcp_mutex);

    if (new_tcb->state != ESTABLISHED) {
        free(new_tcb->rx_buf_buffer);
        list_remove(&new_tcb->node);
        free(new_tcb);
        new_tcb = NULL;
    }

    mutex_unlock(&tcp_mutex);
    return (void *)new_tcb;
}

void *tcp_listen(uint16_t port)
{
    tcp_header header, resp;
    tcb *new_tcb = malloc(sizeof(*new_tcb));

    if (!new_tcb)
        return NULL;

    memset(&header, 0, sizeof(header));
    memset(new_tcb, 0, sizeof(*new_tcb));

    new_tcb->rx_buf_buffer = malloc(TCP_BUF_SZ);

    if (!new_tcb->rx_buf_buffer) {
        free(new_tcb);
        return NULL;
    }

    cbuf_init(&new_tcb->rx_buf, new_tcb->rx_buf_buffer, TCP_BUF_SZ);

    new_tcb->cur_seq_n = 1024;
    new_tcb->state = LISTEN;
    new_tcb->src_port = port;
    new_tcb->dst_port = 0;
    new_tcb->dst_ip = 0;

    mutex_lock(&tcp_mutex);

    list_insert_head(&tcb_head, &new_tcb->node);

    while (new_tcb->state == LISTEN)
        condvar_wait(&tcp_condvar, &tcp_mutex);

    if (new_tcb->state != SYN_RECEIVED) {
        free(new_tcb->rx_buf_buffer);
        free(new_tcb);
        new_tcb = NULL;
        goto out;
    }

    memset(&resp, 0, sizeof(resp));

    tcp_header_prepopulate(new_tcb, &resp);

    resp.syn = 1;
    resp.ack = 1;

    tcp_tx(resp, new_tcb->dst_ip, NULL, 0);

    while (new_tcb->state == SYN_RECEIVED)
        condvar_wait(&tcp_condvar, &tcp_mutex);

    if (new_tcb->state != ESTABLISHED) {
        free(new_tcb->rx_buf_buffer);
        free(new_tcb);
        new_tcb = NULL;
    }

out:
    mutex_unlock(&tcp_mutex);
    return (void *)new_tcb;
}

void tcp_tx_data(void *conn, void *data, size_t len)
{
    tcp_header header;
    void *payload;
    tcb *connection = (tcb *)conn;

    mutex_lock(&tcp_mutex);

    if (connection->state != ESTABLISHED)
        goto out;

    payload = malloc(len);

    if (!payload)
        goto out;

    memcpy(payload, data, len);

    memset(&header, 0, sizeof(header));

    tcp_header_prepopulate(connection, &header);

    header.ack = 1;

    connection->unacked_byte_count += len;

    tcp_tx(header, connection->dst_ip, payload, len);

    while (connection->unacked_byte_count)
        condvar_wait(&tcp_condvar, &tcp_mutex);

out:
    mutex_unlock(&tcp_mutex);
}

int tcp_rx_data(void *conn, void *dst_buf, size_t len)
{
    int ret = EINVAL;
    tcb *connection = (tcb *)conn;

    mutex_lock(&tcp_mutex);

    if (connection->state != ESTABLISHED)
        goto out;

    while (len) {
        size_t no_bytes_to_copy, bytes_in_buf;

        while (cbuf_size(&connection->rx_buf) == 0 &&
               connection->state == ESTABLISHED) {
            condvar_wait(&tcp_condvar, &tcp_mutex);
        }

        if (connection->state != ESTABLISHED)
            goto out;

        bytes_in_buf = cbuf_size(&connection->rx_buf);
        no_bytes_to_copy = bytes_in_buf > len ? len : bytes_in_buf;

        cbuf_pop(&connection->rx_buf, dst_buf, &no_bytes_to_copy);

        len -= no_bytes_to_copy;
        dst_buf += no_bytes_to_copy;
    }
    ret = 0;

out:
    mutex_unlock(&tcp_mutex);
    return ret;
}

void tcp_close(void *conn)
{
    tcb *connection = (tcb *)conn;

    if (connection->state == CLOSE_WAIT) {
        tcp_header our_fin;

        memset(&our_fin, 0, sizeof(our_fin));

        tcp_header_prepopulate(connection, &our_fin);

        our_fin.fin = 1;
        our_fin.ack = 1;

        tcp_tx(our_fin, connection->dst_ip, NULL, 0);

        connection->state = LAST_ACK;
    } else if (connection->state == ESTABLISHED) {
        tcp_header fin;

        memset(&fin, 0, sizeof(fin));

        tcp_header_prepopulate(connection, &fin);

        fin.ack = 1;
        fin.fin = 1;

        tcp_tx(fin, connection->dst_ip, NULL, 0);

        connection->cur_seq_n++;

        connection->state = FIN_WAIT1;
    }
}

static struct protocol_t tcp_protocol  = {
    .rx_pkt = tcp_rx_packet,
    .type = TCP,
    .name = "TCP"
};

void tcp_init(void)
{
    mutex_init(&tcp_mutex);
    condvar_init(&tcp_condvar);
    protocol_register(&tcp_protocol);
}
