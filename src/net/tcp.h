#pragma once
#include <lib/list.h>
#include <lib/cbuf.h>
#include <stdint.h>

typedef struct {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_n;
    uint32_t ack_n;
    uint8_t __reserved_0 : 4;
    uint8_t data_offset : 4;
    uint8_t fin : 1;
    uint8_t syn : 1;
    uint8_t rst : 1;
    uint8_t psh : 1;
    uint8_t ack : 1;
    uint8_t urg : 1;
    uint8_t ece : 1;
    uint8_t cwr : 1;
    uint16_t window_sz;
    uint16_t checksum;
    uint16_t urg_ptr;
} __attribute__((packed)) tcp_header;

enum tcp_state {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    CLOSE_WAIT,
    LAST_ACK,
    FIN_WAIT1,
    FIN_WAIT2,
    CLOSING,
    TIME_WAIT
};

typedef struct
{
    uint32_t cur_seq_n;
    uint32_t cur_ack_n;
    uint32_t unacked_byte_count;
    struct cbuf rx_buf;
    void *rx_buf_buffer;
    enum tcp_state state;
    uint16_t timeout;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t host_window_sz;
    uint32_t dst_ip;
    uint8_t  decrement_timeout : 1;
    uint8_t  timed_out : 1;
    tcp_header *last_msg;
    struct list node;
} tcb;

/* Initialise the TCP layer. */
void tcp_init(void);

#define for_each_tcb(pos)                       \
    list_for_each_entry(&tcb_head, (pos), node)
