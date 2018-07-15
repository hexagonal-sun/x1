#pragma once
#include <stdint.h>

/* Perform a 3-way handshake and establish a TCP connection. */
void *tcp_connect(uint16_t port, uint32_t ip);

/* Listen for an incoming connection on a specific port. */
void *tcp_listen(uint16_t port);

/* Send data down an already-established TCP connection. */
void tcp_tx_data(void *connection, void *data, size_t len);

/* Receive data down an already-established TCP connection. */
int tcp_rx_data(void *connection, void *dst_buf, size_t len);

/* Closed an established TCP connection. */
void tcp_close(void *connection);
