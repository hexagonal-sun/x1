#pragma once
#include <stdint.h>

/* Listen for incoming UDP packets on this particular port.  This
 * should be called before `rdp_rx_data'. */
void *udp_listen(uint16_t port);

/* Free a previously opened handle returned by `udp_listen'. */
void udp_free(void *udp);

/* Receive datagrams for a given udp listener (previously created with
 * `udp_listen') into dst_buf and return when buf_len bytes have been
 * received. */
int udp_rx_data(void *udp, void *dst_buf, uint16_t buf_len);

/* Transmit a payload of `payload_len' bytes, pointed to by `payload',
 * to `dst_ip' and `dst_port' from `src_port'.
 *
 * Note: No splitting of the payload is done; ensure that payload_len
 * is less than the MTU.
 *
 * Returns number of bytes transmitted.  On error <0 is returned.
 */
int udp_xmit_packet(uint16_t src_port, uint16_t dst_port, uint32_t dst_ip,
                     void *payload, int payload_len);
