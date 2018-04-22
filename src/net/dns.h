#ifndef DNS_H_
#define DNS_H_

#include <stdint.h>

const char *dns_get_error(int ret);
int dns_resolve_ipv4(const char *hostname, uint32_t *ipv4_address);

#endif /* DNS_H_ */
