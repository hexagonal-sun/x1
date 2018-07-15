#pragma once
#include <stdint.h>

/* Return a textual string that describes any errors returned by
 * `dns_resolve_ipv4'. */
const char *dns_get_error(int ret);

/* Attempt to resolve a given `hostname' into an `ipv4_address'.
 *
 * Returns 0 on success. */
int dns_resolve_ipv4(const char *hostname, uint32_t *ipv4_address);
