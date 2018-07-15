#pragma once
#include <stdint.h>

const char *dns_get_error(int ret);
int dns_resolve_ipv4(const char *hostname, uint32_t *ipv4_address);
