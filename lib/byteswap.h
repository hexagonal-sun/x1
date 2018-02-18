#pragma once
#include <stdint.h>

/* Swap the endianess of a 16-bit value pointed to by val. */
void swap_endian16(uint16_t *val);

/* Swap the endianess of a 32-bit value pointed to by val. */
void swap_endian32(uint32_t *val);
