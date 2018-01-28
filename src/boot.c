/*
 * Copyright (c) 2017-2018 Richard Braun.
 * Copyright (c) 2017 Jerko Lenstra.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdint.h>
#include <string.h>

#include <lib/macros.h>
#include <lpc17xx.h>

#include "boot.h"
#include "cpu.h"
#include "main.h"

extern char _lma_data_addr;
extern char _data_start;
extern char _data_end;
extern char _bss_start;
extern char _bss_end;

void boot_main(void);

uint8_t boot_stack[BOOT_STACK_SIZE] __aligned(CPU_STACK_ALIGN);

static void
init_clocking(void)
{
    /* Enable the main oscillator and set the correct frequency range
     * (12Mhz). */
    LPC_SC->SCS = (1 << 5);

    /* Wait for Main oscillator startup. */
    while (!(LPC_SC->SCS & (1 << 6))) {};

    /* Set sysclk to the main oscillator. */
    LPC_SC->CLKSRCSEL = 0x1;

    /* Output from the PLL will be 300 Mhz.  We want to divide this
     * down by 3 to produce the CCLK of 100 Mhz. */
    LPC_SC->CCLKCFG = 0x2;

    /* We want an output of 300Mhz from the PLL.  Assuming a
     * pre-divide of 2, M = (300 * 2) / (2 * 12).  Therefore, set: M =
     * 25 and N = 2. */
    LPC_SC->PLL0CFG = 24 | (1 << 16);

    /* Provide the PLL feed sequence. */
    LPC_SC->PLL0FEED = 0xAA;
    LPC_SC->PLL0FEED = 0x55;

    /* Enable the PLL. */
    LPC_SC->PLL0CON = 0x01;

    /* Provide the PLL feed sequence. */
    LPC_SC->PLL0FEED = 0xAA;
    LPC_SC->PLL0FEED = 0x55;

    /* Wait for PLL0 lock */
    while (!(LPC_SC->PLL0STAT & (1 << 26))) {};

    /* Enable and connect PLL0 */
    LPC_SC->PLL0CON = 0x3;

    /* Provide the PLL feed sequence. */
    LPC_SC->PLL0FEED = 0xAA;
    LPC_SC->PLL0FEED = 0x55;

    /* Wait until PLL0 enable and connect. */
    while (!(LPC_SC->PLL0STAT & ((1 << 25) | (1 << 24)))) {};

    /* CPU should now be operating at 100 Mhz. */
}

static void
boot_copy_data(void)
{
    memcpy(&_data_start, &_lma_data_addr, &_data_end - &_data_start);
}

void
boot_main(void)
{
    cpu_intr_disable();
    boot_copy_data();
    init_clocking();
    main();
}
