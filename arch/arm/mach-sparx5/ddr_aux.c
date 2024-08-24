// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * Copyright (c) 2022 Microsemi Corporation
 */

#include <common.h>
#include <asm/io.h>

#include <sparx5_regs.h>

#define DW_APB_LOAD_VAL		(SPARX5_TIMERS_BASE + (0*4))
#define DW_APB_CURR_VAL		(SPARX5_TIMERS_BASE + (1*4))
#define DW_APB_CTRL		(SPARX5_TIMERS_BASE + (2*4))
#define DW_APB_EOI		(SPARX5_TIMERS_BASE + (3*4))
#define DW_APB_INTSTAT		(SPARX5_TIMERS_BASE + (4*4))

#define CLOC_SPEED	(250 * 1000000) /* 250Mhz */
#define NS_PER_TICK	(1000000000/CLOC_SPEED) /* ns = (10 ** 9), ns/tick = 4 */

void ddr_nsleep(u32 t_nsec)
{
	/* init timer */
	t_nsec /= NS_PER_TICK;
	writel(t_nsec, DW_APB_LOAD_VAL);
	writel(0xffffffff, DW_APB_CURR_VAL);
	setbits_le32(DW_APB_CTRL, 0x3);
	while (readl(DW_APB_INTSTAT) == 0)
		;
	clrbits_le32(DW_APB_CTRL, 0x3);
	(void) readl(DW_APB_EOI);
}
