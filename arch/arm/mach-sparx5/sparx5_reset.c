/*
 * Copyright (C) 2021 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <ddr_init.h>
#include <ddr_reg.h>

static int clk_div(uint32_t speed)
{
	if (speed > 625 * 4)	/* 2500 */
		return 4;
	if (speed >= 500 * 4)	/* 2000 */
		return 5;
	if (speed >= 416 * 4)	/* 1664 */
		return 6;
	if (speed >= 312 * 4)	/* 1248 */
		return 8;
	if (speed >= 250 * 4)	/* 1000 */
		return 10;
	if (speed >= 208 * 4)	/* 832 */
		return 12;
	if (speed >= 156 * 4)	/* 624 */
		return 16;
	/* 125MHz */
	return 20;
}

void ddr_reset(const struct ddr_config *cfg , bool assert)
{
	if (assert) {
		VERBOSE("reset:assert\n");

		/* Set DDR clock frequency to match speed */
		mmio_write_32(CLKGEN_LCPLL1_DDR_CLK_CFG,
			      LCPLL1_DDR_CLK_CFG_DDR_CLK_ENA |
			      FIELD_PREP(LCPLL1_DDR_CLK_CFG_DDR_CLK_DIV,
					 clk_div(cfg->info.speed)));

		/* Settle */
		ddr_usleep(10);

		/* Assert resets */
		mmio_setbits_32(CPU_DDRCTRL_RST,
				DDRCTRL_RST_DDRC_RST |
				DDRCTRL_RST_DDR_AXI_RST |
				DDRCTRL_RST_DDR_APB_RST |
				DDRCTRL_RST_DDRPHY_CTL_RST |
				DDRCTRL_RST_DDRPHY_APB_RST);

		/* Start the clocks */
		mmio_setbits_32(CPU_DDRCTRL_CLK,
				DDRCTRL_CLK_DDR_CLK_ENA |
				DDRCTRL_CLK_DDR_AXI_CLK_ENA |
				DDRCTRL_CLK_DDR_APB_CLK_ENA |
				DDRCTRL_CLK_DDRPHY_CTL_CLK_ENA |
				DDRCTRL_CLK_DDRPHY_APB_CLK_ENA);

		/* Allow clocks to settle */
		ddr_nsleep(100);

		/* Deassert presetn once the clocks are active and stable */
		mmio_clrbits_32(CPU_DDRCTRL_RST, DDRCTRL_RST_DDR_APB_RST);

		ddr_nsleep(50);
	} else {
		VERBOSE("reset:deassert\n");

		ddr_nsleep(200);

		/* Deassert the core_ddrc_rstn reset */
		mmio_clrbits_32(CPU_RESET, RESET_MEM_RST);

		/* Deassert DDRC and AXI RST */
		mmio_clrbits_32(CPU_DDRCTRL_RST,
				DDRCTRL_RST_DDRC_RST |
				DDRCTRL_RST_DDR_AXI_RST);

		/* Settle */
		ddr_nsleep(100);

		/* Deassert DDRPHY_APB_RST and DRPHY_CTL_RST */
		mmio_clrbits_32(CPU_DDRCTRL_RST,
				DDRCTRL_RST_DDRPHY_APB_RST | DDRCTRL_RST_DDRPHY_CTL_RST);

		ddr_nsleep(100);
	}
}
