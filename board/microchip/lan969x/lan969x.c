// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * Copyright (C) 2022 Microchip Technology Inc. and its subsidiaries.
 */

#include <common.h>
#include <asm/io.h>
#include <asm/armv8/cpu.h>
#include <asm/armv8/mmu.h>
#include <debug_uart.h>
#include <linux/sizes.h>
#include <asm/global_data.h>
#include <env.h>
#include <env_internal.h>

#include <asm/arch/soc.h>
#include <asm/arch/lan969x_targets_a0.h>
#include <asm/arch/lan969x_regs_a0.h>

DECLARE_GLOBAL_DATA_PTR;

enum {
	BOARD_TYPE_SUNRISE,
	BOARD_TYPE_EV23X71A = 100, /* PCB8398 */
	BOARD_TYPE_PCB10001 = 200, /* SVB */
};

static struct mm_region fa_mem_map[] = {
        {
                .virt = PHYS_SDRAM_1,
                .phys = PHYS_SDRAM_1,
                .size = PHYS_SDRAM_1_SIZE,
                .attrs = PTE_BLOCK_MEMTYPE(MT_NORMAL) |
                         PTE_BLOCK_INNER_SHARE
        }, {
                .virt = LAN969X_QSPI0_MMAP,
                .phys = LAN969X_QSPI0_MMAP,
                .size = LAN969X_QSPI0_RANGE,
                .attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
                         PTE_BLOCK_NON_SHARE |
                         PTE_BLOCK_PXN | PTE_BLOCK_UXN
        }, {
                .virt = LAN969X_DEV_BASE,
                .phys = LAN969X_DEV_BASE,
                .size = LAN969X_DEV_SIZE,
                .attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
                         PTE_BLOCK_NON_SHARE |
                         PTE_BLOCK_PXN | PTE_BLOCK_UXN
        }, {
                /* List terminator */
                0,
        }
};
struct mm_region *mem_map = fa_mem_map;

enum env_location env_get_location(enum env_operation op, int prio)
{
	boot_source_type_t boot_source = tfa_get_boot_source();

	switch(boot_source) {
	case BOOT_SOURCE_EMMC:
		return prio == 0 ? ENVL_MMC : ENVL_UNKNOWN;
	case BOOT_SOURCE_QSPI:
		return prio == 0 ? ENVL_SPI_FLASH : ENVL_UNKNOWN;
	case BOOT_SOURCE_SDMMC:
		return prio == 0 ? ENVL_FAT : ENVL_UNKNOWN;
	default:
		return ENVL_UNKNOWN;
	}
}

void reset_cpu(void)
{
	clrbits_le32(CPU_RESET_PROT_STAT(LAN969X_CPU_BASE),
		     CPU_RESET_PROT_STAT_SYS_RST_PROT_VCORE_M);

	out_le32(GCB_SOFT_RST(LAN969X_GCB_BASE), GCB_SOFT_RST_SOFT_CHIP_RST(1));
}

int print_cpuinfo(void)
{
	printf("CPU:   ARM A53\n");
	return 0;
}

int dram_init(void)
{
	gd->ram_size = tfa_get_dram_size();

	/* Fall-back to compile-time default */
	if (!gd->ram_size)
		gd->ram_size = LAN969X_DDR_SIZE_DEF;

	return 0;
}

static void do_board_detect(void)
{
	/* CPU_BUILDID != 0 on FPGA */
	if (in_le32(CPU_BUILDID(LAN969X_CPU_BASE)) != 0) {
		/* Sunrise FPGA board */
		gd->board_type = BOARD_TYPE_SUNRISE;
		return;
	}

	/* Probe TFA for board type */
	gd->board_type = tfa_get_board_number();

	/* If SVB, just take that for face value */
	if (gd->board_type == BOARD_TYPE_PCB10001)
		return;

	/* EVB is default board (for now) */
	gd->board_type = BOARD_TYPE_EV23X71A;

	return;
}

#if defined(CONFIG_MULTI_DTB_FIT)
int board_fit_config_name_match(const char *name)
{
	if (gd->board_type == 0)
		do_board_detect();

	if (gd->board_type == BOARD_TYPE_SUNRISE &&
	    strcmp(name, "lan969x_sr") == 0)
		return 0;

	if (gd->board_type == BOARD_TYPE_EV23X71A &&
	    strcmp(name, "lan969x_ev23x71a") == 0)
		return 0;

	if (gd->board_type == BOARD_TYPE_PCB10001 &&
	    strcmp(name, "lan969x_pcb10001") == 0)
		return 0;

	return -1;
}
#endif

#if defined(CONFIG_DTB_RESELECT)
int embedded_dtb_select(void)
{
	do_board_detect();
	fdtdec_setup();

	return 0;
}
#endif

static int lan969x_ev23x71a_board_init(void)
{
	u32 val;

	/* Release the reset of the PHYs, for the lan8814 PHYs.
	 * For the lan8840 PHY, it gets out of reset when chip gets out
	 * of reset
	 */
	val = in_le32(GCB_GPIO_ALT1(LAN969X_GCB_BASE, 0));
	val &= ~BIT(62 - 32);
	out_le32(GCB_GPIO_ALT1(LAN969X_GCB_BASE, 0), val);

	val = in_le32(GCB_GPIO_ALT1(LAN969X_GCB_BASE, 1));
	val &= ~BIT(62 - 32);
	out_le32(GCB_GPIO_ALT1(LAN969X_GCB_BASE, 1), val);

	val = in_le32(GCB_GPIO_ALT1(LAN969X_GCB_BASE, 2));
	val &= ~BIT(62 - 32);
	out_le32(GCB_GPIO_ALT1(LAN969X_GCB_BASE, 2), val);

	val = in_le32(GCB_GPIO_OE1(LAN969X_GCB_BASE));
	val |= BIT(62 - 32);
	out_le32(GCB_GPIO_OE1(LAN969X_GCB_BASE), val);

	val = in_le32(GCB_GPIO_OUT_SET1(LAN969X_GCB_BASE));
	val |= BIT(62 - 32);
	out_le32(GCB_GPIO_OUT_SET1(LAN969X_GCB_BASE), val);

	return 0;
}

int board_init(void)
{
	if (gd->board_type == BOARD_TYPE_EV23X71A)
		return lan969x_ev23x71a_board_init();

	return 0;
}

int board_late_init(void)
{
	switch (tfa_get_boot_source()) {
	case BOOT_SOURCE_EMMC:
		env_set("boot_source", "mmc");
		break;
	case BOOT_SOURCE_QSPI:
		env_set("boot_source", "nor");
		break;
	case BOOT_SOURCE_SDMMC:
		env_set("boot_source", "sd");
		break;
	default:
		env_set("boot_source", "");
	}

	if (!env_get("pcb")) {
		if (gd->board_type == BOARD_TYPE_EV23X71A)
			env_set("pcb", "lan9698_ev23x71a_0_at_lan969x");
		if (gd->board_type == BOARD_TYPE_SUNRISE)
			env_set("pcb", "lan9664_sunrise_0_at_lan969x");
		if (gd->board_type == BOARD_TYPE_PCB10001)
			env_set("pcb", "lan9668_pcb10001_0_at_lan969x");
	}

	return 0;
}

#ifdef CONFIG_DEBUG_UART_BOARD_INIT
void board_debug_uart_init(void)
{
	u32 gpio;

	/* Set GPIO 3 and 4 for ALT 1 to be used by FC0 */
	gpio = in_le32(GCB_GPIO_ALT(LAN969X_GCB_BASE, 0));
	gpio |= BIT(3) | BIT(4);
	out_le32(GCB_GPIO_ALT(LAN969X_GCB_BASE, 0), gpio);

	gpio = in_le32(GCB_GPIO_ALT(LAN969X_GCB_BASE, 1));
	gpio &= ~(BIT(3) | BIT(4));
	out_le32(GCB_GPIO_ALT(LAN969X_GCB_BASE, 1), gpio);

	gpio = in_le32(GCB_GPIO_ALT(LAN969X_GCB_BASE, 1));
	gpio &= ~(BIT(3) | BIT(4));
	out_le32(GCB_GPIO_ALT(LAN969X_GCB_BASE, 1), gpio);
}
#endif

int arch_cpu_init(void)
{
	return 0;
}

int mach_cpu_init(void)
{
	return 0;
}
