// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2015 Atmel Corporation
 *		      Wenyou.Yang <wenyou.yang@atmel.com>
 */

#include <common.h>
#include <cpu_func.h>
#include <debug_uart.h>
#include <asm/io.h>
#include <env_internal.h>
#include <fdtdec.h>
#include <linux/delay.h>
#include <phy.h>
#include <asm/arch/soc.h>

#include "lan966x_main.h"
#include "lan966x_cpu_regs.h"
#include "lan966x_top_regs_access.h"

#undef _DEBUG
#define _DEBUG 1

enum {
	BOARD_TYPE_LAN966X_PCB8291 = 1,
	BOARD_TYPE_LAN966X_PCB8290,
	BOARD_TYPE_LAN966X_PCB8281,
	BOARD_TYPE_LAN966X_PCB8281_RGMII,
	BOARD_TYPE_LAN966X_PCB8385,
};

DECLARE_GLOBAL_DATA_PTR;

const unsigned int lan966x_regs[NUM_TARGETS] = {
	0x0,				/*  0 */
	0x0,				/*  1 */
	0x0,				/*  2 */
	0x0,				/*  3 */
	0x0,				/*  4 */
	0xe2010000,			/*  5 (TARGET_CHIP_TOP)*/
	0xe00C0000,			/*  6 (TARGET_CPU) */
	0xe8843000,			/*  7 (TARGET_CPU_SYSCNT)*/
	0x0,				/*  8 */
	0x0,				/*  9 */
	0x0,				/* 10 */
	0xe0084000,			/* 11 (TARGET_DDR_PHY) */
	0xe0080000,			/* 12 (TARGET_DDR_UMCTL2) */
	0x0,				/* 13 */
	0x0,				/* 14 */
	0x0,				/* 15 */
	0x0,				/* 16 */
	0x0,				/* 17 */
	0x0,				/* 18 */
	0x0,				/* 19 */
	0x0,				/* 20 */
	0x0,				/* 21 */
	0x0,				/* 22 */
	0x0,				/* 23 */
	0x0,				/* 24 */
	0x0,				/* 25 */
	0x0,				/* 26 */
	0xe2004000,			/* 27 (TARGET_GCB) */
	0x0,				/* 28 */
	0x0,				/* 29 */
	0x0,				/* 30 */
	0xe0800000,			/* 31 (TARGET_HMATRIX2) */
	0x0,				/* 32 */
	0x0,				/* 33 */
	0x0,				/* 34 */
	0x0,				/* 35 */
	0x0,				/* 36 */
	0x0,				/* 37 */
	0x0,				/* 38 */
	0x0,				/* 39 */
	0x0,				/* 40 */
	0x0,				/* 41 */
	0x0,				/* 42 */
	0x0,				/* 43 */
	0x0,				/* 44 */
	0x0,				/* 45 */
	0x0,				/* 46 */
	0x0,				/* 47 */
	0x0,				/* 48 */
	0x0,				/* 49 */
	0x0,				/* 50 */
	0x0,				/* 51 */
	0x0,				/* 52 */
	0x0,				/* 53 */
	0xe008c000,			/* 54 (TARGET_TIMERS) */
	0x0,				/* 55 */
	0x0,				/* 56 */
	0x0,				/* 57 */
	0x0,				/* 58 */
	0x0,				/* 59 */
	0x0,				/* 60 */
	0x0,				/* 61 */
	0x0,				/* 62 */
	0x0,				/* 63 */
	0x0,				/* 64 */
	0x0,				/* 65 */
};

u32 lan966x_readl(u32 id, u32 tinst, u32 tcnt,
		  u32 gbase, u32 ginst, u32 gcnt, u32 gwidth,
		  u32 raddr, u32 rinst, u32 rcnt, u32 rwidth)
{
	u32 val, addr;

	addr = lan966x_regs[id + (tinst)] + gbase + ((ginst) * gwidth) + raddr + ((rinst) * rwidth);
	val = readl(addr);

	debug("read addr %x val %x\n", addr, val);
	return val;
}

void lan966x_writel(u32 id, u32 tinst, u32 tcnt,
		    u32 gbase, u32 ginst, u32 gcnt, u32 gwidth,
		    u32 raddr, u32 rinst, u32 rcnt, u32 rwidth,
		    u32 val)
{
	u32 addr;

	addr = lan966x_regs[id + (tinst)] + gbase + ((ginst) * gwidth) + raddr + ((rinst) * rwidth);
	writel(val, addr);

	debug("write addr %x val: %x\n", addr, val);
}

#ifdef CONFIG_DEBUG_UART_BOARD_INIT
void board_debug_uart_init(void)
{
	uint32_t gpio;

#ifdef CONFIG_TARGET_LAN966X_EVB
	// ALT1: gpio52(RXD), gpio53(TXD)
	gpio = REG_RD(GCB_GPIO_ALT1(0)) |  ((1<<(52 - 32)) | (1<<(53 - 32)));
	REG_WR(GCB_GPIO_ALT1(0), gpio);

	gpio = REG_RD(GCB_GPIO_ALT1(1)) & ~((1<<(52 - 32)) | (1<<(53 - 32)));
	REG_WR(GCB_GPIO_ALT1(1), gpio);

	gpio = REG_RD(GCB_GPIO_ALT1(2)) & ~((1<<(52 - 32)) | (1<<(53 - 32)));
	REG_WR(GCB_GPIO_ALT1(2), gpio);

	/* switch flexcom 3 to USART mode */
	writel(1, (uint32_t volatile*)0xE0064000);
#endif

#ifdef CONFIG_TARGET_LAN966X_SVB
	// ALT1: gpio25(RXD), gpio26(TXD)
	gpio = REG_RD(GCB_GPIO_ALT(0)) |  ((1<<(25)) | (1<<(26)));
	REG_WR(GCB_GPIO_ALT(0), gpio);

	gpio = REG_RD(GCB_GPIO_ALT(1)) & ~((1<<(25)) | (1<<(26)));
	REG_WR(GCB_GPIO_ALT(1), gpio);

	gpio = REG_RD(GCB_GPIO_ALT(2)) & ~((1<<(25)) | (1<<(26)));
	REG_WR(GCB_GPIO_ALT(2), gpio);

	/* switch flexcom 0 to USART mode */
	writel(1, (uint32_t volatile*)0xE0040000);
#endif
}
#endif

typedef enum {
	LAN966X_STRAP_BOOT_MMC_FC = 0,
	LAN966X_STRAP_BOOT_QSPI_FC = 1,
	LAN966X_STRAP_BOOT_SD_FC = 2,
	LAN966X_STRAP_BOOT_MMC = 3,
	LAN966X_STRAP_BOOT_QSPI = 4,
	LAN966X_STRAP_BOOT_SD = 5,
	LAN966X_STRAP_PCIE_ENDPOINT = 6,
	LAN966X_STRAP_BOOT_MMC_TFAMON_FC = 7,
	LAN966X_STRAP_BOOT_QSPI_TFAMON_FC = 8,
	LAN966X_STRAP_BOOT_SD_TFAMON_FC = 9,
	LAN966X_STRAP_TFAMON_FC0 = 10,
	LAN966X_STRAP_TFAMON_FC2 = 11,
	LAN966X_STRAP_TFAMON_FC3 = 12,
	LAN966X_STRAP_TFAMON_FC4 = 13,
	LAN966X_STRAP_TFAMON_USB = 14,
	LAN966X_STRAP_SPI_SLAVE = 15,
} soc_strapping;

static soc_strapping get_strapping(void)
{
	soc_strapping boot_mode;

	boot_mode = REG_RD(CPU_GPR(0));
	if (boot_mode == 0)
		boot_mode = REG_RD(CPU_GENERAL_STAT);

	boot_mode = CPU_GENERAL_STAT_VCORE_CFG_X(boot_mode);

	return boot_mode;
}

static boot_source_type_t get_boot_source(void)
{
       boot_source_type_t boot_source;

       switch (get_strapping()) {
       case LAN966X_STRAP_BOOT_MMC:
       case LAN966X_STRAP_BOOT_MMC_FC:
       case LAN966X_STRAP_BOOT_MMC_TFAMON_FC:
               boot_source = BOOT_SOURCE_EMMC;
               break;
       case LAN966X_STRAP_BOOT_QSPI:
       case LAN966X_STRAP_BOOT_QSPI_FC:
       case LAN966X_STRAP_BOOT_QSPI_TFAMON_FC:
               boot_source = BOOT_SOURCE_QSPI;
               break;
       case LAN966X_STRAP_BOOT_SD:
       case LAN966X_STRAP_BOOT_SD_FC:
       case LAN966X_STRAP_BOOT_SD_TFAMON_FC:
               boot_source = BOOT_SOURCE_SDMMC;
               break;
               /* These modes are not in LAN966X B0 */
       default:
               boot_source = BOOT_SOURCE_NONE;
               break;
       }

       return boot_source;
}

int board_late_init(void)
{
	boot_source_type_t boot_source;

	lan966x_otp_init();

	boot_source = tfa_get_boot_source();
	if (boot_source == BOOT_SOURCE_NONE)
		boot_source = get_boot_source();

	switch (boot_source) {
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
		u16 pcb;
		if (lan966x_otp_get_pcb(&pcb)) {
			if (pcb == 8291)
				env_set("pcb", "lan9662_ung8291_0_at_lan966x");
			if (pcb == 8290)
				env_set("pcb", "lan9668_ung8290_0_at_lan966x");
			if (pcb == 8309)
				env_set("pcb", "lan9662_ung8309_0_at_lan966x");
		} else {
			if (gd->board_type == BOARD_TYPE_LAN966X_PCB8290)
				env_set("pcb", "lan9668_ung8290_0_at_lan966x");
			if (gd->board_type == BOARD_TYPE_LAN966X_PCB8291)
				env_set("pcb", "lan9662_ung8291_0_at_lan966x");
			if (gd->board_type == BOARD_TYPE_LAN966X_PCB8385)
				env_set("pcb", "lan9668_ung8385_0_at_lan966x");
			if (gd->board_type == BOARD_TYPE_LAN966X_PCB8281)
				env_set("pcb", "lan9668_ung8281_0_at_lan966x");
			if (gd->board_type == BOARD_TYPE_LAN966X_PCB8281_RGMII)
				env_set("pcb", "lan9668_ung8281_rgmii_0_at_lan966x");
		}
	}

	if (!env_get("mac_count")) {
		char text[20];
		if (lan966x_otp_get_mac_count(text))
			env_set("mac_count", text);
	}

	if (!env_get("ethaddr")) {
		u8 mac[6];
		if (lan966x_otp_get_mac(mac)) {
			mac[5] = 1;
			eth_env_set_enetaddr("ethaddr", mac);
			mac[5] = 2;
			eth_env_set_enetaddr("eth1addr", mac);

			if (gd->board_type == BOARD_TYPE_LAN966X_PCB8290 ||
			    gd->board_type == BOARD_TYPE_LAN966X_PCB8385) {
				mac[5] = 3;
				eth_env_set_enetaddr("eth2addr", mac);
				mac[5] = 4;
				eth_env_set_enetaddr("eth3addr", mac);
				mac[5] = 5;
				eth_env_set_enetaddr("eth4addr", mac);
				mac[5] = 6;
				eth_env_set_enetaddr("eth5addr", mac);
				mac[5] = 7;
				eth_env_set_enetaddr("eth6addr", mac);
				mac[5] = 8;
				eth_env_set_enetaddr("eth7addr", mac);
			}
		}
	}

	if (!env_get("serial_number")) {
		char text[20];
		if (lan966x_otp_get_serial_number(text))
			env_set("serial_number", text);
	}

	if (!env_get("partid")) {
		char text[20];
		if (lan966x_otp_get_partid(text))
			env_set("partid", text);
	}

	if (env_get("serial")) {
		struct udevice *devp;
		int node;

		node = fdt_path_offset(gd->fdt_blob, env_get("serial"));
		if (node < 0)
			goto skip_serial;

		if (!uclass_get_device_by_of_offset(UCLASS_SERIAL, node, &devp))
			gd->cur_serial_dev = devp;
	}

skip_serial:
	if (env_get("console") &&
	    gd->board_type == BOARD_TYPE_LAN966X_PCB8290 &&
	    !env_get("lan9668,stop_console_update"))
		env_set("console", "ttyGS0,115200");

	return 0;
}

static void board_pcb8290_init(void)
{
	u32 val;

	/* If board PCB8290, to access the external PHY the GPIO 53 needs to be
	 * output enabled and toggled to a value of 1 */
	val = REG_RD(GCB_GPIO_ALT1(0));
	val &= ~BIT(53 - 32);
	REG_WR(GCB_GPIO_ALT1(0), val);

	val = REG_RD(GCB_GPIO_ALT1(1));
	val &= ~BIT(53 - 32);
	REG_WR(GCB_GPIO_ALT1(1), val);

	val = REG_RD(GCB_GPIO_ALT1(2));
	val &= ~BIT(53 - 32);
	REG_WR(GCB_GPIO_ALT1(2), val);

	val = REG_RD(GCB_GPIO_OE1);
	val |= BIT(53 - 32);
	REG_WR(GCB_GPIO_OE1, val);

	/* Toggle GPIO, otherwise sometimes the PHY can't be accessed */
	val = REG_RD(GCB_GPIO_OUT_SET1);
	val |= BIT(53 - 32);
	REG_WR(GCB_GPIO_OUT_SET1, val);

	val = REG_RD(GCB_GPIO_OUT_CLR1);
	val |= BIT(53 - 32);
	REG_WR(GCB_GPIO_OUT_CLR1, val);

	val = REG_RD(GCB_GPIO_OUT_SET1);
	val |= BIT(53 - 32);
	REG_WR(GCB_GPIO_OUT_SET1, val);

	/* Set GPIO 60 output low */
	val = REG_RD(GCB_GPIO_ALT1(0));
	val &= ~BIT(60 - 32);
	REG_WR(GCB_GPIO_ALT1(0), val);

	val = REG_RD(GCB_GPIO_ALT1(1));
	val &= ~BIT(60 - 32);
	REG_WR(GCB_GPIO_ALT1(1), val);

	val = REG_RD(GCB_GPIO_ALT1(2));
	val &= ~BIT(60 - 32);
	REG_WR(GCB_GPIO_ALT1(2), val);

	val = REG_RD(GCB_GPIO_OE1);
	val |= BIT(60 - 32);
	REG_WR(GCB_GPIO_OE1, val);

	val = REG_RD(GCB_GPIO_OUT_CLR1);
	val |= BIT(60 - 32);
	REG_WR(GCB_GPIO_OUT_CLR1, val);

	/* Set GPIO 61 alt mode 2 */
	val = REG_RD(GCB_GPIO_ALT1(0));
	val &= ~BIT(61 - 32);
	REG_WR(GCB_GPIO_ALT1(0), val);

	val = REG_RD(GCB_GPIO_ALT1(1));
	val |= BIT(61 - 32);
	REG_WR(GCB_GPIO_ALT1(1), val);

	val = REG_RD(GCB_GPIO_ALT1(2));
	val &= ~BIT(61 - 32);
	REG_WR(GCB_GPIO_ALT1(2), val);
}

static void board_pcb8281_rgmii_init(void)
{
	u32 val;

	val = REG_RD(CHIP_TOP_GPIO_CFG(28));
	val &= ~CHIP_TOP_GPIO_CFG_DS_M;
	val |= CHIP_TOP_GPIO_CFG_DS(0);
	REG_WR(CHIP_TOP_GPIO_CFG(28), val);

	val = REG_RD(CHIP_TOP_GPIO_CFG(29));
	val &= ~CHIP_TOP_GPIO_CFG_DS_M;
	val |= CHIP_TOP_GPIO_CFG_DS(0);
	REG_WR(CHIP_TOP_GPIO_CFG(29), val);
}

static void board_pcb8291_init(void)
{
	u32 val;

	/* Set GPIO 29 alt mode 2 for PCIe reset */
	val = REG_RD(GCB_GPIO_ALT(0));
	val &= ~BIT(29);
	REG_WR(GCB_GPIO_ALT(0), val);

	val = REG_RD(GCB_GPIO_ALT(1));
	val |= BIT(29);
	REG_WR(GCB_GPIO_ALT(1), val);

	val = REG_RD(GCB_GPIO_ALT(2));
	val &= ~BIT(29);
	REG_WR(GCB_GPIO_ALT(2), val);
}

int board_init(void)
{
	if (gd->board_type == BOARD_TYPE_LAN966X_PCB8290)
		board_pcb8290_init();

	if (gd->board_type == BOARD_TYPE_LAN966X_PCB8281_RGMII)
		board_pcb8281_rgmii_init();

	if (gd->board_type == BOARD_TYPE_LAN966X_PCB8291 ||
	    gd->board_type == BOARD_TYPE_LAN966X_PCB8385)
		board_pcb8291_init();

	return 0;
}

int dram_init(void)
{
	gd->ram_size = tfa_get_dram_size();

	/* Fall-back to compile-time default */
	if (!gd->ram_size)
		gd->ram_size = DDR_MEM_SIZE_DEF;

	return 0;
}

static void ca7_enable_smp(void)
{
	/* asm code to enable ACTLR.SMP . this is needed for SCU for L2 cache */
	asm  volatile (
		"MRC p15, 0, R1, c1, c0, 1;"
		"ORR R1, R1, #64;"
		"MCR p15, 0, R1, c1, c0, 1;"
	);
}

static void ca7_enable_icache(void)
{
	asm  volatile (
		"mrc 	p15, 0, r1, c1, c0, 0;"
		"orr 	r1, r1, #1<<12;"
		"mcr	p15, 0, r1, c1, c0, 0;"
	);
}

static void ca7_enable_dcache(void)
{
	asm  volatile (
		"mrc 	p15, 0, r1, c1, c0, 0;"
		"orr 	r1, r1, #1<<2;"
		"mcr	p15, 0, r1, c1, c0, 0;"
	);
}

void enable_caches(void)
{
	icache_enable();
	dcache_enable();
}

int mach_cpu_init(void)
{
	ca7_enable_smp();
	ca7_enable_icache();
	ca7_enable_dcache();

	return 0;
}

int board_early_init_f(void)
{
#if defined(CONFIG_DEBUG_UART)
	debug_uart_init();
#endif

	return 0;
}

void reset_cpu(void)
{
	REG_RMW(CPU_RESET_PROT_STAT_SYS_RST_PROT_VCORE(0),
		CPU_RESET_PROT_STAT_SYS_RST_PROT_VCORE_M,
		CPU_RESET_PROT_STAT);

	REG_WR(GCB_SOFT_RST, GCB_SOFT_RST_SOFT_SWC_RST(1));
}

enum env_location env_get_location(enum env_operation op, int prio)
{
	boot_source_type_t boot_source = tfa_get_boot_source();

	if (boot_source == BOOT_SOURCE_NONE)
		boot_source = get_boot_source();

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

static void print_debug_board(void)
{
	u32 strapping = get_strapping();
	if (strapping == LAN966X_STRAP_BOOT_MMC_FC ||
	    strapping == LAN966X_STRAP_BOOT_QSPI_FC ||
	    strapping == LAN966X_STRAP_BOOT_SD_FC)
		debug("board type: %ld\n", gd->board_type);
}

#ifdef CONFIG_TARGET_LAN966X_SVB
static int lan966x_svb_do_board_detect(void)
{
	uint32_t tmp;

	/* Try to access the PHY on external MDIO, if it is present then
	 * it is BOARD_TYPE_LAN966X_PCB8281_RGMII, otherwise is
	 * BOARD_TYPE_LAN966X_PCB8281. To do that first we need to get access
	 * MDIO bus by setting the ALT mode 1 for GPIO 28 and 29.
	 */
	tmp = REG_RD(GCB_GPIO_ALT(0)) |  ((1<<(28)) | (1<<(29)));
	REG_WR(GCB_GPIO_ALT(0), tmp);

	tmp = REG_RD(GCB_GPIO_ALT(1)) & ~((1<<(28)) | (1<<(29)));
	REG_WR(GCB_GPIO_ALT(1), tmp);

	tmp = REG_RD(GCB_GPIO_ALT(2)) & ~((1<<(28)) | (1<<(29)));
	REG_WR(GCB_GPIO_ALT(2), tmp);

	/* Now try to read from the external MDIO bus at address 3 register 2,
	 * there is where the lan8841 is present
	 */
	REG_WR(GCB_MII_CMD(0),
	       GCB_MII_CMD_CMD_VLD(1) |
	       GCB_MII_CMD_CMD_PHYAD(3) |
	       GCB_MII_CMD_CMD_REGAD(2) |
	       GCB_MII_CMD_CMD_OPR_FIELD(2));
	udelay(100);
	tmp = REG_RD(GCB_MII_DATA(0));

	/* In case of error, we presume that there is no PHY */
	if (tmp & (0x2 << 16))
		return BOARD_TYPE_LAN966X_PCB8281;

	return BOARD_TYPE_LAN966X_PCB8281_RGMII;
}
#endif

static void do_board_detect(void)
{
#ifdef CONFIG_TARGET_LAN966X_EVB
	u32 gpio[3];
	u32 val;
	u32 oe;

	REG_RMW(CHIP_TOP_GPIO_CFG_PD(1) |
		CHIP_TOP_GPIO_CFG_PU(0),
		CHIP_TOP_GPIO_CFG_PD_M |
		CHIP_TOP_GPIO_CFG_PU_M,
		CHIP_TOP_GPIO_CFG(24));

	udelay(10);

	if (!(REG_RD(GCB_GPIO_IN) & BIT(24)))
	    gd->board_type = BOARD_TYPE_LAN966X_PCB8291;

	REG_RMW(CHIP_TOP_GPIO_CFG_PD(0) |
		CHIP_TOP_GPIO_CFG_PU(1),
		CHIP_TOP_GPIO_CFG_PD_M |
		CHIP_TOP_GPIO_CFG_PU_M,
		CHIP_TOP_GPIO_CFG(24));

	/* Is it pcb8291 */
	if (gd->board_type != 0)
		goto out;

	/* Now it can be pcb8290 or pcb8384, but first need to save alt mode
	 * so we can restore it back
	 */
	gpio[0] = REG_RD(GCB_GPIO_ALT1(0));
	gpio[1] = REG_RD(GCB_GPIO_ALT1(1));
	gpio[2] = REG_RD(GCB_GPIO_ALT1(2));
	oe = REG_RD(GCB_GPIO_OE1);

	val = oe & ~BIT(53 -32);
	REG_WR(GCB_GPIO_OE1, val);

	REG_WR(GCB_GPIO_ALT1(0), gpio[0] & ~(1 << (53 - 32)));
	REG_WR(GCB_GPIO_ALT1(1), gpio[1] & ~(1 << (53 - 32)));
	REG_WR(GCB_GPIO_ALT1(2), gpio[2] & ~(1 << (53 - 32)));

	if (REG_RD(GCB_GPIO_IN1) & BIT(53 - 32))
		gd->board_type = BOARD_TYPE_LAN966X_PCB8385;
	else
		gd->board_type = BOARD_TYPE_LAN966X_PCB8290;

	/* Now restore everything back */
	REG_WR(GCB_GPIO_OE1, oe);
	REG_WR(GCB_GPIO_ALT1(0), gpio[0]);
	REG_WR(GCB_GPIO_ALT1(1), gpio[1]);
	REG_WR(GCB_GPIO_ALT1(2), gpio[2]);
out:
#endif
#ifdef CONFIG_TARGET_LAN966X_SVB
	gd->board_type = lan966x_svb_do_board_detect();
#endif

	print_debug_board();
}

#if defined(CONFIG_MULTI_DTB_FIT)
int board_fit_config_name_match(const char *name)
{
	if (gd->board_type == 0)
		do_board_detect();

	if (gd->board_type == BOARD_TYPE_LAN966X_PCB8290 &&
	    strcmp(name, "lan966x_pcb8290") == 0)
		return 0;

	if (gd->board_type == BOARD_TYPE_LAN966X_PCB8291 &&
	    strcmp(name, "lan966x_pcb8291") == 0)
		return 0;

	if (gd->board_type == BOARD_TYPE_LAN966X_PCB8385 &&
	    strcmp(name, "lan966x_pcb8385") == 0)
		return 0;

	if (gd->board_type == BOARD_TYPE_LAN966X_PCB8281 &&
	    strcmp(name, "lan966x_pcb8281") == 0)
		return 0;

	if (gd->board_type == BOARD_TYPE_LAN966X_PCB8281_RGMII &&
	    strcmp(name, "lan966x_pcb8281_rgmii") == 0)
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

int print_cpuinfo(void)
{
	printf("CPU: Cortex ARM A7\n");
	return 0;
}
