/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __LAN966X_CONFIG_H
#define __LAN966X_CONFIG_H

#include <linux/sizes.h>

#define CONFIG_ARCH_CPU_INIT

#define CONFIG_BOARD_TYPES
#define CONFIG_SUPPORT_EMMC_BOOT

#define CONFIG_BOOTP_BOOTFILESIZE
#define PHY_ANEG_TIMEOUT                20000

#define CONFIG_SYS_SDRAM_BASE           0x60200000
#define CFG_SYS_INIT_RAM_ADDR           CONFIG_SYS_SDRAM_BASE
#define CFG_SYS_INIT_RAM_SIZE           0x400000

/* Important for relocation */
#define CFG_SYS_SDRAM_BASE              CONFIG_SYS_SDRAM_BASE

#define DDR_MEM_SIZE_DEF (SZ_1G - (SZ_1G / 8))	/* 1Gb with ECC enabled cost 1/8th capacity */
#define DDR_MEM_SIZE_MAX SZ_2G

#define CONFIG_SYS_MMC_ENV_DEV		0

#endif
