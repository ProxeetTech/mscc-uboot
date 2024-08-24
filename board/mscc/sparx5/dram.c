// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * Copyright (c) 2022 Microsemi Corporation
 */

#include <common.h>
#include <linux/libfdt.h>
#include <fdtdec.h>
#include <dm.h>

#include <ddr_init.h>
#include <ddr_reg.h>

#define DDR_PATTERN1 0xAAAAAAAAU
#define DDR_PATTERN2 0x55555555U

DECLARE_GLOBAL_DATA_PTR;

static uint32_t fdt_read_uint32(const void *fdt, int nodeoffset, const char *prop)
{
	const fdt32_t *ac;
	int len;

	ac = fdt_getprop(fdt, nodeoffset, prop, &len);
	if (!ac)
		panic("%s: no %s property\n", __func__, prop);

	return fdt32_to_cpu(*ac);
}

static void fdt_read_string(const void *fdt, int nodeoffset, const char *prop, char *s, size_t maxlen)
{
	const fdt32_t *ac;
	int len;

	ac = fdt_getprop(fdt, nodeoffset, prop, &len);
	if (!ac)
		panic("%s: no %s property\n", __func__, prop);

	strncpy(s, (void *)ac, maxlen);
}

static void fdt_read_array(const void *fdt, int nodeoffset, const char *prop, void *a, size_t nelm)
{
	int err =  fdtdec_get_int_array(fdt, nodeoffset, prop, a, nelm);

	if (err)
		panic("%s: no %s property\n", __func__, prop);
}

/*******************************************************************************
 * This function tests the DDR data bus wiring.
 * This is inspired from the Data Bus Test algorithm written by Michael Barr
 * in "Programming Embedded Systems in C and C++" book.
 * resources.oreilly.com/examples/9781565923546/blob/master/Chapter6/
 * File: memtest.c - This source code belongs to Public Domain.
 * Returns 0 if success, and address value else.
 ******************************************************************************/
static uintptr_t ddr_test_data_bus(void)
{
	uint32_t pattern;

	for (pattern = 1U; pattern != 0U; pattern <<= 1) {
		mmio_write_32(PHYS_DDR, pattern);

		if (mmio_read_32(PHYS_DDR) != pattern) {
			return (uintptr_t)PHYS_DDR;
		}
	}

	return 0;
}

/*******************************************************************************
 * This function tests the DDR address bus wiring.
 * This is inspired from the Data Bus Test algorithm written by Michael Barr
 * in "Programming Embedded Systems in C and C++" book.
 * resources.oreilly.com/examples/9781565923546/blob/master/Chapter6/
 * File: memtest.c - This source code belongs to Public Domain.
 * Returns 0 if success, and address value else.
 ******************************************************************************/
static uintptr_t ddr_test_addr_bus(struct ddr_config *config)
{
	uint64_t addressmask = (config->info.size - 1U);
	uint64_t offset;
	uint64_t testoffset = 0;

	/* Write the default pattern at each of the power-of-two offsets. */
	for (offset = sizeof(uint32_t); (offset & addressmask) != 0U; offset <<= 1) {
		mmio_write_32(PHYS_DDR + (uint32_t)offset, DDR_PATTERN1);
	}

	/* Check for address bits stuck high. */
	mmio_write_32(PHYS_DDR + (uint32_t)testoffset, DDR_PATTERN2);

	for (offset = sizeof(uint32_t); (offset & addressmask) != 0U; offset <<= 1) {
		if (mmio_read_32(PHYS_DDR + (uint32_t)offset) != DDR_PATTERN1) {
			return (uint32_t)(PHYS_DDR + offset);
		}
	}

	mmio_write_32(PHYS_DDR + (uint32_t)testoffset, DDR_PATTERN1);

	/* Check for address bits stuck low or shorted. */
	for (testoffset = sizeof(uint32_t); (testoffset & addressmask) != 0U; testoffset <<= 1) {
		mmio_write_32(PHYS_DDR + (uint32_t)testoffset, DDR_PATTERN2);

		if (mmio_read_32(PHYS_DDR) != DDR_PATTERN1) {
			return PHYS_DDR;
		}

		for (offset = sizeof(uint32_t); (offset & addressmask) != 0U;
		     offset <<= 1) {
			if ((mmio_read_32(PHYS_DDR +
					  (uint32_t)offset) != DDR_PATTERN1) &&
			    (offset != testoffset)) {
				return (uint32_t)(PHYS_DDR + offset);
			}
		}

		mmio_write_32(PHYS_DDR + (uint32_t)testoffset, DDR_PATTERN1);
	}

	return 0;
}

int dram_init(void)
{
	struct ddr_config config = { };
	const void *fdt = gd->fdt_blob;
	int node, ret;

	node = fdt_node_offset_by_compatible(fdt, -1, "microchip,ddr-umctl");
	if (node < 0)
		panic("%s: Cannot read DDR node in DT\n", __func__);

	/* Top-level config data */
	config.info.size = fdt_read_uint32(fdt, node, "microchip,mem-size");
	config.info.speed = fdt_read_uint32(fdt, node, "microchip,mem-speed");
	config.info.bus_width = fdt_read_uint32(fdt, node, "microchip,mem-bus-width");
	fdt_read_string(fdt, node, "microchip,mem-name", config.info.name, sizeof(config.info.name));

	/* Read param grups */
	fdt_read_array(fdt, node, "microchip,main-reg", &config.main, sizeof(config.main) / sizeof(uint32_t));
	fdt_read_array(fdt, node, "microchip,timing-reg", &config.timing, sizeof(config.timing) / sizeof(uint32_t));
	fdt_read_array(fdt, node, "microchip,mapping-reg", &config.mapping, sizeof(config.mapping) / sizeof(uint32_t));
	fdt_read_array(fdt, node, "microchip,phy-reg", &config.phy, sizeof(config.phy) / sizeof(uint32_t));
	fdt_read_array(fdt, node, "microchip,phy_timing-reg", &config.phy_timing, sizeof(config.phy_timing) / sizeof(uint32_t));

	ret = ddr_init(&config);
	if (ret)
		PANIC("DDR initialization returns %d\n", ret);

	if (!ret) {
		uintptr_t err_off;

		err_off = ddr_test_data_bus();
		if (err_off != 0)
			PANIC("DDR data bus test: can't access memory @ %p\n", (void*) err_off);

		err_off = ddr_test_addr_bus(&config);
		if (err_off != 0)
			PANIC("DDR address bus test: can't access memory @ %p\n", (void*) err_off);

		VERBOSE("Memory test passed\n");
	}

	memcpy((void *)VIRT_SDRAM_1, &config, sizeof(config));

	gd->ram_size = config.info.size;

	return 0;
}

void board_add_ram_info(int use_default)
{
	struct ddr_config *config = (void *)VIRT_SDRAM_1;
	int bus_width = config->info.bus_width;

	printf(" (%d MHz", config->info.speed);
	printf(", %s", (config->main.mstr & MSTR_DDR4) ? "DDR4" : "DDR3");
	if (FIELD_GET(MSTR_DATA_BUS_WIDTH, config->main.mstr) == 1) /* Half width */
		bus_width /= 2;
	if (FIELD_GET(MSTR_DATA_BUS_WIDTH, config->main.mstr) == 2) /* Quarter width */
		bus_width /= 4;
	printf(", %dbit", bus_width);
	printf(", %s", (config->main.ecccfg0 & ECCCFG0_ECC_MODE) ? "ECC" : "No ECC");
	if (config->main.mstr & MSTR_EN_2T_TIMING_MODE)
		puts(", 2T");
	if (config->info.name[0])
		printf(", %s", config->info.name);
	puts(")");
}
