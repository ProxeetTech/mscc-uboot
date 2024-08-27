/*
 * Copyright (C) 2023 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common.h>
#include <asm/io.h>
#include <asm/psci.h>
#include <asm/secure.h>
#include <asm/system.h>
#include <asm/spin_table.h>

#include "sparx5_regs.h"

#define MPIDR_AFF0			GENMASK(7, 0)

/*
 * Helper code
 */
static u8 psci_state[CONFIG_ARMV8_PSCI_NR_CPUS] __secure_data = {
	PSCI_AFFINITY_LEVEL_ON,
	PSCI_AFFINITY_LEVEL_OFF,
};

static int psci_reserve_memory(void *fdt, unsigned long rsv_start, unsigned long rsv_end, const char *what)
{
	int ret;

	ret = fdt_add_mem_rsv(fdt, rsv_start, rsv_end - rsv_start);
	if (ret)
		return -ENOSPC;

	printf("   Reserved memory region for %s: addr=%lx size=%lx\n",
	       what, rsv_start, rsv_end - rsv_start);

	return ret;
}

int psci_update_dt(void *fdt)
{
	int ret;

	fdt_psci(fdt);

	/* secure code lives in RAM, keep it alive */
	ret = psci_reserve_memory(fdt,
				  (unsigned long) __secure_start,
				  (unsigned long) __secure_end,
				  "secure PSCI");
	return ret;
}

__secure static void psci_set_state(int cpu, u8 state)
{
	psci_state[cpu] = state;
	dsb();
	isb();
}

__secure static s32 psci_cpu_on_validate_mpidr(u64 mpidr, u32 *cpu)
{
	*cpu = mpidr & MPIDR_AFF0;

	if (mpidr & ~MPIDR_AFF0)
		return ARM_PSCI_RET_INVAL;

	if (*cpu >= CONFIG_ARMV8_PSCI_NR_CPUS)
		return ARM_PSCI_RET_INVAL;

	if (psci_state[*cpu] == PSCI_AFFINITY_LEVEL_ON)
		return ARM_PSCI_RET_ALREADY_ON;

	if (psci_state[*cpu] == PSCI_AFFINITY_LEVEL_ON_PENDING)
		return ARM_PSCI_RET_ON_PENDING;

	return ARM_PSCI_RET_SUCCESS;
}

/*
 * Common PSCI code
 */
/* Return supported PSCI version */
__secure u32 psci_version(void)
{
	return ARM_PSCI_VER_1_0;
}

/*
 * 64bit PSCI code
 */
__secure s32 psci_cpu_on_64(u32 __always_unused function_id, u64 mpidr,
			    u64 entry_point_address, u64 context_id)
{
	u32 cpu = 0;
	int ret;

	ret = psci_cpu_on_validate_mpidr(mpidr, &cpu);
	if (ret != ARM_PSCI_RET_SUCCESS)
		return ret;

	/* Kick off secondary CPU */
	spin_table_cpu_release_addr = entry_point_address;
	asm volatile("sev");

	psci_set_state(cpu, PSCI_AFFINITY_LEVEL_ON);

	return ARM_PSCI_RET_SUCCESS;
}

__secure s32 psci_affinity_info_64(u32 __always_unused function_id,
				   u64 target_affinity, u32 lowest_affinity_level)
{
	u32 cpu = target_affinity & MPIDR_AFF0;

	if (lowest_affinity_level > 0)
		return ARM_PSCI_RET_INVAL;

	if (target_affinity & ~MPIDR_AFF0)
		return ARM_PSCI_RET_INVAL;

	if (cpu >= CONFIG_ARMV8_PSCI_NR_CPUS)
		return ARM_PSCI_RET_INVAL;

	return psci_state[cpu];
}

void __secure __noreturn psci_system_reset(void)
{
	/* Make sure the core is UN-protected from reset */
	clrbits_le32(CPU_RESET_PROT_STAT(SPARX5_CPU_BASE),
		     CPU_RESET_PROT_STAT_SYS_RST_PROT_VCORE_M);

	writel(GCB_SOFT_RST_SOFT_CHIP_RST_M, GCB_SOFT_RST(SPARX5_GCB_BASE));

	while (1)
		;
}

/*
 * 32bit PSCI code
 */
__secure s32 psci_affinity_info(u32 __always_unused function_id,
				u32 target_affinity, u32 lowest_affinity_level)
{
	return psci_affinity_info_64(function_id, target_affinity, lowest_affinity_level);
}

__secure s32 psci_cpu_on(u32 __always_unused function_id, u32 mpidr,
			 u32 entry_point_address, u32 context_id)
{
	return psci_cpu_on_64(function_id, mpidr, entry_point_address, context_id);
}

__secure u32 psci_migrate_info_type(void)
{
	/* Trusted OS is either not present or does not require migration */
	return 2;
}

/*
 * PSCI jump table
 */
__secure s32 psci_features(u32 __always_unused function_id, u32 psci_fid)
{
	switch (psci_fid) {
	case ARM_PSCI_0_2_FN_PSCI_VERSION:
	case ARM_PSCI_0_2_FN_CPU_ON:
	case ARM_PSCI_0_2_FN_AFFINITY_INFO:
	case ARM_PSCI_0_2_FN_MIGRATE_INFO_TYPE:
	case ARM_PSCI_0_2_FN_SYSTEM_RESET:
	case ARM_PSCI_0_2_FN64_CPU_ON:
	case ARM_PSCI_0_2_FN64_AFFINITY_INFO:

	/* PSCI 1.0 interface */
	case ARM_PSCI_1_0_FN_PSCI_FEATURES:

	/*
	 * Not implemented:
	 * ARM_PSCI_0_2_FN_CPU_OFF
	 * ARM_PSCI_0_2_FN64_CPU_SUSPEND
	 * ARM_PSCI_0_2_FN_CPU_SUSPEND
	 * ARM_PSCI_0_2_FN_SYSTEM_OFF
	 * ARM_PSCI_1_0_FN64_CPU_DEFAULT_SUSPEND
	 * ARM_PSCI_1_0_FN64_NODE_HW_STATE
	 * ARM_PSCI_1_0_FN64_STAT_COUNT
	 * ARM_PSCI_1_0_FN64_STAT_RESIDENCY
	 * ARM_PSCI_1_0_FN64_SYSTEM_SUSPEND
	 * ARM_PSCI_1_0_FN_CPU_DEFAULT_SUSPEND
	 * ARM_PSCI_1_0_FN_CPU_FREEZE
	 * ARM_PSCI_1_0_FN_NODE_HW_STATE
	 * ARM_PSCI_1_0_FN_SET_SUSPEND_MODE
	 * ARM_PSCI_1_0_FN_STAT_COUNT
	 * ARM_PSCI_1_0_FN_STAT_RESIDENCY
	 * ARM_PSCI_1_0_FN_SYSTEM_SUSPEND
	 */

	/* Not required, ARM_PSCI_0_2_FN_MIGRATE_INFO_TYPE returns 2 */
	case ARM_PSCI_0_2_FN_MIGRATE:
	case ARM_PSCI_0_2_FN64_MIGRATE:
	/* Not required */
	case ARM_PSCI_0_2_FN_MIGRATE_INFO_UP_CPU:
	case ARM_PSCI_0_2_FN64_MIGRATE_INFO_UP_CPU:
	default:
		return ARM_PSCI_RET_NI;
	}
}
