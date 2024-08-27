#include <asm/arch/soc.h>
#include <linux/arm-smccc.h>

#define SIP_SVC_GET_BOOTSRC	0x8200ff09
#define SIP_SVC_GET_DDR_SIZE	0x8200ff0a
#define SIP_SVC_GET_BOARD_NO	0x8200ff0b

boot_source_type_t tfa_get_boot_source(void)
{
	struct arm_smccc_res res;

	arm_smccc_smc(SIP_SVC_GET_BOOTSRC, -1, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0)
		return BOOT_SOURCE_NONE;

	return (boot_source_type_t) res.a1;
}

phys_size_t tfa_get_dram_size(void)
{
	struct arm_smccc_res res;

	arm_smccc_smc(SIP_SVC_GET_DDR_SIZE, -1, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0)
		return 0;

	return res.a1;
}

int tfa_get_board_number(void)
{
	struct arm_smccc_res res;

	arm_smccc_smc(SIP_SVC_GET_BOARD_NO, -1, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0)
		return 0;

	return res.a1;
}
