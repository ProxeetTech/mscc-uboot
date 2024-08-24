// SPDX-License-Identifier: (GPL-2.0 OR MIT)

#include <asm/gpio.h>
#include <common.h>
#include <config.h>
#include <dm.h>
#include <dm/device-internal.h>
#include <dm/devres.h>
#include <dm/pinctrl.h>
#include <errno.h>
#include <fdtdec.h>
#include <linux/io.h>
#include <linux/types.h>
#include <regmap.h>

/* GPIO standard registers */
#define LAN966X_FUNC_PER_PIN	8

/* GPIO standard registers */
#define LAN966X_GPIO_OUT_SET	0x0
#define LAN966X_GPIO_OUT_CLR	0x4
#define LAN966X_GPIO_OUT	0x8
#define LAN966X_GPIO_IN		0xc
#define LAN966X_GPIO_OE		0x10
#define LAN966X_GPIO_INTR	0x14
#define LAN966X_GPIO_INTR_ENA	0x18
#define LAN966X_GPIO_INTR_IDENT	0x1c
#define LAN966X_GPIO_ALT0	0x20
#define LAN966X_GPIO_ALT1	0x24
#define LAN966X_GPIO_ALT2	0x28
#define LAN966X_GPIO_SD_MAP	0x2c

enum {
	FUNC_CAN0_a,
	FUNC_CAN0_b,
	FUNC_CAN1,
	FUNC_NONE,
	FUNC_FC0_a,
	FUNC_FC0_b,
	FUNC_FC0_c,
	FUNC_FC1_a,
	FUNC_FC1_b,
	FUNC_FC1_c,
	FUNC_FC2_a,
	FUNC_FC2_b,
	FUNC_FC3_a,
	FUNC_FC3_b,
	FUNC_FC3_c,
	FUNC_FC4_a,
	FUNC_FC4_b,
	FUNC_FC4_c,
	FUNC_FC_SHRD0,
	FUNC_FC_SHRD1,
	FUNC_FC_SHRD2,
	FUNC_FC_SHRD3,
	FUNC_FC_SHRD4,
	FUNC_FC_SHRD5,
	FUNC_FC_SHRD6,
	FUNC_FC_SHRD7,
	FUNC_FC_SHRD8,
	FUNC_FC_SHRD9,
	FUNC_FC_SHRD10,
	FUNC_FC_SHRD11,
	FUNC_FC_SHRD12,
	FUNC_FC_SHRD13,
	FUNC_FC_SHRD14,
	FUNC_FC_SHRD15,
	FUNC_FC_SHRD16,
	FUNC_FC_SHRD17,
	FUNC_FC_SHRD18,
	FUNC_FC_SHRD19,
	FUNC_FC_SHRD20,
	FUNC_GPIO,
	FUNC_IB_TRG_a,
	FUNC_IB_TRG_b,
	FUNC_IB_TRG_c,
	FUNC_IRQ_IN_a,
	FUNC_IRQ_IN_b,
	FUNC_IRQ_IN_c,
	FUNC_IRQ_OUT_a,
	FUNC_IRQ_OUT_b,
	FUNC_IRQ_OUT_c,
	FUNC_MIIM_a,
	FUNC_MIIM_b,
	FUNC_MIIM_c,
	FUNC_MIIM_Sa,
	FUNC_MIIM_Sb,
	FUNC_OB_TRG,
	FUNC_OB_TRG_a,
	FUNC_OB_TRG_b,
	FUNC_PI_ADDR,
	FUNC_PI_ALH,
	FUNC_PI_ALL,
	FUNC_PI_DATA,
	FUNC_PI_RD,
	FUNC_PI_WR,
	FUNC_PTPSYNC_1,
	FUNC_PTPSYNC_2,
	FUNC_PTPSYNC_3,
	FUNC_PTPSYNC_4,
	FUNC_PTPSYNC_5,
	FUNC_PTPSYNC_6,
	FUNC_PTPSYNC_7,
	FUNC_QSPI1,
	FUNC_QSPI2,
	FUNC_R,
	FUNC_RECO_a,
	FUNC_RECO_b,
	FUNC_SD,
	FUNC_SFP_SD,
	FUNC_SGPIO,
	FUNC_SGPIO_a,
	FUNC_SGPIO_b,
	FUNC_TACHO_a,
	FUNC_TACHO_b,
	FUNC_TWI_SLC_GATE,
	FUNC_TWI_SLC_GATE_AD,
	FUNC_USB_H_a,
	FUNC_USB_H_b,
	FUNC_USB_H_c,
	FUNC_USB_S_a,
	FUNC_USB_S_b,
	FUNC_USB_S_c,
	FUNC_EMMC,
	FUNC_EMMC_SD,
	FUNC_MAX
};

static const char *const lan966x_function_names[] = {
	[FUNC_CAN0_a]		= "can0_a",
	[FUNC_CAN0_b]		= "can0_b",
	[FUNC_CAN1]		= "can1",
	[FUNC_NONE]		= "none",
	[FUNC_FC0_a]            = "fc0_a",
	[FUNC_FC0_b]            = "fc0_b",
	[FUNC_FC0_c]            = "fc0_c",
	[FUNC_FC1_a]            = "fc1_a",
	[FUNC_FC1_b]            = "fc1_b",
	[FUNC_FC1_c]            = "fc1_c",
	[FUNC_FC2_a]            = "fc2_a",
	[FUNC_FC2_b]            = "fc2_b",
	[FUNC_FC3_a]            = "fc3_a",
	[FUNC_FC3_b]            = "fc3_b",
	[FUNC_FC3_c]            = "fc3_c",
	[FUNC_FC4_a]            = "fc4_a",
	[FUNC_FC4_b]            = "fc4_b",
	[FUNC_FC4_c]            = "fc4_c",
	[FUNC_FC_SHRD0]         = "fc_shrd0",
	[FUNC_FC_SHRD1]         = "fc_shrd1",
	[FUNC_FC_SHRD2]         = "fc_shrd2",
	[FUNC_FC_SHRD3]         = "fc_shrd3",
	[FUNC_FC_SHRD4]         = "fc_shrd4",
	[FUNC_FC_SHRD5]         = "fc_shrd5",
	[FUNC_FC_SHRD6]         = "fc_shrd6",
	[FUNC_FC_SHRD7]         = "fc_shrd7",
	[FUNC_FC_SHRD8]         = "fc_shrd8",
	[FUNC_FC_SHRD9]         = "fc_shrd9",
	[FUNC_FC_SHRD10]        = "fc_shrd10",
	[FUNC_FC_SHRD11]        = "fc_shrd11",
	[FUNC_FC_SHRD12]        = "fc_shrd12",
	[FUNC_FC_SHRD13]        = "fc_shrd13",
	[FUNC_FC_SHRD14]        = "fc_shrd14",
	[FUNC_FC_SHRD15]        = "fc_shrd15",
	[FUNC_FC_SHRD16]        = "fc_shrd16",
	[FUNC_FC_SHRD17]        = "fc_shrd17",
	[FUNC_FC_SHRD18]        = "fc_shrd18",
	[FUNC_FC_SHRD19]        = "fc_shrd19",
	[FUNC_FC_SHRD20]        = "fc_shrd20",
	[FUNC_GPIO]		= "gpio",
	[FUNC_IB_TRG_a]       = "ib_trig_a",
	[FUNC_IB_TRG_b]       = "ib_trig_b",
	[FUNC_IB_TRG_c]       = "ib_trig_c",
	[FUNC_IRQ_IN_a]         = "irq_in_a",
	[FUNC_IRQ_IN_b]         = "irq_in_b",
	[FUNC_IRQ_IN_c]         = "irq_in_c",
	[FUNC_IRQ_OUT_a]        = "irq_out_a",
	[FUNC_IRQ_OUT_b]        = "irq_out_b",
	[FUNC_IRQ_OUT_c]        = "irq_out_c",
	[FUNC_MIIM_a]		= "miim_a",
	[FUNC_MIIM_b]		= "miim_b",
	[FUNC_MIIM_c]		= "miim_c",
	[FUNC_MIIM_Sa]		= "miim_slave_a",
	[FUNC_MIIM_Sb]		= "miim_slave_b",
	[FUNC_OB_TRG]          = "ob_trig",
	[FUNC_OB_TRG_a]        = "ob_trig_a",
	[FUNC_OB_TRG_b]        = "ob_trig_b",
	[FUNC_PI_ADDR]          = "pi_addr",
	[FUNC_PI_ALH]           = "pi_alh",
	[FUNC_PI_ALL]           = "pi_all",
	[FUNC_PI_DATA]          = "pi_data",
	[FUNC_PI_RD]            = "pi_rd",
	[FUNC_PI_WR]            = "pi_wr",
	[FUNC_PTPSYNC_1]	= "ptpsync_1",
	[FUNC_PTPSYNC_2]	= "ptpsync_2",
	[FUNC_PTPSYNC_3]	= "ptpsync_3",
	[FUNC_PTPSYNC_4]	= "ptpsync_4",
	[FUNC_PTPSYNC_5]	= "ptpsync_5",
	[FUNC_PTPSYNC_6]	= "ptpsync_6",
	[FUNC_PTPSYNC_7]	= "ptpsync_7",
	[FUNC_QSPI1]		= "qspi1",
	[FUNC_QSPI2]		= "qspi2",
	[FUNC_R]		= "reserved",
	[FUNC_RECO_a]           = "reco_a",
	[FUNC_RECO_b]           = "reco_b",
	[FUNC_SD]		= "sd",
	[FUNC_SFP_SD]		= "sfp_sd",
	[FUNC_SGPIO]		= "sgpio",
	[FUNC_SGPIO_a]          = "sgpio_a",
	[FUNC_SGPIO_b]          = "sgpio_b",
	[FUNC_TACHO_a]          = "tacho_a",
	[FUNC_TACHO_b]          = "tacho_b",
	[FUNC_TWI_SLC_GATE]     = "twi_slc_gate",
	[FUNC_TWI_SLC_GATE_AD]  = "twi_slc_gate_ad",
	[FUNC_USB_H_a]          = "usb_host_a",
	[FUNC_USB_H_b]          = "usb_host_b",
	[FUNC_USB_H_c]          = "usb_host_c",
	[FUNC_USB_S_a]          = "usb_slave_a",
	[FUNC_USB_S_b]          = "usb_slave_b",
	[FUNC_USB_S_c]          = "usb_slave_c",
	[FUNC_EMMC]		= "emmc",
	[FUNC_EMMC_SD]		= "emmc_sd",
};

struct lan966x_pin_caps {
	unsigned int pin;
	unsigned char functions[LAN966X_FUNC_PER_PIN];
};

struct lan966x_pin_data {
	const char *name;
	struct lan966x_pin_caps *drv_data;
};

#define LAN966x_P(p, f0, f1, f2, f3, f4, f5, f6, f7)          \
static struct lan966x_pin_caps lan966x_pin_##p = {             \
	.pin = p,                                              \
	.functions = {                                         \
		FUNC_##f0, FUNC_##f1, FUNC_##f2,               \
		FUNC_##f3, FUNC_##f4, FUNC_##f5,               \
		FUNC_##f6, FUNC_##f7                           \
	},                                                     \
}

#define REG(r, info, p) ((r) * (info)->stride + (4 * ((p) / 32)))

struct lan966x_pmx_func {
	const char **groups;
	unsigned int ngroups;
};

struct lan966x_pinctrl {
	struct udevice *dev;
	struct pinctrl_dev *pctl;
	struct regmap *map;
	struct lan966x_pmx_func *func;
	int num_func;
	const struct lan966x_pin_data *lan966x_pins;
	int num_pins;
	const char * const *function_names;
	const unsigned long *lan966x_gpios;
	u8 stride;
};

/* Pinmuxing table taken from data sheet */
/*        Pin   FUNC0    FUNC1     FUNC2      FUNC3     FUNC4     FUNC5      FUNC6    FUNC7 */
LAN966x_P(0,    GPIO,    NONE,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(1,    GPIO,    NONE,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(2,    GPIO,    NONE,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(3,    GPIO,    NONE,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(4,    GPIO,    NONE,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(5,    GPIO,    NONE,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(6,    GPIO,    NONE,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(7,    GPIO,    NONE,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(8,    GPIO,   FC0_a,  USB_H_b,   PI_DATA,  USB_S_b,     NONE,      NONE,        R);
LAN966x_P(9,    GPIO,   FC0_a,  USB_H_b,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(10,   GPIO,   FC0_a,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(11,   GPIO,   FC1_a,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(12,   GPIO,   FC1_a,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(13,   GPIO,   FC1_a,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(14,   GPIO,   FC2_a,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(15,   GPIO,   FC2_a,     NONE,   PI_DATA,     NONE,     NONE,      NONE,        R);
LAN966x_P(16,   GPIO,   FC2_a, IB_TRG_a,   PI_ADDR, OB_TRG_a, IRQ_IN_c, IRQ_OUT_c,        R);
LAN966x_P(17,   GPIO,   FC3_a, IB_TRG_a,   PI_ADDR, OB_TRG_a, IRQ_IN_c, IRQ_OUT_c,        R);
LAN966x_P(18,   GPIO,   FC3_a, IB_TRG_a,   PI_ADDR, OB_TRG_a, IRQ_IN_c, IRQ_OUT_c,        R);
LAN966x_P(19,   GPIO,   FC3_a, IB_TRG_a,   PI_ADDR, OB_TRG_a, IRQ_IN_c, IRQ_OUT_c,        R);
LAN966x_P(20,   GPIO,   FC4_a, IB_TRG_a,   PI_ADDR, OB_TRG_a, IRQ_IN_c,      NONE,        R);
LAN966x_P(21,   GPIO,   FC4_a,     NONE,   PI_ADDR, OB_TRG_a,     NONE,      NONE,        R);
LAN966x_P(22,   GPIO,   FC4_a,     NONE,   PI_ADDR, OB_TRG_a,     NONE,      NONE,        R);
LAN966x_P(23,   GPIO,    NONE,     NONE,      NONE, OB_TRG_a,   PI_ALH,      NONE,        R);
LAN966x_P(24,   GPIO,   FC0_b, IB_TRG_a,   USB_H_c, OB_TRG_a, IRQ_IN_c,   TACHO_a,        R);
LAN966x_P(25,   GPIO,   FC0_b, IB_TRG_a,   USB_H_c, OB_TRG_a, IRQ_OUT_c,   SFP_SD,        R);
LAN966x_P(26,   GPIO,   FC0_b, IB_TRG_a,   USB_S_c, OB_TRG_a,   CAN0_a,    SFP_SD,        R);
LAN966x_P(27,   GPIO,    NONE,     NONE,      NONE, OB_TRG_a,   CAN0_a,      NONE,        R);
LAN966x_P(28,   GPIO,  MIIM_a,     NONE,      NONE, OB_TRG_a, IRQ_OUT_c,   SFP_SD,        R);
LAN966x_P(29,   GPIO,  MIIM_a,     NONE,      NONE, OB_TRG_a,     NONE,      NONE,        R);
LAN966x_P(30,   GPIO,   FC3_c,     CAN1,      NONE,   OB_TRG,   RECO_b,      NONE,        R);
LAN966x_P(31,   GPIO,   FC3_c,     CAN1,      NONE,   OB_TRG,   RECO_b,      NONE,        R);
LAN966x_P(32,   GPIO,   FC3_c,     NONE,   SGPIO_a,     NONE,  MIIM_Sa,      NONE,        R);
LAN966x_P(33,   GPIO,   FC1_b,     NONE,   SGPIO_a,     NONE,  MIIM_Sa,    MIIM_b,        R);
LAN966x_P(34,   GPIO,   FC1_b,     NONE,   SGPIO_a,     NONE,  MIIM_Sa,    MIIM_b,        R);
LAN966x_P(35,   GPIO,   FC1_b,     NONE,   SGPIO_a,   CAN0_a,     NONE,      NONE,        R);
LAN966x_P(36,   GPIO,    NONE,  PTPSYNC_1,    NONE,   CAN0_a,     NONE,      NONE,        R);
LAN966x_P(37,   GPIO, FC_SHRD0, PTPSYNC_2, TWI_SLC_GATE_AD, NONE, NONE,      NONE,        R);
LAN966x_P(38,   GPIO,    NONE,  PTPSYNC_3,    NONE,     NONE,     NONE,      NONE,        R);
LAN966x_P(39,   GPIO,    NONE,  PTPSYNC_4,    NONE,     NONE,     NONE,      NONE,        R);
LAN966x_P(40,   GPIO, FC_SHRD1, PTPSYNC_5,    NONE,     NONE,     NONE,      NONE,        R);
LAN966x_P(41,   GPIO,    NONE,  PTPSYNC_6, TWI_SLC_GATE_AD, NONE, NONE,      NONE,        R);
LAN966x_P(42,   GPIO,    NONE,  PTPSYNC_7, TWI_SLC_GATE_AD, NONE, NONE,      NONE,        R);
LAN966x_P(43,   GPIO,   FC2_b,   OB_TRG_b, IB_TRG_b, IRQ_OUT_a,  RECO_a,  IRQ_IN_a,        R);
LAN966x_P(44,   GPIO,   FC2_b,   OB_TRG_b, IB_TRG_b, IRQ_OUT_a,  RECO_a,  IRQ_IN_a,        R);
LAN966x_P(45,   GPIO,   FC2_b,   OB_TRG_b, IB_TRG_b, IRQ_OUT_a,    NONE,  IRQ_IN_a,        R);
LAN966x_P(46,   GPIO,   FC1_c,   OB_TRG_b, IB_TRG_b, IRQ_OUT_a,    NONE,  IRQ_IN_a,        R);
LAN966x_P(47,   GPIO,   FC1_c,   OB_TRG_b, IB_TRG_b, IRQ_OUT_a,    NONE,  IRQ_IN_a,        R);
LAN966x_P(48,   GPIO,   FC1_c,   OB_TRG_b, IB_TRG_b, IRQ_OUT_a,    NONE,  IRQ_IN_a,        R);
LAN966x_P(49,   GPIO, FC_SHRD7,  OB_TRG_b, IB_TRG_b, IRQ_OUT_a, TWI_SLC_GATE, IRQ_IN_a,    R);
LAN966x_P(50,   GPIO, FC_SHRD16, OB_TRG_b, IB_TRG_b, IRQ_OUT_a, TWI_SLC_GATE, NONE,        R);
LAN966x_P(51,   GPIO,   FC3_b,   OB_TRG_b, IB_TRG_c, IRQ_OUT_b,    NONE,  IRQ_IN_b,        R);
LAN966x_P(52,   GPIO,   FC3_b,   OB_TRG_b, IB_TRG_c, IRQ_OUT_b, TACHO_b,  IRQ_IN_b,        R);
LAN966x_P(53,   GPIO,   FC3_b,   OB_TRG_b, IB_TRG_c, IRQ_OUT_b,    NONE,  IRQ_IN_b,        R);
LAN966x_P(54,   GPIO, FC_SHRD8,  OB_TRG_b, IB_TRG_c, IRQ_OUT_b, TWI_SLC_GATE, IRQ_IN_b,    R);
LAN966x_P(55,   GPIO, FC_SHRD9,  OB_TRG_b, IB_TRG_c, IRQ_OUT_b, TWI_SLC_GATE, IRQ_IN_b,    R);
LAN966x_P(56,   GPIO,   FC4_b,   OB_TRG_b, IB_TRG_c, IRQ_OUT_b, FC_SHRD10,    IRQ_IN_b,    R);
LAN966x_P(57,   GPIO,   FC4_b, TWI_SLC_GATE, IB_TRG_c, IRQ_OUT_b, FC_SHRD11, IRQ_IN_b,    R);
LAN966x_P(58,   GPIO,   FC4_b, TWI_SLC_GATE, IB_TRG_c, IRQ_OUT_b, FC_SHRD12, IRQ_IN_b,    R);
LAN966x_P(59,   GPIO,   QSPI1,   MIIM_c,      NONE,     NONE,  MIIM_Sb,      NONE,        R);
LAN966x_P(60,   GPIO,   QSPI1,   MIIM_c,      NONE,     NONE,  MIIM_Sb,      NONE,        R);
LAN966x_P(61,   GPIO,   QSPI1,     NONE,   SGPIO_b,    FC0_c,  MIIM_Sb,      NONE,        R);
LAN966x_P(62,   GPIO,   QSPI1, FC_SHRD13,  SGPIO_b,    FC0_c, TWI_SLC_GATE,  SFP_SD,      R);
LAN966x_P(63,   GPIO,   QSPI1, FC_SHRD14,  SGPIO_b,    FC0_c, TWI_SLC_GATE,  SFP_SD,      R);
LAN966x_P(64,   GPIO,   QSPI1,    FC4_c,   SGPIO_b, FC_SHRD15, TWI_SLC_GATE, SFP_SD,      R);
LAN966x_P(65,   GPIO, USB_H_a,    FC4_c,      NONE, IRQ_OUT_c, TWI_SLC_GATE_AD, NONE,     R);
LAN966x_P(66,   GPIO, USB_H_a,    FC4_c,   USB_S_a, IRQ_OUT_c, IRQ_IN_c,     NONE,        R);
LAN966x_P(67,   GPIO, EMMC_SD,     NONE,     QSPI2,     NONE,     NONE,      NONE,        R);
LAN966x_P(68,   GPIO, EMMC_SD,     NONE,     QSPI2,     NONE,     NONE,      NONE,        R);
LAN966x_P(69,   GPIO, EMMC_SD,     NONE,     QSPI2,     NONE,     NONE,      NONE,        R);
LAN966x_P(70,   GPIO, EMMC_SD,     NONE,     QSPI2,     NONE,     NONE,      NONE,        R);
LAN966x_P(71,   GPIO, EMMC_SD,     NONE,     QSPI2,     NONE,     NONE,      NONE,        R);
LAN966x_P(72,   GPIO, EMMC_SD,     NONE,     QSPI2,     NONE,     NONE,      NONE,        R);
LAN966x_P(73,   GPIO,    EMMC,     NONE,      NONE,       SD,     NONE,      NONE,        R);
LAN966x_P(74,   GPIO,    EMMC,     NONE, FC_SHRD17,       SD, TWI_SLC_GATE,  NONE,        R);
LAN966x_P(75,   GPIO,    EMMC,     NONE, FC_SHRD18,       SD, TWI_SLC_GATE,  NONE,        R);
LAN966x_P(76,   GPIO,    EMMC,     NONE, FC_SHRD19,       SD, TWI_SLC_GATE,  NONE,        R);
LAN966x_P(77,   GPIO, EMMC_SD,     NONE, FC_SHRD20,     NONE, TWI_SLC_GATE,  NONE,        R);

#define LAN966x_PIN(n) {                                      \
	.name = "GPIO_"#n,                                     \
	.drv_data = &lan966x_pin_##n                          \
}

static const struct lan966x_pin_data lan966x_pins[] = {
	LAN966x_PIN(0),
	LAN966x_PIN(1),
	LAN966x_PIN(2),
	LAN966x_PIN(3),
	LAN966x_PIN(4),
	LAN966x_PIN(5),
	LAN966x_PIN(6),
	LAN966x_PIN(7),
	LAN966x_PIN(8),
	LAN966x_PIN(9),
	LAN966x_PIN(10),
	LAN966x_PIN(11),
	LAN966x_PIN(12),
	LAN966x_PIN(13),
	LAN966x_PIN(14),
	LAN966x_PIN(15),
	LAN966x_PIN(16),
	LAN966x_PIN(17),
	LAN966x_PIN(18),
	LAN966x_PIN(19),
	LAN966x_PIN(20),
	LAN966x_PIN(21),
	LAN966x_PIN(22),
	LAN966x_PIN(23),
	LAN966x_PIN(24),
	LAN966x_PIN(25),
	LAN966x_PIN(26),
	LAN966x_PIN(27),
	LAN966x_PIN(28),
	LAN966x_PIN(29),
	LAN966x_PIN(30),
	LAN966x_PIN(31),
	LAN966x_PIN(32),
	LAN966x_PIN(33),
	LAN966x_PIN(34),
	LAN966x_PIN(35),
	LAN966x_PIN(36),
	LAN966x_PIN(37),
	LAN966x_PIN(38),
	LAN966x_PIN(39),
	LAN966x_PIN(40),
	LAN966x_PIN(41),
	LAN966x_PIN(42),
	LAN966x_PIN(43),
	LAN966x_PIN(44),
	LAN966x_PIN(45),
	LAN966x_PIN(46),
	LAN966x_PIN(47),
	LAN966x_PIN(48),
	LAN966x_PIN(49),
	LAN966x_PIN(50),
	LAN966x_PIN(51),
	LAN966x_PIN(52),
	LAN966x_PIN(53),
	LAN966x_PIN(54),
	LAN966x_PIN(55),
	LAN966x_PIN(56),
	LAN966x_PIN(57),
	LAN966x_PIN(58),
	LAN966x_PIN(59),
	LAN966x_PIN(60),
	LAN966x_PIN(61),
	LAN966x_PIN(62),
	LAN966x_PIN(63),
	LAN966x_PIN(64),
	LAN966x_PIN(65),
	LAN966x_PIN(66),
	LAN966x_PIN(67),
	LAN966x_PIN(68),
	LAN966x_PIN(69),
	LAN966x_PIN(70),
	LAN966x_PIN(71),
	LAN966x_PIN(72),
	LAN966x_PIN(73),
	LAN966x_PIN(74),
	LAN966x_PIN(75),
	LAN966x_PIN(76),
	LAN966x_PIN(77),
};

static int lan966x_gpio_probe(struct udevice *dev)
{
	struct gpio_dev_priv *uc_priv;

	uc_priv = dev_get_uclass_priv(dev);
	uc_priv->bank_name = "lan966x-gpio";
	uc_priv->gpio_count = ARRAY_SIZE(lan966x_pins);

	return 0;
}

static int lan966x_gpio_get(struct udevice *dev, unsigned int offset)
{
	struct lan966x_pinctrl *info = dev_get_priv(dev->parent);
	unsigned int val;

	regmap_read(info->map, REG(LAN966X_GPIO_IN, info, offset), &val);

	return !!(val & BIT(offset % 32));
}

static int lan966x_gpio_set(struct udevice *dev, unsigned int offset, int value)
{
	struct lan966x_pinctrl *info = dev_get_priv(dev->parent);

	if (value)
		regmap_write(info->map, REG(LAN966X_GPIO_OUT_SET, info, offset),
			     BIT(offset % 32));
	else
		regmap_write(info->map, REG(LAN966X_GPIO_OUT_CLR, info, offset),
			     BIT(offset % 32));

	return 0;
}

static int lan966x_gpio_get_direction(struct udevice *dev, unsigned int offset)
{
	struct lan966x_pinctrl *info = dev_get_priv(dev->parent);
	unsigned int val;

	regmap_read(info->map, REG(LAN966X_GPIO_OE, info, offset), &val);

	if (val & BIT(offset % 32))
		return GPIOF_OUTPUT;

	return GPIOF_INPUT;
}

static int lan966x_gpio_direction_input(struct udevice *dev, unsigned int offset)
{
	struct lan966x_pinctrl *info = dev_get_priv(dev->parent);
	unsigned int val;

	regmap_read(info->map, REG(LAN966X_GPIO_OE, info, offset), &val);
	regmap_write(info->map, REG(LAN966X_GPIO_OE, info, offset),
		     (~BIT(offset % 32)) & val);

	return 0;
}

static int lan966x_gpio_direction_output(struct udevice *dev,
					 unsigned int offset, int value)
{
	struct lan966x_pinctrl *info = dev_get_priv(dev->parent);
	unsigned int val;

	regmap_read(info->map, REG(LAN966X_GPIO_OE, info, offset), &val);
	regmap_write(info->map, REG(LAN966X_GPIO_OE, info, offset),
		     (BIT(offset % 32)) | val);

	return lan966x_gpio_set(dev, offset, value);
}

const struct dm_gpio_ops lan966x_gpio_ops = {
	.set_value = lan966x_gpio_set,
	.get_value = lan966x_gpio_get,
	.get_function = lan966x_gpio_get_direction,
	.direction_input = lan966x_gpio_direction_input,
	.direction_output = lan966x_gpio_direction_output,
};

static int lan966x_pctl_get_groups_count(struct udevice *dev)
{
	struct lan966x_pinctrl *info = dev_get_priv(dev);

	return info->num_pins;
}

static const char *lan966x_pctl_get_group_name(struct udevice *dev,
					    unsigned int group)
{
	struct lan966x_pinctrl *info = dev_get_priv(dev);

	return info->lan966x_pins[group].name;
}

static int lan966x_get_functions_count(struct udevice *dev)
{
	struct lan966x_pinctrl *info = dev_get_priv(dev);

	return info->num_func;
}

static const char *lan966x_get_function_name(struct udevice *dev,
					  unsigned int function)
{
	struct lan966x_pinctrl *info = dev_get_priv(dev);

	return info->function_names[function];
}

static int lan966x_pin_function_idx(unsigned int pin, unsigned int function,
				    const struct lan966x_pin_data *lan966x_pins)
{
	struct lan966x_pin_caps *p = lan966x_pins[pin].drv_data;
	int i;

	for (i = 0; i < LAN966X_FUNC_PER_PIN; i++) {
		if (function == p->functions[i])
			return i;
	}

	return -1;
}

#define REG_ALT(msb, info, p) (LAN966X_GPIO_ALT0 * (info)->stride + 4 * ((msb) + ((info)->stride * ((p) / 32))))

static int lan966x_pinmux_set_mux(struct udevice *dev,
				  unsigned int pin_selector, unsigned int selector)
{
	struct lan966x_pinctrl *info = dev_get_priv(dev);
	struct lan966x_pin_caps *pin = info->lan966x_pins[pin_selector].drv_data;
	unsigned int p = pin->pin % 32;
	int f;

	f = lan966x_pin_function_idx(pin_selector, selector, info->lan966x_pins);
	if (f < 0)
		return -EINVAL;

	/*
	 * f is encoded on two bits.
	 * bit 0 of f goes in BIT(pin) of ALT[0], bit 1 of f goes in BIT(pin) of
	 * ALT[1], bit 2 of f goes in BIT(pin) of ALT[2]
	 * This is racy because both registers can't be updated at the same time
	 * but it doesn't matter much for now.
	 * Note: ALT0/ALT1/ALT2 are organized specially for 78 gpio targets
	 */
	regmap_update_bits(info->map, REG_ALT(0, info, pin->pin),
			   BIT(p), f << p);
	regmap_update_bits(info->map, REG_ALT(1, info, pin->pin),
			   BIT(p), (f >> 1) << p);
	regmap_update_bits(info->map, REG_ALT(2, info, pin->pin),
			   BIT(p), (f >> 2) << p);

	return 0;
}

const struct pinctrl_ops lan966x_pinctrl_ops = {
	.get_pins_count = lan966x_pctl_get_groups_count,
	.get_pin_name = lan966x_pctl_get_group_name,
	.get_functions_count = lan966x_get_functions_count,
	.get_function_name = lan966x_get_function_name,
	.pinmux_set = lan966x_pinmux_set_mux,
	.set_state = pinctrl_generic_set_state,
};

static struct driver lan966x_gpio_driver = {
	.name	= "lan966x-gpio",
	.id	= UCLASS_GPIO,
	.probe	= lan966x_gpio_probe,
	.ops	= &lan966x_gpio_ops,
};

int lan966x_pinctrl_probe(struct udevice *dev)
{
	struct lan966x_pinctrl *priv = dev_get_priv(dev);
	int ret;

	ret = regmap_init_mem(dev_ofnode(dev), &priv->map);
	if (ret)
		return -EINVAL;

	priv->func = devm_kzalloc(dev, FUNC_MAX * sizeof(struct lan966x_pmx_func),
				  GFP_KERNEL);
	priv->num_func = FUNC_MAX;
	priv->function_names = lan966x_function_names;

	priv->lan966x_pins = lan966x_pins;
	priv->num_pins = ARRAY_SIZE(lan966x_pins);
	priv->stride = 1 + (priv->num_pins - 1) / 32;

	ret = device_bind(dev, &lan966x_gpio_driver, "lan966x-gpio", NULL,
			  dev_ofnode(dev), NULL);

	return ret;
}

static const struct udevice_id lan966x_pinctrl_of_match[] = {
	{.compatible = "mchp,lan966x-pinctrl"},
	{},
};

U_BOOT_DRIVER(lan966x_pinctrl) = {
	.name = "lan966x-pinctrl",
	.id = UCLASS_PINCTRL,
	.of_match = of_match_ptr(lan966x_pinctrl_of_match),
	.probe = lan966x_pinctrl_probe,
	.priv_auto = sizeof(struct lan966x_pinctrl),
	.ops = &lan966x_pinctrl_ops,
};
