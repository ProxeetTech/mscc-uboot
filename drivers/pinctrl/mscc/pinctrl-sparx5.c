// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Microsemi SoCs pinctrl driver
 *
 * Author: <lars.povlsen@microchip.com>
 * Copyright (c) 2018 Microsemi Corporation
 */

#include <common.h>
#include <config.h>
#include <dm.h>
#include <dm/device-internal.h>
#include <dm/lists.h>
#include <dm/pinctrl.h>
#include <dm/root.h>
#include <errno.h>
#include <fdtdec.h>
#include <linux/io.h>
#include <asm/gpio.h>
#include <asm/system.h>
#include "mscc-common.h"

enum {
	FUNC_NONE,
	FUNC_GPIO,
	FUNC_IRQ0_IN,
	FUNC_IRQ0_OUT,
	FUNC_IRQ1_IN,
	FUNC_IRQ1_OUT,
	FUNC_MIIM1,
	FUNC_MIIM2,
	FUNC_MIIM3,
	FUNC_PCI_WAKE,
	FUNC_PTP0,
	FUNC_PTP1,
	FUNC_PTP2,
	FUNC_PTP3,
	FUNC_PWM,
	FUNC_RECO_CLK,
	FUNC_SFP,
	FUNC_SIO,
	FUNC_SIO1,
	FUNC_SIO2,
	FUNC_SPI,
	FUNC_SPI2,
	FUNC_TACHO,
	FUNC_TWI,
	FUNC_TWI2,
	FUNC_TWI3,
	FUNC_TWI_SCL_M,
	FUNC_UART,
	FUNC_UART2,
	FUNC_UART3,
	FUNC_PLL_STAT,
	FUNC_EMMC,
	FUNC_MAX
};

char *sparx5_function_names[] = {
	[FUNC_NONE]		= "none",
	[FUNC_GPIO]		= "gpio",
	[FUNC_IRQ0_IN]		= "irq0_in",
	[FUNC_IRQ0_OUT]		= "irq0_out",
	[FUNC_IRQ1_IN]		= "irq1_in",
	[FUNC_IRQ1_OUT]		= "irq1_out",
	[FUNC_MIIM1]		= "miim1",
	[FUNC_MIIM2]		= "miim2",
	[FUNC_MIIM3]		= "miim3",
	[FUNC_PCI_WAKE]		= "pci_wake",
	[FUNC_PTP0]		= "ptp0",
	[FUNC_PTP1]		= "ptp1",
	[FUNC_PTP2]		= "ptp2",
	[FUNC_PTP3]		= "ptp3",
	[FUNC_PWM]		= "pwm",
	[FUNC_RECO_CLK]		= "reco_clk",
	[FUNC_SFP]		= "sfp",
	[FUNC_SIO]		= "sio",
	[FUNC_SIO1]		= "sio1",
	[FUNC_SIO2]		= "sio2",
	[FUNC_SPI]		= "spi",
	[FUNC_SPI2]		= "spi2",
	[FUNC_TACHO]		= "tacho",
	[FUNC_TWI]		= "twi",
	[FUNC_TWI2]		= "twi2",
	[FUNC_TWI3]		= "twi3",
	[FUNC_TWI_SCL_M]	= "twi_scl_m",
	[FUNC_UART]		= "uart",
	[FUNC_UART2]		= "uart2",
	[FUNC_UART3]		= "uart3",
	[FUNC_PLL_STAT]		= "pll_stat",
	[FUNC_EMMC]		= "emmc",
};

MSCC_P(0,  SIO,       PLL_STAT,  NONE);
MSCC_P(1,  SIO,       NONE,      NONE);
MSCC_P(2,  SIO,       NONE,      NONE);
MSCC_P(3,  SIO,       NONE,      NONE);
MSCC_P(4,  SIO1,      NONE,      NONE);
MSCC_P(5,  SIO1,      NONE,      NONE);
MSCC_P(6,  IRQ0_IN,   IRQ0_OUT,  SFP);
MSCC_P(7,  IRQ1_IN,   IRQ1_OUT,  SFP);
MSCC_P(8,  PTP0,      NONE,      SFP);
MSCC_P(9,  PTP1,      SFP,       TWI_SCL_M);
MSCC_P(10, UART,      NONE,      NONE);
MSCC_P(11, UART,      NONE,      NONE);
MSCC_P(12, SIO1,      NONE,      NONE);
MSCC_P(13, SIO1,      NONE,      NONE);
MSCC_P(14, TWI,       TWI_SCL_M, NONE);
MSCC_P(15, TWI,       NONE,      NONE);
MSCC_P(16, SPI,       TWI_SCL_M, SFP);
MSCC_P(17, SPI,       TWI_SCL_M, SFP);
MSCC_P(18, SPI,       TWI_SCL_M, SFP);
MSCC_P(19, PCI_WAKE,  TWI_SCL_M, SFP);
MSCC_P(20, IRQ0_OUT,  TWI_SCL_M, SFP);
MSCC_P(21, IRQ1_OUT,  TACHO,     SFP);
MSCC_P(22, TACHO,     IRQ0_OUT,  TWI_SCL_M);
MSCC_P(23, PWM,       UART3,     TWI_SCL_M);
MSCC_P(24, PTP2,      UART3,     TWI_SCL_M);
MSCC_P(25, PTP3,      SPI,       TWI_SCL_M);
MSCC_P(26, UART2,     SPI,       TWI_SCL_M);
MSCC_P(27, UART2,     SPI,       TWI_SCL_M);
MSCC_P(28, TWI2,      SPI,       SFP);
MSCC_P(29, TWI2,      SPI,       SFP);
MSCC_P(30, SIO2,      SPI,       PWM);
MSCC_P(31, SIO2,      SPI,       TWI_SCL_M);
MSCC_P(32, SIO2,      SPI,       TWI_SCL_M);
MSCC_P(33, SIO2,      SPI,       SFP);
MSCC_P(34, NONE,      TWI_SCL_M, EMMC);
MSCC_P(35, SFP,       TWI_SCL_M, EMMC);
MSCC_P(36, SFP,       TWI_SCL_M, EMMC);
MSCC_P(37, SFP,       NONE,      EMMC);
MSCC_P(38, NONE,      TWI_SCL_M, EMMC);
MSCC_P(39, SPI2,      TWI_SCL_M, EMMC);
MSCC_P(40, SPI2,      TWI_SCL_M, EMMC);
MSCC_P(41, SPI2,      TWI_SCL_M, EMMC);
MSCC_P(42, SPI2,      TWI_SCL_M, EMMC);
MSCC_P(43, SPI2,      TWI_SCL_M, EMMC);
MSCC_P(44, SPI,       SFP,       EMMC);
MSCC_P(45, SPI,       SFP,       EMMC);
MSCC_P(46, NONE,      SFP,       EMMC);
MSCC_P(47, NONE,      SFP,       EMMC);
MSCC_P(48, TWI3,      SPI,       SFP);
MSCC_P(49, TWI3,      NONE,      SFP);
MSCC_P(50, SFP,       NONE,      TWI_SCL_M);
MSCC_P(51, SFP,       SPI,       TWI_SCL_M);
MSCC_P(52, SFP,       MIIM3,     TWI_SCL_M);
MSCC_P(53, SFP,       MIIM3,     TWI_SCL_M);
MSCC_P(54, SFP,       PTP2,      TWI_SCL_M);
MSCC_P(55, SFP,       PTP3,      PCI_WAKE);
MSCC_P(56, MIIM1,     SFP,       TWI_SCL_M);
MSCC_P(57, MIIM1,     SFP,       TWI_SCL_M);
MSCC_P(58, MIIM2,     SFP,       TWI_SCL_M);
MSCC_P(59, MIIM2,     SFP,       NONE);
MSCC_P(60, RECO_CLK,  NONE,      NONE);
MSCC_P(61, RECO_CLK,  NONE,      NONE);
MSCC_P(62, RECO_CLK,  PLL_STAT,  NONE);
MSCC_P(63, RECO_CLK,  NONE,      NONE);

#define SPARX5_PIN(n) {					\
	.name = "GPIO_"#n,					\
	.drv_data = &mscc_pin_##n				\
}

const struct mscc_pin_data sparx5_pins[] = {
	SPARX5_PIN(0),
	SPARX5_PIN(1),
	SPARX5_PIN(2),
	SPARX5_PIN(3),
	SPARX5_PIN(4),
	SPARX5_PIN(5),
	SPARX5_PIN(6),
	SPARX5_PIN(7),
	SPARX5_PIN(8),
	SPARX5_PIN(9),
	SPARX5_PIN(10),
	SPARX5_PIN(11),
	SPARX5_PIN(12),
	SPARX5_PIN(13),
	SPARX5_PIN(14),
	SPARX5_PIN(15),
	SPARX5_PIN(16),
	SPARX5_PIN(17),
	SPARX5_PIN(18),
	SPARX5_PIN(19),
	SPARX5_PIN(20),
	SPARX5_PIN(21),
	SPARX5_PIN(22),
	SPARX5_PIN(23),
	SPARX5_PIN(24),
	SPARX5_PIN(25),
	SPARX5_PIN(26),
	SPARX5_PIN(27),
	SPARX5_PIN(28),
	SPARX5_PIN(29),
	SPARX5_PIN(30),
	SPARX5_PIN(31),
	SPARX5_PIN(32),
	SPARX5_PIN(33),
	SPARX5_PIN(34),
	SPARX5_PIN(35),
	SPARX5_PIN(36),
	SPARX5_PIN(37),
	SPARX5_PIN(38),
	SPARX5_PIN(39),
	SPARX5_PIN(40),
	SPARX5_PIN(41),
	SPARX5_PIN(42),
	SPARX5_PIN(43),
	SPARX5_PIN(44),
	SPARX5_PIN(45),
	SPARX5_PIN(46),
	SPARX5_PIN(47),
	SPARX5_PIN(48),
	SPARX5_PIN(49),
	SPARX5_PIN(50),
	SPARX5_PIN(51),
	SPARX5_PIN(52),
	SPARX5_PIN(53),
	SPARX5_PIN(54),
	SPARX5_PIN(55),
	SPARX5_PIN(56),
	SPARX5_PIN(57),
	SPARX5_PIN(58),
	SPARX5_PIN(59),
	SPARX5_PIN(60),
	SPARX5_PIN(61),
	SPARX5_PIN(62),
	SPARX5_PIN(63),
};

static int sparx5_gpio_probe(struct udevice *dev)
{
	struct gpio_dev_priv *uc_priv;

	uc_priv = dev_get_uclass_priv(dev);
	uc_priv->bank_name = "sparx5-gpio";
	uc_priv->gpio_count = ARRAY_SIZE(sparx5_pins);

	return 0;
}

static struct driver sparx5_gpio_driver = {
	.name	= "sparx5-gpio",
	.id	= UCLASS_GPIO,
	.probe	= sparx5_gpio_probe,
	.ops	= &mscc_gpio_ops,
};

static const unsigned long sparx5_gpios[] = {
	[MSCC_GPIO_OUT_SET] = 0x00,
	[MSCC_GPIO_OUT_CLR] = 0x08,
	[MSCC_GPIO_OUT] = 0x10,
	[MSCC_GPIO_IN] = 0x18,
	[MSCC_GPIO_OE] = 0x20,
	[MSCC_GPIO_INTR] = 0x28,
	[MSCC_GPIO_INTR_ENA] = 0x30,
	[MSCC_GPIO_INTR_IDENT] = 0x38,
	[MSCC_GPIO_ALT0] = 0x40,
	[MSCC_GPIO_ALT1] = 0x48,
};

int sparx5_pinctrl_probe(struct udevice *dev)
{
	int ret;

	ret = mscc_pinctrl_probe(dev, FUNC_MAX, sparx5_pins,
				 ARRAY_SIZE(sparx5_pins),
				 sparx5_function_names,
				 sparx5_gpios);

	if (ret)
		return ret;

	ret = device_bind(dev, &sparx5_gpio_driver, "sparx5-gpio", NULL,
			  dev_ofnode(dev), NULL);

	if (ret)
		return ret;

	return 0;
}

static const struct udevice_id sparx5_pinctrl_of_match[] = {
	{ .compatible = "mscc,sparx5-pinctrl" },
	{},
};

U_BOOT_DRIVER(sparx5_pinctrl) = {
	.name = "sparx5-pinctrl",
	.id = UCLASS_PINCTRL,
	.of_match = of_match_ptr(sparx5_pinctrl_of_match),
	.probe = sparx5_pinctrl_probe,
	.priv_auto = sizeof(struct mscc_pinctrl),
	.ops = &mscc_pinctrl_ops,
};
