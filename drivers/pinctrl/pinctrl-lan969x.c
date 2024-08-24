// SPDX-License-Identifier: (GPL-2.0 OR MIT)

#include <asm/gpio.h>
#include <common.h>
#include <config.h>
#include <dm.h>
#include <dm/devres.h>
#include <dm/device-internal.h>
#include <dm/pinctrl.h>
#include <errno.h>
#include <fdtdec.h>
#include <linux/io.h>
#include <linux/types.h>
#include <regmap.h>

/* GPIO standard registers */
#define LAN969X_FUNC_PER_PIN	8

/* GPIO standard registers */
#define LAN969X_GPIO_OUT_SET	0x0
#define LAN969X_GPIO_OUT_CLR	0x4
#define LAN969X_GPIO_OUT	0x8
#define LAN969X_GPIO_IN		0xc
#define LAN969X_GPIO_OE		0x10
#define LAN969X_GPIO_INTR	0x14
#define LAN969X_GPIO_INTR_ENA	0x18
#define LAN969X_GPIO_INTR_IDENT	0x1c
#define LAN969X_GPIO_ALT0	0x20
#define LAN969X_GPIO_ALT1	0x24
#define LAN969X_GPIO_ALT2	0x28
#define LAN969X_GPIO_SD_MAP	0x2c

enum {
	FUNC_EMMC_SD,
	FUNC_FC,
	FUNC_GPIO,
	FUNC_MIIM,
	FUNC_NONE,
	FUNC_R,
	FUNC_MAX
};

static const char *const lan969x_function_names[FUNC_MAX] = {
	[FUNC_EMMC_SD]		= "emmc_sd",
	[FUNC_FC]               = "fc",
	[FUNC_GPIO]		= "gpio",
	[FUNC_MIIM]		= "miim",
	[FUNC_NONE]		= "none",
	[FUNC_R]		= "reserved",
};

struct lan969x_pin_caps {
	unsigned int pin;
	unsigned char functions[LAN969X_FUNC_PER_PIN];
};

struct lan969x_pin_data {
	const char *name;
	struct lan969x_pin_caps *drv_data;
};

#define LAN969X_P(p, f0, f1, f2, f3, f4, f5, f6, f7)          \
static struct lan969x_pin_caps lan969x_pin_##p = {             \
	.pin = p,                                              \
	.functions = {                                         \
		FUNC_##f0, FUNC_##f1, FUNC_##f2,               \
		FUNC_##f3, FUNC_##f4, FUNC_##f5,               \
		FUNC_##f6, FUNC_##f7                           \
	},                                                     \
}

#define REG(r, info, p) ((r) * (info)->stride + (4 * ((p) / 32)))

struct lan969x_pmx_func {
	const char **groups;
	unsigned int ngroups;
};

struct lan969x_pinctrl {
	struct udevice *dev;
	struct pinctrl_dev *pctl;
	struct regmap *map;
	struct lan969x_pmx_func *func;
	int num_func;
	const struct lan969x_pin_data *lan969x_pins;
	int num_pins;
	const char * const *function_names;
	const unsigned long *lan969x_gpios;
	u8 stride;
};

/* Pinmuxing table taken from data sheet */
/*        Pin   FUNC0    FUNC1     FUNC2      FUNC3     FUNC4     FUNC5      FUNC6    FUNC7 */
LAN969X_P(0,    GPIO,    NONE,       FC,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(1,    GPIO,    NONE,       FC,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(2,    GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(3,    GPIO,      FC,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(4,    GPIO,      FC,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(5,    GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(6,    GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(7,    GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(8,    GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(9,    GPIO,    MIIM,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(10,   GPIO,    MIIM,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(11,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(12,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(13,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(14,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(15,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(16,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(17,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(18,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(19,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(20,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(21,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(22,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(23,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(24,   GPIO, EMMC_SD,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(25,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(26,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(27,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(28,   GPIO,    NONE,       FC,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(29,   GPIO,    NONE,       FC,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(30,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(31,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(32,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(33,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(34,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(35,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(36,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(37,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(38,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(39,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(40,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(41,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(42,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(43,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(44,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(45,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(46,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(47,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(48,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(49,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(50,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(51,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(52,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(53,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(54,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(55,   GPIO,    NONE,       FC,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(56,   GPIO,    NONE,       FC,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(57,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(58,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(59,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(60,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(61,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(62,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(63,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(64,   GPIO,    NONE,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(65,   GPIO,      FC,     NONE,      NONE,     NONE,     NONE,      NONE,        R);
LAN969X_P(66,   GPIO,      FC,     NONE,      NONE,     NONE,     NONE,      NONE,        R);

#define LAN969X_PIN(n) {                                      \
	.name = "GPIO_"#n,                                     \
	.drv_data = &lan969x_pin_##n                          \
}

static const struct lan969x_pin_data lan969x_pins[] = {
	LAN969X_PIN(0),
	LAN969X_PIN(1),
	LAN969X_PIN(2),
	LAN969X_PIN(3),
	LAN969X_PIN(4),
	LAN969X_PIN(5),
	LAN969X_PIN(6),
	LAN969X_PIN(7),
	LAN969X_PIN(8),
	LAN969X_PIN(9),
	LAN969X_PIN(10),
	LAN969X_PIN(11),
	LAN969X_PIN(12),
	LAN969X_PIN(13),
	LAN969X_PIN(14),
	LAN969X_PIN(15),
	LAN969X_PIN(16),
	LAN969X_PIN(17),
	LAN969X_PIN(18),
	LAN969X_PIN(19),
	LAN969X_PIN(20),
	LAN969X_PIN(21),
	LAN969X_PIN(22),
	LAN969X_PIN(23),
	LAN969X_PIN(24),
	LAN969X_PIN(25),
	LAN969X_PIN(26),
	LAN969X_PIN(27),
	LAN969X_PIN(28),
	LAN969X_PIN(29),
	LAN969X_PIN(30),
	LAN969X_PIN(31),
	LAN969X_PIN(32),
	LAN969X_PIN(33),
	LAN969X_PIN(34),
	LAN969X_PIN(35),
	LAN969X_PIN(36),
	LAN969X_PIN(37),
	LAN969X_PIN(38),
	LAN969X_PIN(39),
	LAN969X_PIN(40),
	LAN969X_PIN(41),
	LAN969X_PIN(42),
	LAN969X_PIN(43),
	LAN969X_PIN(44),
	LAN969X_PIN(45),
	LAN969X_PIN(46),
	LAN969X_PIN(47),
	LAN969X_PIN(48),
	LAN969X_PIN(49),
	LAN969X_PIN(50),
	LAN969X_PIN(51),
	LAN969X_PIN(52),
	LAN969X_PIN(53),
	LAN969X_PIN(54),
	LAN969X_PIN(55),
	LAN969X_PIN(56),
	LAN969X_PIN(57),
	LAN969X_PIN(58),
	LAN969X_PIN(59),
	LAN969X_PIN(60),
	LAN969X_PIN(61),
	LAN969X_PIN(62),
	LAN969X_PIN(63),
	LAN969X_PIN(64),
	LAN969X_PIN(65),
	LAN969X_PIN(66),
};

static int lan969x_gpio_probe(struct udevice *dev)
{
	struct gpio_dev_priv *uc_priv;

	uc_priv = dev_get_uclass_priv(dev);
	uc_priv->bank_name = "lan969x-gpio";
	uc_priv->gpio_count = ARRAY_SIZE(lan969x_pins);

	return 0;
}

static int lan969x_gpio_get(struct udevice *dev, unsigned int offset)
{
	struct lan969x_pinctrl *info = dev_get_priv(dev->parent);
	unsigned int val;

	regmap_read(info->map, REG(LAN969X_GPIO_IN, info, offset), &val);

	return !!(val & BIT(offset % 32));
}

static int lan969x_gpio_set(struct udevice *dev, unsigned int offset, int value)
{
	struct lan969x_pinctrl *info = dev_get_priv(dev->parent);

	if (value)
		regmap_write(info->map, REG(LAN969X_GPIO_OUT_SET, info, offset),
			     BIT(offset % 32));
	else
		regmap_write(info->map, REG(LAN969X_GPIO_OUT_CLR, info, offset),
			     BIT(offset % 32));

	return 0;
}

static int lan969x_gpio_get_direction(struct udevice *dev, unsigned int offset)
{
	struct lan969x_pinctrl *info = dev_get_priv(dev->parent);
	unsigned int val;

	regmap_read(info->map, REG(LAN969X_GPIO_OE, info, offset), &val);

	if (val & BIT(offset % 32))
		return GPIOF_OUTPUT;

	return GPIOF_INPUT;
}

static int lan969x_gpio_direction_input(struct udevice *dev, unsigned int offset)
{
	struct lan969x_pinctrl *info = dev_get_priv(dev->parent);

	regmap_write(info->map, REG(LAN969X_GPIO_OE, info, offset),
		     ~BIT(offset % 32));

	return 0;
}

static int lan969x_gpio_direction_output(struct udevice *dev,
					 unsigned int offset, int value)
{
	struct lan969x_pinctrl *info = dev_get_priv(dev->parent);

	regmap_write(info->map, REG(LAN969X_GPIO_OE, info, offset),
		     BIT(offset % 32));

	return lan969x_gpio_set(dev, offset, value);
}

const struct dm_gpio_ops lan969x_gpio_ops = {
	.set_value = lan969x_gpio_set,
	.get_value = lan969x_gpio_get,
	.get_function = lan969x_gpio_get_direction,
	.direction_input = lan969x_gpio_direction_input,
	.direction_output = lan969x_gpio_direction_output,
};

static int lan969x_pctl_get_groups_count(struct udevice *dev)
{
	struct lan969x_pinctrl *info = dev_get_priv(dev);

	return info->num_pins;
}

static const char *lan969x_pctl_get_group_name(struct udevice *dev,
					    unsigned int group)
{
	struct lan969x_pinctrl *info = dev_get_priv(dev);

	return info->lan969x_pins[group].name;
}

static int lan969x_get_functions_count(struct udevice *dev)
{
	struct lan969x_pinctrl *info = dev_get_priv(dev);

	return info->num_func;
}

static const char *lan969x_get_function_name(struct udevice *dev,
					  unsigned int function)
{
	struct lan969x_pinctrl *info = dev_get_priv(dev);

	return info->function_names[function];
}

static int lan969x_pin_function_idx(unsigned int pin, unsigned int function,
				    const struct lan969x_pin_data *lan969x_pins)
{
	struct lan969x_pin_caps *p = lan969x_pins[pin].drv_data;
	int i;

	for (i = 0; i < LAN969X_FUNC_PER_PIN; i++) {
		if (function == p->functions[i])
			return i;
	}

	return -1;
}

#define REG_ALT(msb, info, p) (LAN969X_GPIO_ALT0 * (info)->stride + 4 * ((msb) + ((info)->stride * ((p) / 32))))

static int lan969x_pinmux_set_mux(struct udevice *dev,
				  unsigned int pin_selector, unsigned int selector)
{
	struct lan969x_pinctrl *info = dev_get_priv(dev);
	struct lan969x_pin_caps *pin = info->lan969x_pins[pin_selector].drv_data;
	unsigned int p = pin->pin % 32;
	int f;

	f = lan969x_pin_function_idx(pin_selector, selector, info->lan969x_pins);
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

const struct pinctrl_ops lan969x_pinctrl_ops = {
	.get_pins_count = lan969x_pctl_get_groups_count,
	.get_pin_name = lan969x_pctl_get_group_name,
	.get_functions_count = lan969x_get_functions_count,
	.get_function_name = lan969x_get_function_name,
	.pinmux_set = lan969x_pinmux_set_mux,
	.set_state = pinctrl_generic_set_state,
};

static struct driver lan969x_gpio_driver = {
	.name	= "lan969x-gpio",
	.id	= UCLASS_GPIO,
	.probe	= lan969x_gpio_probe,
	.ops	= &lan969x_gpio_ops,
};

int lan969x_pinctrl_probe(struct udevice *dev)
{
	struct lan969x_pinctrl *priv = dev_get_priv(dev);
	int ret;

	ret = regmap_init_mem(dev_ofnode(dev), &priv->map);
	if (ret)
		return -EINVAL;

	priv->func = devm_kzalloc(dev, FUNC_MAX * sizeof(struct lan969x_pmx_func), GFP_KERNEL);
	priv->num_func = FUNC_MAX;
	priv->function_names = lan969x_function_names;

	priv->lan969x_pins = lan969x_pins;
	priv->num_pins = ARRAY_SIZE(lan969x_pins);
	priv->stride = 1 + (priv->num_pins - 1) / 32;

	ret = device_bind(dev, &lan969x_gpio_driver, "lan969x-gpio", NULL,
			  dev_ofnode(dev), NULL);

	return ret;
}

static const struct udevice_id lan969x_pinctrl_of_match[] = {
	{.compatible = "mchp,lan969x-pinctrl"},
	{},
};

U_BOOT_DRIVER(lan969x_pinctrl) = {
	.name = "lan969x-pinctrl",
	.id = UCLASS_PINCTRL,
	.of_match = of_match_ptr(lan969x_pinctrl_of_match),
	.probe = lan969x_pinctrl_probe,
	.priv_auto = sizeof(struct lan969x_pinctrl),
	.ops = &lan969x_pinctrl_ops,
};
