// SPDX-License-Identifier: GPL-2.0+

#include <common.h>
#include <asm/io.h>
#include <clk-uclass.h>
#include <div64.h>
#include <dm.h>
#include <regmap.h>
#include <syscon.h>
#include <linux/bitfield.h>

#define GCK_ENA         BIT(0)
#define GCK_SRC_SEL     GENMASK(9, 8)
#define GCK_PRESCALER   GENMASK(23, 16)

struct lan966x_clk {
	void *base;
	int clk_cnt;
	ulong parent_rate;
};

struct lan966x_driver_data {
	int clk_cnt;
	ulong parent_rate;
};

static struct lan966x_driver_data lan966x_data = {
	.clk_cnt = 14,
	.parent_rate = 600000000,
};

static struct lan966x_driver_data lan969x_data = {
	.clk_cnt = 12,
	.parent_rate = 1000000000,
};

static void* lan966x_clk_ctlreg(struct lan966x_clk *gck, u8 id)
{
	return gck->base + (id * sizeof(u32));
}

static ulong lan966x_clk_set_rate(struct clk *clk, ulong rate)
{
	struct lan966x_clk *gck = dev_get_priv(clk->dev);
	unsigned long parent_rate = gck->parent_rate;
	u32 div;

	if (clk->id >= gck->clk_cnt)
		return -ENODEV;

	if (rate == 0)
		return -EINVAL;

	/* Calc divisor */
	div = DIV_ROUND_CLOSEST(parent_rate, rate);

	/* Set src, prescaler */
	clrsetbits_le32(lan966x_clk_ctlreg(gck, clk->id),
			GCK_SRC_SEL | GCK_PRESCALER,
			/* Select CPU_CLK as source always */
			FIELD_PREP(GCK_SRC_SEL, 0x0) |
			/* Divisor - 1 */
			FIELD_PREP(GCK_PRESCALER, (div - 1)));

	return 0;
}

static ulong lan966x_clk_get_rate(struct clk *clk)
{
	struct lan966x_clk *gck = dev_get_priv(clk->dev);
	unsigned long parent_rate = gck->parent_rate;
	u32 div, val;

	if (clk->id >= gck->clk_cnt)
		return -ENODEV;

	val = readl(lan966x_clk_ctlreg(gck, clk->id));

	div = 1 + FIELD_GET(GCK_PRESCALER, val);

	return parent_rate / div;
}

static int lan966x_clk_enable(struct clk *clk)
{
	struct lan966x_clk *gck = dev_get_priv(clk->dev);

	if (clk->id >= gck->clk_cnt)
		return -ENODEV;

	setbits_le32(lan966x_clk_ctlreg(gck, clk->id), GCK_ENA);

	return 0;
}

static int lan966x_clk_disable(struct clk *clk)
{
	struct lan966x_clk *gck = dev_get_priv(clk->dev);

	if (clk->id >= gck->clk_cnt)
		return -ENODEV;

	clrbits_le32(lan966x_clk_ctlreg(gck, clk->id), GCK_ENA);

	return 0;
}

static int lan966x_clk_probe(struct udevice *dev)
{
	struct lan966x_clk *priv = dev_get_priv(dev);
	struct lan966x_driver_data *data;

	priv->base = dev_remap_addr(dev);
	if (IS_ERR(priv->base))
		return PTR_ERR(priv->base);

	/* Get clock count for target device */
	data = (struct lan966x_driver_data*)dev_get_driver_data(dev);
	priv->clk_cnt = data->clk_cnt;
	priv->parent_rate = data->parent_rate;

	return 0;
}

static struct clk_ops lan966x_clk_ops = {
	.disable	= lan966x_clk_disable,
	.enable		= lan966x_clk_enable,
	.get_rate	= lan966x_clk_get_rate,
	.set_rate	= lan966x_clk_set_rate,
};

static const struct udevice_id lan966x_clk_ids[] = {
	{ .compatible = "mchp,lan966x-clk", .data = (unsigned long)&lan966x_data },
	{ .compatible = "mchp,lan969x-clk", .data = (unsigned long)&lan969x_data },
	{ }
};

U_BOOT_DRIVER(lan966x_clk) = {
	.name		= "lan966x_clk",
	.id		= UCLASS_CLK,
	.of_match	= lan966x_clk_ids,
	.priv_auto	= sizeof(struct lan966x_clk),
	.ops		= &lan966x_clk_ops,
	.probe		= lan966x_clk_probe,
};
