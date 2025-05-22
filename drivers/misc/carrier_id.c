#include <common.h>
#include <dm.h>
#include <env.h>
#include <asm/gpio.h>
#include <dm/device_compat.h>
#include <linux/errno.h>

#define CARRIER_ID_NUM_PINS 8

static int carrier_id_probe(struct udevice *dev) {
	u8  id_val = 0;
	char buf[4];
	int ret, i;

	for (i = 0; i < CARRIER_ID_NUM_PINS; i++) {
		struct gpio_desc gpiod;
		int idx   = CARRIER_ID_NUM_PINS - 1 - i;
		int value;

		ret = gpio_request_by_name(dev, "id-gpios", idx, &gpiod,
								   GPIOD_IS_IN | GPIOD_PULL_UP);
		if (ret) {
			dev_err(dev, "id-gpios[%d] request error %d\n", idx, ret);
			return ret;
		}

		value = dm_gpio_get_value(&gpiod);
		if (value < 0) {
			dev_err(dev, "Failed to read id-gpios[%d] (err=%d)\n", idx, value);
			dm_gpio_free(dev, &gpiod);
			return value;
		}

		id_val = (id_val << 1) | (value & 1);

		dm_gpio_free(dev, &gpiod);
	}

	snprintf(buf, sizeof(buf), "%u", id_val);
	env_set("carrier_id", buf);
	dev_info(dev, "Carrier ID = %u\n", id_val);

	return 0;
}

static const struct udevice_id carrier_id_ids[] = {
	{ .compatible = "custom,carrier-id-gpio" },
	{ }
};

U_BOOT_DRIVER(carrier_id) = {
	.name           = "carrier_id",
	.id             = UCLASS_MISC,
	.of_match       = carrier_id_ids,
	.probe          = carrier_id_probe,
};
