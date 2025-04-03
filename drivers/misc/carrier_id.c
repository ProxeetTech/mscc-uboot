#include <common.h>
#include <dm.h>
#include <env.h>
#include <asm/gpio.h>
#include <dm/device_compat.h>
#include <linux/errno.h>

#define CARRIER_ID_NUM_PINS 8

static int carrier_id_probe(struct udevice *dev)
{
	u32 pins[CARRIER_ID_NUM_PINS];
	u8 id_val = 0;
	char buf[4];
	int ret, i;

	ret = dev_read_u32_array(dev, "id-gpios", pins, CARRIER_ID_NUM_PINS);
	if (ret) {
		dev_err(dev, "Failed to read 'id-gpios': ret=%d\n", ret);
		return ret;
	}

	for (i = 0; i < CARRIER_ID_NUM_PINS; i++) {
		unsigned int gpio_num = pins[CARRIER_ID_NUM_PINS - i - 1];
		int value;

		ret = gpio_request(gpio_num, "carrier_id_line");
		if (ret && ret != -EBUSY) {
			dev_err(dev, "Failed to request GPIO %u (err=%d)\n", gpio_num, ret);
			return ret;
		}

		gpio_direction_input(gpio_num);
		value = gpio_get_value(gpio_num);
		if (value < 0) {
			dev_err(dev, "Failed to read GPIO %u (err=%d)\n", gpio_num, value);
			if (!ret)
				gpio_free(gpio_num);
			return value;
		}

		id_val <<= 1;
        id_val |= (value & 1);

		if (!ret)
			gpio_free(gpio_num);
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
