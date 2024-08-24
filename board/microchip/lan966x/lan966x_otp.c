// SPDX-License-Identifier: GPL-2.0+

#include <common.h>
#include <linux/delay.h>
#include <linux/if_ether.h>
#include <asm/io.h>

/*      OTP:OTP_REGS:OTP_PWR_DN */
#define OTP_OTP_PWR_DN(t)         (t + 0x00)

#define OTP_OTP_PWR_DN_OTP_PWRDN_N(x)            ((x) & GENMASK(0, 0))
#define OTP_OTP_PWR_DN_OTP_PWRDN_N_M             GENMASK(0, 0)
#define OTP_OTP_PWR_DN_OTP_PWRDN_N_X(x)          ((x) & GENMASK(0, 0))

/*      OTP:OTP_REGS:OTP_ADDR_HI */
#define OTP_OTP_ADDR_HI(t)        (t + 0x04)

#define OTP_OTP_ADDR_HI_OTP_ADDR_15_11(x)        ((x) & GENMASK(4, 0))
#define OTP_OTP_ADDR_HI_OTP_ADDR_15_11_M         GENMASK(4, 0)
#define OTP_OTP_ADDR_HI_OTP_ADDR_15_11_X(x)      ((x) & GENMASK(4, 0))

/*      OTP:OTP_REGS:OTP_ADDR_LO */
#define OTP_OTP_ADDR_LO(t)        (t + 0x08)

#define OTP_OTP_ADDR_LO_OTP_ADDR_10_3(x)         ((x) & GENMASK(7, 0))
#define OTP_OTP_ADDR_LO_OTP_ADDR_10_3_M          GENMASK(7, 0)
#define OTP_OTP_ADDR_LO_OTP_ADDR_10_3_X(x)       ((x) & GENMASK(7, 0))

/*      OTP:OTP_REGS:OTP_PRGM_DATA */
#define OTP_OTP_PRGM_DATA(t)      (t + 0x10)

#define OTP_OTP_PRGM_DATA_OTP_WR_DATA(x)         ((x) & GENMASK(7, 0))
#define OTP_OTP_PRGM_DATA_OTP_WR_DATA_M          GENMASK(7, 0)
#define OTP_OTP_PRGM_DATA_OTP_WR_DATA_X(x)       ((x) & GENMASK(7, 0))

/*      OTP:OTP_REGS:OTP_PRGM_MODE */
#define OTP_OTP_PRGM_MODE(t)      (t + 0x14)

#define OTP_OTP_PRGM_MODE_OTP_PGM_MODE_BYTE(x)   ((x) & GENMASK(0, 0))
#define OTP_OTP_PRGM_MODE_OTP_PGM_MODE_BYTE_M    GENMASK(0, 0)
#define OTP_OTP_PRGM_MODE_OTP_PGM_MODE_BYTE_X(x) ((x) & GENMASK(0, 0))

/*      OTP:OTP_REGS:OTP_RD_DATA */
#define OTP_OTP_RD_DATA(t)        (t + 0x18)

#define OTP_OTP_RD_DATA_OTP_RD_DATA_FLD(x)       ((x) & GENMASK(7, 0))
#define OTP_OTP_RD_DATA_OTP_RD_DATA_FLD_M        GENMASK(7, 0)
#define OTP_OTP_RD_DATA_OTP_RD_DATA_FLD_X(x)     ((x) & GENMASK(7, 0))

/*      OTP:OTP_REGS:OTP_FUNC_CMD */
#define OTP_OTP_FUNC_CMD(t)       (t + 0x20)

#define OTP_OTP_FUNC_CMD_OTP_FW_SMART_PGM_INIT_ACCESS(x)\
	(((x) << 4) & GENMASK(4, 4))
#define OTP_OTP_FUNC_CMD_OTP_FW_SMART_PGM_INIT_ACCESS_M GENMASK(4, 4)
#define OTP_OTP_FUNC_CMD_OTP_FW_SMART_PGM_INIT_ACCESS_X(x)\
	(((x) & GENMASK(4, 4)) >> 4)

#define OTP_OTP_FUNC_CMD_OTP_FW_SMART_PGM_EN(x)  (((x) << 3) & GENMASK(3, 3))
#define OTP_OTP_FUNC_CMD_OTP_FW_SMART_PGM_EN_M   GENMASK(3, 3)
#define OTP_OTP_FUNC_CMD_OTP_FW_SMART_PGM_EN_X(x) (((x) & GENMASK(3, 3)) >> 3)

#define OTP_OTP_FUNC_CMD_OTP_RESET(x)            (((x) << 2) & GENMASK(2, 2))
#define OTP_OTP_FUNC_CMD_OTP_RESET_M             GENMASK(2, 2)
#define OTP_OTP_FUNC_CMD_OTP_RESET_X(x)          (((x) & GENMASK(2, 2)) >> 2)

#define OTP_OTP_FUNC_CMD_OTP_PROGRAM(x)          (((x) << 1) & GENMASK(1, 1))
#define OTP_OTP_FUNC_CMD_OTP_PROGRAM_M           GENMASK(1, 1)
#define OTP_OTP_FUNC_CMD_OTP_PROGRAM_X(x)        (((x) & GENMASK(1, 1)) >> 1)

#define OTP_OTP_FUNC_CMD_OTP_READ(x)             ((x) & GENMASK(0, 0))
#define OTP_OTP_FUNC_CMD_OTP_READ_M              GENMASK(0, 0)
#define OTP_OTP_FUNC_CMD_OTP_READ_X(x)           ((x) & GENMASK(0, 0))

/*      OTP:OTP_REGS:OTP_CMD_GO */
#define OTP_OTP_CMD_GO(t)         (t + 0x28)

#define OTP_OTP_CMD_GO_OTP_GO(x)                 ((x) & GENMASK(0, 0))
#define OTP_OTP_CMD_GO_OTP_GO_M                  GENMASK(0, 0)
#define OTP_OTP_CMD_GO_OTP_GO_X(x)               ((x) & GENMASK(0, 0))

/*      OTP:OTP_REGS:OTP_PASS_FAIL */
#define OTP_OTP_PASS_FAIL(t)      (t + 0x2c)

#define OTP_OTP_PASS_FAIL_OTP_READ_PROHIBITED(x) (((x) << 3) & GENMASK(3, 3))
#define OTP_OTP_PASS_FAIL_OTP_READ_PROHIBITED_M  GENMASK(3, 3)
#define OTP_OTP_PASS_FAIL_OTP_READ_PROHIBITED_X(x) (((x) & GENMASK(3, 3)) >> 3)

#define OTP_OTP_PASS_FAIL_OTP_WRITE_PROHIBITED(x) (((x) << 2) & GENMASK(2, 2))
#define OTP_OTP_PASS_FAIL_OTP_WRITE_PROHIBITED_M GENMASK(2, 2)
#define OTP_OTP_PASS_FAIL_OTP_WRITE_PROHIBITED_X(x) (((x) & GENMASK(2, 2)) >> 2)

#define OTP_OTP_PASS_FAIL_OTP_PASS(x)            (((x) << 1) & GENMASK(1, 1))
#define OTP_OTP_PASS_FAIL_OTP_PASS_M             GENMASK(1, 1)
#define OTP_OTP_PASS_FAIL_OTP_PASS_X(x)          (((x) & GENMASK(1, 1)) >> 1)

#define OTP_OTP_PASS_FAIL_OTP_FAIL(x)            ((x) & GENMASK(0, 0))
#define OTP_OTP_PASS_FAIL_OTP_FAIL_M             GENMASK(0, 0)
#define OTP_OTP_PASS_FAIL_OTP_FAIL_X(x)          ((x) & GENMASK(0, 0))

/*      OTP:OTP_REGS:OTP_STATUS */
#define OTP_OTP_STATUS(t)         (t + 0x30)

#define OTP_OTP_STATUS_OTP_WEB(x)                (((x) << 3) & GENMASK(3, 3))
#define OTP_OTP_STATUS_OTP_WEB_M                 GENMASK(3, 3)
#define OTP_OTP_STATUS_OTP_WEB_X(x)              (((x) & GENMASK(3, 3)) >> 3)

#define OTP_OTP_STATUS_OTP_PGMEN(x)              (((x) << 2) & GENMASK(2, 2))
#define OTP_OTP_STATUS_OTP_PGMEN_M               GENMASK(2, 2)
#define OTP_OTP_STATUS_OTP_PGMEN_X(x)            (((x) & GENMASK(2, 2)) >> 2)

#define OTP_OTP_STATUS_OTP_CPUMPEN(x)            (((x) << 1) & GENMASK(1, 1))
#define OTP_OTP_STATUS_OTP_CPUMPEN_M             GENMASK(1, 1)
#define OTP_OTP_STATUS_OTP_CPUMPEN_X(x)          (((x) & GENMASK(1, 1)) >> 1)

#define OTP_OTP_STATUS_OTP_BUSY(x)               ((x) & GENMASK(0, 0))
#define OTP_OTP_STATUS_OTP_BUSY_M                GENMASK(0, 0)
#define OTP_OTP_STATUS_OTP_BUSY_X(x)             ((x) & GENMASK(0, 0))

#define WORD_SIZE 1
#define OTP_MEM_SIZE 8192

#define OTP_TAG_OFFSET 4096
#define OTP_TAG_ENTRY_LENGTH 8
#define OTP_TAG_VAL_LENGTH 6

enum otp_tag_type {
	otp_tag_type_invalid,
	otp_tag_type_password,
	otp_tag_type_pcb,
	otp_tag_type_revision,
	otp_tag_type_mac,
	otp_tag_type_mac_count,
};

#define OTP_TAG_GET_SIZE(tag) ((0xff & (uint16_t)tag[7]) / 32)
#define OTP_TAG_GET_TAG(tag)  ((((uint16_t)tag[7]) & 0x4) | tag[6])

struct otp_field {
	char *name;
	u32 offset;
	u32 length;
};

static struct otp_field otp_fields[] = {
	{ .name = "OTP_PRG",			.offset = 0x0,		.length = 4,	},
	{ .name = "FEAT_IDS",			.offset = 0x4,		.length = 1,	},
	{ .name = "PARTID",			.offset = 0x5,		.length = 2,	},
	{ .name = "TST_TRK",			.offset = 0x7,		.length = 1,	},
	{ .name = "SERIAL_NUMBER",		.offset = 0x8,		.length = 8,	},
	{ .name = "SECURE_JTAG",		.offset = 0x10,		.length = 4,	},
	{ .name = "WAFER_JTAG",			.offset = 0x14,		.length = 7,	},
	{ .name = "JTAG_UUID",			.offset = 0x20,		.length = 10,	},
	{ .name = "TRIM",			.offset = 0x30,		.length = 8,	},
	{ .name = "PROTECT_OTP_WRITE",		.offset = 0x40,		.length = 4,	},
	{ .name = "PROTECT_REGION_ADDR",	.offset = 0x44,		.length = 32,	},
	{ .name = "OTP_PCIE_FLAGS",		.offset = 0x64,		.length = 4,	},
	{ .name = "OTP_PCIE_DEV",		.offset = 0x68,		.length = 4,	},
	{ .name = "OTP_PCIE_ID",		.offset = 0x6c,		.length = 8,	},
	{ .name = "OTP_PCIE_BARS",		.offset = 0x74,		.length = 40,	},
	{ .name = "OTP_TBBR_ROTPK",		.offset = 0x100,	.length = 32,	},
	{ .name = "OTP_TBBR_HUK",		.offset = 0x120,	.length = 32,	},
	{ .name = "OTP_TBBR_EK",		.offset = 0x140,	.length = 32,	},
	{ .name = "OTP_TBBR_SSK",		.offset = 0x160,	.length = 32,	},
	{ .name = "OTP_SJTAG_SSK",		.offset = 0x180,	.length = 32,	},
	{ .name = "OTP_STRAP_DISABLE_MASK",	.offset = 0x1a4,	.length = 2,	},
};

struct lan966x_otp {
	u32 base;
};

static struct lan966x_otp lan966x_otp;

static inline void lan966x_writel(u32 addr, u32 val)
{
	writel(val, addr);
}

static inline u32 lan966x_readl(u32 addr)
{
	return readl(addr);
}

static inline void lan966x_clrbits(u32 addr, u32 clear)
{
	writel(readl(addr) & ~clear, addr);
}

static inline void lan966x_setbits(u32 addr, u32 set)
{
	writel(readl(addr) | set, addr);
}

static bool lan966x_otp_wait_flag_clear(u32 reg, u32 flag)
{
	/* Wait at most 500 ms */
	int i = 500 * 1000;
	u32 val;

	while (i--) {
		val = readl(reg);
		if (!(val & flag))
			return true;
		udelay(1);
	}
	return false;
}

static int lan966x_otp_power(struct lan966x_otp *otp, bool up)
{
	if (up) {
		lan966x_clrbits(OTP_OTP_PWR_DN(otp->base),
				OTP_OTP_PWR_DN_OTP_PWRDN_N(1));
		if (!lan966x_otp_wait_flag_clear(OTP_OTP_STATUS(otp->base),
						 OTP_OTP_STATUS_OTP_CPUMPEN(1)))
			return -ETIMEDOUT;
	} else {
		lan966x_setbits(OTP_OTP_PWR_DN(otp->base),
				OTP_OTP_PWR_DN_OTP_PWRDN_N(1));
	}

	return 0;
}

static int lan966x_otp_execute(struct lan966x_otp *otp)
{
	if (!lan966x_otp_wait_flag_clear(OTP_OTP_CMD_GO(otp->base),
					 OTP_OTP_CMD_GO_OTP_GO(1)))
		return -ETIMEDOUT;

	if (!lan966x_otp_wait_flag_clear(OTP_OTP_STATUS(otp->base),
					 OTP_OTP_STATUS_OTP_BUSY(1)))
		return -ETIMEDOUT;

	return 0;
}

static void lan966x_otp_set_address(struct lan966x_otp *otp, u32 offset)
{
	lan966x_writel(OTP_OTP_ADDR_HI(otp->base), 0xff & (offset >> 8));
	lan966x_writel(OTP_OTP_ADDR_LO(otp->base), 0xff & offset);
}

static int lan966x_otp_read_byte(struct lan966x_otp *otp, u32 offset, u8 *dst)
{
	u32 pass;
	int rc;

	lan966x_otp_set_address(otp, offset);
	lan966x_writel(OTP_OTP_FUNC_CMD(otp->base),
		       OTP_OTP_FUNC_CMD_OTP_READ(1));
	lan966x_writel(OTP_OTP_CMD_GO(otp->base),
		       OTP_OTP_CMD_GO_OTP_GO(1));
	rc = lan966x_otp_execute(otp);
	if (!rc) {
		pass = lan966x_readl(OTP_OTP_PASS_FAIL(otp->base));
		if (pass & OTP_OTP_PASS_FAIL_OTP_READ_PROHIBITED(1))
			return -EACCES;
		*dst = (u8) lan966x_readl(OTP_OTP_RD_DATA(otp->base));
	}
	return rc;
}

static int lan966x_otp_read(struct lan966x_otp *otp,
			    unsigned int offset, void *_val, size_t bytes)
{
	u8 *val = _val;
	uint8_t data;
	int i, rc = 0;

	lan966x_otp_power(otp, true);
	for (i = 0; i < bytes; i++) {
		rc = lan966x_otp_read_byte(otp, offset + i, &data);
		if (rc < 0)
			break;
		*val++ = data;
	}
	lan966x_otp_power(otp, false);

	return rc;
}

static bool lan966x_otp_tag_valid(char *tag_raw)
{
	uint8_t size;

	size = OTP_TAG_GET_SIZE(tag_raw);
	if (size != 0 && size != 7)
		return true;

	return false;
}

static bool lan966x_otp_get_tag(struct lan966x_otp *otp, enum otp_tag_type tag,
				u8 *res)
{
	char tag_raw[OTP_TAG_ENTRY_LENGTH];
	int err;
	int i;

	if (res == NULL)
		return false;

	for (i = OTP_TAG_OFFSET; i < OTP_MEM_SIZE; i += OTP_TAG_ENTRY_LENGTH) {
		err = lan966x_otp_read(otp, i, tag_raw, OTP_TAG_ENTRY_LENGTH);
		if (err)
			return false;

		if (!lan966x_otp_tag_valid(tag_raw))
			continue;

		if (OTP_TAG_GET_TAG(tag_raw) != tag)
			continue;

		memcpy(res, tag_raw, OTP_TAG_VAL_LENGTH);

		return true;
	}

	return false;
}

static struct otp_field *lan966x_otp_find_field(struct lan966x_otp *otp, char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(otp_fields); ++i) {
		if (strcmp(otp_fields[i].name, name))
			continue;

		return &otp_fields[i];
	}

	return NULL;
}

static bool lan966x_otp_get_field(struct lan966x_otp *otp, char *name,
				  u8 *res)
{
	struct otp_field *field;
	int err;

	if (res == NULL)
		return false;

	field = lan966x_otp_find_field(otp, name);
	if (!field)
		return false;

	err = lan966x_otp_read(otp, field->offset, res, field->length);
	if (err)
		return false;

	return true;
}

static void lan966x_otp_reverse(u8 *res, int length)
{
	int i;

	if (length <= 0)
		return;

	for (i = 0; i < length / 2; ++i) {
		u8 tmp = res[i];
		res[i] = res[length - i - 1];
		res[length - i - 1] = tmp;
	}
}

bool lan966x_otp_get_mac(u8 *mac)
{
	bool ret;

	ret = lan966x_otp_get_tag(&lan966x_otp, otp_tag_type_mac, mac);
	if (!ret)
		return ret;

	lan966x_otp_reverse(mac, ETH_ALEN);
	return ret;
}

bool lan966x_otp_get_pcb(u16 *pcb)
{
	u8 tmp[2];
	bool ret;

	ret = lan966x_otp_get_tag(&lan966x_otp, otp_tag_type_pcb, tmp);
	if (!ret)
		return ret;

	*pcb = (u16)tmp[1] << 8 | tmp[0];
	return ret;
}

bool lan966x_otp_get_mac_count(char *mac_count)
{
	bool ret;
	u8 tmp;

	ret = lan966x_otp_get_tag(&lan966x_otp, otp_tag_type_mac_count, &tmp);
	if (!ret)
		return ret;

	sprintf(mac_count, "%d", tmp);
	return ret;
}

bool lan966x_otp_get_partid(char *part)
{
	bool ret;
	u8 tmp[2];

	ret = lan966x_otp_get_field(&lan966x_otp, "PARTID", tmp);
	if (!ret)
		return ret;

	sprintf(part, "%d", (u16)tmp[1] << 8 | tmp[0]);
	return ret;
}

bool lan966x_otp_get_serial_number(char *serial)
{
	bool ret;
	u8 tmp[8];

	ret = lan966x_otp_get_field(&lan966x_otp, "SERIAL_NUMBER", tmp);
	if (!ret)
		return ret;

	sprintf(serial, "%02d%02d%02d%02d%02d%02d%02d%02d",
		tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]);
	return ret;
}

void lan966x_otp_init(void)
{
	lan966x_otp.base = 0xe0021000;
}

