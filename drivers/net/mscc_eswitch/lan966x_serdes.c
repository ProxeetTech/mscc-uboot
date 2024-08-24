// SPDX-License-Identifier: (GPL-2.0+ OR MIT)

#include <common.h>
#include <config.h>

#include "lan966x.h"

enum lan966x_sd6g40_mode {
	LAN966X_SD6G40_MODE_QSGMII,
};

enum lan966x_sd6g40_ltx2rx {
	LAN966X_SD6G40_TX2RX_LOOP_NONE,
	LAN966X_SD6G40_LTX2RX
};

struct lan966x_sd6g40_setup_args {
	enum lan966x_sd6g40_mode  mode;
	enum lan966x_sd6g40_ltx2rx tx2rx_loop;
	u8  rx_eq;
	u8  tx_preemp;
	bool txinvert;
	bool rxinvert;
	bool refclk125M;
	bool mute;
};

struct lan966x_sd6g40_mode_args {
	enum lan966x_sd6g40_mode  mode;
	u8 lane_10bit_sel;
	u8 mpll_multiplier;
	u8 ref_clkdiv2;
	u8 tx_rate;
	u8 rx_rate;
};

struct lan966x_sd6g40_setup {
	u8 rx_eq[1];
	u8 tx_preemp[1];
	u8 rx_term_en[1];
	u8 lane_10bit_sel[1];
	u8 tx_invert[1];
	u8 rx_invert[1];
	u8 mpll_multiplier[1];
	u8 lane_loopbk_en[1];
	u8 ref_clkdiv2[1];
	u8 tx_rate[1];
	u8 rx_rate[1];
};

static void lan966x_sd6g40_reg_cfg(struct lan966x_private *lan966x,
				   struct lan966x_sd6g40_setup *res_struct,
				   u32 idx) {
	u32 value;

	/* Note: SerDes HSIO is configured in 1G_LAN mode */
	LAN_RMW(HSIO_SD_CFG_LANE_10BIT_SEL(res_struct->lane_10bit_sel[0]) |
		HSIO_SD_CFG_RX_RATE(res_struct->rx_rate[0]) |
		HSIO_SD_CFG_TX_RATE(res_struct->tx_rate[0]) |
		HSIO_SD_CFG_TX_INVERT(res_struct->tx_invert[0]) |
		HSIO_SD_CFG_RX_INVERT(res_struct->rx_invert[0]) |
		HSIO_SD_CFG_LANE_LOOPBK_EN(res_struct->lane_loopbk_en[0]) |
		HSIO_SD_CFG_RX_RESET(0) |
		HSIO_SD_CFG_TX_RESET(0),
		HSIO_SD_CFG_LANE_10BIT_SEL_M |
		HSIO_SD_CFG_RX_RATE_M |
		HSIO_SD_CFG_TX_RATE_M |
		HSIO_SD_CFG_TX_INVERT_M |
		HSIO_SD_CFG_RX_INVERT_M |
		HSIO_SD_CFG_LANE_LOOPBK_EN_M |
		HSIO_SD_CFG_RX_RESET_M |
		HSIO_SD_CFG_TX_RESET_M,
		lan966x, HSIO_SD_CFG(idx));

	LAN_RMW(HSIO_MPLL_CFG_MPLL_MULTIPLIER(res_struct->mpll_multiplier[0]) |
		HSIO_MPLL_CFG_REF_CLKDIV2(res_struct->ref_clkdiv2[0]),
		HSIO_MPLL_CFG_MPLL_MULTIPLIER_M |
		HSIO_MPLL_CFG_REF_CLKDIV2_M,
		lan966x, HSIO_MPLL_CFG(idx));

	LAN_RMW(HSIO_SD_CFG2_RX_EQ(res_struct->rx_eq[0]),
		HSIO_SD_CFG2_RX_EQ_M,
		lan966x, HSIO_SD_CFG2(idx));

	LAN_RMW(HSIO_SD_CFG2_TX_PREEMPH(res_struct->tx_preemp[0]),
		HSIO_SD_CFG2_TX_PREEMPH_M,
		lan966x, HSIO_SD_CFG2(idx));

	LAN_RMW(HSIO_SD_CFG_RX_TERM_EN(res_struct->rx_term_en[0]),
		HSIO_SD_CFG_RX_TERM_EN_M,
		lan966x, HSIO_SD_CFG(idx));

	LAN_RMW(HSIO_MPLL_CFG_REF_SSP_EN(1),
		HSIO_MPLL_CFG_REF_SSP_EN_M,
		lan966x, HSIO_MPLL_CFG(idx));

	udelay(1000);

	LAN_RMW(HSIO_SD_CFG_PHY_RESET(0),
		HSIO_SD_CFG_PHY_RESET_M,
		lan966x, HSIO_SD_CFG(idx));

	udelay(1000);

	LAN_RMW(HSIO_MPLL_CFG_MPLL_EN(1),
		HSIO_MPLL_CFG_MPLL_EN_M,
		lan966x, HSIO_MPLL_CFG(idx));

	udelay(7000);

	value = LAN_RD(lan966x, HSIO_SD_STAT(idx));
	value = HSIO_SD_STAT_MPLL_STATE_X(value);
	if (value != 0x1)
		printf("The expected value for sd_sd_stat[%u] mpll_state was 0x1 but is 0x%x\n", idx, value);

	LAN_RMW(HSIO_SD_CFG_TX_CM_EN(1),
		HSIO_SD_CFG_TX_CM_EN_M,
		lan966x, HSIO_SD_CFG(idx));

	udelay(1000);

	value = LAN_RD(lan966x, HSIO_SD_STAT(idx));
	value = HSIO_SD_STAT_TX_CM_STATE_X(value);
	if (value != 0x1)
		printf("The expected value for sd_sd_stat[%u] tx_cm_state was 0x1 but is 0x%x\n", idx, value);

	LAN_RMW(HSIO_SD_CFG_RX_PLL_EN(1) |
		HSIO_SD_CFG_TX_EN(1),
		HSIO_SD_CFG_RX_PLL_EN_M |
		HSIO_SD_CFG_TX_EN_M,
		lan966x, HSIO_SD_CFG(idx));

	udelay(1000);

	/* Waiting for serdes 0 rx DPLL to lock...  */
	value = LAN_RD(lan966x, HSIO_SD_STAT(idx));
	value = HSIO_SD_STAT_RX_PLL_STATE_X(value);
	if (value != 0x1)
		printf("The expected value for sd_sd_stat[%u] rx_pll_state was 0x1 but is 0x%x\n", idx, value);

	/* Waiting for serdes 0 tx operational...  */
	value = LAN_RD(lan966x, HSIO_SD_STAT(idx));
	value = HSIO_SD_STAT_TX_STATE_X(value);
	if (value != 0x1)
		printf("The expected value for sd_sd_stat[%u] tx_state was 0x1 but is 0x%x\n", idx, value);

	LAN_RMW(HSIO_SD_CFG_TX_DATA_EN(1) |
		HSIO_SD_CFG_RX_DATA_EN(1),
		HSIO_SD_CFG_TX_DATA_EN_M |
		HSIO_SD_CFG_RX_DATA_EN_M,
		lan966x, HSIO_SD_CFG(idx));
}

static int lan966x_sd6g40_get_conf_from_mode(enum lan966x_sd6g40_mode f_mode,
					     bool ref125M,
					     struct lan966x_sd6g40_mode_args *ret_val) {
	switch(f_mode) {
	case LAN966X_SD6G40_MODE_QSGMII:
		ret_val->lane_10bit_sel = 0;
		if (ref125M) {
			ret_val->mpll_multiplier = 40;
			ret_val->ref_clkdiv2= 0x1;
			ret_val->tx_rate= 0x0;
			ret_val->rx_rate= 0x0;
		} else {
			ret_val->mpll_multiplier = 100;
			ret_val->ref_clkdiv2= 0x0;
			ret_val->tx_rate= 0x0;
			ret_val->rx_rate= 0x0;
		}
		break;
	default:
		return -1;
	}

	return 0;
}

static int lan966x_calc_sd6g40_setup_lane(struct lan966x_sd6g40_setup_args config,
					  struct lan966x_sd6g40_setup *ret_val) {

	struct lan966x_sd6g40_mode_args sd6g40_mode;
	struct lan966x_sd6g40_mode_args *mode_args = &sd6g40_mode;

	if (lan966x_sd6g40_get_conf_from_mode(config.mode, config.refclk125M,
					      mode_args))
		return -1;

	ret_val->lane_10bit_sel[0] = mode_args->lane_10bit_sel;
	ret_val->rx_rate[0] = mode_args->rx_rate;
	ret_val->tx_rate[0] = mode_args->tx_rate;
	ret_val->mpll_multiplier[0] = mode_args->mpll_multiplier;
	ret_val->ref_clkdiv2[0] = mode_args->ref_clkdiv2;
	ret_val->rx_eq[0] = config.rx_eq;
	ret_val->rx_eq[0] = config.tx_preemp;
	ret_val->rx_term_en[0] = 0;

	if (config.tx2rx_loop == LAN966X_SD6G40_LTX2RX) {
		ret_val->lane_loopbk_en[0] = 1;
	} else {
		ret_val->lane_loopbk_en[0] = 0;
	}

	if (config.txinvert) {
		ret_val->tx_invert[0] = 1;
	} else {
		ret_val->tx_invert[0] = 0;
	}

	if (config.rxinvert) {
		ret_val->rx_invert[0] = 1;
	} else {
		ret_val->rx_invert[0] = 0;
	}

	return 0;
}

static int lan966x_sd6g40_setup_lane(struct lan966x_private *lan966x,
				     struct lan966x_sd6g40_setup_args config,
				     u32 idx) {
	struct lan966x_sd6g40_setup calc_results;
	int ret;

	memset(&calc_results, 0x0, sizeof(calc_results));

	ret = lan966x_calc_sd6g40_setup_lane(config, &calc_results);
	if (ret)
		return ret;

	lan966x_sd6g40_reg_cfg(lan966x, &calc_results, idx);

	return 0;
}

int lan966x_sd6g40_setup(struct lan966x_private *lan966x, u32 idx)
{
	struct lan966x_sd6g40_setup_args conf;
	u32 value;

	memset(&conf, 0x0, sizeof(conf));
	conf.mode = LAN966X_SD6G40_MODE_QSGMII;

	// PLL determines whether 125MHz or 25MHz is used
	value = LAN_RD(lan966x, GCB_HW_STAT);
	value = GCB_HW_STAT_PLL_CONF_X(value);
	conf.refclk125M = (value == 1 || value == 2 ? 1 : 0);

	return lan966x_sd6g40_setup_lane(lan966x, conf, idx);
}
