// SPDX-License-Identifier: (GPL-2.0+ OR MIT)

#ifndef _LAN966X_H_
#define _LAN966X_H_

#include <common.h>
#include <linux/iopoll.h>

#include "lan966x_regs.h"

#include "mscc_miim.h"

struct lan966x_port {
	u8 chip_port;
	u8 phy_addr;
	u8 serdes_index;
	u8 phy_mode;

	struct mii_dev *bus;
	struct phy_device *phy;
	struct udevice *dev;
	struct mscc_miim_dev miim;
	struct lan966x_private *lan966x;
};

struct lan966x_private {
	void __iomem *regs[NUM_TARGETS];

	u8 num_phys_ports;
	struct lan966x_port **ports;
};

int lan966x_sd6g40_setup(struct lan966x_private *lan966x, u32 idx);

#define LAN_RD_(lan966x, id, tinst, tcnt,		\
		gbase, ginst, gcnt, gwidth,		\
		raddr, rinst, rcnt, rwidth)		\
	readl(lan966x->regs[id + (tinst)] +		\
	      gbase + ((ginst) * gwidth) +		\
	      raddr + ((rinst) * rwidth))

#define LAN_WR_(val, lan966x, id, tinst, tcnt,		\
		gbase, ginst, gcnt, gwidth,		\
		raddr, rinst, rcnt, rwidth)		\
	writel(val, lan966x->regs[id + (tinst)] +	\
	       gbase + ((ginst) * gwidth) +		\
	       raddr + ((rinst) * rwidth))

#define LAN_RMW_(val, mask, lan966x, id, tinst, tcnt,	\
		 gbase, ginst, gcnt, gwidth,		\
		 raddr, rinst, rcnt, rwidth) do {	\
	u32 _v_;					\
	_v_ = readl(lan966x->regs[id + (tinst)] +	\
		    gbase + ((ginst) * gwidth) +	\
		    raddr + ((rinst) * rwidth));	\
	_v_ = ((_v_ & ~(mask)) | ((val) & (mask)));	\
	writel(_v_, lan966x->regs[id + (tinst)] +	\
	       gbase + ((ginst) * gwidth) +		\
	       raddr + ((rinst) * rwidth)); } while (0)

#define LAN_WR(...) LAN_WR_(__VA_ARGS__)
#define LAN_RD(...) LAN_RD_(__VA_ARGS__)
#define LAN_RMW(...) LAN_RMW_(__VA_ARGS__)


#endif
