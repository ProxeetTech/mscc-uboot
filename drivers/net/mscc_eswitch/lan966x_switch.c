// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * Copyright (c) 2018 Microsemi Corporation
 */

#include <common.h>
#include <config.h>
#include <dm.h>
#include <dm/device_compat.h>
#include <dm/device-internal.h>
#include <dm/devres.h>
#include <dm/of_access.h>
#include <dm/of_addr.h>
#include <fdt_support.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/iopoll.h>
#include <miiphy.h>
#include <net.h>
#include <wait_bit.h>

#include "mscc_miim.h"
#include "lan966x.h"
#include "lan966x_ifh.h"

#define READL_TIMEOUT_US	100000
#define TABLE_UPDATE_TIMEOUT_US 100000

#define IFH_LEN			7

#define PGID_AGGR		64
#define PGID_SRC		80
#define PGID_ENTRIES		89

/* Reserved PGIDs */
#define PGID_CPU		(PGID_AGGR - 6)
#define PGID_UC			(PGID_AGGR - 5)
#define PGID_BC			(PGID_AGGR - 4)
#define PGID_MC			(PGID_AGGR - 3)
#define PGID_MCIPV4		(PGID_AGGR - 2)
#define PGID_MCIPV6		(PGID_AGGR - 1)

#define CPU_PORT		8

#define ETH_ALEN		6

#define LAN966X_BUFFER_CELL_SZ		60

#define MACACCESS_CMD_IDLE		0
#define MACACCESS_CMD_LEARN		1
#define MACACCESS_CMD_FORGET		2
#define MACACCESS_CMD_AGE		3
#define MACACCESS_CMD_GET_NEXT		4
#define MACACCESS_CMD_INIT		5
#define MACACCESS_CMD_READ		6
#define MACACCESS_CMD_WRITE		7
#define MACACCESS_CMD_SYNC_GET_NEXT	8

#define VLANACCESS_CMD_IDLE		0
#define VLANACCESS_CMD_READ		1
#define VLANACCESS_CMD_WRITE		2
#define VLANACCESS_CMD_INIT		3

#define XTR_EOF_0			0x00000080U
#define XTR_EOF_1			0x01000080U
#define XTR_EOF_2			0x02000080U
#define XTR_EOF_3			0x03000080U
#define XTR_PRUNED			0x04000080U
#define XTR_ABORT			0x05000080U
#define XTR_ESCAPE			0x06000080U
#define XTR_NOT_READY			0x07000080U
#define XTR_VALID_BYTES(x)		(4 - (((x) >> 24) & 3))

#define LAN966X_SPEED_1000 1
#define LAN966X_SPEED_100  2
#define LAN966X_SPEED_10   3

/* MAC table entry types.
 * ENTRYTYPE_NORMAL is subject to aging.
 * ENTRYTYPE_LOCKED is not subject to aging.
 * ENTRYTYPE_MACv4 is not subject to aging. For IPv4 multicast.
 * ENTRYTYPE_MACv6 is not subject to aging. For IPv6 multicast.
 */
enum macaccess_entry_type {
	ENTRYTYPE_NORMAL = 0,
	ENTRYTYPE_LOCKED,
	ENTRYTYPE_MACV4,
	ENTRYTYPE_MACV6,
};

struct frame_info {
	u32 len;
	u16 port;
	u16 vid;
	u32 timestamp;
};

static void lan966x_mact_select(struct lan966x_private *lan966x,
				const unsigned char mac[ETH_ALEN],
				unsigned int vid)
{
	u32 macl = 0, mach = 0;

	/* Set the MAC address to handle and the vlan associated in a format
	 * understood by the hardware.
	 */
	mach |= vid    << 16;
	mach |= mac[0] << 8;
	mach |= mac[1] << 0;
	macl |= mac[2] << 24;
	macl |= mac[3] << 16;
	macl |= mac[4] << 8;
	macl |= mac[5] << 0;

	LAN_WR(macl, lan966x, ANA_MACLDATA);
	LAN_WR(mach, lan966x, ANA_MACHDATA);
}

static inline int lan966x_mact_get_status(struct lan966x_private *lan966x)
{
	return LAN_RD(lan966x, ANA_MACACCESS);
}

static inline int lan966x_mact_wait_for_completion(struct lan966x_private *lan966x)
{
	u32 val;

	return readx_poll_timeout(lan966x_mact_get_status,
		lan966x, val,
		(val & ANA_MACACCESS_MAC_TABLE_CMD_M) ==
		MACACCESS_CMD_IDLE, TABLE_UPDATE_TIMEOUT_US);
}

static void lan966x_mact_init(struct lan966x_private *lan966x)
{
	/* Clear the MAC table */
	LAN_WR(MACACCESS_CMD_INIT, lan966x, ANA_MACACCESS);
	lan966x_mact_wait_for_completion(lan966x);
}

static int lan966x_mact_learn(struct lan966x_private *lan966x, int port,
			      const unsigned char mac[ETH_ALEN], unsigned int vid,
			      enum macaccess_entry_type type)
{
	int ret = 0;

	lan966x_mact_select(lan966x, mac, vid);

	/* Issue a write command */
	LAN_WR(ANA_MACACCESS_VALID(1) |
	       ANA_MACACCESS_CHANGE2SW(0) |
	       ANA_MACACCESS_DEST_IDX(port) |
	       ANA_MACACCESS_ENTRYTYPE(type) |
	       ANA_MACACCESS_MAC_TABLE_CMD(MACACCESS_CMD_LEARN),
	       lan966x, ANA_MACACCESS);

	ret = lan966x_mact_wait_for_completion(lan966x);

	return ret;
}

static int lan966x_write_hwaddr(struct udevice *dev)
{
	struct lan966x_port *port = dev_get_priv(dev);
	struct eth_pdata *pdata = dev_get_plat(dev);
	struct lan966x_private *lan966x = port->lan966x;

	lan966x_mact_learn(lan966x, PGID_CPU, pdata->enetaddr, 0,
			   ENTRYTYPE_LOCKED);

	LAN_RMW(ANA_PGID_PGID(BIT(CPU_PORT) | GENMASK(lan966x->num_phys_ports, 0)),
		ANA_PGID_PGID_M, lan966x, ANA_PGID(PGID_UC));

	return 0;
}

static void lan966x_port_init(struct lan966x_port *port)
{
	struct lan966x_private *lan966x = port->lan966x;
	int speed = LAN966X_SPEED_1000, mode = 0;
	struct phy_device *phydev = port->phy;

	switch (phydev->speed) {
	case SPEED_10:
		speed = LAN966X_SPEED_10;
		break;
	case SPEED_100:
		speed = LAN966X_SPEED_100;
		break;
	case SPEED_1000:
		speed = LAN966X_SPEED_1000;
		mode = DEV_MAC_MODE_CFG_GIGA_MODE_ENA(1);
		break;
	}

	if (phydev->interface == PHY_INTERFACE_MODE_QSGMII)
		mode = DEV_MAC_MODE_CFG_GIGA_MODE_ENA(1);

	/* Enable receiving frames on the port, and activate auto-learning of
	 * MAC addresses.
	 */
	LAN_WR(ANA_PORT_CFG_LEARNAUTO(1) |
	       ANA_PORT_CFG_RECV_ENA(1) |
	       ANA_PORT_CFG_PORTID_VAL(port->chip_port),
	       lan966x, ANA_PORT_CFG(port->chip_port));

	LAN_WR(phydev->duplex | mode,
	       lan966x, DEV_MAC_MODE_CFG(port->chip_port));

	if (phydev->interface == PHY_INTERFACE_MODE_GMII) {
		if (phydev->speed == SPEED_1000)
			LAN_RMW(CHIP_TOP_CUPHY_PORT_CFG_GTX_CLK_ENA(1),
				CHIP_TOP_CUPHY_PORT_CFG_GTX_CLK_ENA_M,
				lan966x, CHIP_TOP_CUPHY_PORT_CFG(port->chip_port));
		else
			LAN_RMW(CHIP_TOP_CUPHY_PORT_CFG_GTX_CLK_ENA(0),
				CHIP_TOP_CUPHY_PORT_CFG_GTX_CLK_ENA_M,
				lan966x, CHIP_TOP_CUPHY_PORT_CFG(port->chip_port));
	}

	LAN_RMW(DEV_PCS1G_CFG_PCS_ENA(1), DEV_PCS1G_CFG_PCS_ENA_M,
		lan966x, DEV_PCS1G_CFG(port->chip_port));

	LAN_RMW(DEV_PCS1G_SD_CFG_SD_ENA(0), DEV_PCS1G_SD_CFG_SD_ENA_M,
		lan966x, DEV_PCS1G_SD_CFG(port->chip_port));

	/* Enable MAC module */
	LAN_WR(DEV_MAC_ENA_CFG_RX_ENA(1) | DEV_MAC_ENA_CFG_TX_ENA(1),
	       lan966x, DEV_MAC_ENA_CFG(port->chip_port));

	/* Take out the clock from reset */
	LAN_WR(DEV_CLOCK_CFG_LINK_SPEED(speed),
	       lan966x, DEV_CLOCK_CFG(port->chip_port));

	/* Core: Enable port for frame transfer */
	LAN_WR(QSYS_SW_PORT_MODE_PORT_ENA(1) |
	       QSYS_SW_PORT_MODE_SCH_NEXT_CFG(1) |
	       QSYS_SW_PORT_MODE_INGRESS_DROP_MODE(1),
	       lan966x, QSYS_SW_PORT_MODE(port->chip_port));
}

static inline int lan966x_ram_init(struct lan966x_private *lan966x)
{
	return LAN_RD(lan966x, SYS_RAM_INIT);
}

static inline int lan966x_soft_reset(struct lan966x_private *lan966x)
{
	return LAN_RD(lan966x, GCB_SOFT_RST);
}

static void lan966x_reset_switch(struct lan966x_private *lan966x,
				 bool reset_phy)
{
	int ret;
	u32 val;

	/* Protect the CPU, from reset */
	LAN_RMW(CPU_RESET_PROT_STAT_SYS_RST_PROT_VCORE(1),
		CPU_RESET_PROT_STAT_SYS_RST_PROT_VCORE_M,
		lan966x, CPU_RESET_PROT_STAT);

	/* Reset the switch */
	LAN_WR(0x2, lan966x, GCB_SOFT_RST);
	ret = readx_poll_timeout(lan966x_soft_reset, lan966x,
				 val, val == 0, READL_TIMEOUT_US);
	if (ret)
		return;

	LAN_WR(0x0, lan966x, SYS_RESET_CFG);
	LAN_WR(0x2, lan966x, SYS_RAM_INIT);
	ret = readx_poll_timeout(lan966x_ram_init, lan966x,
				 val, (val & BIT(1)) == 0, READL_TIMEOUT_US);
	if (ret)
		return;
	LAN_WR(0x1, lan966x, SYS_RESET_CFG);

	LAN_RMW(CPU_RESET_PROT_STAT_SYS_RST_PROT_VCORE(0),
		CPU_RESET_PROT_STAT_SYS_RST_PROT_VCORE_M,
		lan966x, CPU_RESET_PROT_STAT);

	/* Take out the 2 internal phys from reset and set force speed 1000 */
	if (reset_phy)
		LAN_RMW(CHIP_TOP_CUPHY_COMMON_CFG_RESET_N(1),
			CHIP_TOP_CUPHY_COMMON_CFG_RESET_N_M,
			lan966x, CHIP_TOP_CUPHY_COMMON_CFG);
}

static int lan966x_phy_init(struct lan966x_port *port)
{
	struct phy_device *phy;

	if (!port->bus)
		return -1;

	phy = phy_connect(port->bus, port->phy_addr, port->dev, port->phy_mode);
	if (!phy)
		return -1;

	port->phy = phy;
	return 0;
}

static void lan966x_rgmii_setup(struct lan966x_port *port)
{
	struct lan966x_private *lan966x = port->lan966x;

	/* The RGMII_1_CFG and RGMII_0_CFG have already the correct values */

	/* Enable RGMII GPIO */
	LAN_RMW(HSIO_HW_CFG_RGMII_ENA(port->serdes_index == 0 ? 0x1 : 0x2),
		HSIO_HW_CFG_RGMII_ENA_M,
		lan966x, HSIO_HW_CFG);

	/* Configure RGMII */
	LAN_RMW(HSIO_RGMII_CFG_RGMII_RX_RST(0) |
		HSIO_RGMII_CFG_RGMII_TX_RST(0),
		HSIO_RGMII_CFG_RGMII_RX_RST_M |
		HSIO_RGMII_CFG_RGMII_TX_RST_M,
		lan966x, HSIO_RGMII_CFG(port->serdes_index));

	/* Setup DLL configuration */
	LAN_RMW(HSIO_DLL_CFG_DLL_RST(0) |
		HSIO_DLL_CFG_DLL_ENA(1) |
		HSIO_DLL_CFG_DELAY_ENA(1) |
		HSIO_DLL_CFG_DLL_CLK_ENA(0),
		HSIO_DLL_CFG_DLL_RST_M |
		HSIO_DLL_CFG_DLL_ENA_M |
		HSIO_DLL_CFG_DELAY_ENA_M |
		HSIO_DLL_CFG_DLL_CLK_ENA_M,
		lan966x, HSIO_DLL_CFG(port->serdes_index == 0 ? 0x0 : 0x2));

	LAN_RMW(HSIO_DLL_CFG_DLL_RST(0) |
		HSIO_DLL_CFG_DLL_ENA(1) |
		HSIO_DLL_CFG_DELAY_ENA(1) |
		HSIO_DLL_CFG_DLL_CLK_ENA(1),
		HSIO_DLL_CFG_DLL_RST_M |
		HSIO_DLL_CFG_DLL_ENA_M |
		HSIO_DLL_CFG_DELAY_ENA_M |
		HSIO_DLL_CFG_DLL_CLK_ENA_M,
		lan966x, HSIO_DLL_CFG(port->serdes_index == 0 ? 0x1 : 0x3));
}

static void lan966x_serdes_setup(struct lan966x_port *port)
{
	struct lan966x_private *lan966x = port->lan966x;

	if (!port->bus)
		return;

	switch (port->phy_mode) {
	case PHY_INTERFACE_MODE_QSGMII:
		if (!port->bus ||
		    port->serdes_index == 0xff)
			break;

		LAN_RMW(HSIO_HW_CFG_QSGMII_ENA(3),
			HSIO_HW_CFG_QSGMII_ENA_M,
			lan966x, HSIO_HW_CFG);
		lan966x_sd6g40_setup(lan966x,
				     port->serdes_index);
		break;
	case PHY_INTERFACE_MODE_GMII:
		LAN_RMW(HSIO_HW_CFG_GMII_ENA(3),
			HSIO_HW_CFG_GMII_ENA_M,
			lan966x, HSIO_HW_CFG);
		break;
	case PHY_INTERFACE_MODE_RGMII:
		LAN_RMW(HSIO_HW_CFG_GMII_ENA(BIT(port->chip_port)),
			HSIO_HW_CFG_GMII_ENA_M,
			lan966x, HSIO_HW_CFG);

		lan966x_rgmii_setup(port);
		break;
	default:
		break;
	}
}

static int lan966x_adjust_link(struct lan966x_port *port)
{
	struct lan966x_private *lan966x = port->lan966x;
	struct phy_device *phydev;
	int i;

	phydev = port->phy;
	phy_config(phydev);
	phy_startup(phydev);

	if (!phydev->link)
		return -1;

	/* If the port is QSGMII then all the ports needs to be enabled */
	for (i = 0; i < lan966x->num_phys_ports; ++i) {
		if (lan966x->ports[i]->phy_mode == PHY_INTERFACE_MODE_QSGMII) {
			LAN_RMW(DEV_CLOCK_CFG_PCS_RX_RST(0) |
				DEV_CLOCK_CFG_PCS_TX_RST(0) |
				DEV_CLOCK_CFG_LINK_SPEED(LAN966X_SPEED_1000),
				DEV_CLOCK_CFG_PCS_RX_RST_M |
				DEV_CLOCK_CFG_PCS_TX_RST_M |
				DEV_CLOCK_CFG_LINK_SPEED_M,
				lan966x, DEV_CLOCK_CFG(i));
		}
	}

	lan966x_port_init(port);

	return 0;
}

static int lan966x_start(struct udevice *dev)
{
	struct lan966x_port *port = dev_get_priv(dev);
	struct lan966x_private *lan966x = port->lan966x;
	int err;
	u32 i;

	lan966x_reset_switch(lan966x, true);
	lan966x_mact_init(lan966x);
	lan966x_write_hwaddr(dev);

	/* Flush queues */
	LAN_WR(LAN_RD(lan966x, QS_XTR_FLUSH) | GENMASK(1, 0),
	       lan966x, QS_XTR_FLUSH);

	/* Allow to drain */
	mdelay(1);

	/* All Queues normal */
	LAN_WR(LAN_RD(lan966x, QS_XTR_FLUSH) & ~(GENMASK(1, 0)),
	       lan966x, QS_XTR_FLUSH);

	/* Set MAC age time to default value, the entry is aged after
	 * 2 * AGE_PERIOD
	 */
	LAN_WR(ANA_AUTOAGE_AGE_PERIOD(150), lan966x, ANA_AUTOAGE);

	/* Disable learning for frames discarded by VLAN ingress filtering */
	LAN_RMW(ANA_ADVLEARN_VLAN_CHK(1), ANA_ADVLEARN_VLAN_CHK_M, lan966x,
		ANA_ADVLEARN);

	/* Setup frame ageing - "2 sec" - The unit is 6.5 us on lan966x */
	LAN_WR(0, lan966x,  SYS_FRM_AGING);

	/* Map the 8 CPU extraction queues to CPU port */
	LAN_WR(0, lan966x, QSYS_CPU_GROUP_MAP);

	/* Do byte-swap and expect status after last data word
	 * Extraction: Mode: manual extraction) | Byte_swap
	 */
	LAN_WR(QS_XTR_GRP_CFG_MODE(1) |
	       QS_XTR_GRP_CFG_BYTE_SWAP(1),
	       lan966x, QS_XTR_GRP_CFG(0));

	/* Injection: Mode: manual injection | Byte_swap */
	LAN_WR(QS_INJ_GRP_CFG_MODE(1) |
	       QS_INJ_GRP_CFG_BYTE_SWAP(1),
	       lan966x, QS_INJ_GRP_CFG(0));

	LAN_RMW(QS_INJ_CTRL_GAP_SIZE(0),
		QS_INJ_CTRL_GAP_SIZE_M,
		lan966x, QS_INJ_CTRL(0));

	/* Enable IFH insertion/parsing on CPU ports */
	LAN_WR(SYS_PORT_MODE_INCL_INJ_HDR(1) |
	       SYS_PORT_MODE_INCL_XTR_HDR(1),
	       lan966x, SYS_PORT_MODE(CPU_PORT));

	/* Setup flooding PGIDs */
	LAN_WR(ANA_FLOODING_IPMC_FLD_MC4_DATA(PGID_MC) |
	       ANA_FLOODING_IPMC_FLD_MC4_CTRL(PGID_MC) |
	       ANA_FLOODING_IPMC_FLD_MC6_DATA(PGID_MC) |
	       ANA_FLOODING_IPMC_FLD_MC6_CTRL(PGID_MC),
	       lan966x, ANA_FLOODING_IPMC);

	/* There are 8 priorities */
	for (i = 0; i < 8; ++i)
		LAN_RMW(ANA_FLOODING_FLD_MULTICAST(PGID_MC) |
			ANA_FLOODING_FLD_BROADCAST(PGID_BC),
			ANA_FLOODING_FLD_MULTICAST_M |
			ANA_FLOODING_FLD_BROADCAST_M, lan966x,
			ANA_FLOODING(i));

	for (i = 0; i < PGID_ENTRIES; ++i)
		/* Set all the entries to obey VLAN_VLAN */
		LAN_RMW(ANA_PGID_CFG_OBEY_VLAN(1), ANA_PGID_CFG_OBEY_VLAN_M,
			lan966x, ANA_PGID_CFG(i));

	for (i = 0; i < lan966x->num_phys_ports; i++) {
		/* Disable bridging by default */
		LAN_RMW(ANA_PGID_PGID(0x0), ANA_PGID_PGID_M,
			lan966x, ANA_PGID(i + PGID_SRC));

		/* Do not forward BPDU frames to the front ports and copy them
		 * to CPU
		 */
		LAN_WR(0xffff, lan966x, ANA_CPU_FWD_BPDU_CFG(i));
	}

	/* Enable switching to/from cpu port */
	LAN_WR(QSYS_SW_PORT_MODE_PORT_ENA(1) |
	       QSYS_SW_PORT_MODE_SCH_NEXT_CFG(1) |
	       QSYS_SW_PORT_MODE_INGRESS_DROP_MODE(1),
	       lan966x,  QSYS_SW_PORT_MODE(CPU_PORT));

	/* Configure and enable the CPU port */
	LAN_RMW(ANA_PGID_PGID(0), ANA_PGID_PGID_M,
		lan966x, ANA_PGID(CPU_PORT));
	LAN_RMW(ANA_PGID_PGID(BIT(CPU_PORT)), ANA_PGID_PGID_M,
		lan966x, ANA_PGID(PGID_CPU));

	/* Multicast to the CPU port and to other ports */
	LAN_RMW(ANA_PGID_PGID(BIT(CPU_PORT) | GENMASK(lan966x->num_phys_ports, 0)),
		ANA_PGID_PGID_M, lan966x, ANA_PGID(PGID_MC));

	/* Broadcast to the CPU port and to other ports */
	LAN_RMW(ANA_PGID_PGID(BIT(CPU_PORT) | GENMASK(lan966x->num_phys_ports, 0)),
		ANA_PGID_PGID_M, lan966x, ANA_PGID(PGID_BC));

	LAN_WR(REW_PORT_CFG_NO_REWRITE(1), lan966x, REW_PORT_CFG(CPU_PORT));

	board_init();
	err = lan966x_phy_init(port);
	if (err)
		return err;

	err = lan966x_adjust_link(port);
	if (err)
		return err;

	lan966x_serdes_setup(port);

	return 0;
}

static void lan966x_stop(struct udevice *dev)
{
	struct lan966x_port *port = dev_get_priv(dev);
	struct lan966x_private *lan966x = port->lan966x;

	lan966x_reset_switch(lan966x, false);
}

static void lan966x_ifh_inject(u32 *ifh, size_t val, size_t pos, size_t length)
{
	int i;

	for (i = pos; i < pos + length; ++i) {
		if (val & BIT(i - pos))
			ifh[IFH_LEN - i / 32 - 1] |= BIT(i % 32);
		else
			ifh[IFH_LEN - i / 32 - 1] &= ~(BIT(i % 32));
	}
}

static void lan966x_gen_ifh(u32 *ifh, struct frame_info *info)
{
	lan966x_ifh_inject(ifh, 1, IFH_POS_BYPASS, 1);
	lan966x_ifh_inject(ifh, info->port, IFH_POS_DSTS, IFH_WID_DSTS);
	lan966x_ifh_inject(ifh, info->vid, IFH_POS_TCI, IFH_WID_TCI);
	lan966x_ifh_inject(ifh, info->timestamp, IFH_POS_TIMESTAMP,
			   IFH_WID_TIMESTAMP);
}

static int lan966x_send(struct udevice *dev, void *packet, int length)
{
	struct lan966x_port *port = dev_get_priv(dev);
	struct lan966x_private *lan966x = port->lan966x;
	struct frame_info info = {};
	u32 *buf = packet;
	u32 ifh[IFH_LEN];
	u8 grp = 0;
	u32 i, val, count, last;

	val = LAN_RD(lan966x, QS_INJ_STATUS);
	if (!(val & QS_INJ_STATUS_FIFO_RDY(BIT(grp))) ||
	    (val & QS_INJ_STATUS_WMARK_REACHED(BIT(grp))))
		return -1;

	/* Write start of frame */
	LAN_WR(QS_INJ_CTRL_GAP_SIZE(1) | QS_INJ_CTRL_SOF(1),
	       lan966x, QS_INJ_CTRL(grp));

	info.port = BIT(port->chip_port);
	memset(ifh, 0x0, IFH_LEN * sizeof(u32));
	lan966x_gen_ifh(ifh, &info);

	for (i = 0; i < IFH_LEN; ++i) {
		/* Wait until the fifo is ready */
		while (!(LAN_RD(lan966x, QS_INJ_STATUS) &
			 QS_INJ_STATUS_FIFO_RDY(BIT(grp))))
				;

		LAN_WR((__force u32)cpu_to_be32(ifh[i]), lan966x,
		       QS_INJ_WR(grp));
	}

	/* Write frame */
	count = (length + 3) / 4;
	last = length % 4;
	for (i = 0; i < count; ++i) {
		/* Wait until the fifo is ready */
		while (!(LAN_RD(lan966x, QS_INJ_STATUS) &
			 QS_INJ_STATUS_FIFO_RDY(BIT(grp))))
				;

		LAN_WR(buf[i], lan966x, QS_INJ_WR(grp));
	}

	/* Add padding */
	while (i < (LAN966X_BUFFER_CELL_SZ / 4)) {
		/* Wait until the fifo is ready */
		while (!(LAN_RD(lan966x, QS_INJ_STATUS) &
			 QS_INJ_STATUS_FIFO_RDY(BIT(grp))))
				;

		LAN_WR(0, lan966x, QS_INJ_WR(grp));
		++i;
	}

	/* Inidcate EOF and valid bytes in the last word */
	LAN_WR(QS_INJ_CTRL_GAP_SIZE(1) |
	       QS_INJ_CTRL_VLD_BYTES(length < LAN966X_BUFFER_CELL_SZ ?
				     0 : last) |
	       QS_INJ_CTRL_EOF(1),
	       lan966x, QS_INJ_CTRL(grp));

	/* Add dummy CRC */
	LAN_WR(0, lan966x, QS_INJ_WR(grp));

	return 0;
}

static int lan966x_ifh_extract(u32 *ifh, size_t pos, size_t length)
{
	int i;
	int val = 0;

	for (i = pos; i < pos + length; ++i)
		val |= ((ifh[IFH_LEN - i / 32 - 1] & BIT(i % 32)) >>
			(i % 32)) << (i - pos);

	return val;
}

static int lan966x_parse_ifh(u32 *ifh, struct frame_info *info)
{
	int i;

	/* The IFH is in network order, switch to CPU order */
	for (i = 0; i < IFH_LEN; i++)
		ifh[i] = ntohl((__force __be32)ifh[i]);

	info->len = lan966x_ifh_extract(ifh, IFH_POS_LEN, IFH_WID_LEN);
	info->port = lan966x_ifh_extract(ifh, IFH_POS_SRCPORT, IFH_WID_SRCPORT);

	info->vid = lan966x_ifh_extract(ifh, IFH_POS_TCI, IFH_WID_TCI);
	info->timestamp = lan966x_ifh_extract(ifh, IFH_POS_TIMESTAMP,
					      IFH_WID_TIMESTAMP);
	return 0;
}

static int lan966x_rx_frame_word(struct lan966x_private *lan966x, u8 grp,
				 bool ifh, u32 *rval)
{
	u32 bytes_valid;
	u32 val;

	val = LAN_RD(lan966x, QS_XTR_RD(grp));
	if (val == XTR_NOT_READY) {
		if (ifh)
			return -EIO;

		do {
			val = LAN_RD(lan966x, QS_XTR_RD(grp));
		} while (val == XTR_NOT_READY);
	}

	switch (val) {
	case XTR_ABORT:
		return -EIO;
	case XTR_EOF_0:
	case XTR_EOF_1:
	case XTR_EOF_2:
	case XTR_EOF_3:
	case XTR_PRUNED:
		bytes_valid = XTR_VALID_BYTES(val);
		val = LAN_RD(lan966x, QS_XTR_RD(grp));
		if (val == XTR_ESCAPE)
			*rval = LAN_RD(lan966x, QS_XTR_RD(grp));
		else
			*rval = val;

		return bytes_valid;
	case XTR_ESCAPE:
		*rval = LAN_RD(lan966x, QS_XTR_RD(grp));

		return 4;
	default:
		*rval = val;

		return 4;
	}
}

static inline int lan966x_data_ready(struct lan966x_private *lan966x)
{
	return LAN_RD(lan966x, QS_XTR_DATA_PRESENT);
}

static int lan966x_recv(struct udevice *dev, int flags, uchar **packetp)
{
	struct lan966x_port *port = dev_get_priv(dev);
	struct lan966x_private *lan966x = port->lan966x;
	u32 *rxbuf = (u32 *)net_rx_packets[0];
	u32 ifh[IFH_LEN] = { 0 };
	struct frame_info info;
	int byte_cnt = 0;
	int grp = 0;
	int sz, len;
	int err, i;
	u32 val;

	if (!(LAN_RD(lan966x, QS_XTR_DATA_PRESENT) & BIT(grp)))
		return -EAGAIN;

	for (i = 0; i < IFH_LEN; i++) {
		err = lan966x_rx_frame_word(lan966x, grp, true, &ifh[i]);
		if (err != 4)
			break;
	}

	if (err != 4)
		goto out;

	/* The error needs to be reseted.
	 * In case there is only 1 frame in the queue, then after the
	 * extraction of ifh and of the frame then the while condition
	 * will failed. Then it would check if it is an err but the err
	 * is 4, as set previously. In this case will try to read the
	 * rest of the frames from the queue. And in case only a part of
	 * the frame is in the queue, it would read only that. So next
	 * time when this function is called it would presume would read
	 * initially the ifh but actually will read the rest of the
	 * previous frame. Therfore reset here the error code, meaning
	 * that there is no error with reading the ifh. Then if there is
	 * an error reading the frame the error will be set and then the
	 * check is partially correct.
	 */
	err = 0;

	lan966x_parse_ifh(ifh, &info);

	byte_cnt = info.len - ETH_FCS_LEN;

	len = 0;
	do {
		sz = lan966x_rx_frame_word(lan966x, grp, false, &val);
		*rxbuf++ = val;
		len += sz;
	} while (len < byte_cnt);

	/* Read the FCS */
	sz = lan966x_rx_frame_word(lan966x, grp, false, &val);

	/* Update the statistics if part of the FCS was read before */
	len -= ETH_FCS_LEN - sz;

	if (sz < 0) {
		err = sz;
		goto out;
	}

	if (err)
		while (LAN_RD(lan966x, QS_XTR_DATA_PRESENT) & BIT(grp))
			LAN_RD(lan966x, QS_XTR_RD(grp));

	rxbuf = (u32 *)net_rx_packets[0];
	*packetp = net_rx_packets[0];

out:
	return byte_cnt;
}

struct mii_dev *lan966x_mdiobus_init(struct mscc_miim_dev *miim, int miim_index,
				     phys_addr_t miim_base, unsigned long miim_size)
{
	struct mii_dev *bus;

	bus = mdio_alloc();

	if (!bus)
		return NULL;

	sprintf(bus->name, "miim-bus%d", miim_index);

	miim->regs = ioremap(miim_base, miim_size);
	bus->priv = miim;
	bus->read = mscc_miim_read;
	bus->write = mscc_miim_write;

	if (mdio_register(bus))
		return NULL;

	return bus;
}

static int lan966x_probe(struct udevice *dev)
{
	struct lan966x_private *lan966x = dev_get_priv(dev->parent);
	struct lan966x_port *port = dev_get_priv(dev);
	struct ofnode_phandle_args phandle;
	unsigned long addr_size;
	ofnode node, mdio_node;
	phys_addr_t addr_base;
	struct mii_dev *bus;
	struct resource res;
	fdt32_t faddr;
	int ret;

	node = dev_ofnode(dev);
	if (!ofnode_valid(node)) {
		dev_err(dev, "Not valid node\n");
		return -EINVAL;
	}

	port->dev = dev;

	/* Get resources */
	ret = ofnode_read_resource(node, 0, &res);
	if (ret) {
		dev_err(dev, "Missing resource\n");
		return ret;
	}
	port->chip_port = res.start;

	/* Connect the parent and the child */
	port->lan966x = lan966x;
	lan966x->ports[port->chip_port] = port;

	ret = ofnode_parse_phandle_with_args(node, "phy-handle", NULL,
					     0, 0, &phandle);
	if (ret)
		return -EINVAL;

	/* Get phy address of mdio bus */
	if (ofnode_read_resource(phandle.node, 0, &res))
		return -ENOMEM;
	port->phy_addr = res.start;

	/* Get mdio node */
	mdio_node = ofnode_get_parent(phandle.node);
	if (ofnode_read_resource(mdio_node, 0, &res))
		return -ENOMEM;
	faddr = cpu_to_fdt32(res.start);

	addr_base = ofnode_translate_address(mdio_node, &faddr);
	addr_size = res.end - res.start;

	/* Add the mdio bus */
	bus = lan966x_mdiobus_init(&port->miim, port->chip_port,
				   addr_base, addr_size);
	if (!bus)
		return -ENOMEM;
	port->bus = bus;

	/* Get the phy mode */
	port->phy_mode = dev_read_phy_mode(dev);

	/* Get the serdes */
	ret = ofnode_parse_phandle_with_args(node, "phys", NULL, 1, 0,
					     &phandle);
	if (!ret)
		port->serdes_index = phandle.args[0];

	return 0;
}

static int lan966x_remove(struct udevice *dev)
{
	struct lan966x_port *port = dev_get_priv(dev);
	struct lan966x_private *lan966x = port->lan966x;

	lan966x_reset_switch(lan966x, false);
	mdio_unregister(port->bus);
	mdio_free(port->bus);

	return 0;
}

static const struct eth_ops lan966x_ops = {
	.start        = lan966x_start,
	.stop         = lan966x_stop,
	.send         = lan966x_send,
	.recv         = lan966x_recv,
	.write_hwaddr = lan966x_write_hwaddr,
};

static struct driver lan966x_driver = {
	.name     = "lan966x-switch",
	.id       = UCLASS_ETH,
	.probe    = lan966x_probe,
	.remove	  = lan966x_remove,
	.ops	  = &lan966x_ops,
	.priv_auto = sizeof(struct lan966x_port),
	.plat_auto = sizeof(struct eth_pdata),
};

static int lan966x_base_probe(struct udevice *dev)
{
	struct lan966x_private *lan966x = dev_get_priv(dev);
	ofnode eth_node, node;
	int ret, i;

	struct {
		enum lan966x_target id;
		char *name;
	} res[] = {
		{ TARGET_ORG, "org" },
		{ TARGET_SYS, "sys" },
		{ TARGET_QS, "qs" },
		{ TARGET_QSYS, "qsys" },
		{ TARGET_ANA, "ana" },
		{ TARGET_REW, "rew" },
		{ TARGET_GCB, "gcb" },
		{ TARGET_CPU, "cpu" },
		{ TARGET_CHIP_TOP, "chip_top" },
		{ TARGET_HSIO, "hsio" },
	};

	for (i = 0; i < ARRAY_SIZE(res); i++) {
		lan966x->regs[res[i].id] = dev_remap_addr_name(dev, res[i].name);
		if (!lan966x->regs[res[i].id]) {
			pr_err
			    ("Error %d: can't get regs base addresses for %s\n",
			     ret, res[i].name);
			return -ENOMEM;
		}
	}

	/* Iterate ports */
	i = 0;
	eth_node = dev_read_first_subnode(dev);
	ofnode_for_each_subnode(node, eth_node)
		++i;

	/* Get the number of ports */
	lan966x->num_phys_ports = i;
	lan966x->ports = devm_kzalloc(dev, i * sizeof(struct lan966x_port*),
				      GFP_KERNEL);

	eth_node = dev_read_first_subnode(dev);
	for (node = ofnode_first_subnode(eth_node);
	     ofnode_valid(node);
	     node = ofnode_next_subnode(node)) {
		struct resource res;
		char res_name[8];
		int index;

		if (ofnode_read_resource(node, 0, &res))
			return -ENOMEM;
		index = res.start;
		snprintf(res_name, sizeof(res_name), "port%d", index);

		lan966x->regs[TARGET_DEV + index] = dev_remap_addr_name(dev, res_name);
	}

	return 0;
}

static int lan966x_base_bind(struct udevice *dev)
{
	ofnode eth_node, node;
	int index = 0;
	int ret;

	/* Can't access lan966x_private because it was not yet allocated */

	/* Bind all the ports and bind the children */
	eth_node = dev_read_first_subnode(dev);
	for (node = ofnode_first_subnode(eth_node);
	     ofnode_valid(node);
	     node = ofnode_next_subnode(node)) {
		struct resource res;
		char *res_name;

		if (ofnode_read_resource(node, 0, &res))
			return -ENOMEM;

		res_name = calloc(1, 16);
		sprintf(res_name, "port%d", index);

		ret = device_bind(dev, &lan966x_driver, res_name, NULL,
				  node, NULL);
		if (ret)
			return ret;

		index += 1;
	}

	return 0;
}

static const struct udevice_id mscc_lan966x_ids[] = {
	{.compatible = "mchp,lan966x-switch"},
	{ /* Sentinel */ }
};

U_BOOT_DRIVER(lan966x_switch) = {
	.name     = "lan966x-switch",
	.id       = UCLASS_MISC,
	.of_match = mscc_lan966x_ids,
	.bind     = lan966x_base_bind,
	.probe    = lan966x_base_probe,
	.priv_auto = sizeof(struct lan966x_private),
};
