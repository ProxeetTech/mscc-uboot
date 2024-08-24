// SPDX-License-Identifier: MIT

#include <miiphy.h>
#include <bitfield.h>
#include <time.h>

/* Microchip PHY ID's */
#define PHY_ID_LAN8814                  0x00221660
#define PHY_ID_LAN8804                  0x00221670

#define LAN8814_EXT_PAGE_ACCESS_CONTROL			0x16
#define LAN8814_EXT_PAGE_ACCESS_ADDRESS_DATA		0x17
#define LAN8814_EXT_PAGE_ACCESS_CTRL_EP_FUNC		0x4000

#define LAN8814_QSGMII_PCS1G_ANEG_CONFIG		0x13
#define LAN8814_QSGMII_PCS1G_ANEG_CONFIG_ANEG_ENA	BIT(3)
#define LAN8814_QSGMII_AUTO_ANEG			0x45
#define LAN8814_QSGMII_AUTO_ANEG_AUTO_ANEG_ENA		BIT(0)
#define LAN8814_ALIGN_SWAP				0x4a
#define LAN8814_ALIGN_TX_A_B_SWAP			0x1
#define LAN8814_ALIGN_TX_A_B_SWAP_MASK			GENMASK(2,0)

#define LAN8814_CONTROL					0x1f
#define LAN8814_CONTROL_POLARITY			BIT(14)

static int lan8814_read_page_reg(struct phy_device *phydev,
				 int page, u32 addr)
{
	u32 data;

	phy_write(phydev, 0, LAN8814_EXT_PAGE_ACCESS_CONTROL, page);
	phy_write(phydev, 0, LAN8814_EXT_PAGE_ACCESS_ADDRESS_DATA, addr);
	phy_write(phydev, 0, LAN8814_EXT_PAGE_ACCESS_CONTROL,
		  (page | LAN8814_EXT_PAGE_ACCESS_CTRL_EP_FUNC));
	data = phy_read(phydev, 0, LAN8814_EXT_PAGE_ACCESS_ADDRESS_DATA);

	return data;
}

static int lan8814_write_page_reg(struct phy_device *phydev,
				  int page, u16 addr, u16 val)
{
	phy_write(phydev, 0, LAN8814_EXT_PAGE_ACCESS_CONTROL, page);
	phy_write(phydev, 0, LAN8814_EXT_PAGE_ACCESS_ADDRESS_DATA, addr);
	phy_write(phydev, 0, LAN8814_EXT_PAGE_ACCESS_CONTROL,
		  (page | LAN8814_EXT_PAGE_ACCESS_CTRL_EP_FUNC));

	val = phy_write(phydev, 0, LAN8814_EXT_PAGE_ACCESS_ADDRESS_DATA, val);
	if (val != 0) {
		debug("Error: phy_write has returned error %d\n", val);
		return val;
	}
	return 0;
}

static int lan8814_config(struct phy_device *phydev)
{
	int val;

	/* Reset the PHY */
	val = lan8814_read_page_reg(phydev, 4, 67);
	val |= BIT(0);
	lan8814_write_page_reg(phydev, 4, 67, val);

	val = phy_read(phydev, 0, 0);
	val |= BIT(9);
	phy_write(phydev, 0, 0, val);

	/* Disable ANEG QSGMII */
	val = lan8814_read_page_reg(phydev, 5,
				    LAN8814_QSGMII_PCS1G_ANEG_CONFIG);
	val &= ~LAN8814_QSGMII_PCS1G_ANEG_CONFIG_ANEG_ENA;
	lan8814_write_page_reg(phydev, 5, LAN8814_QSGMII_PCS1G_ANEG_CONFIG,
			       val);

	val = lan8814_read_page_reg(phydev, 4, LAN8814_QSGMII_AUTO_ANEG);
	val &= ~LAN8814_QSGMII_AUTO_ANEG_AUTO_ANEG_ENA;
	lan8814_write_page_reg(phydev, 4, LAN8814_QSGMII_AUTO_ANEG, val);

	return genphy_config(phydev);
}

static int lan8804_config(struct phy_device *phydev)
{
	int val;

	/* MDI-X setting for swap A,B transmit */
	val = lan8814_read_page_reg(phydev, 2, LAN8814_ALIGN_SWAP);
	val &= ~LAN8814_ALIGN_TX_A_B_SWAP_MASK;
	val |= LAN8814_ALIGN_TX_A_B_SWAP;
	lan8814_write_page_reg(phydev, 2, LAN8814_ALIGN_SWAP, val);

	phy_write(phydev, 0, LAN8814_CONTROL, LAN8814_CONTROL_POLARITY);
	return genphy_config(phydev);
}

static struct phy_driver lan8814_driver = {
	.name = "Microchip lan8814",
	.uid = PHY_ID_LAN8814,
	.mask = 0x00fffff0,
	.features = PHY_GBIT_FEATURES,
	.config = &lan8814_config,
	.startup = &genphy_startup,
	.shutdown = &genphy_shutdown,
};

static struct phy_driver lan8804_driver = {
	.name = "Microchip lan8804",
	.uid = PHY_ID_LAN8804,
	.mask = 0x00fffff0,
	.features = PHY_GBIT_FEATURES,
	.config = &lan8804_config,
	.startup = &genphy_startup,
	.shutdown = &genphy_shutdown,
};

int phy_microchip_init(void)
{
	phy_register(&lan8814_driver);
	phy_register(&lan8804_driver);

	return 0;
}
