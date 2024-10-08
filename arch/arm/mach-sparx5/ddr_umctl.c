/*
 * Copyright (C) 2022 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>

#include <ddr_init.h>
#include <ddr_reg.h>
#include <ddr_xlist.h>

#define PGSR_ERR_MASK		GENMASK_32(30, 19)
#define PGSR_ALL_DONE		GENMASK_32(11, 0)

#define TIME_MS_TO_US(ms)	(ms * 1000U)
#define PHY_TIMEOUT_US_1S	TIME_MS_TO_US(1000U)

static const struct {
	uint32_t mask;
	const char *desc;
} phyerr[] = {
	{ PGSR0_VERR, "VREF Training" },
	{ PGSR0_ZCERR, "Impedance Calibration" },
	{ PGSR0_WLERR, "Write Leveling" },
	{ PGSR0_QSGERR, "DQS Gate Training" },
	{ PGSR0_WLAERR, "Write Leveling Adjustment" },
	{ PGSR0_RDERR, "Read Bit Deskew" },
	{ PGSR0_WDERR, "Write Bit Deskew" },
	{ PGSR0_REERR, "Read Eye Training" },
	{ PGSR0_WEERR, "Write Eye Training" },
	{ PGSR0_CAERR, "CA Training" },
	// { PGSR0_CAWRN, "CA Training Warning" },
	{ PGSR0_SRDERR, "Static Read" },
};

struct reg_desc {
	const char *name;
	uintptr_t reg_addr;
	uint8_t par_offset;	/* Offset for parameter array */
};

#define X(x, y, z)							\
	{								\
		.name = #x,						\
		.reg_addr  = y,						\
		.par_offset = offsetof(struct config_ddr_##z, x),	\
	},

static const struct reg_desc ddr_main_reg[] = {
XLIST_DDR_MAIN
};

static const struct reg_desc ddr_timing_reg[] = {
XLIST_DDR_TIMING
};

static const struct reg_desc ddr_mapping_reg[] = {
XLIST_DDR_MAPPING
};

static const struct reg_desc ddr_phy_reg[] = {
XLIST_DDR_PHY
};

static const struct reg_desc ddr_phy_timing_reg[] = {
XLIST_DDR_PHY_TIMING
};

static inline bool special_register(uintptr_t reg)
{
	return reg == DDR_UMCTL2_SBRCTL; /* Only one special register so far */
}

static inline bool ddr4_only_register(uintptr_t reg)
{
	static uintptr_t ddr4_only[] = {
		DDR_UMCTL2_CRCPARCTL1,
		DDR_UMCTL2_DBICTL,
		DDR_UMCTL2_INIT6,
		DDR_UMCTL2_INIT7,
		DDR_UMCTL2_PCCFG,
		DDR_UMCTL2_DRAMTMG12,
		DDR_UMCTL2_DRAMTMG9,
		DDR_PHY_SCHCR1,
		DDR_PHY_PTR2,
	};
	int i;

	for(i = 0; i < ARRAY_SIZE(ddr4_only); i++)
		if (ddr4_only[i] == reg)
			return true;
	return false;
}

static bool wait_reg_set(uintptr_t reg, uint32_t mask, int usec)
{
	ddr_timeout_t t = timeout_set_us(usec);
	while ((mmio_read_32(reg) & mask) == 0) {
		if (timeout_elapsed(&t)) {
			NOTICE("Timeout waiting for %p mask %08x set\n", (void*)reg, mask);
			return true;
		}
	}
	return false;
}

static bool wait_reg_clr(uintptr_t reg, uint32_t mask, int usec)
{
	ddr_timeout_t t = timeout_set_us(usec);
	while ((mmio_read_32(reg) & mask) != 0) {
		if (timeout_elapsed(&t)) {
			NOTICE("Timeout waiting for %p mask %08x clr\n", (void*)reg, mask);
			return true;
		}
	}
	return false;
}

static void wait_operating_mode(uint32_t mode, int usec)
{
	ddr_timeout_t t = timeout_set_us(usec);
	while ((FIELD_GET(STAT_OPERATING_MODE,
			  mmio_read_32(DDR_UMCTL2_STAT))) != mode) {
		if (timeout_elapsed(&t)) {
			VERBOSE("Timeout waiting for mode %d\n", mode);
			PANIC("wait_operating_mode");
		}
	}
}

static void set_regs(const struct ddr_config *ddr_cfg,
		     const void *cfg,
		     const struct reg_desc *reg,
		     size_t ct)
{
	bool ddr3 = !!(ddr_cfg->main.mstr & MSTR_DDR3);
	int i;

	for (i = 0; i < ct; i++) {
		if (special_register(reg[i].reg_addr))
			continue;
		if (ddr3 && ddr4_only_register(reg[i].reg_addr))
			continue;
		uint32_t val = ((const uint32_t *)cfg)[reg[i].par_offset >> 2];
		mmio_write_32(reg[i].reg_addr, val);
	}
}

static void set_static_ctl(void)
{
	/* Disabling update request initiated by DDR controller during
	 * DDR initialization */
	mmio_setbits_32(DDR_UMCTL2_DFIUPD0,
			DFIUPD0_DIS_AUTO_CTRLUPD_SRX | DFIUPD0_DIS_AUTO_CTRLUPD);
}

/*
 * This mirrors the PHY mrX fields from the controller initX registers
 * to avoid having both in the configuration strcuture.
 */
static void set_mrx_phy(const struct ddr_config *cfg)
{
	bool ddr4 = !!(cfg->main.mstr & MSTR_DDR4);

	mmio_write_32(DDR_PHY_MR0,
		      FIELD_GET(INIT3_MR, cfg->main.init3));
	mmio_write_32(DDR_PHY_MR1,
		      FIELD_GET(INIT3_EMR, cfg->main.init3));
	mmio_write_32(DDR_PHY_MR2,
		      FIELD_GET(INIT4_EMR2, cfg->main.init4));
	mmio_write_32(DDR_PHY_MR3,
		      FIELD_GET(INIT4_EMR3, cfg->main.init4));
	if (ddr4) {
		mmio_write_32(DDR_PHY_MR4,
			      FIELD_GET(INIT6_MR4, cfg->main.init6));
		mmio_write_32(DDR_PHY_MR5,
			      FIELD_GET(INIT6_MR5, cfg->main.init6));
		mmio_write_32(DDR_PHY_MR6,
			      FIELD_GET(INIT7_MR6, cfg->main.init7));
	}
}

static void set_static_phy(const struct ddr_config *cfg)
{
	bool ddr4 = !!(cfg->main.mstr & MSTR_DDR4);
	int bus_divider, bus_width = cfg->info.bus_width;

	/* Configure IO's according to mode */
	mmio_clrsetbits_32(DDR_PHY_PGCR1,
			   PGCR1_IODDRM,
			   FIELD_PREP(PGCR1_IODDRM, ddr4));
	/* Disabling PHY initiated update request during DDR
	 * initialization */
	mmio_clrbits_32(DDR_PHY_DSGCR, DSGCR_PUREN);
	/* Enable data lanes according to configured bus width */
	bus_divider = FIELD_GET(MSTR_DATA_BUS_WIDTH, cfg->main.mstr);
	if (bus_divider == 1) /* Half width */
		bus_width /= 2;
	if (bus_divider == 2) /* Quarter width */
		bus_width /= 4;
	switch (bus_width) {
	case 32:
		/* Add full 32 bit lanes */
		mmio_setbits_32(DDR_PHY_DX0GCR0, DX0GCR0_DXEN);
		mmio_setbits_32(DDR_PHY_DX1GCR0, DX1GCR0_DXEN);
		mmio_setbits_32(DDR_PHY_DX2GCR0, DX2GCR0_DXEN);
		mmio_setbits_32(DDR_PHY_DX3GCR0, DX3GCR0_DXEN);
		break;
	case 16:
		/* Enable two first lanes */
		mmio_setbits_32(DDR_PHY_DX0GCR0, DX0GCR0_DXEN);
		mmio_setbits_32(DDR_PHY_DX1GCR0, DX1GCR0_DXEN);
		/* Disable un-used upper byte lanes */
		mmio_clrbits_32(DDR_PHY_DX2GCR0, DX2GCR0_DXEN);
		mmio_clrbits_32(DDR_PHY_DX3GCR0, DX3GCR0_DXEN);
		break;
	case 8:
		/* Enable first lane */
		mmio_setbits_32(DDR_PHY_DX0GCR0, DX0GCR0_DXEN);
		/* Disable un-used upper byte lanes */
		mmio_clrbits_32(DDR_PHY_DX1GCR0, DX1GCR0_DXEN);
		mmio_clrbits_32(DDR_PHY_DX2GCR0, DX2GCR0_DXEN);
		mmio_clrbits_32(DDR_PHY_DX3GCR0, DX3GCR0_DXEN);
		break;
	default:
		PANIC("Unsupported bus width: %d / BIT(%d) = %d\n",
		      cfg->info.bus_width, bus_divider, bus_width);
		break;
	}
	/* Disable ECC lane according to config */
	if (cfg->main.ecccfg0 & ECCCFG0_ECC_MODE)
		mmio_setbits_32(DDR_PHY_DX4GCR0, DX4GCR0_DXEN);
	else
		mmio_clrbits_32(DDR_PHY_DX4GCR0, DX4GCR0_DXEN);

	/* To capture valid read data for rank0 */
	mmio_clrsetbits_32(DDR_PHY_RANKIDR, RANKIDR_RANKWID,
			   FIELD_PREP(RANKIDR_RANKWID, 0));
#define SET_DGSEL(n)							\
	mmio_clrsetbits_32(DDR_PHY_DX ## n ## GTR0, DX ## n ## GTR0_DGSL, \
			   FIELD_PREP(DX ## n ## GTR0_DGSL, 0x2))
	SET_DGSEL(0);
	SET_DGSEL(1);
	SET_DGSEL(2);
	SET_DGSEL(3);
	SET_DGSEL(4);

	/* To capture valid read data for rank1 */
	mmio_clrsetbits_32(DDR_PHY_RANKIDR, RANKIDR_RANKWID,
			   FIELD_PREP(RANKIDR_RANKWID, 1));
	SET_DGSEL(0);
	SET_DGSEL(1);
	SET_DGSEL(2);
	SET_DGSEL(3);
	SET_DGSEL(4);
#undef SET_DGSEL

	/* VREF IO control register */
	mmio_setbits_32(DDR_PHY_IOVCR0,
			IOVCR0_ACVREFIEN | IOVCR0_ACVREFSEN | IOVCR0_ACVREFPEN);
	mmio_setbits_32(DDR_PHY_IOVCR1, IOVCR1_ZQVREFPEN);
}

static void axi_enable_ports(bool enable)
{
	if (enable) {
		mmio_setbits_32(DDR_UMCTL2_PCTRL_0, PCTRL_0_PORT_EN);
	} else {
		mmio_clrbits_32(DDR_UMCTL2_PCTRL_0, PCTRL_0_PORT_EN);
	}
}

static void ecc_enable_scrubbing(const struct ddr_config *cfg)
{
	VERBOSE("Enable ECC scrubbing\n");

	/* 1.  Disable AXI port. port_en = 0 */
	axi_enable_ports(false);

	/* 2. scrub_mode = 1 */
	mmio_setbits_32(DDR_UMCTL2_SBRCTL, SBRCTL_SCRUB_MODE);

	/* 3. scrub_interval = 0 */
	mmio_clrbits_32(DDR_UMCTL2_SBRCTL, SBRCTL_SCRUB_INTERVAL);

	/* 4. Data pattern = 0 */
	mmio_write_32(DDR_UMCTL2_SBRWDATA0, 0);

	/* 5. (skip) */

	/* 6. Enable SBR programming */
	mmio_setbits_32(DDR_UMCTL2_SBRCTL, SBRCTL_SCRUB_EN);

	/* 7. Poll SBRSTAT.scrub_done */
	if (wait_reg_set(DDR_UMCTL2_SBRSTAT, SBRSTAT_SCRUB_DONE, 1000000))
		PANIC("Timeout SBRSTAT.scrub_done set");

	/* 8. Poll SBRSTAT.scrub_busy */
	if (wait_reg_clr(DDR_UMCTL2_SBRSTAT, SBRSTAT_SCRUB_BUSY, 50))
		PANIC("Timeout SBRSTAT.scrub_busy clear");

	/* 9. Disable SBR programming */
	mmio_clrbits_32(DDR_UMCTL2_SBRCTL, SBRCTL_SCRUB_EN);

	VERBOSE("Initial ECC scrubbing done\n");

	/* Only enable background scrubbing when not using inline ECC.
	 * 'ECCCFG1_ECC_REGION_PARITY_LOCK' is defined only when having
	 * inline ECC configured in controller.
	 */
#if !defined(ECCCFG1_ECC_REGION_PARITY_LOCK)
	/* 10+11: Enable SBR programming again if enabled and interval != 0 */
	if (cfg->main.sbrctl & SBRCTL_SCRUB_EN &&
	    FIELD_GET(SBRCTL_SCRUB_INTERVAL, cfg->main.sbrctl) != 0) {
		mmio_write_32(DDR_UMCTL2_SBRCTL, cfg->main.sbrctl);
		NOTICE("Enabled ECC scrubbing\n");
	}
#endif

	/* 12. Enable AXI port */
	axi_enable_ports(true);
}

static void phy_fifo_reset(void)
{
	mmio_clrbits_32(DDR_PHY_PGCR0, PGCR0_PHYFRST);
	ddr_nsleep(1);
	mmio_setbits_32(DDR_PHY_PGCR0, PGCR0_PHYFRST);
}

static int wait_phy_idone(int tmo)
{
	uint32_t pgsr;
	int i;
	ddr_timeout_t t;

	t = timeout_set_us(tmo);

	do {
		pgsr = mmio_read_32(DDR_PHY_PGSR0);

		if (pgsr & PGSR_ERR_MASK) {
			for (i = 0; i < ARRAY_SIZE(phyerr); i++) {
				if (pgsr & phyerr[i].mask) {
					NOTICE("PHYERR: %s Error\n", phyerr[i].desc);
					return -EIO;
				}
			}
		}

		if (pgsr & PGSR0_IDONE)
			return 0;

	} while(!timeout_elapsed(&t));
	PANIC("PHY IDONE timeout\n");

	return -ETIMEDOUT;
}

static int ddr_phy_init(uint32_t mode, int usec_timout)
{
	int rc;

	mode |= PIR_INIT;

	VERBOSE("ddr_phy_init:start\n");

	/* Now, kick PHY */
	mmio_write_32(DDR_PHY_PIR, mode);

	VERBOSE("pir = 0x%x -> 0x%x\n", mode, mmio_read_32(DDR_PHY_PIR));

	/* Need to wait 10 configuration clock before start polling */
	ddr_nsleep(10);

	rc = wait_phy_idone(usec_timout);

	VERBOSE("ddr_phy_init:exit = %d\n", rc);

	return rc;
}

static int PHY_initialization(void)
{
	/* PHY initialization: PLL initialization, Delay line
	 * calibration, PHY reset and Impedance Calibration
	 */
	return ddr_phy_init(PIR_ZCAL | PIR_PLLINIT | PIR_DCAL | PIR_PHYRST, PHY_TIMEOUT_US_1S);
}

static int DRAM_initialization(bool init_by_pub)
{
	uint32_t init_flags = init_by_pub ? PIR_DRAMRST | PIR_DRAMINIT : PIR_CTLDINIT;

	/* write PHY initialization register for PUB/UMCTL SDRAM initialization */
	return ddr_phy_init(init_flags, PHY_TIMEOUT_US_1S);
}

static void sw_done_start(void)
{
	/* Enter quasi-dynamic mode */
	mmio_write_32(DDR_UMCTL2_SWCTL, 0);
}

static void sw_done_ack(void)
{
	VERBOSE("sw_done_ack:enter\n");

	/* Signal we're done */
	mmio_write_32(DDR_UMCTL2_SWCTL, SWCTL_SW_DONE);

	/* wait for SWSTAT.sw_done_ack to become set */
	if (wait_reg_set(DDR_UMCTL2_SWSTAT, SWSTAT_SW_DONE_ACK, 50))
		PANIC("Timout SWSTAT.sw_done_ack set");

	VERBOSE("sw_done_ack:exit\n");
}

static void ddr_disable_refresh(void)
{
	sw_done_start();
	mmio_setbits_32(DDR_UMCTL2_RFSHCTL3, RFSHCTL3_DIS_AUTO_REFRESH);
	mmio_clrbits_32(DDR_UMCTL2_PWRCTL, PWRCTL_POWERDOWN_EN);
	mmio_clrbits_32(DDR_UMCTL2_DFIMISC, DFIMISC_DFI_INIT_COMPLETE_EN);
	sw_done_ack();
}

static void ddr_restore_refresh(uint32_t rfshctl3, uint32_t pwrctl)
{
	sw_done_start();
	if ((rfshctl3 & RFSHCTL3_DIS_AUTO_REFRESH) == 0)
		mmio_clrbits_32(DDR_UMCTL2_RFSHCTL3, RFSHCTL3_DIS_AUTO_REFRESH);
	if (pwrctl & PWRCTL_POWERDOWN_EN)
		mmio_setbits_32(DDR_UMCTL2_PWRCTL, PWRCTL_POWERDOWN_EN);
	mmio_setbits_32(DDR_UMCTL2_DFIMISC, DFIMISC_DFI_INIT_COMPLETE_EN);
	sw_done_ack();
}

static void VREF_Training_Setup(void)
{
	/* Disable refresh during training */
	mmio_clrbits_32(DDR_PHY_DTCR0, DTCR0_RFSHDT);
	/* Program user programmable data pattern */
	mmio_write_32(DDR_PHY_BISTUDPR, 0xA5A5A5A5);
	/* Program BIST address registers BISTAR0-4 to define the
	 * memory location used during VREF training
	 */
	/* BIST Col 16/64/256/512, BIST Bank 0-3 */
	mmio_write_32(DDR_PHY_BISTAR0,
		      FIELD_PREP(BISTAR0_BCOL, 16) |
		      FIELD_PREP(BISTAR0_BBANK, 0));
	/* BIST Addr Inc 32/128/256/512 */
	mmio_clrsetbits_32(DDR_PHY_BISTAR1, BISTAR1_BAINC,
			   FIELD_PREP(BISTAR1_BAINC, 0));
	/* BIST Row 0-15 */
	mmio_clrsetbits_32(DDR_PHY_BISTAR3, BISTAR3_BROW,
			   FIELD_PREP(BISTAR3_BROW, 0));
	/* Program HOST VREF initial setting to approx. 76.25% of VDDQ */
#define DEF_REFISEL 0x19
#define SET_REFISEL(n) \
	mmio_clrsetbits_32(DDR_PHY_DX ## n ## GCR5, DX ## n ## GCR5_DXREFISELR0, \
			   FIELD_PREP(DX ## n ## GCR5_DXREFISELR0, DEF_REFISEL))
	SET_REFISEL(0);
	SET_REFISEL(1);
	SET_REFISEL(2);
	SET_REFISEL(3);
	SET_REFISEL(4);
#undef SET_REFISEL
	mmio_clrsetbits_32(DDR_PHY_VTCR0, VTCR0_DVINIT,
			   FIELD_PREP(VTCR0_DVINIT, DEF_REFISEL));
#undef DEF_REFISEL
	mmio_clrsetbits_32(DDR_PHY_VTCR1,
			   VTCR1_ENUM | VTCR1_HVSS | VTCR1_VWCR,
			   VTCR1_ENUM | FIELD_PREP(VTCR1_HVSS, 1) | FIELD_PREP(VTCR1_VWCR, 0xF));
}

static int do_data_training(const struct ddr_config *cfg)
{
	bool ddr4 = !!(cfg->main.mstr & MSTR_DDR4);
	uint32_t w, m;
	int rc;

	VERBOSE("do_data_training:enter\n");

	/* Disable Auto refresh and power down before training */
	ddr_disable_refresh();

	/* Write leveling, DQS gate training, Write_latency adjustment must be executed in
	 * asynchronous read mode. After these training are finished, then static read mode
	 * can be set and rest of the training can be executed with a second PIR register.
	 */

	/* By default asynchronous read mode is set : PGCR3.RDMODE = 2'b00 */
	w = mmio_read_32(DDR_PHY_PGCR3);
	if (FIELD_GET(PGCR3_RDMODE, w) != 0) {
		NOTICE("pgcr3: %08x\n", w);
		PANIC("RDMODE not zero");
	}

	/* As per PUB databook (page no. 601), it is recommended to
	 * seed appropriate group of BDLs with a value of x4 or x8
	 * prior to the execution of the data training
	 */
	mmio_write_32(DDR_PHY_DX0BDLR0, 0x08080808);
	mmio_write_32(DDR_PHY_DX0BDLR1, 0x08080808);
	mmio_write_32(DDR_PHY_DX0BDLR2, 0x080808);
	mmio_write_32(DDR_PHY_DX1BDLR0, 0x08080808);
	mmio_write_32(DDR_PHY_DX1BDLR1, 0x08080808);
	mmio_write_32(DDR_PHY_DX1BDLR2, 0x080808);
	if (cfg->info.bus_width == 32) {
		mmio_write_32(DDR_PHY_DX2BDLR0, 0x08080808);
		mmio_write_32(DDR_PHY_DX2BDLR1, 0x08080808);
		mmio_write_32(DDR_PHY_DX2BDLR2, 0x080808);
		mmio_write_32(DDR_PHY_DX3BDLR0, 0x08080808);
		mmio_write_32(DDR_PHY_DX3BDLR1, 0x08080808);
		mmio_write_32(DDR_PHY_DX3BDLR2, 0x080808);
	}
	/* ECC lane enabled? */
	if (cfg->main.ecccfg0 & ECCCFG0_ECC_MODE) {
		mmio_write_32(DDR_PHY_DX4BDLR0, 0x08080808);
		mmio_write_32(DDR_PHY_DX4BDLR1, 0x08080808);
		mmio_write_32(DDR_PHY_DX4BDLR2, 0x080808);
	}

	/* PHY FIFO reset - as recommended in PUB databook */
	phy_fifo_reset();

	/* write PHY initialization register for Write leveling, DQS
	 * gate training, Write_latency adjustment
	 */
	rc = ddr_phy_init(PIR_WL | PIR_QSGATE | PIR_WLADJ, PHY_TIMEOUT_US_1S);
	if (rc)
		return rc;

	/* Static read training must be performed in static read mode.
	 * read/write bit Deskew, read/write Eye Centering training,
	 * VREF training can be performed in static read mode or
	 * asynchronous read mode.
	 */
	mmio_clrsetbits_32(DDR_PHY_PGCR3, PGCR3_RDMODE,
			   FIELD_PREP(PGCR3_RDMODE, 1));

	/* Now, actual data training */
	w = PIR_SRD | PIR_WREYE | PIR_RDEYE | PIR_WRDSKW | PIR_RDDSKW;
	if (ddr4) {
		/* VREF training as well */
		w |= PIR_VREF;
		VREF_Training_Setup();
	}
	rc = ddr_phy_init(w, PHY_TIMEOUT_US_1S);
	if (rc)
		return rc;

	w = mmio_read_32(DDR_PHY_PGSR0);
	m = PGSR_ALL_DONE | PGSR0_SRDDONE | PGSR0_APLOCK; /* *DONE ex CADONE, VDONE */
	if (ddr4)
		m |= PGSR0_VDONE;
	if ((w & m) != m) {
		VERBOSE("pgsr0: got %08x, want %08x\n", w, m);
		PANIC("data training error");
	}

	ddr_restore_refresh(cfg->main.rfshctl3, cfg->main.pwrctl);

	/* Reenabling uMCTL2 initiated update request after executing
	 * DDR initization. Reference: DDR4 MultiPHY PUB databook
	 * (3.11a) PIR.INIT description (pg no. 114)
	 */
	sw_done_start();
	mmio_clrbits_32(DDR_UMCTL2_DFIUPD0, DFIUPD0_DIS_AUTO_CTRLUPD);
	sw_done_ack();

	/* Reenabling PHY update Request after executing DDR
	 * initization. Reference: DDR4 MultiPHY PUB databook (3.11a)
	 * PIR.INIT description (pg no. 114)
	 */
	mmio_setbits_32(DDR_PHY_DSGCR, DSGCR_PUREN);

	/* Enable AXI port(s) */
	axi_enable_ports(true);

	/* Settle */
	ddr_usleep(1);

	VERBOSE("do_data_training:exit\n");

	return 0;
}

int ddr_init(const struct ddr_config *cfg)
{
	VERBOSE("ddr_init:start\n");

	VERBOSE("name = %s\n", cfg->info.name);
	VERBOSE("speed = %d kHz\n", cfg->info.speed);
	VERBOSE("size  = %zdM\n", cfg->info.size / 1024 / 1024);

	/* Reset, start clocks at desired speed */
	ddr_reset(cfg, true);

	/* Set up controller registers */
	set_regs(cfg, &cfg->main, ddr_main_reg, ARRAY_SIZE(ddr_main_reg));
	set_regs(cfg, &cfg->timing, ddr_timing_reg, ARRAY_SIZE(ddr_timing_reg));
	set_regs(cfg, &cfg->mapping, ddr_mapping_reg, ARRAY_SIZE(ddr_mapping_reg));

	/* Static controller settings */
	set_static_ctl();

	/* Release reset */
	ddr_reset(cfg, false);

	/* Set PHY registers */
	set_regs(cfg, &cfg->phy, ddr_phy_reg, ARRAY_SIZE(ddr_phy_reg));
	set_regs(cfg, &cfg->phy_timing, ddr_phy_timing_reg, ARRAY_SIZE(ddr_phy_timing_reg));

	/* Mirror PHY MRx registers */
	set_mrx_phy(cfg);

	/* Static PHY settings */
	set_static_phy(cfg);

	/* PHY FIFO reset - as recommended in PUB databook */
	phy_fifo_reset();

	if (PHY_initialization())
		PANIC("PHY initization failed\n");

	/* Init DRAM (by PUB) */
	if (DRAM_initialization(true))
		PANIC("DDR initization failed\n");

	/* Start quasi-dynamic programming */
	sw_done_start();

	/* PHY initialization complete enable: trigger SDRAM initialisation */
	mmio_setbits_32(DDR_UMCTL2_DFIMISC, DFIMISC_DFI_INIT_COMPLETE_EN);

	/* Signal quasi-dynamic phase end, await ack */
	sw_done_ack();

	/* wait 2ms for STAT.operating_mode to become "normal" */
	wait_operating_mode(1, TIME_MS_TO_US(2U));

	if (do_data_training(cfg))
		PANIC("Data training failed\n");

	if (cfg->main.ecccfg0 & ECCCFG0_ECC_MODE)
		ecc_enable_scrubbing(cfg);

	VERBOSE("ddr_init:done\n");

	return 0;
}
