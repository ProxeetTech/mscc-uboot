/*
 Copyright (c) 2004-2018 Microsemi Corporation "Microsemi".

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
*/

#ifndef _MSCC_SPARX5_REGS_HSIOWRAP_H_
#define _MSCC_SPARX5_REGS_HSIOWRAP_H_

#include "mscc_sparx5_regs_common.h"

/***********************************************************************
 *
 * Target: \a HSIOWRAP
 *
 * 
 *
 ***********************************************************************/

/**
 * Register Group: \a HSIOWRAP:SYNC_ETH_CFG
 *
 * SYNC_ETH Configuration Registers
 */


/** 
 * \brief Recovered Clock Configuration
 *
 * \details
 * This register is replicated once per recovered clock destination.
 * Replications 0-3 are GPIO mapped recovered clocks 0 though 3.
 * Replications 4-7 are SD10G mapped recovered clocks.
 *
 * Register: \a HSIOWRAP:SYNC_ETH_CFG:SYNC_ETH_CFG
 *
 * @param ri Register: SYNC_ETH_CFG (??), 0-3
 */
#define MSCC_HSIOWRAP_SYNC_ETH_CFG(ri)       MSCC_IOREG(MSCC_TO_HSIO_WRAP,0x0 + (ri))

/** 
 * \brief
 * Select recovered clock source.
 *
 * \details 
 * 0-16: Select SD6G 0 through 16 recovered RX data clock
 * 17-32: Select SD10G 0 through 15 recovered RX data lock
 * 33: Select AUX1 clock from LCPLL1 reference
 * 34: Select AUX2 clock from LCPLL1 reference
 * 35: Select AUX3 clock from LCPLL1 reference
 * 36: Select AUX4 clock from LCPLL1 reference
 * Other values are reserved.
 *
 * Field: ::MSCC_HSIOWRAP_SYNC_ETH_CFG . SEL_RECO_CLK_SRC
 */
#define  MSCC_F_HSIOWRAP_SYNC_ETH_CFG_SEL_RECO_CLK_SRC(x)  (GENMASK(5,0) & ((x) << 0))
#define  MSCC_M_HSIOWRAP_SYNC_ETH_CFG_SEL_RECO_CLK_SRC     GENMASK(5,0)
#define  MSCC_X_HSIOWRAP_SYNC_ETH_CFG_SEL_RECO_CLK_SRC(x)  (((x) >> 0) & GENMASK(5,0))

/** 
 * \brief
 * Select recovered clock divider.
 *
 * \details 
 * 0: Divide clock by 2
 * 1: Divide clock by 4
 * 2: Divide clock by 8
 * 3: Divide clock by 16
 * 4: Divide clock by 5
 * 5: Divide clock by 25
 * 6: No clock dividing
 * 7: Reserved
 *
 * Field: ::MSCC_HSIOWRAP_SYNC_ETH_CFG . SEL_RECO_CLK_DIV
 */
#define  MSCC_F_HSIOWRAP_SYNC_ETH_CFG_SEL_RECO_CLK_DIV(x)  (GENMASK(10,8) & ((x) << 8))
#define  MSCC_M_HSIOWRAP_SYNC_ETH_CFG_SEL_RECO_CLK_DIV     GENMASK(10,8)
#define  MSCC_X_HSIOWRAP_SYNC_ETH_CFG_SEL_RECO_CLK_DIV(x)  (((x) >> 8) & GENMASK(2,0))

/** 
 * \brief
 * Set to enable recovered clock generation. Bit is also used to enable
 * corresponding GPIO pad. 
 *
 * \details 
 * 0: Disable (high-impedance)
 * 1: Enable (output recovered clock)
 *
 * Field: ::MSCC_HSIOWRAP_SYNC_ETH_CFG . RECO_CLK_ENA
 */
#define  MSCC_F_HSIOWRAP_SYNC_ETH_CFG_RECO_CLK_ENA(x)   ((x) ? BIT(12) : 0)
#define  MSCC_M_HSIOWRAP_SYNC_ETH_CFG_RECO_CLK_ENA      BIT(12)
#define  MSCC_X_HSIOWRAP_SYNC_ETH_CFG_RECO_CLK_ENA(x)   ((x) & BIT(12) ? 1 : 0)

/**
 * Register Group: \a HSIOWRAP:GPIO_CFG
 *
 * Registers for accessing the GPIO pad cell configuration
 */


/** 
 * \brief GPIO pad cell configuration
 *
 * \details
 * Register: \a HSIOWRAP:GPIO_CFG:GPIO_CFG
 *
 * @param ri Replicator: x_FFL_DEVCPU_GPIO_CNT (??), 0-63
 */
#define MSCC_HSIOWRAP_GPIO_CFG(ri)           MSCC_IOREG(MSCC_TO_HSIO_WRAP,0x4 + (ri))

/** 
 * \brief
 * Controls the drive strength of GPIO outputs
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_GPIO_CFG . G_DS
 */
#define  MSCC_F_HSIOWRAP_GPIO_CFG_G_DS(x)               (GENMASK(1,0) & ((x) << 0))
#define  MSCC_M_HSIOWRAP_GPIO_CFG_G_DS                  GENMASK(1,0)
#define  MSCC_X_HSIOWRAP_GPIO_CFG_G_DS(x)               (((x) >> 0) & GENMASK(1,0))

/** 
 * \brief
 * Enable schmitt trigger function on GPIO inputs
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_GPIO_CFG . G_ST
 */
#define  MSCC_F_HSIOWRAP_GPIO_CFG_G_ST(x)               ((x) ? BIT(2) : 0)
#define  MSCC_M_HSIOWRAP_GPIO_CFG_G_ST                  BIT(2)
#define  MSCC_X_HSIOWRAP_GPIO_CFG_G_ST(x)               ((x) & BIT(2) ? 1 : 0)

/** 
 * \brief
 * Enable pull up resistor on GPIO inputs. Should not be set to '1' when
 * G_PD is '1'
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_GPIO_CFG . G_PU
 */
#define  MSCC_F_HSIOWRAP_GPIO_CFG_G_PU(x)               ((x) ? BIT(3) : 0)
#define  MSCC_M_HSIOWRAP_GPIO_CFG_G_PU                  BIT(3)
#define  MSCC_X_HSIOWRAP_GPIO_CFG_G_PU(x)               ((x) & BIT(3) ? 1 : 0)

/** 
 * \brief
 * Enable pull down resistor on GPIO inputs. Should not be set to '1' when
 * G_PU is '1'
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_GPIO_CFG . G_PD
 */
#define  MSCC_F_HSIOWRAP_GPIO_CFG_G_PD(x)               ((x) ? BIT(4) : 0)
#define  MSCC_M_HSIOWRAP_GPIO_CFG_G_PD                  BIT(4)
#define  MSCC_X_HSIOWRAP_GPIO_CFG_G_PD(x)               ((x) & BIT(4) ? 1 : 0)

/**
 * Register Group: \a HSIOWRAP:TEMP_SENSOR
 *
 * Temperature sensor control
 */


/** 
 * \brief Temperature Sensor Control
 *
 * \details
 * Register: \a HSIOWRAP:TEMP_SENSOR:TEMP_SENSOR_CTRL
 */
#define MSCC_HSIOWRAP_TEMP_SENSOR_CTRL       MSCC_IOREG(MSCC_TO_HSIO_WRAP,0x44)

/** 
 * \brief
 * Set to force reading of temperature. This field only works when
 * SAMPLE_ENA is cleared. The read will either instantaneously or
 * synchronized to the RDY output of the temperature sensor if the sensor
 * is enabled.	The temperature sensor can be configured to run
 * continuously by using these settings:FORCE_POWER_UP = 1Wait 50
 * usFORCE_CLK = 1Wait 5 usFORCE_NO_RST = 1Wait 5 usFORCE_RUN =
 * 1FORCE_TEMP_RD= 1This will cause the temperature sensor to sample
 * continuously and provide the result in TEMP_SENSOR_STAT.TEMP.  The
 * status TEMP_SENSOR_STAT.TEMP_VALID will be 1 after the first sample.
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CTRL . FORCE_TEMP_RD
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_TEMP_RD(x)  ((x) ? BIT(4) : 0)
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_TEMP_RD     BIT(4)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_TEMP_RD(x)  ((x) & BIT(4) ? 1 : 0)

/** 
 * \brief
 * Set to force RUN signal towards temperature sensor. This field only
 * works when SAMPLE_ENA is cleared.
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CTRL . FORCE_RUN
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_RUN(x)  ((x) ? BIT(3) : 0)
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_RUN     BIT(3)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_RUN(x)  ((x) & BIT(3) ? 1 : 0)

/** 
 * \brief
 * Set to force the RSTN signal towards temperature sensor (release of
 * reset). This field only works when SAMPLE_ENA is cleared.
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CTRL . FORCE_NO_RST
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_NO_RST(x)  ((x) ? BIT(2) : 0)
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_NO_RST     BIT(2)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_NO_RST(x)  ((x) & BIT(2) ? 1 : 0)

/** 
 * \brief
 * Set to force the PD signal towards temperature sensor. This field only
 * works when SAMPLE_ENA is cleared.
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CTRL . FORCE_POWER_UP
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_POWER_UP(x)  ((x) ? BIT(1) : 0)
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_POWER_UP     BIT(1)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_POWER_UP(x)  ((x) & BIT(1) ? 1 : 0)

/** 
 * \brief
 * Set to force a clock signal towards the temperature sensor. The clock
 * frequency will be controlled by the TEMP_SENSOR_CFG.CLK_CYCLES_1US
 * setting. This field only works when SAMPLE_ENA is cleared.
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CTRL . FORCE_CLK
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_CLK(x)  ((x) ? BIT(0) : 0)
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_CLK     BIT(0)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CTRL_FORCE_CLK(x)  ((x) & BIT(0) ? 1 : 0)


/** 
 * \brief Temperature Sensor Configuration
 *
 * \details
 * Register: \a HSIOWRAP:TEMP_SENSOR:TEMP_SENSOR_CFG
 */
#define MSCC_HSIOWRAP_TEMP_SENSOR_CFG        MSCC_IOREG(MSCC_TO_HSIO_WRAP,0x45)

/** 
 * \brief
 * The number of system clock cycles in one 1us. This is used to generated
 * the temperature sensor clock signal (CLK.)  The frequency of CLK must be
 * higher than 0.75Mhz and lower than 2Mhz.
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CFG . CLK_CYCLES_1US
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CFG_CLK_CYCLES_1US(x)  (GENMASK(24,15) & ((x) << 15))
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CFG_CLK_CYCLES_1US     GENMASK(24,15)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CFG_CLK_CYCLES_1US(x)  (((x) >> 15) & GENMASK(9,0))

/** 
 * \brief
 * Trim value. This value should only be modified as a result of a sensor
 * calibration
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CFG . TRIM_VAL
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CFG_TRIM_VAL(x)    (GENMASK(14,11) & ((x) << 11))
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CFG_TRIM_VAL       GENMASK(14,11)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CFG_TRIM_VAL(x)    (((x) >> 11) & GENMASK(3,0))

/** 
 * \brief
 * Set this field to enable calibration of the sensor. A 0.7V signal must
 * be applied to the calibration input.The calibration procedure is as
 * follows:Set SAMPLE_ENA to 0Apply 0.7V +/- 10% to the calibration input
 * pinMeasure actual voltage on calibration input with highest possible
 * precisionSet CAL_ENA to 1Set SAMPLE_ENA to 1Read TEMP_SENSOR_STAT.TEMP
 * and use this value and the calibration voltage to calculate the
 * calibration temperature.Find TRIM_VAL:Set SAMPLE_ENA to 0Set CAL_ENA to
 * 0Set SAMPLE_ENA to 1Change TRIM_VAL until TEMP_SENSOR_STAT.TEMP results
 * in a temperature as close as possible to the calibration
 * temperatureNormal mode:Set SAMPLE_ENA to 1Use TRIM_VAL obtained from
 * calibration
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CFG . CAL_ENA
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CFG_CAL_ENA(x)     ((x) ? BIT(10) : 0)
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CFG_CAL_ENA        BIT(10)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CFG_CAL_ENA(x)     ((x) & BIT(10) ? 1 : 0)

/** 
 * \brief
 * Power up delay. The unit is number of sensor CLK cycles. See:
 * CLK_CYCLES_1USDefault value corresponds to a 50us delay, which is the
 * minimum required value.
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CFG . PWR_UP_DELAY
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CFG_PWR_UP_DELAY(x)  (GENMASK(9,3) & ((x) << 3))
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CFG_PWR_UP_DELAY     GENMASK(9,3)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CFG_PWR_UP_DELAY(x)  (((x) >> 3) & GENMASK(6,0))

/** 
 * \brief
 * Set this bit to start a temperature sample cycle. This is only used if
 * continuous sampling is disabled.Procedure:Set START_CAPTURE to 1Wait
 * until hardware clears START_CAPTURE Read temperature from
 * TEMP_SENSOR_STAT.TEMP
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CFG . START_CAPTURE
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CFG_START_CAPTURE(x)  ((x) ? BIT(2) : 0)
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CFG_START_CAPTURE     BIT(2)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CFG_START_CAPTURE(x)  ((x) & BIT(2) ? 1 : 0)

/** 
 * \brief
 * Set this field to enable continuous sampling of temperature. The latest
 * sample value will be available in TEMP_SENSOR_STAT.TEMP
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CFG . CONTINUOUS_MODE
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CFG_CONTINUOUS_MODE(x)  ((x) ? BIT(1) : 0)
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CFG_CONTINUOUS_MODE     BIT(1)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CFG_CONTINUOUS_MODE(x)  ((x) & BIT(1) ? 1 : 0)

/** 
 * \brief
 * Set this field to enable sampling of temperature. The sensor will be
 * taken out of power down mode and the temperature sampling is stared when
 * SAMPLE_ENA is set to 1
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_CFG . SAMPLE_ENA
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_CFG_SAMPLE_ENA(x)  ((x) ? BIT(0) : 0)
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_CFG_SAMPLE_ENA     BIT(0)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_CFG_SAMPLE_ENA(x)  ((x) & BIT(0) ? 1 : 0)


/** 
 * \brief Temperature Sensor Status
 *
 * \details
 * Register: \a HSIOWRAP:TEMP_SENSOR:TEMP_SENSOR_STAT
 */
#define MSCC_HSIOWRAP_TEMP_SENSOR_STAT       MSCC_IOREG(MSCC_TO_HSIO_WRAP,0x46)

/** 
 * \brief
 * This field is set when valid temperature data is available in
 * TEMP_SENSOR_STAT.TEMP
 *
 * \details 
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_STAT . TEMP_VALID
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_STAT_TEMP_VALID(x)  ((x) ? BIT(12) : 0)
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_STAT_TEMP_VALID     BIT(12)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_STAT_TEMP_VALID(x)  ((x) & BIT(12) ? 1 : 0)

/** 
 * \brief
 * Temperature data readout This field is valid when
 * TEMP_SENSOR_STAT.TEMP_VALID is set. This field is continually updated
 * while the temperature sensor is enabled. See TEMP_SENSOR_CFG.SAMPLE_ENA
 * for more information.
 *
 * \details 
 * Temp(C) = TEMP_SENSOR_STAT.TEMP / 4096 * 352.2 - 109.4
 *
 * Field: ::MSCC_HSIOWRAP_TEMP_SENSOR_STAT . TEMP
 */
#define  MSCC_F_HSIOWRAP_TEMP_SENSOR_STAT_TEMP(x)       (GENMASK(11,0) & ((x) << 0))
#define  MSCC_M_HSIOWRAP_TEMP_SENSOR_STAT_TEMP          GENMASK(11,0)
#define  MSCC_X_HSIOWRAP_TEMP_SENSOR_STAT_TEMP(x)       (((x) >> 0) & GENMASK(11,0))


#endif /* _MSCC_SPARX5_REGS_HSIOWRAP_H_ */
