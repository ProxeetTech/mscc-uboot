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

#ifndef _MSCC_SPARX5_REGS_SUBCPU_SYS_CFG_H_
#define _MSCC_SPARX5_REGS_SUBCPU_SYS_CFG_H_

#include "mscc_sparx5_regs_common.h"

#define MSCC_SUBCPU_SYS_CFG_GPR(ri)          MSCC_IOREG(MSCC_TO_SUBCPU,0x0 + (ri))
#define  MSCC_F_SUBCPU_SYS_CFG_GPR_GPR(x)               (x)
#define  MSCC_M_SUBCPU_SYS_CFG_GPR_GPR                  0xffffffff
#define  MSCC_X_SUBCPU_SYS_CFG_GPR_GPR(x)               (x)

#define MSCC_SUBCPU_SYS_CFG_GENERAL_CTRL     MSCC_IOREG(MSCC_TO_SUBCPU,0x8)
#define  MSCC_F_SUBCPU_SYS_CFG_GENERAL_CTRL_BOOT_MODE_ENA(x)  ((x) ? BIT(4) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_GENERAL_CTRL_BOOT_MODE_ENA     BIT(4)
#define  MSCC_X_SUBCPU_SYS_CFG_GENERAL_CTRL_BOOT_MODE_ENA(x)  ((x) & BIT(4) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_GENERAL_CTRL_UART_GPIOS_ENA(x)  ((x) ? BIT(3) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_GENERAL_CTRL_UART_GPIOS_ENA     BIT(3)
#define  MSCC_X_SUBCPU_SYS_CFG_GENERAL_CTRL_UART_GPIOS_ENA(x)  ((x) & BIT(3) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_GENERAL_CTRL_I2C_GPIOS_ENA(x)  ((x) ? BIT(2) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_GENERAL_CTRL_I2C_GPIOS_ENA     BIT(2)
#define  MSCC_X_SUBCPU_SYS_CFG_GENERAL_CTRL_I2C_GPIOS_ENA(x)  ((x) & BIT(2) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_GENERAL_CTRL_WDT_RST_FORCE(x)  ((x) ? BIT(1) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_GENERAL_CTRL_WDT_RST_FORCE     BIT(1)
#define  MSCC_X_SUBCPU_SYS_CFG_GENERAL_CTRL_WDT_RST_FORCE(x)  ((x) & BIT(1) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_GENERAL_CTRL_SOFT_RST(x)  ((x) ? BIT(0) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_GENERAL_CTRL_SOFT_RST     BIT(0)
#define  MSCC_X_SUBCPU_SYS_CFG_GENERAL_CTRL_SOFT_RST(x)  ((x) & BIT(0) ? 1 : 0)

#define MSCC_SUBCPU_SYS_CFG_GENERAL_STAT     MSCC_IOREG(MSCC_TO_SUBCPU,0x9)
#define  MSCC_F_SUBCPU_SYS_CFG_GENERAL_STAT_REG_IF_ERR(x)  (GENMASK(3,1) & ((x) << 1))
#define  MSCC_M_SUBCPU_SYS_CFG_GENERAL_STAT_REG_IF_ERR     GENMASK(3,1)
#define  MSCC_X_SUBCPU_SYS_CFG_GENERAL_STAT_REG_IF_ERR(x)  (((x) >> 1) & GENMASK(2,0))
#define  MSCC_F_SUBCPU_SYS_CFG_GENERAL_STAT_CPU_SLEEPING(x)  ((x) ? BIT(0) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_GENERAL_STAT_CPU_SLEEPING     BIT(0)
#define  MSCC_X_SUBCPU_SYS_CFG_GENERAL_STAT_CPU_SLEEPING(x)  ((x) & BIT(0) ? 1 : 0)

#define MSCC_SUBCPU_SYS_CFG_RESET_PROTECT    MSCC_IOREG(MSCC_TO_SUBCPU,0xa)
#define  MSCC_F_SUBCPU_SYS_CFG_RESET_PROTECT_SOFT_RST_PROT_AMBA(x)  ((x) ? BIT(3) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_RESET_PROTECT_SOFT_RST_PROT_AMBA     BIT(3)
#define  MSCC_X_SUBCPU_SYS_CFG_RESET_PROTECT_SOFT_RST_PROT_AMBA(x)  ((x) & BIT(3) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_RESET_PROTECT_SOFT_RST_PROT_WDT(x)  ((x) ? BIT(2) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_RESET_PROTECT_SOFT_RST_PROT_WDT     BIT(2)
#define  MSCC_X_SUBCPU_SYS_CFG_RESET_PROTECT_SOFT_RST_PROT_WDT(x)  ((x) & BIT(2) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_RESET_PROTECT_SYS_RST_PROT_SUBCPU_SYS(x)  ((x) ? BIT(1) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_RESET_PROTECT_SYS_RST_PROT_SUBCPU_SYS     BIT(1)
#define  MSCC_X_SUBCPU_SYS_CFG_RESET_PROTECT_SYS_RST_PROT_SUBCPU_SYS(x)  ((x) & BIT(1) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_RESET_PROTECT_LOCK_RST_PROT_SUBCPU(x)  ((x) ? BIT(0) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_RESET_PROTECT_LOCK_RST_PROT_SUBCPU     BIT(0)
#define  MSCC_X_SUBCPU_SYS_CFG_RESET_PROTECT_LOCK_RST_PROT_SUBCPU(x)  ((x) & BIT(0) ? 1 : 0)

#define MSCC_SUBCPU_SYS_CFG_RESET_STAT       MSCC_IOREG(MSCC_TO_SUBCPU,0xb)
#define  MSCC_F_SUBCPU_SYS_CFG_RESET_STAT_SYS_RST_STICKY(x)  ((x) ? BIT(5) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_RESET_STAT_SYS_RST_STICKY     BIT(5)
#define  MSCC_X_SUBCPU_SYS_CFG_RESET_STAT_SYS_RST_STICKY(x)  ((x) & BIT(5) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_RESET_STAT_FORCE_RST_STICKY(x)  ((x) ? BIT(4) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_RESET_STAT_FORCE_RST_STICKY     BIT(4)
#define  MSCC_X_SUBCPU_SYS_CFG_RESET_STAT_FORCE_RST_STICKY(x)  ((x) & BIT(4) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_RESET_STAT_SOFT_RST_CPU_STICKY(x)  ((x) ? BIT(3) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_RESET_STAT_SOFT_RST_CPU_STICKY     BIT(3)
#define  MSCC_X_SUBCPU_SYS_CFG_RESET_STAT_SOFT_RST_CPU_STICKY(x)  ((x) & BIT(3) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_RESET_STAT_SOFT_RST_CFG_STICKY(x)  ((x) ? BIT(2) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_RESET_STAT_SOFT_RST_CFG_STICKY     BIT(2)
#define  MSCC_X_SUBCPU_SYS_CFG_RESET_STAT_SOFT_RST_CFG_STICKY(x)  ((x) & BIT(2) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_RESET_STAT_LOCK_RST_STICKY(x)  ((x) ? BIT(1) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_RESET_STAT_LOCK_RST_STICKY     BIT(1)
#define  MSCC_X_SUBCPU_SYS_CFG_RESET_STAT_LOCK_RST_STICKY(x)  ((x) & BIT(1) ? 1 : 0)
#define  MSCC_F_SUBCPU_SYS_CFG_RESET_STAT_WDT_RST_STICKY(x)  ((x) ? BIT(0) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_RESET_STAT_WDT_RST_STICKY     BIT(0)
#define  MSCC_X_SUBCPU_SYS_CFG_RESET_STAT_WDT_RST_STICKY(x)  ((x) & BIT(0) ? 1 : 0)

#define MSCC_SUBCPU_SYS_CFG_SS_FORCE_ENA(gi)  MSCC_IOREG_IX(MSCC_TO_SUBCPU,0xc,gi,4,0,0)
#define  MSCC_F_SUBCPU_SYS_CFG_SS_FORCE_ENA_SS_FORCE_ENA(x)  ((x) ? BIT(0) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_SS_FORCE_ENA_SS_FORCE_ENA     BIT(0)
#define  MSCC_X_SUBCPU_SYS_CFG_SS_FORCE_ENA_SS_FORCE_ENA(x)  ((x) & BIT(0) ? 1 : 0)

#define MSCC_SUBCPU_SYS_CFG_SS_FORCE(gi)     MSCC_IOREG_IX(MSCC_TO_SUBCPU,0xc,gi,4,0,1)
#define  MSCC_F_SUBCPU_SYS_CFG_SS_FORCE_SS_FORCE(x)     ((x) ? BIT(0) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_SS_FORCE_SS_FORCE        BIT(0)
#define  MSCC_X_SUBCPU_SYS_CFG_SS_FORCE_SS_FORCE(x)     ((x) & BIT(0) ? 1 : 0)

#define MSCC_SUBCPU_SYS_CFG_SS_MASK(gi)      MSCC_IOREG_IX(MSCC_TO_SUBCPU,0xc,gi,4,0,2)
#define  MSCC_F_SUBCPU_SYS_CFG_SS_MASK_SS_MASK(x)       (GENMASK(3,0) & ((x) << 0))
#define  MSCC_M_SUBCPU_SYS_CFG_SS_MASK_SS_MASK          GENMASK(3,0)
#define  MSCC_X_SUBCPU_SYS_CFG_SS_MASK_SS_MASK(x)       (((x) >> 0) & GENMASK(3,0))

#define MSCC_SUBCPU_SYS_CFG_MST_CONTENTION_FORCE(gi)  MSCC_IOREG_IX(MSCC_TO_SUBCPU,0xc,gi,4,0,3)
#define  MSCC_F_SUBCPU_SYS_CFG_MST_CONTENTION_FORCE_MST_CONT_FORCE(x)  ((x) ? BIT(0) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_MST_CONTENTION_FORCE_MST_CONT_FORCE     BIT(0)
#define  MSCC_X_SUBCPU_SYS_CFG_MST_CONTENTION_FORCE_MST_CONT_FORCE(x)  ((x) & BIT(0) ? 1 : 0)

#define MSCC_SUBCPU_SYS_CFG_TWI_CONFIG       MSCC_IOREG(MSCC_TO_SUBCPU,0x14)
#define  MSCC_F_SUBCPU_SYS_CFG_TWI_CONFIG_TWI_CNT_RELOAD(x)  (GENMASK(8,1) & ((x) << 1))
#define  MSCC_M_SUBCPU_SYS_CFG_TWI_CONFIG_TWI_CNT_RELOAD     GENMASK(8,1)
#define  MSCC_X_SUBCPU_SYS_CFG_TWI_CONFIG_TWI_CNT_RELOAD(x)  (((x) >> 1) & GENMASK(7,0))
#define  MSCC_F_SUBCPU_SYS_CFG_TWI_CONFIG_TWI_DELAY_ENABLE(x)  ((x) ? BIT(0) : 0)
#define  MSCC_M_SUBCPU_SYS_CFG_TWI_CONFIG_TWI_DELAY_ENABLE     BIT(0)
#define  MSCC_X_SUBCPU_SYS_CFG_TWI_CONFIG_TWI_DELAY_ENABLE(x)  ((x) & BIT(0) ? 1 : 0)

#define MSCC_SUBCPU_SYS_CFG_TWI_SPIKE_FILTER_CFG  MSCC_IOREG(MSCC_TO_SUBCPU,0x15)
#define  MSCC_F_SUBCPU_SYS_CFG_TWI_SPIKE_FILTER_CFG_SPIKE_FILTER_CFG(x)  (GENMASK(4,0) & ((x) << 0))
#define  MSCC_M_SUBCPU_SYS_CFG_TWI_SPIKE_FILTER_CFG_SPIKE_FILTER_CFG     GENMASK(4,0)
#define  MSCC_X_SUBCPU_SYS_CFG_TWI_SPIKE_FILTER_CFG_SPIKE_FILTER_CFG(x)  (((x) >> 0) & GENMASK(4,0))


#endif /* _MSCC_SPARX5_REGS_SUBCPU_SYS_CFG_H_ */
