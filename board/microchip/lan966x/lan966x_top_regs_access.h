
#ifndef _LAN966X_TOP_REGS_ACCESS_H_
#define _LAN966X_TOP_REGS_ACCESS_H_

extern const unsigned int lan966x_regs[];

u32 lan966x_readl(u32 id, u32 tinst, u32 tcnt,
		  u32 gbase, u32 ginst, u32 gcnt, u32 gwidth,
		  u32 raddr, u32 rinst, u32 rcnt, u32 rwidth);
void lan966x_writel(u32 id, u32 tinst, u32 tcnt,
		    u32 gbase, u32 ginst, u32 gcnt, u32 gwidth,
		    u32 raddr, u32 rinst, u32 rcnt, u32 rwidth,
		    u32 data);

#define REG_RD_(id, tinst, tcnt, gbase, ginst, gcnt, gwidth, raddr, rinst, rcnt, rwidth) \
	(readl(lan966x_regs[id + (tinst)] + gbase + ((ginst) * gwidth) +		\
	       raddr + ((rinst) * rwidth)))
#define REG_WR_(id, tinst, tcnt, gbase, ginst, gcnt, gwidth, raddr, rinst, rcnt, rwidth, data) \
	(writel(data, lan966x_regs[id + (tinst)] + gbase + ((ginst) * gwidth) +		\
	       raddr + ((rinst) * rwidth)))

#define REG_RMW_(val, mask, id, tinst, tcnt,		\
		 gbase, ginst, gcnt, gwidth,		\
		 raddr, rinst, rcnt, rwidth) do {	\
	u32 _v_;					\
	_v_ = readl(lan966x_regs[id + (tinst)] +	\
		    gbase + ((ginst) * gwidth) +	\
		    raddr + ((rinst) * rwidth));	\
	_v_ = ((_v_ & ~(mask)) | ((val) & (mask)));	\
	writel(_v_, lan966x_regs[id + (tinst)] +	\
	       gbase + ((ginst) * gwidth) +		\
	       raddr + ((rinst) * rwidth)); } while (0)

#define REG_RD(...) REG_RD_(__VA_ARGS__)
#define REG_WR(...) REG_WR_(__VA_ARGS__)

#define REG_RMW(...) REG_RMW_(__VA_ARGS__)

#endif
