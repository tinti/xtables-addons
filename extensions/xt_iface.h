#ifndef _LINUX_NETFILTER_XT_IFACE_H
#define _LINUX_NETFILTER_XT_IFACE_H 1

#define DEBUG 0
#define _MODULE_NAME "iface"
#define _MODULE_REVISION 0

#if DEBUG
#if _KERNEL
#define DEBUGP(format, args...) printk(KERN_INFO "xt_"_MODULE_NAME": "format"\n", ##args)
#else
#define DEBUGP(format, args...) printf("# DEBUG: libxt_"_MODULE_NAME": "format"\n", ##args)
#endif
#else
#define DEBUGP(format, args...)
#endif

#define XT_IFACE_FLAGCOUNT 11

enum {
	XT_IFACE_UP          = 1 << 0,
	XT_IFACE_BROADCAST   = 1 << 1,
	XT_IFACE_LOOPBACK    = 1 << 2,
	XT_IFACE_POINTOPOINT = 1 << 3,
	XT_IFACE_RUNNING     = 1 << 4,
	XT_IFACE_NOARP       = 1 << 5,
	XT_IFACE_PROMISC     = 1 << 6,
	XT_IFACE_MULTICAST   = 1 << 7,
	XT_IFACE_DYNAMIC     = 1 << 8,
	XT_IFACE_LOWER_UP    = 1 << 9,
	XT_IFACE_DORMANT     = 1 << 10,
	XT_IFACE_IFACE       = 1 << 15,
};

struct xt_iface_flag_pairs {
	u_int16_t iface_flag;
	u_int32_t iff_flag;
};

struct xt_iface_mtinfo {
	char ifname[IFNAMSIZ];
	u_int16_t flags;
	u_int16_t invflags;
};

#endif
