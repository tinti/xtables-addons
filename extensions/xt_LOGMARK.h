#ifndef _LINUX_NETFILTER_XT_LOGMARK_TARGET_H
#define _LINUX_NETFILTER_XT_LOGMARK_TARGET_H 1

enum {
	XT_LOGMARK_NFMARK  = 1 << 0,
	XT_LOGMARK_CTMARK  = 1 << 1,
	XT_LOGMARK_SECMARK = 1 << 2,
};

struct xt_logmark_tginfo {
	char prefix[14];
	u_int8_t level;
	u_int8_t flags;
};

#endif /* _LINUX_NETFILTER_XT_LOGMARK_TARGET_H */
