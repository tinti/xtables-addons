#ifndef _LINUX_NETFILTER_XT_DNETMAP_H
#define _LINUX_NETFILTER_XT_DNETMAP_H 1

enum {
	XT_DNETMAP_TTL = 1 << 0,
	XT_DNETMAP_REUSE = 1 << 1,
	XT_DNETMAP_PREFIX = 1 << 2,
};

struct xt_DNETMAP_tginfo {
	struct nf_nat_ipv4_multi_range_compat prefix;
	__u8 flags;
	__s16 ttl;
};

#endif
