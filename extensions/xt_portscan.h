#ifndef _LINUX_NETFILTER_XT_PORTSCAN_H
#define _LINUX_NETFILTER_XT_PORTSCAN_H 1

struct xt_portscan_mtinfo {
	uint8_t match_stealth, match_syn, match_cn, match_gr;
};

#endif /* _LINUX_NETFILTER_XT_PORTSCAN_H */
