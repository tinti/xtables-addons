#ifndef _LINUX_NETFILTER_XT_TARGET_RAWNAT
#define _LINUX_NETFILTER_XT_TARGET_RAWNAT 1

struct xt_rawnat_tginfo {
	union nf_inet_addr addr;
	__u8 mask;
};

#endif /* _LINUX_NETFILTER_XT_TARGET_RAWNAT */
