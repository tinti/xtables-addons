/*
 *	"RAWNAT" target extension for Xtables - untracked NAT
 *	Copyright © Jan Engelhardt, 2008 - 2009
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include "compat_xtables.h"
#include "xt_RAWNAT.h"

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#	define WITH_IPV6 1
#endif

static inline __be32
remask(__be32 addr, __be32 repl, unsigned int shift)
{
	uint32_t mask = (shift == 32) ? 0 : (~(uint32_t)0 >> shift);
	return htonl((ntohl(addr) & mask) | (ntohl(repl) & ~mask));
}

#ifdef WITH_IPV6
static void
rawnat_ipv6_mask(__be32 *addr, const __be32 *repl, unsigned int mask)
{
	switch (mask) {
	case 0:
		break;
	case 1 ... 31:
		addr[0] = remask(addr[0], repl[0], mask);
		break;
	case 32:
		addr[0] = repl[0];
		break;
	case 33 ... 63:
		addr[0] = repl[0];
		addr[1] = remask(addr[1], repl[1], mask - 32);
		break;
	case 64:
		addr[0] = repl[0];
		addr[1] = repl[1];
		break;
	case 65 ... 95:
		addr[0] = repl[0];
		addr[1] = repl[1];
		addr[2] = remask(addr[2], repl[2], mask - 64);
	case 96:
		addr[0] = repl[0];
		addr[1] = repl[1];
		addr[2] = repl[2];
		break;
	case 97 ... 127:
		addr[0] = repl[0];
		addr[1] = repl[1];
		addr[2] = repl[2];
		addr[3] = remask(addr[3], repl[3], mask - 96);
		break;
	case 128:
		addr[0] = repl[0];
		addr[1] = repl[1];
		addr[2] = repl[2];
		addr[3] = repl[3];
		break;
	}
}
#endif

static void rawnat4_update_l4(struct sk_buff *skb, __be32 oldip, __be32 newip)
{
	struct iphdr *iph = ip_hdr(skb);
	void *transport_hdr = (void *)iph + ip_hdrlen(skb);
	struct tcphdr *tcph;
	struct udphdr *udph;
	bool cond;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		tcph = transport_hdr;
		inet_proto_csum_replace4(&tcph->check, skb, oldip, newip, true);
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		udph = transport_hdr;
		cond = udph->check != 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
		cond |= skb->ip_summed == CHECKSUM_PARTIAL;
#endif
		if (cond) {
			inet_proto_csum_replace4(&udph->check, skb,
				oldip, newip, true);
			if (udph->check == 0)
				udph->check = CSUM_MANGLED_0;
		}
		break;
	}
}

static unsigned int rawnat4_writable_part(const struct iphdr *iph)
{
	unsigned int wlen = sizeof(*iph);

	switch (iph->protocol) {
	case IPPROTO_TCP:
		wlen += sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		wlen += sizeof(struct udphdr);
		break;
	}
	return wlen;
}

static unsigned int
rawsnat_tg4(struct sk_buff **pskb, const struct xt_action_param *par)
{
	const struct xt_rawnat_tginfo *info = par->targinfo;
	struct iphdr *iph;
	__be32 new_addr;

	iph = ip_hdr(*pskb);
	new_addr = remask(iph->saddr, info->addr.ip, info->mask);
	if (iph->saddr == new_addr)
		return XT_CONTINUE;

	if (!skb_make_writable(pskb, rawnat4_writable_part(iph)))
		return NF_DROP;

	iph = ip_hdr(*pskb);
	csum_replace4(&iph->check, iph->saddr, new_addr);
	rawnat4_update_l4(*pskb, iph->saddr, new_addr);
	iph->saddr = new_addr;
	return XT_CONTINUE;
}

static unsigned int
rawdnat_tg4(struct sk_buff **pskb, const struct xt_action_param *par)
{
	const struct xt_rawnat_tginfo *info = par->targinfo;
	struct iphdr *iph;
	__be32 new_addr;

	iph = ip_hdr(*pskb);
	new_addr = remask(iph->daddr, info->addr.ip, info->mask);
	if (iph->daddr == new_addr)
		return XT_CONTINUE;

	if (!skb_make_writable(pskb, rawnat4_writable_part(iph)))
		return NF_DROP;

	iph = ip_hdr(*pskb);
	csum_replace4(&iph->check, iph->daddr, new_addr);
	rawnat4_update_l4(*pskb, iph->daddr, new_addr);
	iph->daddr = new_addr;
	return XT_CONTINUE;
}

#ifdef WITH_IPV6
static bool rawnat6_prepare_l4(struct sk_buff **pskb, unsigned int *l4offset,
    unsigned int *l4proto)
{
	static const unsigned int types[] =
		{IPPROTO_TCP, IPPROTO_UDP, IPPROTO_UDPLITE};
	unsigned int i;
	int err;

	*l4proto = NEXTHDR_MAX;

	for (i = 0; i < ARRAY_SIZE(types); ++i) {
		err = ipv6_find_hdr(*pskb, l4offset, types[i], NULL);
		if (err >= 0) {
			*l4proto = types[i];
			break;
		}
		if (err != -ENOENT)
			return false;
	}

	switch (*l4proto) {
	case IPPROTO_TCP:
		if (!skb_make_writable(pskb, *l4offset + sizeof(struct tcphdr)))
			return false;
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		if (!skb_make_writable(pskb, *l4offset + sizeof(struct udphdr)))
			return false;
		break;
	}

	return true;
}

static void rawnat6_update_l4(struct sk_buff *skb, unsigned int l4proto,
    unsigned int l4offset, const struct in6_addr *oldip,
    const struct in6_addr *newip)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	struct tcphdr *tcph;
	struct udphdr *udph;
	unsigned int i;
	bool cond;

	switch (l4proto) {
	case IPPROTO_TCP:
		tcph = (void *)iph + l4offset;
		for (i = 0; i < 4; ++i)
			inet_proto_csum_replace4(&tcph->check, skb,
				oldip->s6_addr32[i], newip->s6_addr32[i], true);
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		udph = (void *)iph + l4offset;
		cond = udph->check;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
		cond |= skb->ip_summed == CHECKSUM_PARTIAL;
#endif
		if (cond) {
			for (i = 0; i < 4; ++i)
				inet_proto_csum_replace4(&udph->check, skb,
					oldip->s6_addr32[i],
					newip->s6_addr32[i], true);
			if (udph->check == 0)
				udph->check = CSUM_MANGLED_0;
		}
		break;
	}
}

static unsigned int
rawsnat_tg6(struct sk_buff **pskb, const struct xt_action_param *par)
{
	const struct xt_rawnat_tginfo *info = par->targinfo;
	unsigned int l4offset, l4proto;
	struct ipv6hdr *iph;
	struct in6_addr new_addr;

	iph = ipv6_hdr(*pskb);
	memcpy(&new_addr, &iph->saddr, sizeof(new_addr));
	rawnat_ipv6_mask(new_addr.s6_addr32, info->addr.ip6, info->mask);
	if (ipv6_addr_cmp(&iph->saddr, &new_addr) == 0)
		return XT_CONTINUE;
	if (!rawnat6_prepare_l4(pskb, &l4offset, &l4proto))
		return NF_DROP;
	iph = ipv6_hdr(*pskb);
	rawnat6_update_l4(*pskb, l4proto, l4offset, &iph->saddr, &new_addr);
	memcpy(&iph->saddr, &new_addr, sizeof(new_addr));
	return XT_CONTINUE;
}

static unsigned int
rawdnat_tg6(struct sk_buff **pskb, const struct xt_action_param *par)
{
	const struct xt_rawnat_tginfo *info = par->targinfo;
	unsigned int l4offset, l4proto;
	struct ipv6hdr *iph;
	struct in6_addr new_addr;

	iph = ipv6_hdr(*pskb);
	memcpy(&new_addr, &iph->daddr, sizeof(new_addr));
	rawnat_ipv6_mask(new_addr.s6_addr32, info->addr.ip6, info->mask);
	if (ipv6_addr_cmp(&iph->daddr, &new_addr) == 0)
		return XT_CONTINUE;
	if (!rawnat6_prepare_l4(pskb, &l4offset, &l4proto))
		return NF_DROP;
	iph = ipv6_hdr(*pskb);
	rawnat6_update_l4(*pskb, l4proto, l4offset, &iph->daddr, &new_addr);
	memcpy(&iph->daddr, &new_addr, sizeof(new_addr));
	return XT_CONTINUE;
}
#endif

static int rawnat_tg_check(const struct xt_tgchk_param *par)
{
	if (strcmp(par->table, "raw") == 0 ||
	    strcmp(par->table, "rawpost") == 0)
		return 0;

	printk(KERN_ERR KBUILD_MODNAME " may only be used in the \"raw\" or "
	       "\"rawpost\" table.\n");
	return -EINVAL;
}

static struct xt_target rawnat_tg_reg[] __read_mostly = {
	{
		.name       = "RAWSNAT",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = rawsnat_tg4,
		.targetsize = sizeof(struct xt_rawnat_tginfo),
		.checkentry = rawnat_tg_check,
		.me         = THIS_MODULE,
	},
#ifdef WITH_IPV6
	{
		.name       = "RAWSNAT",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = rawsnat_tg6,
		.targetsize = sizeof(struct xt_rawnat_tginfo),
		.checkentry = rawnat_tg_check,
		.me         = THIS_MODULE,
	},
#endif
	{
		.name       = "RAWDNAT",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = rawdnat_tg4,
		.targetsize = sizeof(struct xt_rawnat_tginfo),
		.checkentry = rawnat_tg_check,
		.me         = THIS_MODULE,
	},
#ifdef WITH_IPV6
	{
		.name       = "RAWDNAT",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = rawdnat_tg6,
		.targetsize = sizeof(struct xt_rawnat_tginfo),
		.checkentry = rawnat_tg_check,
		.me         = THIS_MODULE,
	},
#endif
};

static int __init rawnat_tg_init(void)
{
	return xt_register_targets(rawnat_tg_reg, ARRAY_SIZE(rawnat_tg_reg));
}

static void __exit rawnat_tg_exit(void)
{
	xt_unregister_targets(rawnat_tg_reg, ARRAY_SIZE(rawnat_tg_reg));
}

module_init(rawnat_tg_init);
module_exit(rawnat_tg_exit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_DESCRIPTION("Xtables: conntrack-less raw NAT");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_RAWSNAT");
MODULE_ALIAS("ipt_RAWDNAT");
MODULE_ALIAS("ip6t_RAWSNAT");
MODULE_ALIAS("ip6t_RAWDNAT");
