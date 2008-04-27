/*
 *	"SYSRQ" target extension for Netfilter
 *	Copyright © Jan Engelhardt <jengelh [at] medozas de>, 2008
 *
 *	Based upon the ipt_SYSRQ idea by Marek Zalem <marek [at] terminus sk>
 *	xt_SYSRQ does not use hashing or timestamps.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	version 2 or 3 as published by the Free Software Foundation.
 */
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/sysrq.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/x_tables.h>
#include <net/ip.h>
#include "compat_xtables.h"

static bool sysrq_once;
static char sysrq_password[64];
module_param_string(password, sysrq_password, sizeof(sysrq_password),
	S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(password, "password for remote sysrq");

static unsigned int sysrq_tg(const void *pdata, uint16_t len)
{
	const char *data = pdata;
	char c;

	if (*sysrq_password == '\0') {
		if (!sysrq_once)
			printk(KERN_INFO KBUILD_MODNAME "No password set\n");
		sysrq_once = true;
		return NF_DROP;
	}

	if (len == 0)
		return NF_DROP;

	c = *data;
	if (strncmp(&data[1], sysrq_password, len - 1) != 0) {
		printk(KERN_INFO KBUILD_MODNAME "Failed attempt - "
		       "password mismatch\n");
		return NF_DROP;
	}

	handle_sysrq(c, NULL);
	return NF_ACCEPT;
}

static unsigned int sysrq_tg4(struct sk_buff *skb, const struct net_device *in,
    const struct net_device *out, unsigned int hooknum,
    const struct xt_target *target, const void *targinfo)
{
	const struct iphdr *iph;
	const struct udphdr *udph;
	uint16_t len;

	if (skb_linearize(skb) < 0)
		return NF_DROP;

	iph  = ip_hdr(skb);
	udph = (void *)iph + ip_hdrlen(skb);
	len  = ntohs(udph->len) - sizeof(struct udphdr);

	printk(KERN_INFO KBUILD_MODNAME ": " NIPQUAD_FMT ":%u -> :%u len=%u\n",
	       NIPQUAD(iph->saddr), htons(udph->source), htons(udph->dest),
	       len);
	return sysrq_tg((void *)udph + sizeof(struct udphdr), len);
}

static unsigned int sysrq_tg6(struct sk_buff *skb, const struct net_device *in,
    const struct net_device *out, unsigned int hooknum,
    const struct xt_target *target, const void *targinfo)
{
	const struct ipv6hdr *iph;
	const struct udphdr *udph;
	uint16_t len;

	if (skb_linearize(skb) < 0)
		return NF_DROP;

	iph  = ipv6_hdr(skb);
	udph = udp_hdr(skb);
	len  = ntohs(udph->len) - sizeof(struct udphdr);

	printk(KERN_INFO KBUILD_MODNAME ": " NIP6_FMT ":%hu -> :%hu len=%u\n",
	       NIP6(iph->saddr), ntohs(udph->source),
	       ntohs(udph->dest), len);
	return sysrq_tg(udph + sizeof(struct udphdr), len);
}

static bool sysrq_tg_check(const char *table, const void *ventry,
    const struct xt_target *target, void *targinfo, unsigned int hook_mask)
{
	if (target->family == PF_INET) {
		const struct ipt_entry *entry = ventry;

		if ((entry->ip.proto != IPPROTO_UDP &&
		    entry->ip.proto != IPPROTO_UDPLITE) ||
		    entry->ip.invflags & XT_INV_PROTO)
			goto out;
	} else if (target->family == PF_INET6) {
		const struct ip6t_entry *entry = ventry;

		if ((entry->ipv6.proto != IPPROTO_UDP &&
		    entry->ipv6.proto != IPPROTO_UDPLITE) ||
		    entry->ipv6.invflags & XT_INV_PROTO)
			goto out;
	}

	return true;

 out:
	printk(KERN_ERR KBUILD_MODNAME ": only available for UDP and UDP-Lite");
	return false;
}

static struct xt_target sysrq_tg_reg[] __read_mostly = {
	{
		.name       = "SYSRQ",
		.family     = PF_INET,
		.revision   = 0,
		.target     = sysrq_tg4,
		.checkentry = sysrq_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "SYSRQ",
		.family     = PF_INET6,
		.revision   = 0,
		.target     = sysrq_tg6,
		.checkentry = sysrq_tg_check,
		.me         = THIS_MODULE,
	},
};

static int __init sysrq_tg_init(void)
{
	return xt_register_targets(sysrq_tg_reg, ARRAY_SIZE(sysrq_tg_reg));
}

static void __exit sysrq_tg_exit(void)
{
	return xt_unregister_targets(sysrq_tg_reg, ARRAY_SIZE(sysrq_tg_reg));
}

module_init(sysrq_tg_init);
module_exit(sysrq_tg_exit);
MODULE_DESCRIPTION("Xtables: triggering SYSRQ remotely");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_LICENSE("GPL");
