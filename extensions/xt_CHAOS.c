/*
 *	CHAOS target for netfilter
 *	Copyright © CC Computer Consultants GmbH, 2006 - 2007
 *	Contact: Jan Engelhardt <jengelh@computergmbh.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License; either version
 *	2 or 3 as published by the Free Software Foundation.
 */
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/stat.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/netfilter_ipv4/ipt_REJECT.h>
#include <net/ip.h>
#include "xt_CHAOS.h"
static struct xt_match *xm_tcp;
static struct xt_target *xt_delude, *xt_reject, *xt_tarpit;
#include "compat_xtables.h"
#define PFX KBUILD_MODNAME ": "

/* Module parameters */
static unsigned int reject_percentage = ~0U * .01;
static unsigned int delude_percentage = ~0U * .0101;
module_param(reject_percentage, uint, S_IRUGO | S_IWUSR);
module_param(delude_percentage, uint, S_IRUGO | S_IWUSR);

/* References to other matches/targets */

static int have_delude, have_tarpit;

/* Static data for other matches/targets */
static const struct ipt_reject_info reject_params = {
	.with = ICMP_HOST_UNREACH,
};

static const struct xt_tcp tcp_params = {
	.spts = {0, ~0},
	.dpts = {0, ~0},
};

/* CHAOS functions */
static void xt_chaos_total(const struct xt_chaos_tginfo *info,
    struct sk_buff *skb, const struct net_device *in,
    const struct net_device *out, unsigned int hooknum)
{
	const struct iphdr *iph = ip_hdr(skb);
	const int protoff       = 4 * iph->ihl;
	const int offset        = ntohs(iph->frag_off) & IP_OFFSET;
	typeof(xt_tarpit) destiny;
	bool ret;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
	int hotdrop = false;
#else
	bool hotdrop = false;
#endif

	ret = xm_tcp->match(skb, in, out, xm_tcp, &tcp_params,
	                    offset, protoff, &hotdrop);
	if (!ret || hotdrop || (unsigned int)net_random() > delude_percentage)
		return;

	destiny = (info->variant == XTCHAOS_TARPIT) ? xt_tarpit : xt_delude;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
	destiny->target(&skb, in, out, hooknum, destiny, NULL, NULL);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
	destiny->target(&skb, in, out, hooknum, destiny, NULL);
#else
	destiny->target(skb, in, out, hooknum, destiny, NULL);
#endif
	return;
}

static unsigned int chaos_tg(struct sk_buff *skb, const struct net_device *in,
    const struct net_device *out, unsigned int hooknum,
    const struct xt_target *target, const void *targinfo)
{
	/*
	 * Equivalent to:
	 * -A chaos -m statistic --mode random --probability \
	 *         $reject_percentage -j REJECT --reject-with host-unreach;
	 * -A chaos -p tcp -m statistic --mode random --probability \
	 *         $delude_percentage -j DELUDE;
	 * -A chaos -j DROP;
	 */
	const struct xt_chaos_tginfo *info = targinfo;
	const struct iphdr *iph = ip_hdr(skb);

	if ((unsigned int)net_random() <= reject_percentage)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
		return xt_reject->target(&skb, in, out, hooknum,
		       target->__compat_target, &reject_params, NULL);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
		return xt_reject->target(&skb, in, out, hooknum,
		       target->__compat_target, &reject_params);
#else
		return xt_reject->target(skb, in, out, hooknum, target,
		       &reject_params);
#endif

	/* TARPIT/DELUDE may not be called from the OUTPUT chain */
	if (iph->protocol == IPPROTO_TCP &&
	    info->variant != XTCHAOS_NORMAL && hooknum != NF_INET_LOCAL_OUT)
		xt_chaos_total(info, skb, in, out, hooknum);

	return NF_DROP;
}

static bool chaos_tg_check(const char *tablename, const void *entry,
    const struct xt_target *target, void *targinfo, unsigned int hook_mask)
{
	const struct xt_chaos_tginfo *info = targinfo;

	if (info->variant == XTCHAOS_DELUDE && !have_delude) {
		printk(KERN_WARNING PFX "Error: Cannot use --delude when "
		       "DELUDE module not available\n");
		return false;
	}
	if (info->variant == XTCHAOS_TARPIT && !have_tarpit) {
		printk(KERN_WARNING PFX "Error: Cannot use --tarpit when "
		       "TARPIT module not available\n");
		return false;
	}

	return true;
}

static struct xt_target chaos_tg_reg = {
	.name       = "CHAOS",
	.family     = AF_INET,
	.table      = "filter",
	.hooks      = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) |
	              (1 << NF_INET_LOCAL_OUT),
	.target     = chaos_tg,
	.checkentry = chaos_tg_check,
	.targetsize = sizeof(struct xt_chaos_tginfo),
	.me         = THIS_MODULE,
};

static int __init chaos_tg_init(void)
{
	int ret = -EINVAL;

	xm_tcp = xt_request_find_match(AF_INET, "tcp", 0);
	if (xm_tcp == NULL) {
		printk(KERN_WARNING PFX "Error: Could not find or load "
		       "\"tcp\" match\n");
		return -EINVAL;
	}

	xt_reject = xt_request_find_target(AF_INET, "REJECT", 0);
	if (xt_reject == NULL) {
		printk(KERN_WARNING PFX "Error: Could not find or load "
		       "\"REJECT\" target\n");
		goto out2;
	}

	xt_tarpit   = xt_request_find_target(AF_INET, "TARPIT", 0);
	have_tarpit = xt_tarpit != NULL;
	if (!have_tarpit)
		printk(KERN_WARNING PFX "Warning: Could not find or load "
		       "\"TARPIT\" target\n");

	xt_delude   = xt_request_find_target(AF_INET, "DELUDE", 0);
	have_delude = xt_delude != NULL;
	if (!have_delude)
		printk(KERN_WARNING PFX "Warning: Could not find or load "
		       "\"DELUDE\" target\n");

	if ((ret = xt_register_target(&chaos_tg_reg)) != 0) {
		printk(KERN_WARNING PFX "xt_register_target returned "
		       "error %d\n", ret);
		goto out3;
	}

	return 0;

 out3:
 	if (have_delude)
 		module_put(xt_delude->me);
	if (have_tarpit)
		module_put(xt_tarpit->me);
	module_put(xt_reject->me);
 out2:
	module_put(xm_tcp->me);
	return ret;
}

static void __exit chaos_tg_exit(void)
{
	xt_unregister_target(&chaos_tg_reg);
	module_put(xm_tcp->me);
	module_put(xt_reject->me);
	if (have_delude)
		module_put(xt_delude->me);
	if (have_tarpit)
		module_put(xt_tarpit->me);
	return;
}

module_init(chaos_tg_init);
module_exit(chaos_tg_exit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@computergmbh.de>");
MODULE_DESCRIPTION("Xtables: Network scan slowdown with non-deterministic results");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_CHAOS");
