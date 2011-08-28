/*
 *	"CHAOS" target extension for Xtables
 *	Copyright © Jan Engelhardt <jengelh [at] medozas de>, 2006 - 2008
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/stat.h>
#include <linux/version.h>
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
static void
xt_chaos_total(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_chaos_tginfo *info = par->targinfo;
	const struct iphdr *iph = ip_hdr(skb);
	const int thoff         = 4 * iph->ihl;
	const int fragoff       = ntohs(iph->frag_off) & IP_OFFSET;
	typeof(xt_tarpit) destiny;
	bool ret;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
	int hotdrop = false;
#else
	bool hotdrop = false;
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
	ret = xm_tcp->match(skb, par->in, par->out, xm_tcp, &tcp_params,
	                    fragoff, thoff, &hotdrop);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
	{
		struct xt_match_param local_par = {
			.in        = par->in,
			.out       = par->out,
			.match     = xm_tcp,
			.matchinfo = &tcp_params,
			.fragoff   = fragoff,
			.thoff     = thoff,
			.hotdrop   = &hotdrop,
		};
		ret = xm_tcp->match(skb, &local_par);
	}
#else
	{
		struct xt_action_param local_par;
		local_par.in        = par->in,
		local_par.out       = par->out,
		local_par.match     = xm_tcp;
		local_par.matchinfo = &tcp_params;
		local_par.fragoff   = fragoff;
		local_par.thoff     = thoff;
		local_par.hotdrop   = false;
		ret = xm_tcp->match(skb, &local_par);
		hotdrop = local_par.hotdrop;
	}
#endif
	if (!ret || hotdrop || (unsigned int)net_random() > delude_percentage)
		return;

	destiny = (info->variant == XTCHAOS_TARPIT) ? xt_tarpit : xt_delude;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
	destiny->target(&skb, par->in, par->out, par->hooknum, destiny, NULL, NULL);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
	destiny->target(&skb, par->in, par->out, par->hooknum, destiny, NULL);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
	destiny->target(skb, par->in, par->out, par->hooknum, destiny, NULL);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
	{
		struct xt_target_param local_par = {
			.in       = par->in,
			.out      = par->out,
			.hooknum  = par->hooknum,
			.target   = destiny,
			.targinfo = par->targinfo,
			.family   = par->family,
		};
		destiny->target(skb, &local_par);
	}
#else
	{
		struct xt_action_param local_par;
		local_par.in       = par->in;
		local_par.out      = par->out;
		local_par.hooknum  = par->hooknum;
		local_par.target   = destiny;
		local_par.targinfo = par->targinfo;
		local_par.family   = par->family;
		destiny->target(skb, &local_par);
	}
#endif
}

static unsigned int
chaos_tg(struct sk_buff **pskb, const struct xt_action_param *par)
{
	/*
	 * Equivalent to:
	 * -A chaos -m statistic --mode random --probability \
	 *         $reject_percentage -j REJECT --reject-with host-unreach;
	 * -A chaos -p tcp -m statistic --mode random --probability \
	 *         $delude_percentage -j DELUDE;
	 * -A chaos -j DROP;
	 */
	const struct xt_chaos_tginfo *info = par->targinfo;
	struct sk_buff *skb = *pskb;
	const struct iphdr *iph = ip_hdr(skb);

	if ((unsigned int)net_random() <= reject_percentage) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
		return xt_reject->target(pskb, par->in, par->out, par->hooknum,
		       xt_reject, &reject_params, NULL);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
		return xt_reject->target(pskb, par->in, par->out, par->hooknum,
		       xt_reject, &reject_params);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
		return xt_reject->target(skb, par->in, par->out, par->hooknum,
		       xt_reject, &reject_params);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
		struct xt_target_param local_par = {
			.in       = par->in,
			.out      = par->out,
			.hooknum  = par->hooknum,
			.target   = xt_reject,
			.targinfo = &reject_params,
		};
		return xt_reject->target(skb, &local_par);
#else
		struct xt_action_param local_par;
		local_par.in       = par->in;
		local_par.out      = par->out;
		local_par.hooknum  = par->hooknum;
		local_par.target   = xt_reject;
		local_par.targinfo = &reject_params;
		return xt_reject->target(skb, &local_par);
#endif
	}

	/* TARPIT/DELUDE may not be called from the OUTPUT chain */
	if (iph->protocol == IPPROTO_TCP &&
	    info->variant != XTCHAOS_NORMAL &&
	    par->hooknum != NF_INET_LOCAL_OUT)
		xt_chaos_total(skb, par);

	return NF_DROP;
}

static int chaos_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_chaos_tginfo *info = par->targinfo;

	if (info->variant == XTCHAOS_DELUDE && !have_delude) {
		printk(KERN_WARNING PFX "Error: Cannot use --delude when "
		       "DELUDE module not available\n");
		return -EINVAL;
	}
	if (info->variant == XTCHAOS_TARPIT && !have_tarpit) {
		printk(KERN_WARNING PFX "Error: Cannot use --tarpit when "
		       "TARPIT module not available\n");
		return -EINVAL;
	}

	return 0;
}

static struct xt_target chaos_tg_reg = {
	.name       = "CHAOS",
	.revision   = 0,
	.family     = NFPROTO_IPV4,
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

	xm_tcp = xt_request_find_match(NFPROTO_IPV4, "tcp", 0);
	if (xm_tcp == NULL) {
		printk(KERN_WARNING PFX "Error: Could not find or load "
		       "\"tcp\" match\n");
		return -EINVAL;
	}

	xt_reject = xt_request_find_target(NFPROTO_IPV4, "REJECT", 0);
	if (xt_reject == NULL) {
		printk(KERN_WARNING PFX "Error: Could not find or load "
		       "\"REJECT\" target\n");
		goto out2;
	}

	xt_tarpit   = xt_request_find_target(NFPROTO_IPV4, "TARPIT", 0);
	have_tarpit = xt_tarpit != NULL;
	if (!have_tarpit)
		printk(KERN_WARNING PFX "Warning: Could not find or load "
		       "\"TARPIT\" target\n");

	xt_delude   = xt_request_find_target(NFPROTO_IPV4, "DELUDE", 0);
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
}

module_init(chaos_tg_init);
module_exit(chaos_tg_exit);
MODULE_DESCRIPTION("Xtables: Network scan slowdown with non-deterministic results");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_CHAOS");
