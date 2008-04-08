/*
 *	xt_LOGMARK - netfilter mark logging
 *	useful for debugging
 *
 *	Copyright © CC Computer Consultants, 2007 - 2008
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	version 2 or 3 as published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/x_tables.h>
//#include <net/netfilter/nf_conntrack.h>
#include "compat_xtables.h"
#include "xt_LOGMARK.h"

static const char *const hook_names[] = {
	[NF_INET_PRE_ROUTING]  = "PREROUTING",
	[NF_INET_LOCAL_IN]     = "INPUT",
	[NF_INET_FORWARD]      = "FORWARD",
	[NF_INET_LOCAL_OUT]    = "OUTPUT",
	[NF_INET_POST_ROUTING] = "POSTROUTING",
};

static const char *const dir_names[] = {
	"ORIGINAL", "REPLY",
};

static unsigned int
logmark_tg(struct sk_buff *skb, const struct net_device *in,
           const struct net_device *out, unsigned int hooknum,
           const struct xt_target *target, const void *targinfo)
{
	const struct xt_logmark_tginfo *info = targinfo;
	const struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	printk("<%u>%.*s""hook=%s nfmark=0x%x secmark=0x%x classify=0x%x",
	       info->level, (unsigned int)sizeof(info->prefix), info->prefix,
	       hook_names[hooknum],
	       skb_nfmark(skb), skb->secmark, skb->priority);

	ct = nf_ct_get(skb, &ctinfo);
	printk(" ctdir=%s", dir_names[ctinfo >= IP_CT_IS_REPLY]);
	if (ct == NULL) {
		printk(" ct=NULL ctmark=NULL ctstate=INVALID ctstatus=NONE");
	} else if (ct == &nf_conntrack_untracked) {
		printk(" ct=UNTRACKED ctmark=NULL ctstate=UNTRACKED ctstatus=NONE");
	} else {
		printk(" ct=0x%p ctmark=0x%x ctstate=", ct, ct->mark);
		ctinfo %= IP_CT_IS_REPLY;
		if (ctinfo == IP_CT_NEW)
			printk("NEW");
		else if (ctinfo == IP_CT_ESTABLISHED)
			printk("ESTABLISHED");
		else if (ctinfo == IP_CT_RELATED)
			printk("RELATED");
		if (test_bit(IPS_SRC_NAT_BIT, &ct->status))
			printk(",SNAT");
		if (test_bit(IPS_DST_NAT_BIT, &ct->status))
			printk(",DNAT");

		printk(" ctstatus=");
		if (ct->status & IPS_EXPECTED)
			printk("EXPECTED");
		if (ct->status & IPS_SEEN_REPLY)
			printk(",SEEN_REPLY");
		if (ct->status & IPS_ASSURED)
			printk(",ASSURED");
		if (ct->status & IPS_CONFIRMED)
			printk(",CONFIRMED");
	}

	printk("\n");
	return XT_CONTINUE;
}

static bool
logmark_tg_check(const char *tablename, const void *e,
                 const struct xt_target *target, void *targinfo,
                 unsigned int hook_mask)
{
	const struct xt_logmark_tginfo *info = targinfo;

	if (info->level >= 8) {
		pr_debug("LOGMARK: level %u >= 8\n", info->level);
		return false;
	}

	return true;
}

static struct xt_target logmark_tg_reg[] __read_mostly = {
	{
		.name       = "LOGMARK",
		.revision   = 0,
		.family     = AF_INET,
		.checkentry = logmark_tg_check,
		.target     = logmark_tg,
		.targetsize = sizeof(struct xt_logmark_tginfo),
		.me         = THIS_MODULE,
	},
	{
		.name       = "LOGMARK",
		.revision   = 0,
		.family     = AF_INET6,
		.checkentry = logmark_tg_check,
		.target     = logmark_tg,
		.targetsize = sizeof(struct xt_logmark_tginfo),
		.me         = THIS_MODULE,
	},
};

static int __init logmark_tg_init(void)
{
	return xt_register_targets(logmark_tg_reg, ARRAY_SIZE(logmark_tg_reg));
}

static void __exit logmark_tg_exit(void)
{
	xt_unregister_targets(logmark_tg_reg, ARRAY_SIZE(logmark_tg_reg));
}

module_init(logmark_tg_init);
module_exit(logmark_tg_exit);
MODULE_DESCRIPTION("Xtables: netfilter mark logging to syslog");
MODULE_AUTHOR("Jan Engelhardt <jengelh@computergmbh.de>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_LOGMARK");
MODULE_ALIAS("ip6t_LOGMARK");
