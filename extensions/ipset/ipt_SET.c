/* Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 *                         Martin Josefsson <gandalf@wlug.westbo.se>
 * Copyright (C) 2003-2004 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* ipt_SET.c - netfilter target to manipulate IP sets */

#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include <linux/netfilter_ipv4.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#include <linux/netfilter_ipv4/ip_tables.h>
#define xt_register_target	ipt_register_target
#define xt_unregister_target	ipt_unregister_target
#define xt_target		ipt_target
#define XT_CONTINUE		IPT_CONTINUE
#else
#include <linux/netfilter/x_tables.h>
#endif
#include "ipt_set.h"
#include "../compat_xtables.h"

static unsigned int
target(struct sk_buff **pskb, const struct xt_target_param *par)
{
	const struct ipt_set_info_target *info = par->targinfo;

	if (info->add_set.index != IP_SET_INVALID_ID)
		ip_set_addip_kernel(info->add_set.index,
				    *pskb,
				    info->add_set.flags);
	if (info->del_set.index != IP_SET_INVALID_ID)
		ip_set_delip_kernel(info->del_set.index,
				    *pskb,
				    info->del_set.flags);

	return XT_CONTINUE;
}

static bool
checkentry(const struct xt_tgchk_param *par)
{
	struct ipt_set_info_target *info = par->targinfo;
	ip_set_id_t index;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
	if (targinfosize != IPT_ALIGN(sizeof(*info))) {
		DP("bad target info size %u", targinfosize);
		return 0;
	}
#endif

	if (info->add_set.index != IP_SET_INVALID_ID) {
		index = ip_set_get_byindex(info->add_set.index);
		if (index == IP_SET_INVALID_ID) {
			ip_set_printk("cannot find add_set index %u as target",
				      info->add_set.index);
			return 0;	/* error */
		}
	}

	if (info->del_set.index != IP_SET_INVALID_ID) {
		index = ip_set_get_byindex(info->del_set.index);
		if (index == IP_SET_INVALID_ID) {
			ip_set_printk("cannot find del_set index %u as target",
				      info->del_set.index);
			return 0;	/* error */
		}
	}
	if (info->add_set.flags[IP_SET_MAX_BINDINGS] != 0
	    || info->del_set.flags[IP_SET_MAX_BINDINGS] != 0) {
		ip_set_printk("That's nasty!");
		return 0;	/* error */
	}

	return 1;
}

static void destroy(const struct xt_tgdtor_param *par)
{
	struct ipt_set_info_target *info = par->targinfo;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
	if (targetsize != IPT_ALIGN(sizeof(struct ipt_set_info_target))) {
		ip_set_printk("invalid targetsize %d", targetsize);
		return;
	}
#endif
	if (info->add_set.index != IP_SET_INVALID_ID)
		ip_set_put_byindex(info->add_set.index);
	if (info->del_set.index != IP_SET_INVALID_ID)
		ip_set_put_byindex(info->del_set.index);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
static struct xt_target SET_target = {
	.name 		= "SET",
	.target 	= target,
	.checkentry 	= checkentry,
	.destroy 	= destroy,
	.me 		= THIS_MODULE
};
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17) */
static struct xt_target SET_target = {
	.name 		= "SET",
	.family		= AF_INET,
	.target 	= target,
	.targetsize	= sizeof(struct ipt_set_info_target),
	.checkentry 	= checkentry,
	.destroy 	= destroy,
	.me 		= THIS_MODULE
};
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
MODULE_DESCRIPTION("iptables IP set target module");

static int __init ipt_SET_init(void)
{
	return xt_register_target(&SET_target);
}

static void __exit ipt_SET_fini(void)
{
	xt_unregister_target(&SET_target);
}

module_init(ipt_SET_init);
module_exit(ipt_SET_fini);
