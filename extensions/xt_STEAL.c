/*
 *	"STEAL" demo target extension for Xtables
 *	written by Jan Engelhardt <jengelh [at] medozas de>, 2008 - 2009
 *	placed in the Public Domain
 */
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include "compat_xtables.h"

static unsigned int
steal_tg(struct sk_buff **pskb, const struct xt_action_param *par)
{
	kfree_skb(*pskb);
	return NF_STOLEN;
}

static struct xt_target steal_tg_reg[] __read_mostly = {
	{
		.name     = "STEAL",
		.revision = 0,
		.family   = NFPROTO_UNSPEC,
		.target   = steal_tg,
		.me       = THIS_MODULE,
	},
	{
		.name     = "STEAL",
		.revision = 0,
		.family   = NFPROTO_IPV6,
		.target   = steal_tg,
		.me       = THIS_MODULE,
	},
	{
		.name     = "STEAL",
		.revision = 0,
		.family   = NFPROTO_ARP,
		.target   = steal_tg,
		.me       = THIS_MODULE,
	},
	{
		.name     = "STEAL",
		.revision = 0,
		.family   = NFPROTO_BRIDGE,
		.target   = steal_tg,
		.me       = THIS_MODULE,
	},
};

static int __init steal_tg_init(void)
{
	return xt_register_targets(steal_tg_reg, ARRAY_SIZE(steal_tg_reg));
}

static void __exit steal_tg_exit(void)
{
	xt_unregister_targets(steal_tg_reg, ARRAY_SIZE(steal_tg_reg));
}

module_init(steal_tg_init);
module_exit(steal_tg_exit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_DESCRIPTION("Xtables: Silently DROP packets on output chain");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_STEAL");
MODULE_ALIAS("ip6t_STEAL");
MODULE_ALIAS("arpt_STEAL");
MODULE_ALIAS("ebt_STEAL");
