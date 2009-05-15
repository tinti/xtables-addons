/*
 *	rawpost table for ip_tables
 *	written by Jan Engelhardt <jengelh [at] medozas de>, 2008 - 2009
 *	placed in the Public Domain
 */
#include <linux/module.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/version.h>
#include <net/ip.h>
#include "compat_xtables.h"
#include "compat_rawpost.h"

enum {
	RAWPOST_VALID_HOOKS = 1 << NF_INET_POST_ROUTING,
};

static struct {
	struct ipt_replace repl;
	struct ipt_standard entries[1];
	struct ipt_error term;
} rawpost4_initial __initdata = {
	.repl = {
		.name        = "rawpost",
		.valid_hooks = RAWPOST_VALID_HOOKS,
		.num_entries = 2,
		.size        = sizeof(struct ipt_standard) +
		               sizeof(struct ipt_error),
		.hook_entry  = {
			[NF_INET_POST_ROUTING] = 0,
		},
		.underflow = {
			[NF_INET_POST_ROUTING] = 0,
		},
	},
	.entries = {
		IPT_STANDARD_INIT(NF_ACCEPT),	/* POST_ROUTING */
	},
	.term = IPT_ERROR_INIT,			/* ERROR */
};

static struct xt_table *rawpost4_ptable;

static struct xt_table rawpost4_itable = {
	.name        = "rawpost",
	.af          = NFPROTO_IPV4,
	.valid_hooks = RAWPOST_VALID_HOOKS,
	.me          = THIS_MODULE,
};

static unsigned int rawpost4_hook_fn(unsigned int hook, sk_buff_t *skb,
    const struct net_device *in, const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
	return ipt_do_table(skb, hook, in, out, rawpost4_ptable);
#else
	return ipt_do_table(skb, hook, in, out, rawpost4_ptable, NULL);
#endif
}

static struct nf_hook_ops rawpost4_hook_ops __read_mostly = {
	.hook     = rawpost4_hook_fn,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_LAST,
	.owner    = THIS_MODULE,
};

static int __init rawpost4_table_init(void)
{
	int ret;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 29)
	rwlock_init(&rawpost4_itable.lock);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	rawpost4_ptable = ipt_register_table(&init_net, &rawpost4_itable,
	                  &rawpost4_initial.repl);
	if (IS_ERR(rawpost4_ptable))
		return PTR_ERR(rawpost4_ptable);
#else
	ret = ipt_register_table(&rawpost4_itable, &rawpost4_initial.repl);
	if (ret < 0)
		return ret;
	rawpost4_ptable = &rawpost4_itable;
#endif

	ret = nf_register_hook(&rawpost4_hook_ops);
	if (ret < 0)
		goto out;

	return ret;

 out:
	ipt_unregister_table(rawpost4_ptable);
	return ret;
}

static void __exit rawpost4_table_exit(void)
{
	nf_unregister_hook(&rawpost4_hook_ops);
	ipt_unregister_table(rawpost4_ptable);
}

module_init(rawpost4_table_init);
module_exit(rawpost4_table_exit);
MODULE_DESCRIPTION("Xtables: rawpost table for use with RAWNAT");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_LICENSE("GPL");
