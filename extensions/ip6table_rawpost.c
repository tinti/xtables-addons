/*
 *	rawpost table for ip6_tables
 *	written by Jan Engelhardt <jengelh [at] medozas de>, 2008 - 2009
 *	placed in the Public Domain
 */
#include <linux/module.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/ip.h>
#include "compat_xtables.h"
#include "compat_rawpost.h"

enum {
	RAWPOST_VALID_HOOKS = 1 << NF_INET_POST_ROUTING,
};

static struct {
	struct ip6t_replace repl;
	struct ip6t_standard entries[1];
	struct ip6t_error term;
} rawpost6_initial __initdata = {
	.repl = {
		.name        = "rawpost",
		.valid_hooks = RAWPOST_VALID_HOOKS,
		.num_entries = 2,
		.size        = sizeof(struct ip6t_standard) +
		               sizeof(struct ip6t_error),
		.hook_entry  = {
			[NF_INET_POST_ROUTING] = 0,
		},
		.underflow = {
			[NF_INET_POST_ROUTING] = 0,
		},
	},
	.entries = {
		IP6T_STANDARD_INIT(NF_ACCEPT),	/* POST_ROUTING */
	},
	.term = IP6T_ERROR_INIT,		/* ERROR */
};

static struct xt_table *rawpost6_ptable;

static struct xt_table rawpost6_itable = {
	.name        = "rawpost",
	.af          = NFPROTO_IPV6,
	.valid_hooks = RAWPOST_VALID_HOOKS,
	.me          = THIS_MODULE,
};

static unsigned int rawpost6_hook_fn(unsigned int hook, sk_buff_t *skb,
    const struct net_device *in, const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
	return ip6t_do_table(skb, hook, in, out, rawpost6_ptable);
#else
	return ip6t_do_table(skb, hook, in, out, rawpost6_ptable, NULL);
#endif
}

static struct nf_hook_ops rawpost6_hook_ops __read_mostly = {
	.hook     = rawpost6_hook_fn,
	.pf       = NFPROTO_IPV6,
	.hooknum  = NF_INET_POST_ROUTING,
	.priority = NF_IP6_PRI_LAST,
	.owner    = THIS_MODULE,
};

static int __init rawpost6_table_init(void)
{
	int ret;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 29)
	rwlock_init(&rawpost6_itable.lock);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	rawpost6_ptable = ip6t_register_table(&init_net, &rawpost6_itable,
	                  &rawpost6_initial.repl);
	if (IS_ERR(rawpost6_ptable))
		return PTR_ERR(rawpost6_ptable);
#else
	ret = ip6t_register_table(&rawpost6_itable, &rawpost6_initial.repl);
	if (ret < 0)
		return ret;
	rawpost6_ptable = &rawpost6_itable;
#endif

	ret = nf_register_hook(&rawpost6_hook_ops);
	if (ret < 0)
		goto out;

	return ret;

 out:
	ip6t_unregister_table(rawpost6_ptable);
	return ret;
}

static void __exit rawpost6_table_exit(void)
{
	nf_unregister_hook(&rawpost6_hook_ops);
	ip6t_unregister_table(rawpost6_ptable);
}

module_init(rawpost6_table_init);
module_exit(rawpost6_table_exit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_LICENSE("GPL");
