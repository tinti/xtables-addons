#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/ip.h>
#include <net/checksum.h>

#include <linux/netfilter/x_tables.h>
#include "xt_IPMARK.h"
#include "compat_xtables.h"

MODULE_AUTHOR("Grzegorz Janoszka <Grzegorz@Janoszka.pl>");
MODULE_DESCRIPTION("IP tables IPMARK: mark based on ip address");
MODULE_LICENSE("GPL");

static unsigned int
ipmark_tg(struct sk_buff *skb,
       const struct net_device *in,
       const struct net_device *out,
       unsigned int hooknum,
       const struct xt_target *target,
       const void *targinfo)
{
	const struct ipt_ipmark_target_info *ipmarkinfo = targinfo;
	struct iphdr *iph = ip_hdr(skb);
	unsigned long mark;

	if (ipmarkinfo->addr == IPT_IPMARK_SRC)
		mark = (unsigned long) ntohl(iph->saddr);
	else
		mark = (unsigned long) ntohl(iph->daddr);

	mark &= ipmarkinfo->andmask;
	mark |= ipmarkinfo->ormask;

	skb_nfmark(skb) = mark;
	return XT_CONTINUE;
}

static struct xt_target ipt_ipmark_reg = {
	.name		= "IPMARK",
	.family		= AF_INET,
	.table		= "mangle",
	.target		= ipmark_tg,
	.targetsize	= sizeof(struct ipt_ipmark_target_info),
	.me		= THIS_MODULE
};

static int __init ipmark_tg_init(void)
{
	return xt_register_target(&ipt_ipmark_reg);
}

static void __exit ipmark_tg_exit(void)
{
	xt_unregister_target(&ipt_ipmark_reg);
}

module_init(ipmark_tg_init);
module_exit(ipmark_tg_exit);
