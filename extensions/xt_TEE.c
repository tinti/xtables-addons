/*
 *	"TEE" target extension for Xtables
 *	Copyright © Sebastian Claßen <sebastian.classen [at] freenet de>, 2007
 *	Jan Engelhardt <jengelh [at] medozas de>, 2007 - 2008
 *
 *	based on ipt_ROUTE.c from Cédric de Launois
 *	<delaunois [at] info ucl ac be>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	version 2, as published by the Free Software Foundation.
 */
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/route.h>
#include <linux/skbuff.h>
#include <net/checksum.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <linux/netfilter/x_tables.h>

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#	define WITH_CONNTRACK 1
#	include <net/netfilter/nf_conntrack.h>
static struct nf_conn tee_track;
#endif
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#	define WITH_IPV6 1
#endif

#include "compat_xtables.h"
#include "xt_TEE.h"

static const union nf_inet_addr tee_zero_address;

/*
 * Try to route the packet according to the routing keys specified in
 * route_info. Keys are :
 *  - ifindex :
 *      0 if no oif preferred,
 *      otherwise set to the index of the desired oif
 *  - route_info->gateway :
 *      0 if no gateway specified,
 *      otherwise set to the next host to which the pkt must be routed
 * If success, skb->dev is the output device to which the packet must
 * be sent and skb->dst is not NULL
 *
 * RETURN: false - if an error occured
 *         true  - if the packet was succesfully routed to the
 *                 destination desired
 */
static bool
tee_tg_route4(struct sk_buff *skb, const struct xt_tee_tginfo *info)
{
	const struct iphdr *iph = ip_hdr(skb);
	int err;
	struct rtable *rt;
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	fl.iif  = skb->iif;
	fl.mark = skb->mark;
	fl.nl_u.ip4_u.daddr = info->gw.ip;
	fl.nl_u.ip4_u.tos   = RT_TOS(iph->tos);
	fl.nl_u.ip4_u.scope = RT_SCOPE_UNIVERSE;

	/* Trying to route the packet using the standard routing table. */
	err = ip_route_output_key(&init_net, &rt, &fl);
	if (err != 0) {
		if (net_ratelimit())
			pr_debug(KBUILD_MODNAME
			         ": could not route packet (%d)", err);
		return false;
	}

	dst_release(skb->dst);
	skb->dst      = &rt->u.dst;
	skb->dev      = skb->dst->dev;
	skb->protocol = htons(ETH_P_IP);
	return true;
}

static inline bool dev_hh_avail(const struct net_device *dev)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
	return dev->hard_header != NULL;
#else
	return dev->header_ops != NULL;
#endif
}

/*
 * Stolen from ip_finish_output2
 * PRE : skb->dev is set to the device we are leaving by
 *       skb->dst is not NULL
 * POST: the packet is sent with the link layer header pushed
 *       the packet is destroyed
 */
static void tee_tg_send(struct sk_buff *skb)
{
	const struct dst_entry *dst  = skb->dst;
	const struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);

	/* Be paranoid, rather than too clever. */
	if (unlikely(skb_headroom(skb) < hh_len && dev_hh_avail(dev))) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (skb2 == NULL) {
			kfree_skb(skb);
			return;
		}
		if (skb->sk != NULL)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
	}

	if (dst->hh != NULL) {
		neigh_hh_output(dst->hh, skb);
	} else if (dst->neighbour != NULL) {
		dst->neighbour->output(skb);
	} else {
		if (net_ratelimit())
			pr_debug(KBUILD_MODNAME "no hdr & no neighbour cache!\n");
		kfree_skb(skb);
	}
}

/*
 * To detect and deter routed packet loopback when using the --tee option, we
 * take a page out of the raw.patch book: on the copied skb, we set up a fake
 * ->nfct entry, pointing to the local &route_tee_track. We skip routing
 * packets when we see they already have that ->nfct.
 */
static unsigned int
tee_tg4(struct sk_buff **pskb, const struct xt_target_param *par)
{
	const struct xt_tee_tginfo *info = par->targinfo;
	struct sk_buff *skb = *pskb;

#ifdef WITH_CONNTRACK
	if (skb->nfct == &tee_track.ct_general) {
		/*
		 * Loopback - a packet we already routed, is to be
		 * routed another time. Avoid that, now.
		 */
		if (net_ratelimit())
			pr_debug(KBUILD_MODNAME "loopback - DROP!\n");
		return NF_DROP;
	}
#endif

	if (!skb_make_writable(pskb, sizeof(struct iphdr)))
		return NF_DROP;
	skb = *pskb;

	/*
	 * If we are in INPUT, the checksum must be recalculated since
	 * the length could have changed as a result of defragmentation.
	 */
	if (par->hooknum == NF_INET_LOCAL_IN) {
		struct iphdr *iph = ip_hdr(skb);
		iph->check = 0;
		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
	}

	/*
	 * Copy the skb, and route the copy. Will later return %XT_CONTINUE for
	 * the original skb, which should continue on its way as if nothing has
	 * happened. The copy should be independantly delivered to the TEE --gw.
	 */
	skb = skb_copy(skb, GFP_ATOMIC);
	if (skb == NULL) {
		if (net_ratelimit())
			pr_debug(KBUILD_MODNAME "copy failed!\n");
		return XT_CONTINUE;
	}

#ifdef WITH_CONNTRACK
	/*
	 * Tell conntrack to forget this packet since it may get confused
	 * when a packet is leaving with dst address == our address.
	 * Good idea? Dunno. Need advice.
	 *
	 * NEW: mark the skb with our &tee_track, so we avoid looping
	 * on any already routed packet.
	 */
	nf_conntrack_put(skb->nfct);
	skb->nfct     = &tee_track.ct_general;
	skb->nfctinfo = IP_CT_NEW;
	nf_conntrack_get(skb->nfct);
#endif

	/*
	 * Normally, we would just use ip_local_out. Because iph->check is
	 * already correct, we could take a shortcut and call dst_output
	 * [forwards to ip_output] directly. ip_output however will invoke
	 * Netfilter hooks and cause reentrancy. So we skip that too and go
	 * directly to ip_finish_output. Since we should not do XFRM, control
	 * passes to ip_finish_output2. That function is not exported, so it is
	 * copied here as tee_ip_direct_send.
	 *
	 * We do no XFRM on the cloned packet on purpose! The choice of
	 * iptables match options will control whether the raw packet or the
	 * transformed version is cloned.
	 *
	 * Also on purpose, no fragmentation is done, to preserve the
	 * packet as best as possible.
	 */
	if (tee_tg_route4(skb, info))
		tee_tg_send(skb);

	return XT_CONTINUE;
}

#ifdef WITH_IPV6
static bool
tee_tg_route6(struct sk_buff *skb, const struct xt_tee_tginfo *info)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	struct dst_entry *dst;
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	fl.iif  = skb->iif;
	fl.mark = skb->mark;
	fl.nl_u.ip6_u.daddr = info->gw.in6;
	fl.nl_u.ip6_u.flowlabel = ((iph->flow_lbl[0] & 0xF) << 16) |
		(iph->flow_lbl[1] << 8) | iph->flow_lbl[2];

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 25)
	dst = ip6_route_output(NULL, &fl);
#else
	dst = ip6_route_output(dev_net(skb->dev), NULL, &fl);
#endif
	if (dst == NULL) {
		if (net_ratelimit())
			printk(KERN_ERR "ip6_route_output failed for tee\n");
		return false;
	}

	dst_release(skb->dst);
	skb->dst      = dst;
	skb->dev      = skb->dst->dev;
	skb->protocol = htons(ETH_P_IPV6);
	return true;
}

static unsigned int
tee_tg6(struct sk_buff **pskb, const struct xt_target_param *par)
{
	const struct xt_tee_tginfo *info = par->targinfo;
	struct sk_buff *skb = *pskb;

	/* Try silence. */
#ifdef WITH_CONNTRACK
	if (skb->nfct == &tee_track.ct_general)
		return NF_DROP;
#endif

	if ((skb = skb_copy(skb, GFP_ATOMIC)) == NULL)
		return XT_CONTINUE;

#ifdef WITH_CONNTRACK
	nf_conntrack_put(skb->nfct);
	skb->nfct     = &tee_track.ct_general;
	skb->nfctinfo = IP_CT_NEW;
	nf_conntrack_get(skb->nfct);
#endif
	if (tee_tg_route6(skb, info))
		tee_tg_send(skb);

	return XT_CONTINUE;
}
#endif /* WITH_IPV6 */

static bool tee_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_tee_tginfo *info = par->targinfo;

	/* 0.0.0.0 and :: not allowed */
	return memcmp(&info->gw, &tee_zero_address,
	       sizeof(tee_zero_address)) != 0;
}

static struct xt_target tee_tg_reg[] __read_mostly = {
	{
		.name       = "TEE",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.table      = "mangle",
		.target     = tee_tg4,
		.targetsize = sizeof(struct xt_tee_tginfo),
		.checkentry = tee_tg_check,
		.me         = THIS_MODULE,
	},
#ifdef WITH_IPV6
	{
		.name       = "TEE",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.table      = "mangle",
		.target     = tee_tg6,
		.targetsize = sizeof(struct xt_tee_tginfo),
		.checkentry = tee_tg_check,
		.me         = THIS_MODULE,
	},
#endif
};

static int __init tee_tg_init(void)
{
#ifdef WITH_CONNTRACK
	/*
	 * Set up fake conntrack (stolen from raw.patch):
	 * - to never be deleted, not in any hashes
	 */
	atomic_set(&tee_track.ct_general.use, 1);

	/* - and look it like as a confirmed connection */
	set_bit(IPS_CONFIRMED_BIT, &tee_track.status);

	/* Initialize fake conntrack so that NAT will skip it */
	tee_track.status |= IPS_NAT_DONE_MASK;
#endif

	return xt_register_targets(tee_tg_reg, ARRAY_SIZE(tee_tg_reg));
}

static void __exit tee_tg_exit(void)
{
	xt_unregister_targets(tee_tg_reg, ARRAY_SIZE(tee_tg_reg));
	/* [SC]: shoud not we cleanup tee_track here? */
}

module_init(tee_tg_init);
module_exit(tee_tg_exit);
MODULE_AUTHOR("Sebastian Claßen <sebastian.classen@freenet.ag>");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_DESCRIPTION("Xtables: Reroute packet copy");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_TEE");
MODULE_ALIAS("ip6t_TEE");
