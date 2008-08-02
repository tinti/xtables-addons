/*
 *	"ECHO" (RFC 862) target extension for Xtables
 *	Sample module for "Writing your own Netfilter Modules"
 *	Copyright © Jan Engelhardt <jengelh [at] medozas de>, 2008
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */

#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/netfilter/x_tables.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#	include <linux/netfilter_bridge.h>
#endif
#include <net/ip.h>
#include "compat_xtables.h"

static unsigned int echo_tg4(struct sk_buff *oldskb,
    const struct net_device *in, const struct net_device *out,
    unsigned int hooknum, const struct xt_target *target, const void *targinfo)
{
	const struct udphdr *oldudp;
	const struct iphdr *oldip;
	struct udphdr *newudp, oldudp_buf;
	struct iphdr *newip;
	struct sk_buff *newskb;
	unsigned int addr_type, data_len;
	void *payload;

	/* This allows us to do the copy operation in fewer lines of code. */
	if (skb_linearize(oldskb) < 0)
		return NF_DROP;

	oldip  = ip_hdr(oldskb);
	oldudp = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
	         sizeof(struct udphdr), &oldudp_buf);
	if (oldudp == NULL)
		return NF_DROP;
	if (ntohs(oldudp->len) <= sizeof(struct udphdr))
		return NF_DROP;

	newskb = alloc_skb(LL_MAX_HEADER + sizeof(struct iphdr) +
	         ntohs(oldudp->len), GFP_ATOMIC);
	if (newskb == NULL)
		return NF_DROP;

	skb_reserve(newskb, LL_MAX_HEADER);
	skb_reset_network_header(newskb);
	newip = (void *)skb_put(newskb, sizeof(struct iphdr));
	newip->version  = 4;
	newip->ihl      = sizeof(struct iphdr) / 4;
	newip->tos      = oldip->tos;
	newip->id       = 0;
	newip->frag_off = htons(IP_DF);
	newip->protocol = oldip->protocol;
	newip->check    = 0;
	newip->saddr    = oldip->daddr;
	newip->daddr    = oldip->saddr;

	newudp = (void *)skb_put(newskb, sizeof(struct udphdr));
	newudp->source = oldudp->dest;
	newudp->dest   = oldudp->source;
	newudp->len    = oldudp->len;
	newudp->check  = 0;

	data_len = htons(oldudp->len) - sizeof(*oldudp);
	payload  = skb_header_pointer(oldskb, ip_hdrlen(oldskb) +
	           sizeof(*oldudp), data_len, NULL);
	memcpy(skb_put(newskb, data_len), payload, data_len);

	addr_type = RTN_UNSPEC;
#ifdef CONFIG_BRIDGE_NETFILTER
	if (hooknum != NF_INET_FORWARD || (newskb->nf_bridge != NULL &&
	    newskb->nf_bridge->mask & BRNF_BRIDGED))
#else
	if (hooknum != NF_INET_FORWARD)
#endif
		addr_type = RTN_LOCAL;

	/* ip_route_me_harder expects skb->dst to be set */
	dst_hold(oldskb->dst);
	newskb->dst = oldskb->dst;

	if (ip_route_me_harder(newskb, addr_type) < 0)
		goto free_nskb;

	newip->ttl        = dst_metric(newskb->dst, RTAX_HOPLIMIT);
	newskb->ip_summed = CHECKSUM_NONE;

	/* "Never happens" (?) */
	if (newskb->len > dst_mtu(newskb->dst))
		goto free_nskb;

	nf_ct_attach(newskb, oldskb);
	ip_local_out(newskb);
	return NF_DROP;

 free_nskb:
	kfree_skb(newskb);
	return NF_DROP;
}

static struct xt_target echo_tg_reg __read_mostly = {
	.name       = "ECHO",
	.revision   = 0,
	.family     = AF_INET,
	.proto      = IPPROTO_UDP,
	.table      = "filter",
	.target     = echo_tg4,
	.targetsize = XT_ALIGN(0),
	.me         = THIS_MODULE,
};

static int __init echo_tg_init(void)
{
	return xt_register_target(&echo_tg_reg);
}

static void __exit echo_tg_exit(void)
{
	return xt_unregister_target(&echo_tg_reg);
}

module_init(echo_tg_init);
module_exit(echo_tg_exit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@computergmbh.de>");
MODULE_DESCRIPTION("Xtables: ECHO diagnosis target");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_ECHO");
