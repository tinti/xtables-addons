/*
 *	"TARPIT" target extension to Xtables
 *	Kernel module to capture and hold incoming TCP connections using
 *	no local per-connection resources.
 *
 *	Copyright © Aaron Hopkins <tools [at] die net>, 2002
 *
 *	Based on ipt_REJECT.c and offering functionality similar to
 *	LaBrea <http://www.hackbusters.net/LaBrea/>.
 *
 *	<<<
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *	>>>
 *
 * Goal:
 * - Allow incoming TCP connections to be established.
 * - Passing data should result in the connection being switched to the
 *   persist state (0 byte window), in which the remote side stops sending
 *   data and asks to continue every 60 seconds.
 * - Attempts to shut down the connection should be ignored completely, so
 *   the remote side ends up having to time it out.
 *
 * This means:
 * - Reply to TCP SYN,!ACK,!RST,!FIN with SYN-ACK, window 5 bytes
 * - Reply to TCP SYN,ACK,!RST,!FIN with RST to prevent spoofing
 * - Reply to TCP !SYN,!RST,!FIN with ACK, window 0 bytes, rate-limited
 */

#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#	include <linux/netfilter_bridge.h>
#endif
#include <net/route.h>
#include <net/tcp.h>
#include "compat_xtables.h"

static void tarpit_tcp(struct sk_buff *oldskb, unsigned int hook)
{
	struct tcphdr _otcph, *oth, *tcph;
	unsigned int addr_type = RTN_UNSPEC;
	struct sk_buff *nskb;
	struct iphdr *niph;
	u_int16_t tmp;

	/* A truncated TCP header is not going to be useful */
	if (oldskb->len < ip_hdrlen(oldskb) + sizeof(struct tcphdr))
		return;

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
	                         sizeof(_otcph), &_otcph);
	if (oth == NULL)
		return;

	/* No replies for RST, FIN or !SYN,!ACK */
	if (oth->rst || oth->fin || (!oth->syn && !oth->ack))
		return;

	/* Rate-limit replies to !SYN,ACKs */
#if 0
	if (!oth->syn && oth->ack)
		if (!xrlim_allow(rt_dst(ort), HZ))
			return;
#endif

	/* Check checksum. */
	if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
		return;

	/*
	 * Copy skb (even if skb is about to be dropped, we cannot just
	 * clone it because there may be other things, such as tcpdump,
	 * interested in it)
	 */
	nskb = skb_copy_expand(oldskb, LL_MAX_HEADER,
	                       skb_tailroom(oldskb), GFP_ATOMIC);
	if (nskb == NULL)
		return;

	/* This packet will not be the same as the other: clear nf fields */
	nf_reset(nskb);
	skb_nfmark(nskb) = 0;
	skb_init_secmark(nskb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
	skb_shinfo(nskb)->gso_size = 0;
	skb_shinfo(nskb)->gso_segs = 0;
	skb_shinfo(nskb)->gso_type = 0;
#endif

	tcph = (struct tcphdr *)(skb_network_header(nskb) + ip_hdrlen(nskb));

	/* Swap source and dest */
	niph         = ip_hdr(nskb);
	niph->daddr  = xchg(&niph->saddr, niph->daddr);
	tmp          = tcph->source;
	tcph->source = tcph->dest;
	tcph->dest   = tmp;

	/* Truncate to length (no data) */
	tcph->doff    = sizeof(struct tcphdr) / 4;
	skb_trim(nskb, ip_hdrlen(nskb) + sizeof(struct tcphdr));
	niph->tot_len = htons(nskb->len);

	/* Use supplied sequence number or make a new one */
	tcph->seq = oth->ack ? oth->ack_seq : 0;

	/* Our SYN-ACKs must have a >0 window */
	tcph->window  = (oth->syn && !oth->ack) ? htons(5) : 0;
	tcph->urg_ptr = 0;

	/* Reset flags */
	((u_int8_t *)tcph)[13] = 0;

	if (oth->syn && oth->ack) {
		tcph->rst     = true;
		tcph->ack_seq = false;
	} else {
		tcph->syn     = oth->syn;
		tcph->ack     = 1;
		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn);
	}

	/* Adjust TCP checksum */
	tcph->check = 0;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
	tcph->check = tcp_v4_check(tcph, sizeof(struct tcphdr), niph->saddr,
	              niph->daddr, csum_partial((char *)tcph,
	              sizeof(struct tcphdr), 0));
#else
	tcph->check = tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
	              niph->daddr, csum_partial((char *)tcph,
	              sizeof(struct tcphdr), 0));
#endif

	/* Set DF, id = 0 */
	niph->frag_off = htons(IP_DF);
	niph->id       = 0;

#ifdef CONFIG_BRIDGE_NETFILTER
	if (hook != NF_INET_FORWARD || (nskb->nf_bridge != NULL &&
	    nskb->nf_bridge->mask & BRNF_BRIDGED))
#else
	if (hook != NF_INET_FORWARD)
#endif
		addr_type = RTN_LOCAL;

	if (ip_route_me_harder(&nskb, addr_type))
		goto free_nskb;
	else
		niph = ip_hdr(nskb);

	nskb->ip_summed = CHECKSUM_NONE;

	/* Adjust IP TTL */
	niph->ttl = dst_metric(skb_dst(nskb), RTAX_HOPLIMIT);

	/* Adjust IP checksum */
	niph->check = 0;
	niph->check = ip_fast_csum(skb_network_header(nskb), niph->ihl);

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

	NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_OUT, nskb, NULL,
		skb_dst(nskb)->dev, dst_output);
	return;

 free_nskb:
	kfree_skb(nskb);
}

static unsigned int
tarpit_tg(struct sk_buff **pskb, const struct xt_action_param *par)
{
	const struct sk_buff *skb = *pskb;
	const struct iphdr *iph = ip_hdr(skb);
	const struct rtable *rt = skb_rtable(skb);

	/* Do we have an input route cache entry? (Not in PREROUTING.) */
	if (rt == NULL)
		return NF_DROP;

	/* No replies to physical multicast/broadcast */
	/* skb != PACKET_OTHERHOST handled by ip_rcv() */
	if (skb->pkt_type != PACKET_HOST)
		return NF_DROP;

	/* Now check at the protocol level */
	if (rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		return NF_DROP;

	/*
	 * Our naive response construction does not deal with IP
	 * options, and probably should not try.
	 */
	if (ip_hdrlen(skb) != sizeof(struct iphdr))
		return NF_DROP;

	/* We are not interested in fragments */
	if (iph->frag_off & htons(IP_OFFSET))
		return NF_DROP;

	tarpit_tcp(*pskb, par->hooknum);
	return NF_DROP;
}

static struct xt_target tarpit_tg_reg __read_mostly = {
	.name   = "TARPIT",
	.revision = 0,
	.family = NFPROTO_IPV4,
	.table  = "filter",
	.hooks  = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD),
	.proto  = IPPROTO_TCP,
	.target = tarpit_tg,
	.me     = THIS_MODULE,
};

static int __init tarpit_tg_init(void)
{
	return xt_register_target(&tarpit_tg_reg);
}

static void __exit tarpit_tg_exit(void)
{
	xt_unregister_target(&tarpit_tg_reg);
}

module_init(tarpit_tg_init);
module_exit(tarpit_tg_exit);
MODULE_DESCRIPTION("Xtables: \"TARPIT\", capture and hold TCP connections");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_TARPIT");
