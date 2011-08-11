/*
  This is a module which is used for PSD (portscan detection)
  Derived from scanlogd v2.1 written by Solar Designer <solar@false.com>
  and LOG target module.

  Copyright (C) 2000,2001 astaro AG

  This file is distributed under the terms of the GNU General Public
  License (GPL). Copies of the GPL can be obtained from:
     ftp://prep.ai.mit.edu/pub/gnu/GPL

  2000-05-04 Markus Hennig <hennig@astaro.de> : initial
  2000-08-18 Dennis Koslowski <koslowski@astaro.de> : first release
  2000-12-01 Dennis Koslowski <koslowski@astaro.de> : UDP scans detection added
  2001-01-02 Dennis Koslowski <koslowski@astaro.de> : output modified
  2001-02-04 Jan Rekorajski <baggins@pld.org.pl> : converted from target to match
  2004-05-05 Martijn Lievaart <m@rtij.nl> : ported to 2.6
  2007-04-05 Mohd Nawawi Mohamad Jamili <nawawi@tracenetworkcorporation.com> : ported to 2.6.18
  2008-03-21 Mohd Nawawi Mohamad Jamili <nawawi@tracenetworkcorporation.com> : ported to 2.6.24
  2009-08-07 Mohd Nawawi Mohamad Jamili <nawawi@tracenetworkcorporation.com> : ported to xtables-addons
*/

#define pr_fmt(x) KBUILD_MODNAME ": " x
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/spinlock.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include "xt_psd.h"
#include "compat_xtables.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dennis Koslowski <koslowski@astaro.com>");
MODULE_AUTHOR("Martijn Lievaart <m@rtij.nl>");
MODULE_AUTHOR("Jan Rekorajski <baggins@pld.org.pl>");
MODULE_AUTHOR(" Mohd Nawawi Mohamad Jamili <nawawi@tracenetworkcorporation.com>");
MODULE_DESCRIPTION("Xtables: PSD - portscan detection");
MODULE_ALIAS("ipt_psd");

#define HF_DADDR_CHANGING   0x01
#define HF_SPORT_CHANGING   0x02
#define HF_TOS_CHANGING	    0x04
#define HF_TTL_CHANGING	    0x08

/*
 * Information we keep per each target port
 */
struct port {
	u_int16_t number;      /* port number */
	u_int8_t proto;        /* protocol number */
	u_int8_t and_flags;    /* tcp ANDed flags */
	u_int8_t or_flags;     /* tcp ORed flags */
};

/*
 * Information we keep per each source address.
 */
struct host {
	struct host *next;						/* Next entry with the same hash */
	unsigned long timestamp;					/* Last update time */
	struct in_addr src_addr;				/* Source address */
	struct in_addr dest_addr;				/* Destination address */
	unsigned short src_port;				/* Source port */
	int count;								/* Number of ports in the list */
	int weight;								/* Total weight of ports in the list */
	struct port ports[SCAN_MAX_COUNT - 1];	/* List of ports */
	unsigned char tos;						/* TOS */
	unsigned char ttl;						/* TTL */
	unsigned char flags;					/* HF_ flags bitmask */
};

/*
 * State information.
 */
static struct {
	spinlock_t lock;
	struct host list[LIST_SIZE];	/* List of source addresses */
	struct host *hash[HASH_SIZE];	/* Hash: pointers into the list */
	int index;						/* Oldest entry to be replaced */
} state;

/*
 * Convert an IP address into a hash table index.
 */
static inline int hashfunc(struct in_addr addr)
{
	unsigned int value;
	int hash;

	value = addr.s_addr;
	hash = 0;
	do {
		hash ^= value;
	} while ((value >>= HASH_LOG) != 0);

	return hash & (HASH_SIZE - 1);
}

static bool
xt_psd_match(const struct sk_buff *pskb, struct xt_action_param *match)
{
	const struct iphdr *iph;
	const struct tcphdr *tcph = NULL;
	const struct udphdr *udph;
	union {
		struct tcphdr tcph;
		struct udphdr udph;
	} _buf;
	struct in_addr addr;
	u_int16_t src_port,dest_port;
  	u_int8_t tcp_flags, proto;
	unsigned long now;
	struct host *curr, *last, **head;
	int hash, index, count;
	/* Parameters from userspace */
	const struct xt_psd_info *psdinfo = match->matchinfo;

	/* IP header */
	iph = ip_hdr(pskb);

	/* Sanity check */
	if (iph->frag_off & htons(IP_OFFSET)) {
		pr_debug("sanity check failed\n");
		return false;
	}

	/* TCP or UDP ? */
	proto = iph->protocol;
	/* Get the source address, source & destination ports, and TCP flags */

	addr.s_addr = iph->saddr;
	/* We're using IP address 0.0.0.0 for a special purpose here, so don't let
	 * them spoof us. [DHCP needs this feature - HW] */
	if (addr.s_addr == 0) {
		pr_debug("spoofed source address (0.0.0.0)\n");
		return false;
	}

	if (proto == IPPROTO_TCP) {
		tcph = skb_header_pointer(pskb, match->thoff,
		       sizeof(_buf.tcph), &_buf.tcph);
		if (tcph == NULL)
			return false;

		/* Yep, it's dirty */
		src_port = tcph->source;
		dest_port = tcph->dest;
		tcp_flags = *((u_int8_t*)tcph + 13);
	} else if (proto == IPPROTO_UDP || proto == IPPROTO_UDPLITE) {
		udph = skb_header_pointer(pskb, match->thoff,
		       sizeof(_buf.udph), &_buf.udph);
		if (udph == NULL)
			return false;
		src_port  = udph->source;
		dest_port = udph->dest;
		tcp_flags = 0;
	} else {
		pr_debug("protocol not supported\n");
		return false;
	}

	/* Use jiffies here not to depend on someone setting the time while we're
	 * running; we need to be careful with possible return value overflows. */
	now = jiffies;

	spin_lock(&state.lock);

	/* Do we know this source address already? */
	count = 0;
	last = NULL;
	if ((curr = *(head = &state.hash[hash = hashfunc(addr)])) != NULL)
		do {
			if (curr->src_addr.s_addr == addr.s_addr)
				break;
			count++;
			if (curr->next != NULL)
				last = curr;
		} while ((curr = curr->next) != NULL);

	if (curr != NULL) {

		/* We know this address, and the entry isn't too old. Update it. */
		if (now - curr->timestamp <= (psdinfo->delay_threshold*HZ)/100 &&
		    time_after_eq(now, curr->timestamp)) {

			/* Just update the appropriate list entry if we've seen this port already */
			for (index = 0; index < curr->count; index++) {
				if (curr->ports[index].number == dest_port) {
					curr->ports[index].proto = proto;
					curr->ports[index].and_flags &= tcp_flags;
					curr->ports[index].or_flags |= tcp_flags;
					goto out_no_match;
				}
			}

			/* TCP/ACK and/or TCP/RST to a new port? This could be an outgoing connection. */
			if (proto == IPPROTO_TCP && (tcph->ack || tcph->rst))
				goto out_no_match;

			/* Packet to a new port, and not TCP/ACK: update the timestamp */
			curr->timestamp = now;

			/* Logged this scan already? Then drop the packet. */
			if (curr->weight >= psdinfo->weight_threshold)
				goto out_match;

			/* Specify if destination address, source port, TOS or TTL are not fixed */
			if (curr->dest_addr.s_addr != iph->daddr)
				curr->flags |= HF_DADDR_CHANGING;
			if (curr->src_port != src_port)
				curr->flags |= HF_SPORT_CHANGING;
			if (curr->tos != iph->tos)
				curr->flags |= HF_TOS_CHANGING;
			if (curr->ttl != iph->ttl)
				curr->flags |= HF_TTL_CHANGING;

			/* Update the total weight */
			curr->weight += (ntohs(dest_port) < 1024) ?
				psdinfo->lo_ports_weight : psdinfo->hi_ports_weight;

			/* Got enough destination ports to decide that this is a scan? */
			/* Then log it and drop the packet. */
			if (curr->weight >= psdinfo->weight_threshold)
				goto out_match;

			/* Remember the new port */
			if (curr->count < SCAN_MAX_COUNT) {
				curr->ports[curr->count].number = dest_port;
				curr->ports[curr->count].proto = proto;
				curr->ports[curr->count].and_flags = tcp_flags;
				curr->ports[curr->count].or_flags = tcp_flags;
				curr->count++;
			}

			goto out_no_match;
		}

		/* We know this address, but the entry is outdated. Mark it unused, and
		 * remove from the hash table. We'll allocate a new entry instead since
		 * this one might get re-used too soon. */
		curr->src_addr.s_addr = 0;
		if (last != NULL)
			last->next = last->next->next;
		else if (*head != NULL)
			*head = (*head)->next;
		last = NULL;
	}

	/* We don't need an ACK from a new source address */
	if (proto == IPPROTO_TCP && tcph->ack)
		goto out_no_match;

	/* Got too many source addresses with the same hash value? Then remove the
	 * oldest one from the hash table, so that they can't take too much of our
	 * CPU time even with carefully chosen spoofed IP addresses. */
	if (count >= HASH_MAX && last != NULL)
		last->next = NULL;

	/* We're going to re-use the oldest list entry, so remove it from the hash
	 * table first (if it is really already in use, and isn't removed from the
	 * hash table already because of the HASH_MAX check above). */

	/* First, find it */
	if (state.list[state.index].src_addr.s_addr != 0)
		head = &state.hash[hashfunc(state.list[state.index].src_addr)];
	else
		head = &last;
	last = NULL;
	if ((curr = *head) != NULL)
		do {
			if (curr == &state.list[state.index])
				break;
			last = curr;
		} while ((curr = curr->next) != NULL);

	/* Then, remove it */
	if (curr != NULL) {
		if (last != NULL)
			last->next = last->next->next;
		else if (*head != NULL)
			*head = (*head)->next;
	}

	/* Get our list entry */
	curr = &state.list[state.index++];
	if (state.index >= LIST_SIZE)
		state.index = 0;

	/* Link it into the hash table */
	head = &state.hash[hash];
	curr->next = *head;
	*head = curr;

	/* And fill in the fields */
	curr->timestamp = now;
	curr->src_addr = addr;
	curr->dest_addr.s_addr = iph->daddr;
	curr->src_port = src_port;
	curr->count = 1;
	curr->weight = (ntohs(dest_port) < 1024) ? psdinfo->lo_ports_weight : psdinfo->hi_ports_weight;
	curr->ports[0].number = dest_port;
	curr->ports[0].proto = proto;
	curr->ports[0].and_flags = tcp_flags;
	curr->ports[0].or_flags = tcp_flags;
	curr->tos = iph->tos;
	curr->ttl = iph->ttl;

out_no_match:
	spin_unlock(&state.lock);
	return false;

out_match:
	spin_unlock(&state.lock);
	return true;
}

static struct xt_match xt_psd_reg __read_mostly = {
	.name		= "psd",
	.family    = NFPROTO_IPV4,
	.revision  = 1,
	.match		= xt_psd_match,
	.matchsize	= sizeof(struct xt_psd_info),
	.me			= THIS_MODULE,
};

static int __init xt_psd_init(void)
{
	spin_lock_init(&(state.lock));
	return xt_register_match(&xt_psd_reg);
}

static void __exit xt_psd_exit(void)
{
        xt_unregister_match(&xt_psd_reg);
}

module_init(xt_psd_init);
module_exit(xt_psd_exit);

