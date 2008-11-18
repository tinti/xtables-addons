/*
 *	"DHCPADDR" extensions for Xtables
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
#include <linux/types.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <linux/netfilter/x_tables.h>
#include "xt_DHCPADDR.h"
#include "compat_xtables.h"

struct dhcp_message {
	uint8_t op, htype, hlen, hops;
	__be32 xid;
	__be16 secs, flags;
	__be32 ciaddr, yiaddr, siaddr, giaddr;
	char chaddr[16];
	/* Omitting all unneeded fields saves runtime memory */
	/* char sname[64], file[128]; */
};

static void ether_set(unsigned char *addr, const unsigned char *op,
    uint8_t mask)
{
	uint8_t lo_mask;
	unsigned int i;

	for (i = 0; i < ETH_ALEN && mask > 0; ++i) {
		lo_mask = mask % 8;
		/* FF << 4 >> 4 = 0F */
		lo_mask = ~(uint8_t)0U << lo_mask >> lo_mask;
		addr[i] &= lo_mask;
		addr[i] |= op[i] & ~lo_mask;
		if (mask >= 8)
			mask -= 8;
		else
			mask = 0;
	}
}

static bool ether_cmp(const unsigned char *lh, const unsigned char *rh,
    uint8_t mask)
{
	uint8_t lo_mask;
	unsigned int i;
#define ZMAC_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define ZMACHEX(s) s[0], s[1], s[2], s[3], s[4], s[5]

	for (i = 0; i < ETH_ALEN && mask > 0; ++i) {
		lo_mask = mask % 8;
		/* ~(0xFF << 4 >> 4) = ~0x0F = 0xF0 */
		lo_mask = ~(~(uint8_t)0U << lo_mask >> lo_mask);
		if ((lh[i] ^ rh[i]) & lo_mask)
			return false;
		if (mask >= 8)
			mask -= 8;
		else
			mask = 0;
	}
	return true;
}

static bool
dhcpaddr_mt(const struct sk_buff *skb, const struct xt_match_param *par)
{
	const struct dhcpaddr_info *info = par->matchinfo;
	const struct dhcp_message *dh;
	struct dhcp_message dhcpbuf;

	dh = skb_header_pointer(skb, par->thoff + sizeof(struct udphdr),
	     sizeof(dhcpbuf), &dhcpbuf);
	if (dh == NULL)
		/*
		 * No hotdrop. This packet does not look like DHCP, but other
		 * matches may still have a valid reason to get their chance
		 * to match on this.
		 */
		return false;

	return ether_cmp((const void *)dh->chaddr, info->addr, info->mask);
}

static unsigned int
dhcpaddr_tg(struct sk_buff **pskb, const struct xt_target_param *par)
{
	const struct dhcpaddr_info *info = par->targinfo;
	struct dhcp_message dhcpbuf, *dh;
	struct udphdr udpbuf, *udph;
	struct sk_buff *skb = *pskb;
	unsigned int i;

	if (!skb_make_writable(pskb, 0))
		return NF_DROP;

	udph = skb_header_pointer(skb, ip_hdrlen(skb),
	       sizeof(udpbuf), &udpbuf);
	if (udph == NULL)
		return NF_DROP;

	dh = skb_header_pointer(skb, ip_hdrlen(skb) + sizeof(udpbuf),
	     sizeof(dhcpbuf), &dhcpbuf);
	if (dh == NULL)
		return NF_DROP;

	for (i = 0; i < sizeof(dh->chaddr); i += 2)
		csum_replace2(&udph->check, *(const __be16 *)dh->chaddr, 0);

	memset(dh->chaddr, 0, sizeof(dh->chaddr));
	ether_set(dh->chaddr, info->addr, info->mask);

	for (i = 0; i < sizeof(dh->chaddr); i += 2)
		csum_replace2(&udph->check, 0, *(const __be16 *)dh->chaddr);

	return XT_CONTINUE;
}

static struct xt_target dhcpaddr_tg_reg __read_mostly = {
	.name       = "DHCPADDR",
	.revision   = 0,
	.family     = NFPROTO_IPV4,
	.proto      = IPPROTO_UDP,
	.table      = "mangle",
	.target     = dhcpaddr_tg,
	.targetsize = XT_ALIGN(sizeof(struct dhcpaddr_info)),
	.me         = THIS_MODULE,
};

static struct xt_match dhcpaddr_mt_reg __read_mostly = {
	.name       = "dhcpaddr",
	.revision   = 0,
	.family     = NFPROTO_IPV4,
	.proto      = IPPROTO_UDP,
	.match      = dhcpaddr_mt,
	.matchsize  = XT_ALIGN(sizeof(struct dhcpaddr_info)),
	.me         = THIS_MODULE,
};

static int __init dhcpaddr_init(void)
{
	int ret;

	ret = xt_register_target(&dhcpaddr_tg_reg);
	if (ret != 0)
		return ret;
	ret = xt_register_match(&dhcpaddr_mt_reg);
	if (ret != 0) {
		xt_unregister_target(&dhcpaddr_tg_reg);
		return ret;
	}
	return 0;
}

static void __exit dhcpaddr_exit(void)
{
	xt_unregister_target(&dhcpaddr_tg_reg);
	xt_unregister_match(&dhcpaddr_mt_reg);
}

module_init(dhcpaddr_init);
module_exit(dhcpaddr_exit);
MODULE_DESCRIPTION("Xtables: Clamp DHCP MAC to packet MAC addresses");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_DHCPADDR");
MODULE_ALIAS("ipt_dhcpaddr");
