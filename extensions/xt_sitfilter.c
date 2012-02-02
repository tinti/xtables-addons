/*
 *	"sitfilter" match extension for Xtables
 *
 *	Description: This module allows to link IPv4 and IPv6 addresses
 *      that are tunneled in one another.
 *
 *	Authors:
 *	Vinicius Tinti <viniciustinti [at] gmail com>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License; either version 2
 *	or 3 of the License, as published by the Free Software Foundation.
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "xt_sitfilter.h"
#include "compat_xtables.h"

MODULE_AUTHOR("Vinicius Tinti <viniciustinti@gmail.com>");
MODULE_DESCRIPTION("This module allows to match IPv6 in IPv4 addresses");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_sitfilter");
MODULE_ALIAS("ip6t_sitfilter");

static bool
sitfilter_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	struct xt_sitfilter_mtinfo *info = par->matchinfo;	

	const struct iphdr *iph = ip_hdr(skb);
        unsigned int iplen = ip_hdrlen(skb);

	uint32_t ipv4_src = ntohl(iph->saddr);
	uint32_t ipv6_src[4];

	/* destination part
	   NOT IN USE
	uint32_t ipv6_dst[4];
	uint32_t ipv4_dst = ntohl(iph->daddr);
	*/

	/* getting the payload which is an IPv6 packet */
	unsigned char* data = (unsigned char*) skb->data + iplen;

	/* ipv6 use fixed packet size therefore
	   8 bytes after the ip source is located
	   and 24 after the ip destination is located */
	unsigned char* ip6saddr = data + 8;
	/* destination 
	   NOT IN USE
	unsigned char* ip6daddr = data + 8 + 16;
	*/

	/* get ipv6 address */
	ipv6_src[0] = ntohl(*(((uint32_t*) ip6saddr)+0));
	ipv6_src[1] = ntohl(*(((uint32_t*) ip6saddr)+1));
	ipv6_src[2] = ntohl(*(((uint32_t*) ip6saddr)+2));
	ipv6_src[3] = ntohl(*(((uint32_t*) ip6saddr)+3));

	/* get ipv6 address
	   NOT IN USE
	ipv6_dst[0] = ntohl(*(((uint32_t*) ip6daddr)+0));
	ipv6_dst[1] = ntohl(*(((uint32_t*) ip6daddr)+1));
	ipv6_dst[2] = ntohl(*(((uint32_t*) ip6daddr)+2));
	ipv6_dst[3] = ntohl(*(((uint32_t*) ip6daddr)+3));
	*/

	/* prepare the mask that holds the bits which are interesting */
	uint32_t mask = 0xffffffff << (32 - info->bit_len);

	/* shift the ipv4 interested bits */
	uint32_t ipv4_masked = ipv4_src << info->ipv4_start;

	/* shift the ipv6 interested bits in a special case that
	   the start bit is 32 multiple. { 0, 32, 64, 96 }
	*/
	uint32_t ipv6_masked = ipv6_src[info->ipv6_start / 32];

	/* shift in the other cases */
	if ((info->ipv6_start % 32) != 0) {
		/* create 64 bits shift helper to deal with overflows and underflows
		   and create pointers for upper and lower parts
		*/
		uint64_t shift_helper = 0;
                uint32_t *low = (uint32_t *) &shift_helper;
                uint32_t *greater = ((uint32_t *) &shift_helper) + 1;

		/* use the pointers to write the correct data */
                *low = ipv6_src[info->ipv6_start / 32];
                *greater = ipv6_src[(info->ipv6_start / 32) + 1];

		/* perform the shift and get lower part */
                shift_helper <<= (info->ipv6_start % 32);
                ipv6_masked = *low;
	}

	/* mask to get only the interested bits */
	ipv4_masked = ipv4_masked & mask;
	ipv6_masked = ipv6_masked & mask;

	/* finally check if the result match */
	if (ipv4_masked == ipv6_masked)
	{
		pr_info("TRUE \n");
		return true;
	}
	else
	{
		pr_info("FALSE \n");
		return false;
	}
}

static int sitfilter_mt_check(const struct xt_mtchk_param *par)
{
	const struct xt_sitfilter_mtinfo *info = par->matchinfo;
	int ret = 0;

	/* Verify IPv4 limit */
	if ((info->ipv4_start + info->bit_len) > 32) {
		printk(KERN_ERR 
			" ipv4 start bit plus bit length must be lower than/equal 32");
		ret = -EINVAL;
	}

	/* Verify IPv6 limit */
	if ((info->ipv6_start + info->bit_len) > 128) {
		printk(KERN_ERR 
			" ipv6 start bit plus bit length must be lower than/equal 128");
		ret = -EINVAL;
	}


	pr_info("sitfilter succesfuly register");
	return ret;
}

static void sitfilter_mt_destroy(const struct xt_mtdtor_param *par)
{
//	pr_info("sitfilter succesfuly destroyed");
}

static struct xt_match sitfilter_mt_reg[] __read_mostly = {
	{
		.name       = "sitfilter",
		.revision   = 1,
		.family     = NFPROTO_IPV4,
		.proto      = 41,
		.matchsize  = sizeof(struct xt_sitfilter_mtinfo),
		.match      = sitfilter_mt,
		.checkentry = sitfilter_mt_check,
		.destroy    = sitfilter_mt_destroy,
		.me         = THIS_MODULE,
	},
	/* Not ready for IPv6 yet */
	/* Do not uncomment this
	{
		.name       = "sitfilter",
		.revision   = 1,
		.family     = NFPROTO_IPV6,
		.matchsize  = sizeof(struct xt_sitfilter_mtinfo),
		.match      = sitfilter_mt,
		.checkentry = sitfilter_mt_check,
		.destroy    = sitfilter_mt_destroy,
		.me         = THIS_MODULE,
	},
	*/
};

static int __init sitfilter_mt_init(void)
{
	return xt_register_matches(sitfilter_mt_reg, ARRAY_SIZE(sitfilter_mt_reg));
}

static void __exit sitfilter_mt_exit(void)
{
	xt_unregister_matches(sitfilter_mt_reg, ARRAY_SIZE(sitfilter_mt_reg));
}

module_init(sitfilter_mt_init);
module_exit(sitfilter_mt_exit);
