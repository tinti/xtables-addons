/* iptables kernel module for the geoip match
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Copyright (c) 2004, 2005, 2006, 2007, 2008
 * Samuel Jean & Nicolas Bouliane
 */
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>
#include "xt_geoip.h"
#include "compat_xtables.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Bouliane");
MODULE_AUTHOR("Samuel Jean");
MODULE_DESCRIPTION("xtables module for geoip match");
MODULE_ALIAS("ipt_geoip");

struct geoip_info *head = NULL;
static spinlock_t geoip_lock = SPIN_LOCK_UNLOCKED;

static struct geoip_info *add_node(struct geoip_info *memcpy)
{
	struct geoip_info *p = kmalloc(sizeof(struct geoip_info), GFP_KERNEL);

	struct geoip_subnet *s;

	if (p == NULL)
		return NULL;
	if (copy_from_user(p, memcpy, sizeof(struct geoip_info)) != 0)
		goto free_p;

	s = kmalloc(p->count * sizeof(struct geoip_subnet), GFP_KERNEL);
	if (s == NULL)
		goto free_p;
	if (copy_from_user(s, p->subnets, p->count * sizeof(struct geoip_subnet)) != 0)
		goto free_s;

	spin_lock_bh(&geoip_lock);

	p->subnets = s;
	p->ref = 1;
	p->next = head;
	p->prev = NULL;
	if (p->next)
		p->next->prev = p;
	head = p;

	spin_unlock_bh(&geoip_lock);
	return p;
 free_s:
	kfree(s);
 free_p:
	kfree(p);
	return NULL;
}

static void geoip_try_remove_node(struct geoip_info *p)
{
	spin_lock_bh(&geoip_lock);
	if (!atomic_dec_and_test((atomic_t *)&p->ref)) {
		spin_unlock_bh(&geoip_lock);
		return;
	}

	if (p->next) { /* Am I following a node ? */
		p->next->prev = p->prev;
		if (p->prev) p->prev->next = p->next; /* Is there a node behind me ? */
		else head = p->next; /* No? Then I was the head */
	}

	else
		if (p->prev) /* Is there a node behind me ? */
			p->prev->next = NULL;
		else
			head = NULL; /* No, we're alone */

	/* So now am unlinked or the only one alive, right ?
	 * What are you waiting ? Free up some memory!
	 */

	kfree(p->subnets);
	kfree(p);

	spin_unlock_bh(&geoip_lock);
	return;
}

static struct geoip_info *find_node(u_int16_t cc)
{
	struct geoip_info *p = head;
	spin_lock_bh(&geoip_lock);

	while (p) {
		if (p->cc == cc) {
			atomic_inc((atomic_t *)&p->ref);
			spin_unlock_bh(&geoip_lock);
			return p;
		}
		p = p->next;
	}
	spin_unlock_bh(&geoip_lock);
	return NULL;
}

static bool xt_geoip_mt(const struct sk_buff *skb, const struct net_device *in,
    const struct net_device *out, const struct xt_match *match,
    const void *matchinfo, int offset, unsigned int protoff, bool *hotdrop)
{
	const struct xt_geoip_match_info *info = matchinfo;
	const struct geoip_info *node; /* This keeps the code sexy */
	const struct iphdr *iph = ip_hdr(skb);
	u_int32_t ip, i, j;

	if (info->flags & XT_GEOIP_SRC)
		ip = ntohl(iph->saddr);
	else
		ip = ntohl(iph->daddr);

	spin_lock_bh(&geoip_lock);
	for (i = 0; i < info->count; i++) {
		if ((node = info->mem[i]) == NULL) {
			printk(KERN_ERR "xt_geoip: what the hell ?? '%c%c' isn't loaded into memory... skip it!\n",
					COUNTRY(info->cc[i]));

			continue;
		}

		for (j = 0; j < node->count; j++)
			if ((ip > node->subnets[j].begin) && (ip < node->subnets[j].end)) {
				spin_unlock_bh(&geoip_lock);
				return (info->flags & XT_GEOIP_INV) ? 0 : 1;
			}
	}

	spin_unlock_bh(&geoip_lock);
	return (info->flags & XT_GEOIP_INV) ? 1 : 0;
}

static bool xt_geoip_mt_checkentry(const char *table, const void *entry,
    const struct xt_match *match, void *matchinfo, unsigned int hook_mask)
{
	struct xt_geoip_match_info *info = matchinfo;
	struct geoip_info *node;
	u_int8_t i;

	for (i = 0; i < info->count; i++) {
		node = find_node(info->cc[i]);
		if (node == NULL)
			if ((node = add_node(info->mem[i])) == NULL) {
				printk(KERN_ERR
						"xt_geoip: unable to load '%c%c' into memory\n",
						COUNTRY(info->cc[i]));
				return 0;
			}

		/* Overwrite the now-useless pointer info->mem[i] with
		 * a pointer to the node's kernelspace structure.
		 * This avoids searching for a node in the match() and
		 * destroy() functions.
		 */
		info->mem[i] = node;
	}

	return 1;
}

static void xt_geoip_mt_destroy(const struct xt_match *match, void *matchinfo)
{
	struct xt_geoip_match_info *info = matchinfo;
	struct geoip_info *node; /* this keeps the code sexy */
	u_int8_t i;

	/* This entry has been removed from the table so
	 * decrease the refcount of all countries it is
	 * using.
	 */

	for (i = 0; i < info->count; i++)
		if ((node = info->mem[i]) != NULL) {
			/* Free up some memory if that node isn't used
			 * anymore. */
			geoip_try_remove_node(node);
		}
		else
			/* Something strange happened. There's no memory allocated for this
			 * country.  Please send this bug to the mailing list. */
			printk(KERN_ERR
					"xt_geoip: What happened peejix ? What happened acidfu ?\n"
					"xt_geoip: please report this bug to the maintainers\n");
	return;
}

static struct xt_match xt_geoip_match __read_mostly = {
	.family     = AF_INET,
	.name       = "geoip",
	.match      = xt_geoip_mt,
	.checkentry = xt_geoip_mt_checkentry,
	.destroy    = xt_geoip_mt_destroy,
	.matchsize  = sizeof(struct xt_geoip_match_info),
	.me         = THIS_MODULE,
};

static int __init xt_geoip_mt_init(void)
{
	return xt_register_match(&xt_geoip_match);
}

static void __exit xt_geoip_mt_fini(void)
{
	xt_unregister_match(&xt_geoip_match);
}

module_init(xt_geoip_mt_init);
module_exit(xt_geoip_mt_fini);
