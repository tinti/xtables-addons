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
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
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

struct geoip_country_kernel {
	struct list_head list;
	struct geoip_subnet *subnets;
	atomic_t ref;
	unsigned int count;
	unsigned short cc;
};

static LIST_HEAD(geoip_head);
static DEFINE_SPINLOCK(geoip_lock);

static struct geoip_country_kernel *
geoip_add_node(const struct geoip_country_user __user *umem_ptr)
{
	struct geoip_country_user umem;
	struct geoip_country_kernel *p;
	struct geoip_subnet *s;
	int ret;

	if (copy_from_user(&umem, umem_ptr, sizeof(umem)) != 0)
		return ERR_PTR(-EFAULT);

	p = kmalloc(sizeof(struct geoip_country_kernel), GFP_KERNEL);
	if (p == NULL)
		return ERR_PTR(-ENOMEM);

	p->count   = umem.count;
	p->cc      = umem.cc;

	s = vmalloc(p->count * sizeof(struct geoip_subnet));
	if (s == NULL) {
		ret = -ENOMEM;
		goto free_p;
	}
	if (copy_from_user(s, (const void __user *)(unsigned long)umem.subnets,
	    p->count * sizeof(struct geoip_subnet)) != 0) {
		ret = -EFAULT;
		goto free_s;
	}

	p->subnets = s;
	atomic_set(&p->ref, 1);
	INIT_LIST_HEAD(&p->list);

	spin_lock(&geoip_lock);
	list_add_tail_rcu(&p->list, &geoip_head);
	spin_unlock(&geoip_lock);

	return p;

 free_s:
	vfree(s);
 free_p:
	kfree(p);
	return ERR_PTR(ret);
}

static void geoip_try_remove_node(struct geoip_country_kernel *p)
{
	spin_lock(&geoip_lock);
	if (!atomic_dec_and_test(&p->ref)) {
		spin_unlock(&geoip_lock);
		return;
	}

	/* So now am unlinked or the only one alive, right ?
	 * What are you waiting ? Free up some memory!
	 */
	list_del_rcu(&p->list);
	spin_unlock(&geoip_lock);

	synchronize_rcu();
	vfree(p->subnets);
	kfree(p);
}

static struct geoip_country_kernel *find_node(unsigned short cc)
{
	struct geoip_country_kernel *p;
	spin_lock(&geoip_lock);

	list_for_each_entry_rcu(p, &geoip_head, list)
		if (p->cc == cc) {
			atomic_inc(&p->ref);
			spin_unlock(&geoip_lock);
			return p;
		}

	spin_unlock(&geoip_lock);
	return NULL;
}

static bool geoip_bsearch(const struct geoip_subnet *range,
    uint32_t addr, int lo, int hi)
{
	int mid;

	if (hi <= lo)
		return false;
	mid = (lo + hi) / 2;
	if (range[mid].begin <= addr && addr <= range[mid].end)
		return true;
	if (range[mid].begin > addr)
		return geoip_bsearch(range, addr, lo, mid);
	else if (range[mid].end < addr)
		return geoip_bsearch(range, addr, mid + 1, hi);

	WARN_ON(true);
	return false;
}

static bool
xt_geoip_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_geoip_match_info *info = par->matchinfo;
	const struct geoip_country_kernel *node;
	const struct iphdr *iph = ip_hdr(skb);
	unsigned int i;
	uint32_t ip;

	if (info->flags & XT_GEOIP_SRC)
		ip = ntohl(iph->saddr);
	else
		ip = ntohl(iph->daddr);

	rcu_read_lock();
	for (i = 0; i < info->count; i++) {
		if ((node = info->mem[i].kernel) == NULL) {
			printk(KERN_ERR "xt_geoip: what the hell ?? '%c%c' isn't loaded into memory... skip it!\n",
					COUNTRY(info->cc[i]));

			continue;
		}

		if (geoip_bsearch(node->subnets, ip, 0, node->count)) {
			rcu_read_unlock();
			return !(info->flags & XT_GEOIP_INV);
		}
	}

	rcu_read_unlock();
	return info->flags & XT_GEOIP_INV;
}

static int xt_geoip_mt_checkentry(const struct xt_mtchk_param *par)
{
	struct xt_geoip_match_info *info = par->matchinfo;
	struct geoip_country_kernel *node;
	unsigned int i;

	for (i = 0; i < info->count; i++) {
		node = find_node(info->cc[i]);
		if (node == NULL) {
			node = geoip_add_node((const void __user *)(unsigned long)info->mem[i].user);
			if (IS_ERR(node)) {
				printk(KERN_ERR
						"xt_geoip: unable to load '%c%c' into memory: %ld\n",
						COUNTRY(info->cc[i]), PTR_ERR(node));
				return PTR_ERR(node);
			}
		}

		/* Overwrite the now-useless pointer info->mem[i] with
		 * a pointer to the node's kernelspace structure.
		 * This avoids searching for a node in the match() and
		 * destroy() functions.
		 */
		info->mem[i].kernel = node;
	}

	return 0;
}

static void xt_geoip_mt_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_geoip_match_info *info = par->matchinfo;
	struct geoip_country_kernel *node;
	unsigned int i;

	/* This entry has been removed from the table so
	 * decrease the refcount of all countries it is
	 * using.
	 */

	for (i = 0; i < info->count; i++)
		if ((node = info->mem[i].kernel) != NULL) {
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
}

static struct xt_match xt_geoip_match __read_mostly = {
	.name       = "geoip",
	.revision   = 1,
	.family     = NFPROTO_IPV4,
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
