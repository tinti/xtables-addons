/* DNETMAP - dynamic two-way 1:1 NAT mapping of IPv4 network addresses.
 * The mapping can be applied to source (POSTROUTING|OUTPUT)
 * or destination (PREROUTING),
 */

/* (C) 2011 Marek Kierdelewicz <marek@koba.pl>
 *
 * module is dedicated to my wife Eliza and my daughters Jula and Ola :* :* :*
 *
 * module audited and cleaned-up by Jan Engelhardt
 *
 * module uses some code and ideas from following modules:
 * - "NETMAP" module by Svenning Soerensen <svenning@post5.tele.dk>
 * - "recent" module by Stephen Frost <sfrost@snowman.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <linux/version.h>
#include <net/netfilter/nf_nat_rule.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
#	include <net/netfilter/nf_nat.h>
#else
#	include <linux/netfilter/nf_nat.h>
#endif
#include "compat_xtables.h"
#include "xt_DNETMAP.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marek Kierdelewicz <marek@koba.pl>");
MODULE_DESCRIPTION(
	"Xtables: dynamic two-way 1:1 NAT mapping of IPv4 addresses");
MODULE_ALIAS("ipt_DNETMAP");

static unsigned int default_ttl = 600;
static unsigned int proc_perms = S_IRUGO | S_IWUSR;
static unsigned int proc_uid;
static unsigned int proc_gid;
static unsigned int default_hash_size = 256;
static unsigned int hash_size = 256;
static unsigned int disable_log;
static unsigned int whole_prefix = 1;
module_param(default_ttl, uint, S_IRUSR);
MODULE_PARM_DESC(default_ttl,
		 " default ttl value to be used if rule doesn't specify any (default: 600)");
module_param(hash_size, uint, S_IRUSR);
MODULE_PARM_DESC(hash_size,
		 " hash size for ip lists, needs to be power of 2 (default: 256)");
module_param(disable_log, uint, S_IRUSR);
MODULE_PARM_DESC(disable_log,
		 " disables logging of bind/timeout events (default: 0)");
module_param(whole_prefix, uint, S_IRUSR);
MODULE_PARM_DESC(whole_prefix,
		 " use network and broadcast addresses of specified prefix for bindings (default: 1)");

static unsigned int jtimeout;

struct dnetmap_entry {
	struct list_head list;
	/* priv2entry */
	struct list_head glist;
	/* pub2entry */
	struct list_head grlist;
	struct list_head lru_list;
	__be32 prenat_addr;
	__be32 postnat_addr;
	unsigned long stamp;
	struct dnetmap_prefix *prefix;
};

struct dnetmap_prefix {
	struct nf_nat_ipv4_multi_range_compat prefix;
	char prefix_str[16];
	struct list_head list;
	unsigned int refcnt;
	/* lru entry list */
	struct list_head lru_list;
	/* hash based on prenat-ips */
	struct list_head iphash[0];
};

struct dnetmap_net {
	struct list_head prefixes;
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *xt_dnetmap;
#endif
	/* global hash */
	struct list_head *dnetmap_iphash;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
static int dnetmap_net_id;
static inline struct dnetmap_net *dnetmap_pernet(struct net *net)
{
	return net_generic(net, dnetmap_net_id);
}
#else
struct dnetmap_net *dnetmap;
#define dnetmap_pernet(x) dnetmap
#endif

static DEFINE_SPINLOCK(dnetmap_lock);
static DEFINE_MUTEX(dnetmap_mutex);

#ifdef CONFIG_PROC_FS
static const struct file_operations dnetmap_tg_fops;
#endif

static int dnetmap_stat_proc_read(char __user *buffer, char **start,
				  off_t offset, int length, int *eof,
				  void *data);

static inline unsigned int dnetmap_entry_hash(const __be32 addr)
{
	return ntohl(addr) & (hash_size - 1);
}

static struct dnetmap_entry *
dnetmap_entry_lookup(struct dnetmap_net *dnetmap_net, const __be32 addr)
{
	struct dnetmap_entry *e;
	unsigned int h;

	h = dnetmap_entry_hash(addr);

	list_for_each_entry(e, &dnetmap_net->dnetmap_iphash[h], glist)
		if (memcmp(&e->prenat_addr, &addr, sizeof(addr)) == 0)
			return e;
	return NULL;
}

static struct dnetmap_entry *
dnetmap_entry_rlookup(struct dnetmap_net *dnetmap_net, const __be32 addr)
{
	struct dnetmap_entry *e;
	unsigned int h;

	h = dnetmap_entry_hash(addr);

	list_for_each_entry(e, &dnetmap_net->dnetmap_iphash[hash_size + h],
	    grlist)
		if (memcmp(&e->postnat_addr, &addr, sizeof(addr)) == 0)
			return e;
	return NULL;
}

static struct dnetmap_prefix *
dnetmap_prefix_lookup(struct dnetmap_net *dnetmap_net,
		      const struct nf_nat_ipv4_multi_range_compat *mr)
{
	struct dnetmap_prefix *p;

	list_for_each_entry(p, &dnetmap_net->prefixes, list)
		if (memcmp(&p->prefix, mr, sizeof(*mr)) == 0)
			return p;
	return NULL;
}

static void dnetmap_prefix_flush(struct dnetmap_net *dnetmap_net,
				 struct dnetmap_prefix *p)
{
	struct dnetmap_entry *e, *next;
	unsigned int i;

	for (i = 0; i < hash_size; i++) {
		list_for_each_entry_safe(e, next,
					 &dnetmap_net->dnetmap_iphash[i], glist)
			if (e->prefix == p)
				list_del(&e->glist);

		list_for_each_entry_safe(e, next,
					 &dnetmap_net->
					 dnetmap_iphash[hash_size + i], grlist)
			if (e->prefix == p)
				list_del(&e->grlist);

		list_for_each_entry_safe(e, next, &p->iphash[i], list) {
			list_del(&e->list);
			list_del(&e->lru_list);
			kfree(e);
		}
	}
}

static int dnetmap_tg_check(const struct xt_tgchk_param *par)
{
	struct dnetmap_net *dnetmap_net = dnetmap_pernet(par->net);
	const struct xt_DNETMAP_tginfo *tginfo = par->targinfo;
	const struct nf_nat_ipv4_multi_range_compat *mr = &tginfo->prefix;
	struct dnetmap_prefix *p;
	struct dnetmap_entry *e;
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *pde_data, *pde_stat;
	char proc_str_data[20];
	char proc_str_stat[25];
#endif
	int ret = -EINVAL;
	int i;
	__be32 a;
	__u32 ip_min, ip_max, ip;

	/* prefix not specified - no need to do anything */
	if (!(tginfo->flags & XT_DNETMAP_PREFIX)) {
		ret = 0;
		return ret;
	}

	if (!(mr->range[0].flags & NF_NAT_RANGE_MAP_IPS)) {
		pr_debug("DNETMAP:check: bad MAP_IPS.\n");
		return -EINVAL;
	}
	if (mr->rangesize != 1) {
		pr_debug("DNETMAP:check: bad rangesize %u.\n", mr->rangesize);
		return -EINVAL;
	}

	mutex_lock(&dnetmap_mutex);
	p = dnetmap_prefix_lookup(dnetmap_net, mr);

	if (p != NULL) {
		p->refcnt++;
		ret = 0;
		goto out;
	}

	p = kzalloc(sizeof(*p) + sizeof(struct list_head) * hash_size * 2,
		    GFP_KERNEL);
	if (p == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	p->refcnt = 1;
	memcpy(&p->prefix, mr, sizeof(*mr));

	INIT_LIST_HEAD(&p->lru_list);
	for (i = 0; i < hash_size * 2; i++)
		INIT_LIST_HEAD(&p->iphash[i]);

	ip_min = ntohl(mr->range[0].min_ip) + (whole_prefix == 0);
	ip_max = ntohl(mr->range[0].max_ip) - (whole_prefix == 0);

	sprintf(p->prefix_str, NIPQUAD_FMT "/%u", NIPQUAD(mr->range[0].min_ip),
		33 - ffs(~(ip_min ^ ip_max)));
#ifdef CONFIG_PROC_FS
	sprintf(proc_str_data, NIPQUAD_FMT "_%u", NIPQUAD(mr->range[0].min_ip),
		33 - ffs(~(ip_min ^ ip_max)));
	sprintf(proc_str_stat, NIPQUAD_FMT "_%u_stat", NIPQUAD(mr->range[0].min_ip),
		33 - ffs(~(ip_min ^ ip_max)));
#endif
	printk(KERN_INFO KBUILD_MODNAME ": new prefix %s\n", p->prefix_str);

	for (ip = ip_min; ip <= ip_max; ip++) {
		a = htonl(ip);
		e = kmalloc(sizeof(*e), GFP_ATOMIC);
		if (e == NULL)
			return 0;
		e->postnat_addr = a;
		e->prenat_addr = 0;
		e->stamp = jiffies;
		e->prefix = p;
		list_add_tail(&e->lru_list, &p->lru_list);
	}

#ifdef CONFIG_PROC_FS
	/* data */
	pde_data = proc_create_data(proc_str_data, proc_perms,
				    dnetmap_net->xt_dnetmap,
				    &dnetmap_tg_fops, p);
	if (pde_data == NULL) {
		kfree(p);
		ret = -ENOMEM;
		goto out;
	}
	pde_data->uid = proc_uid;
	pde_data->gid = proc_gid;

	/* statistics */
	pde_stat = create_proc_entry(proc_str_stat, proc_perms,
				     dnetmap_net->xt_dnetmap);
	if (pde_stat == NULL) {
		kfree(p);
		ret = -ENOMEM;
		goto out;
	}
	pde_stat->data = p;
	pde_stat->read_proc = dnetmap_stat_proc_read;
	pde_stat->uid = proc_uid;
	pde_stat->gid = proc_gid;
#endif

	spin_lock_bh(&dnetmap_lock);
	list_add_tail(&p->list, &dnetmap_net->prefixes);
	spin_unlock_bh(&dnetmap_lock);
	ret = 0;

out:
	mutex_unlock(&dnetmap_mutex);
	return ret;
}

static unsigned int
dnetmap_tg(struct sk_buff **pskb, const struct xt_action_param *par)
{
	struct sk_buff *skb = *pskb;
	struct net *net = dev_net(par->in ? par->in : par->out);
	struct dnetmap_net *dnetmap_net = dnetmap_pernet(net);
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	__be32 prenat_ip, postnat_ip, prenat_ip_prev;
	const struct xt_DNETMAP_tginfo *tginfo = par->targinfo;
	const struct nf_nat_ipv4_multi_range_compat *mr = &tginfo->prefix;
	struct nf_nat_ipv4_range newrange;
	struct dnetmap_entry *e;
	struct dnetmap_prefix *p;
	__s32 jttl;

	NF_CT_ASSERT(par->hooknum == NF_INET_POST_ROUTING ||
		     par->hooknum == NF_INET_LOCAL_OUT ||
		     par->hooknum == NF_INET_PRE_ROUTING);
	ct = nf_ct_get(skb, &ctinfo);

	jttl = tginfo->flags & XT_DNETMAP_TTL ? tginfo->ttl * HZ : jtimeout;

	/* in prerouting we try to map postnat-ip to prenat-ip */
	if (par->hooknum == NF_INET_PRE_ROUTING) {
		postnat_ip = ip_hdr(skb)->daddr;

		spin_lock_bh(&dnetmap_lock);

		e = dnetmap_entry_rlookup(dnetmap_net, postnat_ip);

		if (e == NULL)
			goto no_rev_map;	/* no binding found */

		/* if prefix is specified, we check if
		it matches lookedup entry */
		if (tginfo->flags & XT_DNETMAP_PREFIX)
			if (memcmp(mr, &e->prefix, sizeof(*mr)))
				goto no_rev_map;
		/* don't reset ttl if flag is set */
		if (jttl >= 0) {
			p = e->prefix;
			e->stamp = jiffies + jttl;
			list_move_tail(&e->lru_list, &p->lru_list);
		}

		spin_unlock_bh(&dnetmap_lock);

		newrange = ((struct nf_nat_ipv4_range) {
			    mr->range[0].flags | NF_NAT_RANGE_MAP_IPS,
			    e->prenat_addr, e->prenat_addr,
			    mr->range[0].min, mr->range[0].max});

		/* Hand modified range to generic setup. */
		return nf_nat_setup_info(ct, &newrange,
					 HOOK2MANIP(par->hooknum));

	}

	prenat_ip = ip_hdr(skb)->saddr;
	spin_lock_bh(&dnetmap_lock);

	p = dnetmap_prefix_lookup(dnetmap_net, mr);
	e = dnetmap_entry_lookup(dnetmap_net, prenat_ip);

	if (e == NULL) {	/* need for new binding */

bind_new_prefix:
		e = list_entry(p->lru_list.next, struct dnetmap_entry,
			       lru_list);
		if (e->prenat_addr != 0 && time_before(jiffies, e->stamp)) {
			if (!disable_log)
				printk(KERN_INFO KBUILD_MODNAME
				       ": ip " NIPQUAD_FMT " - no free adresses in prefix %s\n",
				       NIPQUAD(prenat_ip), p->prefix_str);
			goto no_free_ip;
		}

		postnat_ip = e->postnat_addr;

		if (e->prenat_addr != 0) {
			prenat_ip_prev = e->prenat_addr;
			if (!disable_log)
				printk(KERN_INFO KBUILD_MODNAME
				       ": timeout binding " NIPQUAD_FMT " -> " NIPQUAD_FMT "\n",
				       NIPQUAD(prenat_ip_prev), NIPQUAD(postnat_ip) );
			list_del(&e->list);
			list_del(&e->glist);
			list_del(&e->grlist);
		}

		e->prenat_addr = prenat_ip;
		e->stamp = jiffies + jttl;
		list_move_tail(&e->lru_list, &p->lru_list);
		list_add_tail(&e->list,
			      &p->iphash[dnetmap_entry_hash(prenat_ip)]);
		list_add_tail(&e->glist,
			      &dnetmap_net->
			      dnetmap_iphash[dnetmap_entry_hash(prenat_ip)]);
		list_add_tail(&e->grlist,
			      &dnetmap_net->dnetmap_iphash[hash_size +
							   dnetmap_entry_hash
							   (postnat_ip)]);
		if (!disable_log)
			printk(KERN_INFO KBUILD_MODNAME
			       ": add binding " NIPQUAD_FMT " -> " NIPQUAD_FMT "\n",
						 NIPQUAD(prenat_ip),NIPQUAD(postnat_ip));

	} else {

		if (!(tginfo->flags & XT_DNETMAP_REUSE))
			if (time_before(e->stamp, jiffies) && p != e->prefix) {
				if (!disable_log)
					printk(KERN_INFO KBUILD_MODNAME
					       ": timeout binding " NIPQUAD_FMT " -> " NIPQUAD_FMT "\n",
					       NIPQUAD(e->prenat_addr),
					       NIPQUAD(e->postnat_addr));
				list_del(&e->list);
				list_del(&e->glist);
				list_del(&e->grlist);
				e->prenat_addr = 0;
				goto bind_new_prefix;
			}
		/* don't reset ttl if flag is set */
		if (jttl >= 0) {
			e->stamp = jiffies + jttl;
			p = e->prefix;
			list_move_tail(&e->lru_list, &p->lru_list);
		}
		postnat_ip = e->postnat_addr;
	}

	spin_unlock_bh(&dnetmap_lock);

	newrange = ((struct nf_nat_ipv4_range) {
		    mr->range[0].flags | NF_NAT_RANGE_MAP_IPS,
		    postnat_ip, postnat_ip,
		    mr->range[0].min, mr->range[0].max});

	/* Hand modified range to generic setup. */
	return nf_nat_setup_info(ct, &newrange, HOOK2MANIP(par->hooknum));

no_rev_map:
no_free_ip:
	spin_unlock_bh(&dnetmap_lock);
	return XT_CONTINUE;

}

static void dnetmap_tg_destroy(const struct xt_tgdtor_param *par)
{
	struct dnetmap_net *dnetmap_net = dnetmap_pernet(par->net);
	const struct xt_DNETMAP_tginfo *tginfo = par->targinfo;
	const struct nf_nat_ipv4_multi_range_compat *mr = &tginfo->prefix;
	struct dnetmap_prefix *p;
#ifdef CONFIG_PROC_FS
	char str[25];
#endif

	if (!(tginfo->flags & XT_DNETMAP_PREFIX))
		return;

	mutex_lock(&dnetmap_mutex);
	p = dnetmap_prefix_lookup(dnetmap_net, mr);
	if (--p->refcnt == 0) {
		spin_lock_bh(&dnetmap_lock);
		list_del(&p->list);
		spin_unlock_bh(&dnetmap_lock);
#ifdef CONFIG_PROC_FS
		sprintf(str, NIPQUAD_FMT "_%u", NIPQUAD(mr->range[0].min_ip),
			33 - ffs(~(ntohl(mr->range[0].min_ip ^
			mr->range[0].max_ip))));
		remove_proc_entry(str, dnetmap_net->xt_dnetmap);
		sprintf(str, NIPQUAD_FMT "_%u_stat", NIPQUAD(mr->range[0].min_ip),
			33 - ffs(~(ntohl(mr->range[0].min_ip ^
			mr->range[0].max_ip))));
		remove_proc_entry(str, dnetmap_net->xt_dnetmap);
#endif
		dnetmap_prefix_flush(dnetmap_net, p);
		kfree(p);
	}
	mutex_unlock(&dnetmap_mutex);
}

#ifdef CONFIG_PROC_FS
struct dnetmap_iter_state {
	const struct dnetmap_prefix *p;
	unsigned int bucket;
};

static void *dnetmap_seq_start(struct seq_file *seq, loff_t * pos)
__acquires(dnetmap_lock)
{
	struct dnetmap_iter_state *st = seq->private;
	const struct dnetmap_prefix *prefix = st->p;
	struct dnetmap_entry *e;
	loff_t p = *pos;

	spin_lock_bh(&dnetmap_lock);

	list_for_each_entry(e, &prefix->lru_list, lru_list)
		if (p-- == 0)
			return e;
	return NULL;
}

static void *dnetmap_seq_next(struct seq_file *seq, void *v, loff_t * pos)
{
	struct dnetmap_iter_state *st = seq->private;
	const struct dnetmap_prefix *prefix = st->p;
	const struct dnetmap_entry *e = v;
	const struct list_head *head = e->lru_list.next;

	if (head == &prefix->lru_list)
		return NULL;

	++*pos;
	return list_entry(head, struct dnetmap_entry, lru_list);
}

static void dnetmap_seq_stop(struct seq_file *s, void *v)
__releases(dnetmap_lock)
{
	spin_unlock_bh(&dnetmap_lock);
}

static int dnetmap_seq_show(struct seq_file *seq, void *v)
{
	const struct dnetmap_entry *e = v;

	seq_printf(seq, NIPQUAD_FMT " -> " NIPQUAD_FMT " --- ttl: %d lasthit: %lu\n",
		   NIPQUAD(e->prenat_addr), NIPQUAD(e->postnat_addr),
		   (int)(e->stamp - jiffies) / HZ, (e->stamp - jtimeout) / HZ);
	return 0;
}

static const struct seq_operations dnetmap_seq_ops = {
	.start = dnetmap_seq_start,
	.next = dnetmap_seq_next,
	.stop = dnetmap_seq_stop,
	.show = dnetmap_seq_show,
};

static int dnetmap_seq_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	struct dnetmap_iter_state *st;

	st = __seq_open_private(file, &dnetmap_seq_ops, sizeof(*st));
	if (st == NULL)
		return -ENOMEM;

	st->p = pde->data;
	return 0;
}

static const struct file_operations dnetmap_tg_fops = {
	.open = dnetmap_seq_open,
	.read = seq_read,
	.release = seq_release_private,
	.owner = THIS_MODULE,
};

/* for statistics */
static int dnetmap_stat_proc_read(char __user *buffer, char **start,
				  off_t offset, int length, int *eof,
				  void *data)
{
	const struct dnetmap_prefix *p = data;
	struct dnetmap_entry *e;
	unsigned int used, all;
	long int ttl, sum_ttl;

	used = 0;
	all = 0;
	sum_ttl = 0;

	spin_lock_bh(&dnetmap_lock);

	list_for_each_entry(e, &p->lru_list, lru_list) {

		ttl = e->stamp - jiffies;
		if (e->prenat_addr != 0 && ttl >= 0) {
			used++;
			sum_ttl += ttl;
		}
		all++;
	}

	sum_ttl = used > 0 ? sum_ttl / (used * HZ) : 0;
	sprintf(buffer, "%u %u %ld\n", used, all, sum_ttl);

	if (length >= strlen(buffer))
		*eof = true;

	spin_unlock_bh(&dnetmap_lock);

	return strlen(buffer);
}

static int __net_init dnetmap_proc_net_init(struct net *net)
{
	struct dnetmap_net *dnetmap_net = dnetmap_pernet(net);

	dnetmap_net->xt_dnetmap = proc_mkdir("xt_DNETMAP", net->proc_net);
	if (dnetmap_net->xt_dnetmap == NULL)
		return -ENOMEM;
	return 0;
}

static void __net_exit dnetmap_proc_net_exit(struct net *net)
{
	proc_net_remove(net, "xt_DNETMAP");
}

#else
static inline int dnetmap_proc_net_init(struct net *net)
{
	return 0;
}

static inline void dnetmap_proc_net_exit(struct net *net)
{
}
#endif /* CONFIG_PROC_FS */

static int __net_init dnetmap_net_init(struct net *net)
{
	struct dnetmap_net *dnetmap_net = dnetmap_pernet(net);
	int i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
	dnetmap = kmalloc(sizeof(struct dnetmap_net),GFP_ATOMIC);
	if (dnetmap == NULL)
		return -ENOMEM;
	dnetmap_net = dnetmap;
#endif

	dnetmap_net->dnetmap_iphash = kmalloc(sizeof(struct list_head) *
					      hash_size * 2, GFP_ATOMIC);
	if (dnetmap_net->dnetmap_iphash == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&dnetmap_net->prefixes);
	for (i = 0; i < hash_size * 2; i++)
		INIT_LIST_HEAD(&dnetmap_net->dnetmap_iphash[i]);
	return dnetmap_proc_net_init(net);
}

static void __net_exit dnetmap_net_exit(struct net *net)
{
	struct dnetmap_net *dnetmap_net = dnetmap_pernet(net);

	BUG_ON(!list_empty(&dnetmap_net->prefixes));
	kfree(dnetmap_net->dnetmap_iphash);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
	kfree(dnetmap_net);
#endif
	dnetmap_proc_net_exit(net);
}

static struct pernet_operations dnetmap_net_ops = {
	.init = dnetmap_net_init,
	.exit = dnetmap_net_exit,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	.id   = &dnetmap_net_id,
	.size = sizeof(struct dnetmap_net),
#endif
};

static struct xt_target dnetmap_tg_reg __read_mostly = {
	.name       = "DNETMAP",
	.family     = NFPROTO_IPV4,
	.target     = dnetmap_tg,
	.targetsize = sizeof(struct xt_DNETMAP_tginfo),
	.table      = "nat",
	.hooks      = (1 << NF_INET_POST_ROUTING) | (1 << NF_INET_LOCAL_OUT) |
	              (1 << NF_INET_PRE_ROUTING),
	.checkentry = dnetmap_tg_check,
	.destroy    = dnetmap_tg_destroy,
	.me         = THIS_MODULE
};

static int __init dnetmap_tg_init(void)
{
	int err;

	/* verify parameters */
	if (ffs(hash_size) != fls(hash_size) || hash_size <= 0) {
		pr_info("bad hash_size parameter value - using defaults");
		hash_size = default_hash_size;
	}

	jtimeout = default_ttl * HZ;

	err = register_pernet_subsys(&dnetmap_net_ops);
	if (err)
		return err;

	err = xt_register_target(&dnetmap_tg_reg);
	if (err)
		unregister_pernet_subsys(&dnetmap_net_ops);

	return err;
}

static void __exit dnetmap_tg_exit(void)
{
	xt_unregister_target(&dnetmap_tg_reg);
	unregister_pernet_subsys(&dnetmap_net_ops);
}

module_init(dnetmap_tg_init);
module_exit(dnetmap_tg_exit);
