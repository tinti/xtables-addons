/*
 * netfilter module to enforce network quotas
 *
 * Sam Johnston <samj@samj.net>
 */
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include <linux/netfilter/x_tables.h>
#include "xt_quota2.h"
#include "compat_xtables.h"

static DEFINE_SPINLOCK(quota2_lock);
static struct proc_dir_entry *proc_xt_quota;
static unsigned int quota_list_perms = S_IRUGO | S_IWUSR;
static unsigned int quota_list_uid   = 0;
static unsigned int quota_list_gid   = 0;
module_param_named(perms, quota_list_perms, uint, S_IRUGO | S_IWUSR);
module_param_named(uid, quota_list_uid, uint, S_IRUGO | S_IWUSR);
module_param_named(gid, quota_list_gid, uint, S_IRUGO | S_IWUSR);

static int quota_proc_read(char *page, char **start, off_t offset,
                           int count, int *eof, void *data)
{
	const struct xt_quota_mtinfo2 *q = data;

	return snprintf(page, PAGE_SIZE, "%llu\n", q->quota);
}

static int quota_proc_write(struct file *file, const char __user *input,
                            unsigned long size, void *data)
{
	struct xt_quota_mtinfo2 *q = data;
	char buf[sizeof("18446744073709551616")];

	if (size > sizeof(buf))
		size = sizeof(buf);
	if (copy_from_user(buf, input, size) != 0)
		return -EFAULT;
	buf[sizeof(buf)-1] = '\0';

	q->quota = simple_strtoul(buf, NULL, 0);
	return size;
}

static bool
quota_mt2_check(const char *tablename, const void *entry,
                const struct xt_match *match, void *matchinfo,
                unsigned int hook_mask)
{
	struct xt_quota_mtinfo2 *q = matchinfo;

	if (q->flags & ~XT_QUOTA_MASK)
		return false;
	q->name[sizeof(q->name)-1] = '\0';

	if (*q->name == '\0') {
		q->procfs_entry = NULL;
	} else if (*q->name == '.' || strchr(q->name, '/') != NULL) {
		printk(KERN_ERR "xt_quota.2: illegal name\n");
		return false;
	} else {
		struct proc_dir_entry *p =
			create_proc_entry(q->name, quota_list_perms,
		                          proc_xt_quota);
		if (p == NULL || IS_ERR(p)) {
			printk(KERN_ERR "xt_quota.2: create_proc_entry failed with %ld\n", PTR_ERR(p));
			return false;
		}
		q->procfs_entry = p;
		p->owner        = THIS_MODULE;
		p->data         = q;
		p->read_proc    = quota_proc_read;
		p->write_proc   = quota_proc_write;
		p->uid          = quota_list_uid;
		p->gid          = quota_list_gid;
	}

	/* For SMP, we only want to use one set of counters. */
	q->master = q;
	return true;
}

static void quota_mt2_destroy(const struct xt_match *match, void *matchinfo)
{
	struct xt_quota_mtinfo2 *q = matchinfo;

	if (q->procfs_entry != NULL)
		remove_proc_entry(q->name, proc_xt_quota);
}

static bool
quota_mt2(const struct sk_buff *skb, const struct net_device *in,
          const struct net_device *out, const struct xt_match *match,
          const void *matchinfo, int offset, unsigned int protoff,
          bool *hotdrop)
{
	struct xt_quota_mtinfo2 *q =
		((const struct xt_quota_mtinfo2 *)matchinfo)->master;
	bool ret = q->flags & XT_QUOTA_INVERT;

	if (q->flags & XT_QUOTA_GROW) {
		spin_lock_bh(&quota2_lock);
		q->quota += skb->len;
		spin_unlock_bh(&quota2_lock);
		ret = true;
	} else {
		spin_lock_bh(&quota2_lock);
		if (q->quota >= skb->len) {
			q->quota -= skb->len;
			ret = !ret;
		} else {
			/* we do not allow even small packets from now on */
			q->quota = 0;
		}
		spin_unlock_bh(&quota2_lock);
	}

	return ret;
}

static struct xt_match quota_mt2_reg[] __read_mostly = {
	{
		.name       = "quota2",
		.revision   = 2,
		.family     = AF_INET,
		.checkentry = quota_mt2_check,
		.match      = quota_mt2,
		.destroy    = quota_mt2_destroy,  
		.matchsize  = sizeof(struct xt_quota_mtinfo2),
		.me         = THIS_MODULE,
	},
	{
		.name       = "quota2",
		.revision   = 2,
		.family     = AF_INET6,
		.checkentry = quota_mt2_check,
		.match      = quota_mt2,
		.destroy    = quota_mt2_destroy,  
		.matchsize  = sizeof(struct xt_quota_mtinfo2),
		.me         = THIS_MODULE,
	},
};

static int __init quota_mt2_init(void)
{
	int ret;

	proc_xt_quota = proc_mkdir("xt_quota", init_net__proc_net);
	if (proc_xt_quota == NULL)
		return -EACCES;

	ret = xt_register_matches(quota_mt2_reg, ARRAY_SIZE(quota_mt2_reg));
	if (ret < 0)
		remove_proc_entry("xt_quota", init_net__proc_net);
	return ret;
}

static void __exit quota_mt2_exit(void)
{
	xt_unregister_matches(quota_mt2_reg, ARRAY_SIZE(quota_mt2_reg));
	remove_proc_entry("xt_quota", init_net__proc_net);
}

module_init(quota_mt2_init);
module_exit(quota_mt2_exit);
MODULE_DESCRIPTION("Xtables: countdown quota match; up counter");
MODULE_AUTHOR("Sam Johnston <samj@samj.net>");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_quota2");
MODULE_ALIAS("ip6t_quota2");
