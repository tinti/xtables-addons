/*
 *	xt_condition
 *
 *	Description: This module allows firewall rules to match using
 *	condition variables available through procfs.
 *
 *	Authors:
 *	Stephane Ouellette <ouellettes@videotron.ca>, 2002-10-22
 *	Massimiliano Hofer <max@nucleus.it>, 2006-05-15
 *
 *	This software is distributed under the terms of the GNU GPL.
 */
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include <asm/uaccess.h>
#include "xt_condition.h"
#include "compat_xtables.h"

#ifndef CONFIG_PROC_FS
#	error "proc file system support is required for this module"
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#	define proc_net init_net.proc_net
#endif

/* Defaults, these can be overridden on the module command-line. */
static unsigned int condition_list_perms = S_IRUGO | S_IWUSR;
static unsigned int condition_uid_perms = 0;
static unsigned int condition_gid_perms = 0;

MODULE_AUTHOR("Stephane Ouellette <ouellettes@videotron.ca>");
MODULE_AUTHOR("Massimiliano Hofer <max@nucleus.it>");
MODULE_DESCRIPTION("Allows rules to match against condition variables");
MODULE_LICENSE("GPL");
module_param(condition_list_perms, uint, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(condition_list_perms, "permissions on /proc/net/nf_condition/* files");
module_param(condition_uid_perms, uint, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(condition_uid_perms, "user owner of /proc/net/nf_condition/* files");
module_param(condition_gid_perms, uint, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(condition_gid_perms, "group owner of /proc/net/nf_condition/* files");
MODULE_ALIAS("ipt_condition");
MODULE_ALIAS("ip6t_condition");

struct condition_variable {
	struct list_head list;
	struct proc_dir_entry *status_proc;
	unsigned int refcount;
	bool enabled;
};

/* proc_lock is a user context only semaphore used for write access */
/*           to the conditions' list.                               */
static DECLARE_MUTEX(proc_lock);

static LIST_HEAD(conditions_list);
static struct proc_dir_entry *proc_net_condition;

static int condition_proc_read(char __user *buffer, char **start, off_t offset,
                               int length, int *eof, void *data)
{
	const struct condition_variable *var = data;

	buffer[0] = var->enabled ? '1' : '0';
	buffer[1] = '\n';
	if (length >= 2)
		*eof = true;

	return 2;
}

static int condition_proc_write(struct file *file, const char __user *buffer,
                                unsigned long length, void *data)
{
	struct condition_variable *var = data;
	char newval;

	if (length > 0) {
		if (get_user(newval, buffer) != 0)
			return -EFAULT;
		/* Match only on the first character */
		switch (newval) {
		case '0':
			var->enabled = false;
			break;
		case '1':
			var->enabled = true;
			break;
		}
	}

	return length;
}

static bool
condition_mt(const struct sk_buff *skb, const struct net_device *in,
             const struct net_device *out, const struct xt_match *match,
             const void *matchinfo, int offset, unsigned int protoff,
             bool *hotdrop)
{
	const struct xt_condition_mtinfo *info = matchinfo;
	struct condition_variable *var;
	int condition_status = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(var, &conditions_list, list) {
		if (strcmp(info->name, var->status_proc->name) == 0) {
			condition_status = var->enabled;
			break;
		}
	}
	rcu_read_unlock();

	return condition_status ^ info->invert;
}

static bool
condition_mt_check(const char *tablename, const void *entry,
                   const struct xt_match *match, void *matchinfo,
                   unsigned int hook_mask)
{
	const struct xt_condition_mtinfo *info = matchinfo;
	struct list_head *pos;
	struct condition_variable *var;

	/* Forbid certain names */
	if (*info->name == '\0' || *info->name == '.' ||
	    info->name[sizeof(info->name)-1] != '\0' ||
	    memchr(info->name, '/', sizeof(info->name)) != NULL) {
		printk(KERN_INFO KBUILD_MODNAME ": name not allowed or too "
		       "long: \"%.*s\"\n", sizeof(info->name), info->name);
		return false;
	}

	/*
	 * Let's acquire the lock, check for the condition and add it
	 * or increase the reference counter.
	 */
	if (down_interruptible(&proc_lock))
		return false;

	list_for_each(pos, &conditions_list) {
		var = list_entry(pos, struct condition_variable, list);
		if (strcmp(info->name, var->status_proc->name) == 0) {
			var->refcount++;
			up(&proc_lock);
			return true;
		}
	}

	/* At this point, we need to allocate a new condition variable. */
	var = kmalloc(sizeof(struct condition_variable), GFP_KERNEL);

	if (var == NULL) {
		up(&proc_lock);
		return false;
	}

	/* Create the condition variable's proc file entry. */
	var->status_proc = create_proc_entry(info->name, condition_list_perms, proc_net_condition);

	if (var->status_proc == NULL) {
		kfree(var);
		up(&proc_lock);
		return false;
	}

	var->refcount = 1;
	var->enabled  = false;
	var->status_proc->owner = THIS_MODULE;
	var->status_proc->data  = var;
	wmb();
	var->status_proc->read_proc  = condition_proc_read;
	var->status_proc->write_proc = condition_proc_write;

	list_add_rcu(&var->list, &conditions_list);

	var->status_proc->uid = condition_uid_perms;
	var->status_proc->gid = condition_gid_perms;

	up(&proc_lock);

	return true;
}

static void condition_mt_destroy(const struct xt_match *match, void *matchinfo)
{
	const struct xt_condition_mtinfo *info = matchinfo;
	struct list_head *pos;
	struct condition_variable *var;

	down(&proc_lock);

	list_for_each(pos, &conditions_list) {
		var = list_entry(pos, struct condition_variable, list);
		if (strcmp(info->name, var->status_proc->name) == 0) {
			if (--var->refcount == 0) {
				list_del_rcu(pos);
				remove_proc_entry(var->status_proc->name, proc_net_condition);
				up(&proc_lock);
				/*
				 * synchronize_rcu() would be good enough, but
				 * synchronize_net() guarantees that no packet
				 * will go out with the old rule after
				 * succesful removal.
				 */
				synchronize_net();
				kfree(var);
				return;
			}
			break;
		}
	}

	up(&proc_lock);
}

static struct xt_match condition_mt_reg[] __read_mostly = {
	{
		.name       = "condition",
		.revision   = 0,
		.family     = PF_INET,
		.matchsize  = XT_ALIGN(sizeof(struct xt_condition_mtinfo)),
		.match      = condition_mt,
		.checkentry = condition_mt_check,
		.destroy    = condition_mt_destroy,
		.me         = THIS_MODULE,
	},
	{
		.name       = "condition",
		.revision   = 0,
		.family     = PF_INET6,
		.matchsize  = XT_ALIGN(sizeof(struct xt_condition_mtinfo)),
		.match      = condition_mt,
		.checkentry = condition_mt_check,
		.destroy    = condition_mt_destroy,
		.me         = THIS_MODULE,
	},
};

static const char *const dir_name = "nf_condition";

static int __init condition_mt_init(void)
{
	int ret;

	proc_net_condition = proc_mkdir(dir_name, proc_net);
	if (proc_net_condition == NULL)
		return -EACCES;

	ret = xt_register_matches(condition_mt_reg, ARRAY_SIZE(condition_mt_reg));
	if (ret < 0) {
		remove_proc_entry(dir_name, proc_net);
		return ret;
	}

	return 0;
}

static void __exit condition_mt_exit(void)
{
	xt_unregister_matches(condition_mt_reg, ARRAY_SIZE(condition_mt_reg));
	remove_proc_entry(dir_name, proc_net);
}

module_init(condition_mt_init);
module_exit(condition_mt_exit);
