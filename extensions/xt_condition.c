/*-------------------------------------------*\
|          Netfilter Condition Module         |
|                                             |
|  Description: This module allows firewall   |
|    rules to match using condition variables |
|    stored in /proc files.                   |
|                                             |
|  Author: Stephane Ouellette     2002-10-22  |
|          <ouellettes@videotron.ca>          |
|          Massimiliano Hofer     2006-05-15  |
|          <max@nucleus.it>                   |
|                                             |
|  History:                                   |
|    2003-02-10  Second version with improved |
|                locking and simplified code. |
|    2006-05-15  2.6.16 adaptations.          |
|                Locking overhaul.            |
|                Various bug fixes.           |
|                                             |
|  This software is distributed under the     |
|  terms of the GNU GPL.                      |
\*-------------------------------------------*/

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <asm/semaphore.h>
#include <linux/string.h>
#include <linux/list.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <linux/netfilter/x_tables.h>
#include "xt_condition.h"
#include "compat_xtables.h"

#ifndef CONFIG_PROC_FS
#error  "Proc file system support is required for this module"
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#	define proc_net init_net.proc_net
#endif

/* Defaults, these can be overridden on the module command-line. */
static unsigned int condition_list_perms = 0644;
static unsigned int condition_uid_perms = 0;
static unsigned int condition_gid_perms = 0;

MODULE_AUTHOR("Stephane Ouellette <ouellettes@videotron.ca> and Massimiliano Hofer <max@nucleus.it>");
MODULE_DESCRIPTION("Allows rules to match against condition variables");
MODULE_LICENSE("GPL");
module_param(condition_list_perms, uint, 0600);
MODULE_PARM_DESC(condition_list_perms,"permissions on /proc/net/nf_condition/* files");
module_param(condition_uid_perms, uint, 0600);
MODULE_PARM_DESC(condition_uid_perms,"user owner of /proc/net/nf_condition/* files");
module_param(condition_gid_perms, uint, 0600);
MODULE_PARM_DESC(condition_gid_perms,"group owner of /proc/net/nf_condition/* files");
MODULE_ALIAS("ipt_condition");
MODULE_ALIAS("ip6t_condition");

struct condition_variable {
	struct list_head list;
	struct proc_dir_entry *status_proc;
	unsigned int refcount;
        int enabled;   /* TRUE == 1, FALSE == 0 */
};

/* proc_lock is a user context only semaphore used for write access */
/*           to the conditions' list.                               */
static DECLARE_MUTEX(proc_lock);

static LIST_HEAD(conditions_list);
static struct proc_dir_entry *proc_net_condition = NULL;

static int
xt_condition_read_info(char __user *buffer, char **start, off_t offset,
			int length, int *eof, void *data)
{
	const struct condition_variable *var = data;

	buffer[0] = (var->enabled) ? '1' : '0';
	buffer[1] = '\n';
	if (length>=2)
		*eof = 1;

	return 2;
}


static int
xt_condition_write_info(struct file *file, const char __user *buffer,
			 unsigned long length, void *data)
{
	struct condition_variable *var = data;
	char newval;

	if (length>0) {
		if (get_user(newval, buffer) != 0)
			return -EFAULT;
	        /* Match only on the first character */
		switch (newval) {
		case '0':
			var->enabled = 0;
			break;
		case '1':
			var->enabled = 1;
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
	static const char * const forbidden_names[]={ "", ".", ".." };
	const struct xt_condition_mtinfo *info = matchinfo;
	struct list_head *pos;
	struct condition_variable *var, *newvar;

	int i;

	/* We don't want a '/' in a proc file name. */
	for (i=0; i < CONDITION_NAME_LEN && info->name[i] != '\0'; i++)
		if (info->name[i] == '/')
			return 0;
	/* We can't handle file names longer than CONDITION_NAME_LEN and */
	/* we want a NULL terminated string. */
	if (i == CONDITION_NAME_LEN)
		return 0;

	/* We don't want certain reserved names. */
	for (i=0; i < sizeof(forbidden_names)/sizeof(char *); i++)
		if(strcmp(info->name, forbidden_names[i])==0)
			return 0;

	/* Let's acquire the lock, check for the condition and add it */
	/* or increase the reference counter.                         */
	if (down_interruptible(&proc_lock))
	   return -EINTR;

	list_for_each(pos, &conditions_list) {
		var = list_entry(pos, struct condition_variable, list);
		if (strcmp(info->name, var->status_proc->name) == 0) {
			var->refcount++;
			up(&proc_lock);
			return 1;
		}
	}

	/* At this point, we need to allocate a new condition variable. */
	newvar = kmalloc(sizeof(struct condition_variable), GFP_KERNEL);

	if (newvar == NULL) {
		up(&proc_lock);
		return -ENOMEM;
	}

	/* Create the condition variable's proc file entry. */
	newvar->status_proc = create_proc_entry(info->name, condition_list_perms, proc_net_condition);

	if (newvar->status_proc == NULL) {
		kfree(newvar);
		up(&proc_lock);
		return -ENOMEM;
	}

	newvar->refcount = 1;
	newvar->enabled = 0;
	newvar->status_proc->owner = THIS_MODULE;
	newvar->status_proc->data = newvar;
	wmb();
	newvar->status_proc->read_proc = xt_condition_read_info;
	newvar->status_proc->write_proc = xt_condition_write_info;

	list_add_rcu(&newvar->list, &conditions_list);

	newvar->status_proc->uid = condition_uid_perms;
	newvar->status_proc->gid = condition_gid_perms;

	up(&proc_lock);

	return 1;
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
				/* synchronize_rcu() would be goog enough, but synchronize_net() */
				/* guarantees that no packet will go out with the old rule after */
				/* succesful removal.                                            */
				synchronize_net();
				kfree(var);
				return;
			}
			break;
		}
	}

	up(&proc_lock);
}

static struct xt_match condition_match = {
	.name = "condition",
	.family = PF_INET,
	.matchsize  = XT_ALIGN(sizeof(struct xt_condition_mtinfo)),
	.match      = condition_mt,
	.checkentry = condition_mt_check,
	.destroy    = condition_mt_destroy,
	.me = THIS_MODULE
};

static struct xt_match condition6_match = {
	.name = "condition",
	.family = PF_INET6,
	.matchsize  = XT_ALIGN(sizeof(struct xt_condition_mtinfo)),
	.match      = condition_mt,
	.checkentry = condition_mt_check,
	.destroy    = condition_mt_destroy,
	.me = THIS_MODULE
};

static const char *const dir_name = "nf_condition";

static int __init
init(void)
{
	int errorcode;

	proc_net_condition = proc_mkdir(dir_name, proc_net);
	if (proc_net_condition == NULL) {
		remove_proc_entry(dir_name, proc_net);
		return -EACCES;
	}

        errorcode = xt_register_match(&condition_match);
	if (errorcode) {
		xt_unregister_match(&condition_match);
		remove_proc_entry(dir_name, proc_net);
		return errorcode;
	}

	errorcode = xt_register_match(&condition6_match);
	if (errorcode) {
		xt_unregister_match(&condition6_match);
		xt_unregister_match(&condition_match);
		remove_proc_entry(dir_name, proc_net);
		return errorcode;
	}

	return 0;
}

static void __exit
fini(void)
{
	xt_unregister_match(&condition6_match);
	xt_unregister_match(&condition_match);
	remove_proc_entry(dir_name, proc_net);
}

module_init(init);
module_exit(fini);
