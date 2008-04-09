#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_arp.h>
#include <net/ip.h>
#include <net/route.h>
#include "compat_skbuff.h"
#include "compat_xtnu.h"

static inline int unable(const char *cause)
{
	if (net_ratelimit())
		printk(KERN_ERR KBUILD_MODNAME
		       ": compat layer limits reached (%s) - dropping packets\n", cause);
	return -1;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
static int xtnu_match_run(const struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out,
    const struct xt_match *cm, const void *matchinfo, int offset,
    unsigned int protoff, int *hotdrop)
{
	struct xtnu_match *nm = xtcompat_numatch(cm);
	bool lo_drop, lo_ret;

	if (nm == NULL || nm->match == NULL)
		return false;
	lo_ret = nm->match(skb, in, out, nm, matchinfo,
	         offset, protoff, &lo_drop);
	*hotdrop = lo_drop;
	return lo_ret;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
static int xtnu_match_check(const char *table, const void *entry,
    const struct xt_match *cm, void *matchinfo, unsigned int matchinfosize,
    unsigned int hook_mask)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
static int xtnu_match_check(const char *table, const void *entry,
    const struct xt_match *cm, void *matchinfo, unsigned int hook_mask)
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
{
	struct xtnu_match *nm = xtcompat_numatch(cm);

	if (nm == NULL)
		return false;
	if (nm->checkentry == NULL)
		return true;
	return nm->checkentry(table, entry, nm, matchinfo, hook_mask);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
static void xtnu_match_destroy(const struct xt_match *cm, void *matchinfo,
    unsigned int matchinfosize)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
static void xtnu_match_destroy(const struct xt_match *cm, void *matchinfo)
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
{
	struct xtnu_match *nm = xtcompat_numatch(cm);

	if (nm != NULL && nm->destroy != NULL)
		nm->destroy(nm, matchinfo);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
int xtnu_register_match(struct xtnu_match *nt)
{
	struct xt_match *ct;
	char *tmp;
	int ret;

	ct = kzalloc(sizeof(struct xt_match), GFP_KERNEL);
	if (ct == NULL)
		return -ENOMEM;

	tmp = (char *)ct->name;
	memcpy(tmp, nt->name, sizeof(nt->name));
	tmp = (char *)(ct->name + sizeof(ct->name) - sizeof(void *));
	*(tmp-1) = '\0';
	memcpy(tmp, &nt, sizeof(void *));

	ct->revision   = nt->revision;
	ct->family     = nt->family;
	ct->table      = (char *)nt->table;
	ct->hooks      = nt->hooks;
	ct->proto      = nt->proto;
	ct->match      = xtnu_match_run;
	ct->checkentry = xtnu_match_check;
	ct->destroy    = xtnu_match_destroy;
	ct->matchsize  = nt->matchsize;
	ct->me         = nt->me;

	nt->__compat_match = ct;
	ret = xt_register_match(ct);
	if (ret != 0)
		kfree(ct);
	return ret;
}
EXPORT_SYMBOL_GPL(xtnu_register_match);

int xtnu_register_matches(struct xtnu_match *nt, unsigned int num)
{
	unsigned int i;
	int ret;

	for (i = 0; i < num; ++i) {
		ret = xtnu_register_match(&nt[i]);
		if (ret < 0) {
			if (i > 0)
				xtnu_unregister_matches(nt, i);
			return ret;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(xtnu_register_matches);

void xtnu_unregister_match(struct xtnu_match *nt)
{
	xt_unregister_match(nt->__compat_match);
	kfree(nt->__compat_match);
}
EXPORT_SYMBOL_GPL(xtnu_unregister_match);

void xtnu_unregister_matches(struct xtnu_match *nt, unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; ++i)
		xtnu_unregister_match(&nt[i]);
}
EXPORT_SYMBOL_GPL(xtnu_unregister_matches);
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
static unsigned int xtnu_target_run(struct sk_buff **pskb,
    const struct net_device *in, const struct net_device *out,
    unsigned int hooknum, const struct xt_target *ct, const void *targinfo,
    void *userdata)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
static unsigned int xtnu_target_run(struct sk_buff **pskb,
    const struct net_device *in, const struct net_device *out,
    unsigned int hooknum, const struct xt_target *ct, const void *targinfo)
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
{
	struct xtnu_target *nt = xtcompat_nutarget(ct);
	if (nt != NULL && nt->target != NULL)
		return nt->target(*pskb, in, out, hooknum, nt, targinfo);
	return XT_CONTINUE;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
static int xtnu_target_check(const char *table, const void *entry,
    const struct xt_target *ct, void *targinfo,
    unsigned int targinfosize, unsigned int hook_mask)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
static int xtnu_target_check(const char *table, const void *entry,
    const struct xt_target *ct, void *targinfo, unsigned int hook_mask)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
static bool xtnu_target_check(const char *table, const void *entry,
    const struct xt_target *ct, void *targinfo, unsigned int hook_mask)
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
{
	struct xtnu_target *nt = xtcompat_nutarget(ct);
	if (nt == NULL)
		return false;
	if (nt->checkentry == NULL)
		/* this is valid, just like if there was no function */
		return true;
	return nt->checkentry(table, entry, nt, targinfo, hook_mask);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
static void xtnu_target_destroy(const struct xt_target *ct, void *targinfo,
    unsigned int targinfosize)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
static void xtnu_target_destroy(const struct xt_target *ct, void *targinfo)
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
{
	struct xtnu_target *nt = xtcompat_nutarget(ct);
	if (nt != NULL && nt->destroy != NULL)
		nt->destroy(nt, targinfo);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
int xtnu_register_target(struct xtnu_target *nt)
{
	struct xt_target *ct;
	char *tmp;
	int ret;

	ct = kzalloc(sizeof(struct xt_target), GFP_KERNEL);
	if (ct == NULL)
		return -ENOMEM;

	tmp = (char *)ct->name;
	memcpy(tmp, nt->name, sizeof(nt->name));
	tmp = (char *)(ct->name + sizeof(ct->name) - sizeof(void *));
	*(tmp-1) = '\0';
	memcpy(tmp, &nt, sizeof(void *));

	ct->revision   = nt->revision;
	ct->family     = nt->family;
	ct->table      = (char *)nt->table;
	ct->hooks      = nt->hooks;
	ct->proto      = nt->proto;
	ct->target     = xtnu_target_run;
	ct->checkentry = xtnu_target_check;
	ct->destroy    = xtnu_target_destroy;
	ct->targetsize = nt->targetsize;
	ct->me         = nt->me;

	nt->__compat_target = ct;
	ret = xt_register_target(ct);
	if (ret != 0)
		kfree(ct);
	return ret;
}
EXPORT_SYMBOL_GPL(xtnu_register_target);

int xtnu_register_targets(struct xtnu_target *nt, unsigned int num)
{
	unsigned int i;
	int ret;

	for (i = 0; i < num; ++i) {
		ret = xtnu_register_target(&nt[i]);
		if (ret < 0) {
			if (i > 0)
				xtnu_unregister_targets(nt, i);
			return ret;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(xtnu_register_targets);

void xtnu_unregister_target(struct xtnu_target *nt)
{
	xt_unregister_target(nt->__compat_target);
	kfree(nt->__compat_target);
}
EXPORT_SYMBOL_GPL(xtnu_unregister_target);

void xtnu_unregister_targets(struct xtnu_target *nt, unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; ++i)
		xtnu_unregister_target(&nt[i]);
}
EXPORT_SYMBOL_GPL(xtnu_unregister_targets);
#endif

struct xt_match *xtnu_request_find_match(unsigned int af, const char *name,
    uint8_t revision)
{
	static const char *const xt_prefix[] = {
		[AF_UNSPEC] = "x",
		[AF_INET]   = "ip",
		[AF_INET6]  = "ip6",
#ifdef AF_ARP
		[AF_ARP]    = "arp",
#elif defined(NF_ARP) && NF_ARP != AF_UNSPEC
		[NF_ARP]    = "arp",
#endif
	};
	struct xt_match *match;

	match = try_then_request_module(xt_find_match(af, name, revision),
		"%st_%s", xt_prefix[af], name);
	if (IS_ERR(match) || match == NULL)
		return NULL;

	return match;
}
EXPORT_SYMBOL_GPL(xtnu_request_find_match);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
int xtnu_ip_route_me_harder(struct sk_buff *skb, unsigned int addr_type)
{
	struct sk_buff *nskb = skb;
	int ret;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
	ret = ip_route_me_harder(&skb);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
	ret = ip_route_me_harder(&nskb, addr_type);
#endif
	if (nskb != skb)
		return unable(__func__);
	return ret;
}
EXPORT_SYMBOL_GPL(xtnu_ip_route_me_harder);

int xtnu_skb_make_writable(struct sk_buff *skb, unsigned int len)
{
	struct sk_buff *nskb = skb;
	int ret;

	ret = skb_make_writable(&skb, len);
	if (nskb != skb)
		return unable(__func__);
	return ret;
}
EXPORT_SYMBOL_GPL(xtnu_skb_make_writable);
#endif

#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 24)
static int __xtnu_ip_local_out(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->tot_len = htons(skb->len);
	ip_send_check(iph);
	return nf_hook(PF_INET, NF_IP_LOCAL_OUT, skb, NULL,
	               skb->dst->dev, dst_output);
}

int xtnu_ip_local_out(struct sk_buff *skb)
{
	int err;

	err = __xtnu_ip_local_out(skb);
	if (likely(err == 1))
		err = dst_output(skb);

	return err;
}
EXPORT_SYMBOL_GPL(xtnu_ip_local_out);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
static int __xtnu_ip_local_out(struct sk_buff **pskb)
{
	struct iphdr *iph = ip_hdr(*pskb);

	iph->tot_len = htons((*pskb)->len);
	ip_send_check(iph);
	return nf_hook(PF_INET, NF_IP_LOCAL_OUT, pskb, NULL,
	               (*pskb)->dst->dev, dst_output);
}

int xtnu_ip_local_out(struct sk_buff *skb)
{
	int err;

	err = __xtnu_ip_local_out(&skb);
	if (likely(err == 1))
		err = dst_output(skb);

	return err;
}
EXPORT_SYMBOL_GPL(xtnu_ip_local_out);
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
int xtnu_ip_route_output_key(void *net, struct rtable **rp, struct flowi *flp)
{
	return ip_route_output_flow(rp, flp, NULL, 0);
}
EXPORT_SYMBOL_GPL(xtnu_ip_route_output_key);
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19)
int xtnu_neigh_hh_output(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned int hh_alen;

	read_lock_bh(&hh->hh_lock);
	hh_alen = HH_DATA_ALIGN(hh->hh_len);
	memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
	read_unlock_bh(&hh->hh_lock);
	skb_push(skb, hh->hh_len);
	return hh->hh_output(skb);
}
EXPORT_SYMBOL_GPL(xtnu_neigh_hh_output);
#endif

MODULE_LICENSE("GPL");
