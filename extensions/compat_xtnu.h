#ifndef _COMPAT_XTNU_H
#define _COMPAT_XTNU_H 1

#include <linux/list.h>
#include <linux/netfilter/x_tables.h>
#include <linux/spinlock.h>

struct flowi;
struct module;
struct net_device;
struct rtable;
struct sk_buff;

struct xtnu_match {
	struct list_head list;
	char name[XT_FUNCTION_MAXNAMELEN - 1 - sizeof(void *)];
	bool (*match)(const struct sk_buff *, const struct net_device *,
		const struct net_device *, const struct xtnu_match *,
		const void *, int, unsigned int, bool *);
	bool (*checkentry)(const char *, const void *,
		const struct xtnu_match *, void *, unsigned int);
	void (*destroy)(const struct xtnu_match *, void *);
	struct module *me;
	const char *table;
	unsigned int matchsize, hooks;
	unsigned short proto, family;
	uint8_t revision;

	void *__compat_match;
};

struct xtnu_target {
	struct list_head list;
	char name[XT_FUNCTION_MAXNAMELEN - 1 - sizeof(void *)];
	unsigned int (*target)(struct sk_buff *, const struct net_device *,
		const struct net_device *, unsigned int,
		const struct xtnu_target *, const void *);
	bool (*checkentry)(const char *, const void *,
		const struct xtnu_target *, void *, unsigned int);
	void (*destroy)(const struct xtnu_target *, void *);
	struct module *me;
	const char *table;
	unsigned int targetsize, hooks;
	unsigned short proto, family;
	uint8_t revision;

	void *__compat_target;
};

static inline struct xtnu_match *xtcompat_numatch(const struct xt_match *m)
{
	void *q;
	memcpy(&q, m->name + sizeof(m->name) - sizeof(void *), sizeof(void *));
	return q;
}

static inline struct xtnu_target *xtcompat_nutarget(const struct xt_target *t)
{
	void *q;
	memcpy(&q, t->name + sizeof(t->name) - sizeof(void *), sizeof(void *));
	return q;
}

extern int xtnu_ip_local_out(struct sk_buff *);
extern int xtnu_ip_route_me_harder(struct sk_buff *, unsigned int);
extern int xtnu_register_match(struct xtnu_match *);
extern int xtnu_ip_route_output_key(void *, struct rtable **, struct flowi *);
extern void xtnu_unregister_match(struct xtnu_match *);
extern int xtnu_register_matches(struct xtnu_match *, unsigned int);
extern void xtnu_unregister_matches(struct xtnu_match *, unsigned int);
extern int xtnu_register_target(struct xtnu_target *);
extern void xtnu_unregister_target(struct xtnu_target *);
extern int xtnu_register_targets(struct xtnu_target *, unsigned int);
extern void xtnu_unregister_targets(struct xtnu_target *, unsigned int);
extern struct xt_match *xtnu_request_find_match(unsigned int,
	const char *, uint8_t);

#endif /* _COMPAT_XTNU_H */
