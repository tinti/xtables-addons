match:

	/* true/false */
	int
	(*match)(
		const struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		const struct xt_match *match,
		const void *matchinfo,
		int offset,
		unsigned int protoff,
		int *hotdrop,
	);

	/* true/false */
	int
	(*checkentry)(
		const char *tablename,
		const void *ip,
		const struct xt_match *match,
		void *matchinfo,
		unsigned int matchinfosize,
		unsigned int hook_mask,
	);

	void
	(*destroy)(
		const struct xt_match *match,
		void *matchinfo,
		unsigned int matchinfosize,
	);

target:

	/* verdict */
	unsigned int
	(*target)(
		struct sk_buff **pskb,
		const struct net_device *in,
		const struct net_device *out,
		unsigned int hooknum,
		const struct xt_target *target,
		const void *targinfo,
		void *userdata,
	);

	/* true/false */
	int
	(*checkentry)(
		const char *tablename,
		const void *entry,
		const struct xt_target *target,
		void *targinfo,
		unsigned int targinfosize,
		unsigned int hook_mask,
	);

	void
	(*destroy)(
		const struct xt_target *target,
		void *targinfo,
		unsigned int targinfosize,
	);
