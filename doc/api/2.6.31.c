match:

	/* true/false */
	bool
	(*match)(
		const struct sk_buff *skb,
		const struct xt_match_param *,
	);

	/* true/false */
	bool
	(*checkentry)(
		const struct xt_mtchk_param *,
	);

	void
	(*destroy)(
		const struct xt_mtdtor_param *,
	);

target:

	unsigned int
	(*target)(
		struct sk_buff *skb,
		const struct xt_target_param *,
	);

	/* true/false */
	bool
	(*checkentry)(
		const struct xt_tgchk_param *,
	);

	void
	(*destroy)(
		const struct xt_tgdtor_param *,
	);
