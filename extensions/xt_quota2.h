#ifndef _XT_QUOTA_H
#define _XT_QUOTA_H

enum xt_quota_flags {
	XT_QUOTA_INVERT = 0x1,
	XT_QUOTA_GROW   = 0x2,
	XT_QUOTA_MASK   = 0x3,

	XT_QUOTA_COUNTER_NAME_LENGTH = 31,
};

struct quota_counter;

struct xt_quota_mtinfo2 {
	char name[XT_QUOTA_COUNTER_NAME_LENGTH];
	u_int8_t flags;

	/* Comparison-invariant */
	aligned_u64 quota;

	/* Used internally by the kernel */
	struct quota_counter *master __attribute__((aligned(8)));
};

#endif /* _XT_QUOTA_H */
