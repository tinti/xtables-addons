#ifndef _XT_QUOTA_H
#define _XT_QUOTA_H

enum xt_quota_flags {
	XT_QUOTA_INVERT = 0x1,
	XT_QUOTA_GROW   = 0x2,
	XT_QUOTA_MASK   = 0x3,
};

struct quota_sysfs_entry;

struct xt_quota_mtinfo2 {
	char name[31];
	u_int8_t flags;

	/* Comparison-invariant section */
	aligned_u64 quota;

	/* Used internally by the kernel */
	struct xt_quota_mtinfo2 *master __attribute__((aligned(8)));
	void *procfs_entry __attribute__((aligned(8)));
};

#endif /* _XT_QUOTA_H */
