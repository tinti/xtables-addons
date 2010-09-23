#include <stdio.h>
#include <xtables.h>
#include "compat_user.h"

static void steal_tg_help(void)
{
	printf("STEAL takes no options\n\n");
}

static int steal_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                          const void *entry, struct xt_entry_target **target)
{
	return 0;
}

static void steal_tg_check(unsigned int flags)
{
}

static struct xtables_target steal_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "STEAL",
	.family        = NFPROTO_UNSPEC,
	.help          = steal_tg_help,
	.parse         = steal_tg_parse,
	.final_check   = steal_tg_check,
};

static void _init(void)
{
	xtables_register_target(&steal_tg_reg);
}
