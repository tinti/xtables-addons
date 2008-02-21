#include <stdio.h>
#include <getopt.h>
#include <xtables.h>

static void tarpit_tg_help(void)
{
	printf("TARPIT takes no options\n\n");
}

static int tarpit_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_target **target)
{
	return 0;
}

static void tarpit_tg_check(unsigned int flags)
{
}

static struct xtables_target tarpit_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "TARPIT",
	.family        = AF_INET,
	.size          = XT_ALIGN(0),
	.userspacesize = XT_ALIGN(0),
	.help          = tarpit_tg_help,
	.parse         = tarpit_tg_parse,
	.final_check   = tarpit_tg_check,
};

static void _init(void)
{
	xtables_register_target(&tarpit_tg_reg);
}
