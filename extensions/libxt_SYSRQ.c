/*
 *	"SYSRQ" target extension to iptables
 *	this file is in the Public Domain
 */
#include <stdio.h>
#include <getopt.h>
#include <xtables.h>

static void sysrq_tg_help(void)
{
	printf("SYSRQ takes no options\n\n");
}

static int sysrq_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                          const void *entry, struct xt_entry_target **target)
{
	return 0;
}

static void sysrq_tg_check(unsigned int flags)
{
}

static struct xtables_target sysrq_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "SYSRQ",
	.revision      = 1,
	.family        = PF_UNSPEC,
	.size          = XT_ALIGN(0),
	.userspacesize = XT_ALIGN(0),
	.help          = sysrq_tg_help,
	.parse         = sysrq_tg_parse,
	.final_check   = sysrq_tg_check,
};

static __attribute__((constructor)) void sysrq_tg_ldr(void)
{
	xtables_register_target(&sysrq_tg_reg);
}
