/* Shared library add-on to iptables to add IPMARK target support.
 * (C) 2003 by Grzegorz Janoszka <Grzegorz.Janoszka@pro.onet.pl>
 *
 * based on original MARK target
 *
 * This program is distributed under the terms of GNU GPL
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include "xt_IPMARK.h"

#define IPT_ADDR_USED        1
#define IPT_AND_MASK_USED    2
#define IPT_OR_MASK_USED     4

/* Function which prints out usage message. */
static void ipmark_tg_help(void)
{
	printf(
"IPMARK target options:\n"
"  --addr src/dst         use source or destination ip address\n"
"  --and-mask value       logical AND ip address with this value becomes MARK\n"
"  --or-mask value        logical OR ip address with this value becomes MARK\n"
"\n");
}

static const struct option ipmark_tg_opts[] = {
	{ "addr", 1, 0, '1' },
	{ "and-mask", 1, 0, '2' },
	{ "or-mask", 1, 0, '3' },
	{NULL},
};

/* Initialize the target. */
static void ipmark_tg_init(struct xt_entry_target *t)
{
	struct xt_ipmark_tginfo *info = (void *)t->data;

	info->andmask = ~0U;
}

static int ipmark_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_target **target)
{
	struct xt_ipmark_tginfo *info = (void *)(*target)->data;

	switch (c) {
		char *end;
	case '1':
		if(!strcmp(optarg, "src")) info->selector=XT_IPMARK_SRC;
		  else if(!strcmp(optarg, "dst")) info->selector=XT_IPMARK_DST;
		    else exit_error(PARAMETER_PROBLEM, "Bad addr value `%s' - should be `src' or `dst'", optarg);
		if (*flags & IPT_ADDR_USED)
			exit_error(PARAMETER_PROBLEM,
			           "IPMARK target: Can't specify --addr twice");
		*flags |= IPT_ADDR_USED;
		break;
	
	case '2':
		info->andmask = strtoul(optarg, &end, 0);
		if (*end != '\0' || end == optarg)
			exit_error(PARAMETER_PROBLEM, "Bad and-mask value `%s'", optarg);
		if (*flags & IPT_AND_MASK_USED)
			exit_error(PARAMETER_PROBLEM,
			           "IPMARK target: Can't specify --and-mask twice");
		*flags |= IPT_AND_MASK_USED;
		break;
	case '3':
		info->ormask = strtoul(optarg, &end, 0);
		if (*end != '\0' || end == optarg)
			exit_error(PARAMETER_PROBLEM, "Bad or-mask value `%s'", optarg);
		if (*flags & IPT_OR_MASK_USED)
			exit_error(PARAMETER_PROBLEM,
			           "IPMARK target: Can't specify --or-mask twice");
		*flags |= IPT_OR_MASK_USED;
		break;

	default:
		return 0;
	}

	return 1;
}

static void ipmark_tg_check(unsigned int flags)
{
	if (!(flags & IPT_ADDR_USED))
		exit_error(PARAMETER_PROBLEM,
		           "IPMARK target: Parameter --addr is required");
}

static void
ipmark_tg_print(const void *entry, const struct xt_entry_target *target,
                int numeric)
{
	const struct xt_ipmark_tginfo *info = (const void *)target->data;

	if (info->selector == XT_IPMARK_SRC)
		printf("IPMARK src ip");
	else
		printf("IPMARK dst ip");

	if (info->andmask != ~0U)
		printf(" and 0x%x ", (unsigned int)info->andmask);
	if (info->ormask != 0)
		printf(" or 0x%x ", (unsigned int)info->ormask);
}

static void
ipmark_tg_save(const void *entry, const struct xt_entry_target *target)
{
	const struct xt_ipmark_tginfo *info = (const void *)target->data;

	if (info->selector == XT_IPMARK_SRC)
		printf("--addr src ");
	else
		printf("--addr dst ");

	if (info->andmask != ~0U)
		printf("--and-mask 0x%x ", (unsigned int)info->andmask);
	if (info->ormask != 0)
		printf("--or-mask 0x%x ", (unsigned int)info->ormask);
}

static struct xtables_target ipmark_tg4_reg = {
	.version       = XTABLES_VERSION,
	.name          = "IPMARK",
	.family        = PF_INET,
	.revision      = 0,
	.size          = XT_ALIGN(sizeof(struct xt_ipmark_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_ipmark_tginfo)),
	.help          = ipmark_tg_help,
	.init          = ipmark_tg_init,
	.parse         = ipmark_tg_parse,
	.final_check   = ipmark_tg_check,
	.print         = ipmark_tg_print,
	.save          = ipmark_tg_save,
	.extra_opts    = ipmark_tg_opts,
};

static void _init(void)
{
	xtables_register_target(&ipmark_tg4_reg);
}
