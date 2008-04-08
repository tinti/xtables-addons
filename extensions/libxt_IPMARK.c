/* Shared library add-on to iptables to add IPMARK target support.
 * (C) 2003 by Grzegorz Janoszka <Grzegorz.Janoszka@pro.onet.pl>
 *
 * based on original MARK target
 *
 * This program is distributed under the terms of GNU GPL
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include "xt_IPMARK.h"

#define IPT_ADDR_USED        1
#define IPT_AND_MASK_USED    2
#define IPT_OR_MASK_USED     4

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"IPMARK target options:\n"
"  --addr src/dst         use source or destination ip address\n"
"  --and-mask value       logical AND ip address with this value becomes MARK\n"
"  --or-mask value        logical OR ip address with this value becomes MARK\n"
"\n");
}

static struct option opts[] = {
	{ "addr", 1, 0, '1' },
	{ "and-mask", 1, 0, '2' },
	{ "or-mask", 1, 0, '3' },
	{ 0 }
};

/* Initialize the target. */
static void
init(struct xt_entry_target *t)
{
	struct xt_ipmark_tginfo *info = (void *)t->data;

	info->andmask = ~0U;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
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

static void
final_check(unsigned int flags)
{
	if (!(flags & IPT_ADDR_USED))
		exit_error(PARAMETER_PROBLEM,
		           "IPMARK target: Parameter --addr is required");
	if (!(flags & (IPT_AND_MASK_USED | IPT_OR_MASK_USED)))
		exit_error(PARAMETER_PROBLEM,
		           "IPMARK target: Parameter --and-mask or --or-mask is required");
}

/* Prints out the targinfo. */
static void
print(const void *entry, const struct xt_entry_target *target,
      int numeric)
{
	const struct xt_ipmark_tginfo *info = (const void *)target->data;

	if (info->selector == XT_IPMARK_SRC)
	  printf("IPMARK src");
	else
	  printf("IPMARK dst");
	printf(" ip and 0x%x or 0x%x",
	       (unsigned int)info->andmask, (unsigned int)info->ormask);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const void *entry, const struct xt_entry_target *target)
{
	const struct xt_ipmark_tginfo *info = (const void *)target->data;

	if (info->selector == XT_IPMARK_SRC)
	  printf("--addr=src ");
	else
	  printf("--addr=dst ");
	if (info->andmask != ~0U)
		printf("--and-mask 0x%x ", (unsigned int)info->andmask);
	if (info->ormask != 0)
		printf("--or-mask 0x%x ", (unsigned int)info->ormask);
}

static struct xtables_target ipmark = {
	.next          = NULL,
	.name          = "IPMARK",
	.version       = XTABLES_VERSION,
	.size          = XT_ALIGN(sizeof(struct xt_ipmark_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_ipmark_tginfo)),
	.help          = &help,
	.init          = &init,
	.parse         = &parse,
	.final_check   = &final_check,
	.print         = &print,
	.save          = &save,
	.extra_opts    = opts
};

void _init(void)
{
	xtables_register_target(&ipmark);
}
