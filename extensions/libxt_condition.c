/* Shared library add-on to iptables for condition match */
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <xtables.h>
#include "xt_condition.h"

static void condition_help(void)
{
	printf(
"condition match options:\n"
"[!] --condition name    Match on boolean value stored in procfs file\n"
);
}

static const struct option condition_opts[] = {
	{.name = "condition", .has_arg = true, .val = 'X'},
	{NULL},
};

static int condition_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_match **match)
{
	struct xt_condition_mtinfo *info = (void *)(*match)->data;

	if (c == 'X') {
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify multiple conditions");

		if (strlen(optarg) < sizeof(info->name))
			strcpy(info->name, optarg);
		else
			exit_error(PARAMETER_PROBLEM,
				   "File name too long");

		info->invert = invert;
		*flags = 1;
		return true;
	}

	return false;
}

static void condition_check(unsigned int flags)
{
	if (flags == 0)
		exit_error(PARAMETER_PROBLEM,
			   "Condition match: must specify --condition");
}

static void condition_print(const void *ip, const struct xt_entry_match *match,
                            int numeric)
{
	const struct xt_condition_mtinfo *info = (const void *)match->data;

	printf("condition %s%s ", (info->invert) ? "!" : "", info->name);
}


static void condition_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_condition_mtinfo *info = (const void *)match->data;

	printf("--condition %s\"%s\" ", (info->invert) ? "! " : "", info->name);
}

static struct xtables_match condition_mt_reg = {
	.name 		= "condition",
	.revision	= 0,
	.family		= PF_UNSPEC,
	.version 	= XTABLES_VERSION,
	.size 		= XT_ALIGN(sizeof(struct xt_condition_mtinfo)),
	.userspacesize 	= XT_ALIGN(sizeof(struct xt_condition_mtinfo)),
	.help 		= condition_help,
	.parse 		= condition_parse,
	.final_check	= condition_check,
	.print 		= condition_print,
	.save 		= condition_save,
	.extra_opts 	= condition_opts,
};

static void _init(void)
{
	xtables_register_match(&condition_mt_reg);
}
