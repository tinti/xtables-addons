/*
 *	"LOGMARK" target extension for iptables
 *	Copyright © Jan Engelhardt <jengelh [at] medozas de>, 2008
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include "xt_LOGMARK.h"

enum {
	F_LEVEL  = 1 << 0,
	F_PREFIX = 1 << 1,
};

static const struct option logmark_tg_opts[] = {
	{.name = "log-level",   .has_arg = true,  .val = 'l'},
	{.name = "log-prefix",  .has_arg = true,  .val = 'p'},
	{NULL},
};

static void logmark_tg_help(void)
{
	printf(
"LOGMARK target options:\n"
"  --log-level level      Level of logging (numeric, 0-8)\n"
"  --log-prefix prefix    Prefix log messages with this string\n"
);
}

static void logmark_tg_init(struct xt_entry_target *target)
{
	struct xt_logmark_tginfo *info = (void *)target->data;

	info->level   = 4;
	*info->prefix = '\0';
}

static int
logmark_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                 const void *entry, struct xt_entry_target **target)
{
	struct xt_logmark_tginfo *info = (void *)(*target)->data;
	unsigned int x;

	switch (c) {
	case 'l': /* --log-level */
		param_act(P_ONLY_ONCE, "LOGMARK", "--log-level", *flags & F_LEVEL);
		param_act(P_NO_INVERT, "LOGMARK", "--log-level", invert);
		if (!strtonum(optarg, NULL, &x, 0, 8))
			param_act(P_BAD_VALUE, "LOGMARK", "--log-level", optarg);
		info->level = x;
		*flags |= F_LEVEL;
		return true;

	case 'p': /* --log-prefix */
		param_act(P_ONLY_ONCE, "LOGMARK", "--log-prefix", *flags & F_PREFIX);
		param_act(P_NO_INVERT, "LOGMARK", "--log-prefix", invert);
		if (strlen(optarg) > sizeof(info->prefix))
			exit_error(PARAMETER_PROBLEM, "LOGMARK: Maximum "
			           "prefix length is %zu",
			           sizeof(info->prefix));
		if (strchr(optarg, '\n'))
			exit_error(PARAMETER_PROBLEM, "LOGMARK: Newlines not "
			           "allowed in log prefix");
		strncpy(info->prefix, optarg, sizeof(info->prefix));
		*flags |= F_PREFIX;
		return true;
	}
	return false;
}

static void
logmark_tg_print(const void *ip, const struct xt_entry_target *target,
                 int numeric)
{
	const struct xt_logmark_tginfo *info = (void *)target->data;

	printf("LOGMARK level %u prefix \"%s\" ", info->level, info->prefix);
}

static void
logmark_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_logmark_tginfo *info = (void *)target->data;

	if (info->level != 4)
		printf("--log-level %u ", info->level);
	if (*info->prefix != '\0')
		printf("--log-prefix \"%s\" ", info->prefix);
}

static struct xtables_target logmark_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "LOGMARK",
	.revision      = 0,
	.family        = AF_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_logmark_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_logmark_tginfo)),
	.help          = logmark_tg_help,
	.init          = logmark_tg_init,
	.parse         = logmark_tg_parse,
	.print         = logmark_tg_print,
	.save          = logmark_tg_save,
	.extra_opts    = logmark_tg_opts,
};

void _init(void);
void _init(void)
{
	xtables_register_target(&logmark_tg_reg);
}
