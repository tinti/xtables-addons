#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include "xt_LOGMARK.h"

enum {
	F_LEVEL   = 1 << 0,
	F_PREFIX  = 1 << 1,
	F_NFMARK  = 1 << 2,
	F_CTMARK  = 1 << 3,
	F_SECMARK = 1 << 4,
};

static const struct option logmark_tg_opts[] = {
	{.name = "log-level",   .has_arg = true,  .val = 'l'},
	{.name = "log-prefix",  .has_arg = true,  .val = 'p'},
	{.name = "log-nfmark",  .has_arg = false, .val = 'n'},
	{.name = "log-ctmark",  .has_arg = false, .val = 'c'},
	{.name = "log-secmark", .has_arg = false, .val = 's'},
	{},
};

static void logmark_tg_help(void)
{
	printf(
"LOGMARK target options:\n"
"  --log-level level      Level of logging (numeric, 0-8)\n"
"  --log-prefix prefix    Prefix log messages with this string\n"
"  --log-nfmark           Log the packet mark\n"
"  --log-ctmark           Log the connection mark\n"
"  --log-secmark          Log the security mark of the packet\n"
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

	case 'n': /* --log-nfmark */
		param_act(P_ONLY_ONCE, "LOGMARK", "--log-nfmark", *flags & F_NFMARK);
		param_act(P_NO_INVERT, "LOGMARK", "--log-nfmark", invert);
		info->flags |= XT_LOGMARK_NFMARK;
		*flags |= F_NFMARK;
		return true;

	case 'c': /* --log-ctmark */
		param_act(P_ONLY_ONCE, "LOGMARK", "--log-ctmark", *flags & F_CTMARK);
		param_act(P_NO_INVERT, "LOGMARK", "--log-ctmark", invert);
		info->flags |= XT_LOGMARK_CTMARK;
		*flags |= F_CTMARK;
		return true;

	case 's': /* --log-secmark */
		param_act(P_ONLY_ONCE, "LOGMARK", "--log-secmark", *flags & F_SECMARK);
		param_act(P_NO_INVERT, "LOGMARK", "--log-secmark", invert);
		info->flags |= XT_LOGMARK_SECMARK;
		*flags |= F_SECMARK;
		return true;
	}
	return false;
}

static void
logmark_tg_print(const void *ip, const struct xt_entry_target *target,
                 int numeric)
{
	const struct xt_logmark_tginfo *info = (void *)target->data;

	printf("LOGMARK level %u prefix \"%s\"", info->level, info->prefix);
	if (info->flags & XT_LOGMARK_NFMARK)
		printf(" nfmark");
	if (info->flags & XT_LOGMARK_CTMARK)
		printf(" ctmark");
	if (info->flags & XT_LOGMARK_SECMARK)
		printf(" secmark");
	printf("; ");
}

static void
logmark_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_logmark_tginfo *info = (void *)target->data;

	if (info->level != 4)
		printf("--log-level %u ", info->level);
	if (*info->prefix != '\0')
		printf("--log-prefix \"%s\" ", info->prefix);
	if (info->flags & XT_LOGMARK_NFMARK)
		printf("--log-nfmark ");
	if (info->flags & XT_LOGMARK_CTMARK)
		printf("--log-ctmark ");
	if (info->flags & XT_LOGMARK_SECMARK)
		printf("--log-secmark ");
}

static struct xtables_target logmark_tg_reg = {
	.version       = IPTABLES_VERSION,
	.name          = "LOGMARK",
	.revision      = 0,
	.family        = AF_INET,
	.size          = XT_ALIGN(sizeof(struct xt_logmark_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_logmark_tginfo)),
	.help          = logmark_tg_help,
	.init          = logmark_tg_init,
	.parse         = logmark_tg_parse,
	.print         = logmark_tg_print,
	.save          = logmark_tg_save,
	.extra_opts    = logmark_tg_opts,
};

static struct xtables_target logmark_tg6_reg = {
	.version       = IPTABLES_VERSION,
	.name          = "LOGMARK",
	.revision      = 0,
	.family        = AF_INET6,
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
	xtables_register_target(&logmark_tg6_reg);
}
