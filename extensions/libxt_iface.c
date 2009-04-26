/*
 * Shared library add-on to iptables to add interface state matching
 * support.
 *
 * (C) 2008 Gáspár Lajos <gaspar.lajos@glsys.eu>
 *
 * This program is released under the terms of GNU GPL version 2.
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xtables.h>
#include "xt_iface.h"

static const struct option iface_mt_opts[] = {
	{.name = "iface",	.has_arg = true,  .val = 'i'},
	{.name = "up",		.has_arg = false, .val = 'u'},
	{.name = "down",	.has_arg = false, .val = 'U'}, /* not up */
	{.name = "broadcast",	.has_arg = false, .val = 'b'},
	{.name = "loopback",	.has_arg = false, .val = 'l'},
	{.name = "pointopoint",	.has_arg = false, .val = 'p'},
	{.name = "pointtopoint",.has_arg = false, .val = 'p'}, /* eq pointopoint */
	{.name = "running",	.has_arg = false, .val = 'r'},
	{.name = "noarp",	.has_arg = false, .val = 'n'},
	{.name = "arp",		.has_arg = false, .val = 'N'}, /* not noarp */
	{.name = "promisc",	.has_arg = false, .val = 'o'},
	{.name = "promiscous",	.has_arg = false, .val = 'o'}, /* eq promisc */
	{.name = "multicast",	.has_arg = false, .val = 'm'},
	{.name = "dynamic",	.has_arg = false, .val = 'd'},
	{.name = "lower_up",	.has_arg = false, .val = 'w'},
	{.name = "dormant",	.has_arg = false, .val = 'a'},
	{.name = NULL},
};

static void iface_print_opt(const struct xt_iface_mtinfo *info,
    const unsigned int option, const char *command)
{
	if (info->flags & option)
		printf(" %s", command);
	if (info->invflags & option)
		printf(" ! %s", command);
}

static void iface_setflag(struct xt_iface_mtinfo *info,
    unsigned int *flags, int invert, u_int16_t flag, const char *command)
{
	if (*flags & flag)
		xtables_error(PARAMETER_PROBLEM,
			"iface: \"--%s\" flag already specified", command);
	if (invert)
		info->invflags |= flag;
	else
		info->flags |= flag;
	*flags |= flag;
}

static bool iface_valid_name(const char *name)
{
	static const char invalid_chars[] = ".+!*";

	return strlen(name) < IFNAMSIZ && strpbrk(name, invalid_chars) == NULL;
}

static void iface_mt_help(void)
{
	printf(
	"iface match options:\n"
	"    --iface interface\t\tName of interface\n"
	"[!] --up\n"
	"[!] --down\t\t\tmatch if UP flag (not) set\n"
	"[!] --broadcast\t\tmatch if BROADCAST flag (not) set\n"
	"[!] --loopback\t\t\tmatch if LOOPBACK flag (not) set\n"
	"[!] --pointopoint\n"
	"[!] --pointtopoint\t\tmatch if POINTOPOINT flag (not) set\n"
	"[!] --running\t\t\tmatch if RUNNING flag (not) set\n"
	"[!] --noarp\n"
	"[!] --arp\t\t\tmatch if NOARP flag (not) set\n"
	"[!] --promisc\n"
	"[!] --promiscous\t\tmatch if PROMISC flag (not) set\n"
	"[!] --multicast\t\tmatch if MULTICAST flag (not) set\n"
	"[!] --dynamic\t\t\tmatch if DYNAMIC flag (not) set\n"
	"[!] --lower_up\t\t\tmatch if LOWER_UP flag (not) set\n"
	"[!] --dormant\t\t\tmatch if DORMANT flag (not) set\n");
}

static int iface_mt_parse(int c, char **argv, int invert, unsigned int *flags,
    const void *entry, struct xt_entry_match **match)
{
	struct xt_iface_mtinfo *info = (void *)(*match)->data;

	switch (c) {
	case 'U':
		c = 'u';
		invert = !invert;
		break;
	case 'N':
		c = 'n';
		invert = !invert;
		break;
	}

	switch (c) {
	case 'i': /* interface name */
		if (*flags & XT_IFACE_IFACE)
			xtables_error(PARAMETER_PROBLEM,
				"iface: Interface name already specified");
		if (!iface_valid_name(optarg))
			xtables_error(PARAMETER_PROBLEM,
				"iface: Invalid interface name!");
		strcpy(info->ifname, optarg);
		*flags |= XT_IFACE_IFACE;
		return true;
	case 'u': /* UP */
		iface_setflag(info, flags, invert, XT_IFACE_UP, "up");
		return true;
	case 'b': /* BROADCAST */
		iface_setflag(info, flags, invert, XT_IFACE_BROADCAST, "broadcast");
		return true;
	case 'l': /* LOOPBACK */
		iface_setflag(info, flags, invert, XT_IFACE_LOOPBACK, "loopback");
		return true;
	case 'p': /* POINTOPOINT */
		iface_setflag(info, flags, invert, XT_IFACE_POINTOPOINT, "pointopoint");
		return true;
	case 'r': /* RUNNING */
		iface_setflag(info, flags, invert, XT_IFACE_RUNNING, "running");
		return true;
	case 'n': /* NOARP */
		iface_setflag(info, flags, invert, XT_IFACE_NOARP, "noarp");
		return true;
	case 'o': /* PROMISC */
		iface_setflag(info, flags, invert, XT_IFACE_PROMISC, "promisc");
		return true;
	case 'm': /* MULTICAST */
		iface_setflag(info, flags, invert, XT_IFACE_MULTICAST, "multicast");
		return true;
	case 'd': /* DYNAMIC */
		iface_setflag(info, flags, invert, XT_IFACE_DYNAMIC, "dynamic");
		return true;
	case 'w': /* LOWER_UP */
		iface_setflag(info, flags, invert, XT_IFACE_LOWER_UP, "lower_up");
		return true;
	case 'a': /* DORMANT */
		iface_setflag(info, flags, invert, XT_IFACE_DORMANT, "dormant");
		return true;
	}
	return false;
}

static void iface_mt_check(unsigned int flags)
{
	if (!(flags & XT_IFACE_IFACE))
		xtables_error(PARAMETER_PROBLEM,
			"iface: You must specify an interface");
	if (flags == 0 || flags == XT_IFACE_IFACE)
		xtables_error(PARAMETER_PROBLEM,
			"iface: You must specify at least one option");
}

static void iface_mt_print(const void *ip, const struct xt_entry_match *match,
    int numeric)
{
	const struct xt_iface_mtinfo *info = (const void *)match->data;

	printf("iface: \"%s\" [state:", info->ifname);
	iface_print_opt(info, XT_IFACE_UP,          "up");
	iface_print_opt(info, XT_IFACE_BROADCAST,   "broadcast");
	iface_print_opt(info, XT_IFACE_LOOPBACK,    "loopback");
	iface_print_opt(info, XT_IFACE_POINTOPOINT, "pointopoint");
	iface_print_opt(info, XT_IFACE_RUNNING,     "running");
	iface_print_opt(info, XT_IFACE_NOARP,       "noarp");
	iface_print_opt(info, XT_IFACE_PROMISC,     "promisc");
	iface_print_opt(info, XT_IFACE_MULTICAST,   "multicast");
	iface_print_opt(info, XT_IFACE_DYNAMIC,     "dynamic");
	iface_print_opt(info, XT_IFACE_LOWER_UP,    "lower_up");
	iface_print_opt(info, XT_IFACE_DORMANT,     "dormant");
	printf("] ");
}

static void iface_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_iface_mtinfo *info = (const void *)match->data;

	printf(" --iface %s", info->ifname);
	iface_print_opt(info, XT_IFACE_UP,          "--up");
	iface_print_opt(info, XT_IFACE_BROADCAST,   "--broadcast");
	iface_print_opt(info, XT_IFACE_LOOPBACK,    "--loopback");
	iface_print_opt(info, XT_IFACE_POINTOPOINT, "--pointopoint");
	iface_print_opt(info, XT_IFACE_RUNNING,     "--running");
	iface_print_opt(info, XT_IFACE_NOARP,       "--noarp");
	iface_print_opt(info, XT_IFACE_PROMISC,     "--promisc");
	iface_print_opt(info, XT_IFACE_MULTICAST,   "--multicast");
	iface_print_opt(info, XT_IFACE_DYNAMIC,     "--dynamic");
	iface_print_opt(info, XT_IFACE_LOWER_UP,    "--lower_up");
	iface_print_opt(info, XT_IFACE_DORMANT,     "--dormant");
	printf(" ");
}

static struct xtables_match iface_mt_reg = {
	.version	= XTABLES_VERSION,
	.name		= "iface",
	.revision	= 0,
	.family		= AF_INET,
	.size		= XT_ALIGN(sizeof(struct xt_iface_mtinfo)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_iface_mtinfo)),
	.help		= iface_mt_help,
	.parse		= iface_mt_parse,
	.final_check	= iface_mt_check,
	.print		= iface_mt_print,
	.save		= iface_mt_save,
	.extra_opts	= iface_mt_opts,
};

static struct xtables_match iface_mt6_reg = {
	.version	= XTABLES_VERSION,
	.name		= "iface",
	.revision	= 0,
	.family		= AF_INET6,
	.size		= XT_ALIGN(sizeof(struct xt_iface_mtinfo)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_iface_mtinfo)),
	.help		= iface_mt_help,
	.parse		= iface_mt_parse,
	.final_check	= iface_mt_check,
	.print		= iface_mt_print,
	.save		= iface_mt_save,
	.extra_opts	= iface_mt_opts,
};

static void _init(void)
{
	xtables_register_match(&iface_mt_reg);
	xtables_register_match(&iface_mt6_reg);
}
