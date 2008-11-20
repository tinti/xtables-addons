/*
 *	"dhcpaddr" match extension for iptables
 *	Copyright © Jan Engelhardt <jengelh [at] medozas de>, 2008
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <xtables.h>
#include "xt_DHCPADDR.h"
#include "mac.c"

enum {
	F_MAC = 1 << 0,
};

static const struct option dhcpaddr_mt_opts[] = {
	{.name = "mac", .has_arg = true, .val = 'M'},
	{NULL},
};

static void dhcpaddr_mt_help(void)
{
	printf(
"dhcpaddr match options:\n"
"[!] --mac lladdr[/mask]    Match on MAC address in DHCP Client Host field\n"
	);
}

static int dhcpaddr_mt_parse(int c, char **argv, int invert,
    unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
	struct dhcpaddr_info *info = (void *)(*match)->data;

	switch (c) {
	case 'M':
		param_act(P_ONLY_ONCE, "dhcpaddr", "--mac", *flags & F_MAC);
		param_act(P_NO_INVERT, "dhcpaddr", "--mac", invert);
		if (!mac_parse(optarg, info->addr, &info->mask))
			param_act(P_BAD_VALUE, "dhcpaddr", "--mac", optarg);
		if (invert)
			info->invert = true;
		*flags |= F_MAC;
		return true;
	}

	return false;
}

static void dhcpaddr_mt_check(unsigned int flags)
{
	if (flags == 0)
		exit_error(PARAMETER_PROBLEM, "dhcpaddr match: "
		           "--mac parameter required");
}

static void dhcpaddr_mt_print(const void *ip,
    const struct xt_entry_match *match, int numeric)
{
	const struct dhcpaddr_info *info = (void *)match->data;

	printf("dhcpaddr %s" DH_MAC_FMT "/%u ",
	       info->invert ? "!" : "", DH_MAC_HEX(info->addr), info->mask);
}

static void dhcpaddr_mt_save(const void *ip,
    const struct xt_entry_match *match)
{
	const struct dhcpaddr_info *info = (void *)match->data;

	if (info->invert)
		printf("! ");
	printf("--mac " DH_MAC_FMT "/%u ",
	       DH_MAC_HEX(info->addr), info->mask);
}

static struct xtables_match dhcpaddr_mt_reg = {
	.version       = XTABLES_VERSION,
	.name          = "dhcpaddr",
	.revision      = 0,
	.family        = PF_INET,
	.size          = XT_ALIGN(sizeof(struct dhcpaddr_info)),
	.userspacesize = XT_ALIGN(sizeof(struct dhcpaddr_info)),
	.help          = dhcpaddr_mt_help,
	.parse         = dhcpaddr_mt_parse,
	.final_check   = dhcpaddr_mt_check,
	.print         = dhcpaddr_mt_print,
	.save          = dhcpaddr_mt_save,
	.extra_opts    = dhcpaddr_mt_opts,
};

static __attribute__((constructor)) void dhcpaddr_mt_ldr(void)
{
	xtables_register_match(&dhcpaddr_mt_reg);
}
