/*
 *	"DHCPADDR" target extension for iptables
 *	Copyright © Jan Engelhardt <jengelh [at] medozas de>, 2008
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <xtables.h>
#include "xt_DHCPADDR.h"
#include "mac.c"

enum {
	F_MAC = 1 << 0,
};

static const struct option dhcpaddr_tg_opts[] = {
	{.name = "set-mac", .has_arg = true, .val = 'M'},
	{NULL},
};

static void dhcpaddr_tg_help(void)
{
	printf(
"DHCPADDDR target options:\n"
"  --set-mac lladdr[/mask]    Set MAC address in DHCP Client Host field\n"
	);
}

static int dhcpaddr_tg_parse(int c, char **argv, int invert,
    unsigned int *flags, const void *entry, struct xt_entry_target **target)
{
	struct dhcpaddr_info *info = (void *)(*target)->data;

	switch (c) {
	case 'M':
		param_act(P_ONLY_ONCE, "DHCPADDR", "--set-mac", *flags & F_MAC);
		param_act(P_NO_INVERT, "DHCPADDR", "--set-mac", invert);
		if (!mac_parse(optarg, info->addr, &info->mask))
			param_act(P_BAD_VALUE, "DHCPADDR", "--set-mac", optarg);
		*flags |= F_MAC;
		return true;
	}

	return false;
}

static void dhcpaddr_tg_check(unsigned int flags)
{
	if (flags == 0)
		exit_error(PARAMETER_PROBLEM, "DHCPADDR target: "
		           "--set-mac parameter required");
}

static void dhcpaddr_tg_print(const void *ip,
    const struct xt_entry_target *target, int numeric)
{
	const struct dhcpaddr_info *info = (void *)target->data;

	printf("DHCPADDR %s" DH_MAC_FMT "/%u ",
	       info->invert ? "!" : "", DH_MAC_HEX(info->addr), info->mask);
}

static void dhcpaddr_tg_save(const void *ip,
    const struct xt_entry_target *target)
{
	const struct dhcpaddr_info *info = (const void *)target->data;

	if (info->invert)
		printf("! ");
	printf("--set-mac " DH_MAC_FMT "/%u ",
	       DH_MAC_HEX(info->addr), info->mask);
}

static struct xtables_target dhcpaddr_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "DHCPADDR",
	.revision      = 0,
	.family        = PF_INET,
	.size          = XT_ALIGN(sizeof(struct dhcpaddr_info)),
	.userspacesize = XT_ALIGN(sizeof(struct dhcpaddr_info)),
	.help          = dhcpaddr_tg_help,
	.parse         = dhcpaddr_tg_parse,
	.final_check   = dhcpaddr_tg_check,
	.print         = dhcpaddr_tg_print,
	.save          = dhcpaddr_tg_save,
	.extra_opts    = dhcpaddr_tg_opts,
};

static __attribute__((constructor)) void dhcpaddr_tg_ldr(void)
{
	xtables_register_target(&dhcpaddr_tg_reg);
}
