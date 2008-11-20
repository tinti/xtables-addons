/*
 *	"TEE" target extension for iptables
 *	Copyright © Sebastian Claßen <sebastian.classen [at] freenet.ag>, 2007
 *	Jan Engelhardt <jengelh [at] medozas de>, 2007 - 2008
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <sys/socket.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <xtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include "xt_TEE.h"

enum {
	FLAG_GATEWAY = 1 << 0,
};

static const struct option tee_tg_opts[] = {
	{.name = "gateway", .has_arg = true, .val = 'g'},
	{NULL},
};

static void tee_tg_help(void)
{
	printf(
"TEE target options:\n"
"  --gateway IPADDR    Route packet via the gateway given by address\n"
"\n");
}

static int tee_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
	struct xt_tee_tginfo *info = (void *)(*target)->data;
	const struct in_addr *ia;

	switch (c) {
	case 'g':
		if (*flags & FLAG_GATEWAY)
			exit_error(PARAMETER_PROBLEM,
			           "Cannot specify --gw more than once");

		if (check_inverse(optarg, &invert, NULL, 0))
			exit_error(PARAMETER_PROBLEM,
			           "Unexpected \"!\" after --gateway");

		ia = numeric_to_ipaddr(optarg);
		if (ia == NULL)
			exit_error(PARAMETER_PROBLEM,
			           "Invalid IP address %s", optarg);

		memcpy(&info->gw, ia, sizeof(*ia));
		*flags |= FLAG_GATEWAY;
		return true;
	}

	return false;
}

static void tee_tg_check(unsigned int flags)
{
	if (flags == 0)
		exit_error(PARAMETER_PROBLEM, "TEE target: "
		           "--gateway parameter required");
}

static void tee_tg_print(const void *ip, const struct xt_entry_target *target,
                         int numeric)
{
	const struct xt_tee_tginfo *info = (const void *)target->data;

	if (numeric)
		printf("TEE gw:%s ", ipaddr_to_anyname(&info->gw.in));
	else
		printf("TEE gw:%s ", ipaddr_to_numeric(&info->gw.in));
}

static void tee_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_tee_tginfo *info = (const void *)target->data;

	printf("--gateway %s ", ipaddr_to_numeric(&info->gw.in));
}

static struct xtables_target tee_tg_reg = {
	.name          = "TEE",
	.version       = XTABLES_VERSION,
	.size          = XT_ALIGN(sizeof(struct xt_tee_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_tee_tginfo)),
	.help          = tee_tg_help,
	.parse         = tee_tg_parse,
	.final_check   = tee_tg_check,
	.print         = tee_tg_print,
	.save          = tee_tg_save,
	.extra_opts    = tee_tg_opts,
};

static __attribute__((constructor)) void tee_tg_ldr(void)
{
	xtables_register_target(&tee_tg_reg);
}
