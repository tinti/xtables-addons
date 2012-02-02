/*
 *	"sitfilter" match extension for Xtables
 *
 *	Description: This module allows to link IPv4 and IPv6 addresses
 *      that are tunneled in one another.
 *
 *	Authors:
 *	Vinicius Tinti <viniciustinti [at] gmail com>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License; either version 2
 *	or 3 of the License, as published by the Free Software Foundation.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>
#include <xtables.h>
#include "xt_sitfilter.h"
#include "compat_user.h"

static void sitfilter_help(void)
{
	printf(
"sitfilter match options:\n"
"--v4-start bit            Bit to start mapping in Ipv4\n"
" --v6-start bit            Bit to start mapping in Ipv6\n"
" --bit-len number of bits  Number of bits\n"
);
}

static const struct option sitfilter_opts[] = {
	{.name = "v4-start", .has_arg = true, .val = '4'},
	{.name = "v6-start", .has_arg = true, .val = '6'},
	{.name = "bit-len", .has_arg = true, .val = 'b'},
	{NULL},
};

static int sitfilter_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_match **match)
{
	struct xt_sitfilter_mtinfo *info = (void *)(*match)->data;
	uint8_t characters = -1;
	int process = false;

	switch(c) {
		case '4': { /* --v4-start */
			if (*flags & XT_SITFILTER_IPV4)
			xtables_error(PARAMETER_PROBLEM,
				   "Can't specify multiple sitfilters");

			if (optarg)
				characters = strlen(optarg);

			if (characters == 1)
				process = isdigit(optarg[0]);
	
			if (characters == 2)
				process = isdigit(optarg[0]) && isdigit(optarg[1]);

			if (process)
			{
				/* Get arguments */
				info->ipv4_start = atoi(optarg);

				/* Verify range */
				if ((info->ipv4_start >= 0) && (info->ipv4_start < 32))
				{
					/* Valid range */
					*flags |= XT_SITFILTER_IPV4;
					return true;
				}
				else
				{
					/* Invalid range */
					xtables_error(PARAMETER_PROBLEM,
						   "IPv4 range must be 'x' in 0 <= x < 32");
					return false;
				} 
			}
			break;
		}
		case '6': { /* --v6-start */
			if (*flags & XT_SITFILTER_IPV6)
			xtables_error(PARAMETER_PROBLEM,
				   "Can't specify multiple sitfilters");

			if (optarg)
				characters = strlen(optarg);

			if (characters == 1)
				process = isdigit(optarg[0]);
	
			if (characters == 2)
				process = isdigit(optarg[0]) && isdigit(optarg[1]);

			if (characters == 3)
				process = isdigit(optarg[0]) && isdigit(optarg[1]) && isdigit(optarg[2]);

			if (process)
			{
				/* Get arguments */
				info->ipv6_start = atoi(optarg);

				/* Verify range */
				if ((info->ipv6_start >= 0) && (info->ipv4_start < 128))
				{
					/* Valid range */
					*flags |= XT_SITFILTER_IPV6;
					return true;
				}
				else
				{
					/* Invalid range */
					xtables_error(PARAMETER_PROBLEM,
						   "IPv6 range must be 'x' in 0 <= x < 128");
					return false;
				} 
			}
			break;
		}
		case 'b': { /* --bit-len */
			if (*flags & XT_SITFILTER_BITLEN)
			xtables_error(PARAMETER_PROBLEM,
				   "Can't specify multiple sitfilters");

			if (optarg)
				characters = strlen(optarg);

			if (characters == 1)
				process = isdigit(optarg[0]);
	
			if (characters == 2)
				process = isdigit(optarg[0]) && isdigit(optarg[1]);

			if (process)
			{
				/* Get arguments */
				info->bit_len = atoi(optarg);

				/* Verify range */
				if ((info->bit_len > 0) && (info->bit_len <= 32))
				{
					/* Valid range */
					*flags |= XT_SITFILTER_BITLEN;
					return true;
				}
				else
				{
					/* Invalid range */
					xtables_error(PARAMETER_PROBLEM,
						   "Bit length range must be 'x' in 0 < x <= 32");
					return false;
				} 
			}
			break;
		}
		default:
			return false;	
	}

	return false;
}

static void sitfilter_check(unsigned int flags)
{
	if (!(flags & XT_SITFILTER_IPV4))
		xtables_error(PARAMETER_PROBLEM,
			   "Condition match: must specify --v4-start");
		
	if (!(flags & XT_SITFILTER_IPV6))
		xtables_error(PARAMETER_PROBLEM,
			   "Condition match: must specify --v6-start");

	if (!(flags & XT_SITFILTER_BITLEN))
		xtables_error(PARAMETER_PROBLEM,
			   "Condition match: must specify --bit-len");
}

static void sitfilter_print(const void *ip, const struct xt_entry_match *match,
                            int numeric)
{
	const struct xt_sitfilter_mtinfo *info = (const void *)match->data;
	printf("sitfilter --v4-start %u --v6-start %u --bit-len %u", info->ipv4_start, info->ipv6_start, info->bit_len);
}


static void sitfilter_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_sitfilter_mtinfo *info = (const void *)match->data;
	printf("--v4-start %u --v6-start %u --bit-len %u", info->ipv4_start, info->ipv6_start, info->bit_len);
}

static struct xtables_match sitfilter_mt_reg = {
	.name 		= "sitfilter",
	.revision	= 1,
	.family		= NFPROTO_UNSPEC,
	.version 	= XTABLES_VERSION,
	.size 		= XT_ALIGN(sizeof(struct xt_sitfilter_mtinfo)),
	.userspacesize 	= XT_ALIGN(sizeof(struct xt_sitfilter_mtinfo)),
	.help 		= sitfilter_help,
	.parse 		= sitfilter_parse,
	.final_check	= sitfilter_check,
	.print 		= sitfilter_print,
	.save 		= sitfilter_save,
	.extra_opts 	= sitfilter_opts,
};

static __attribute__((constructor)) void sitfilter_mt_ldr(void)
{
	xtables_register_match(&sitfilter_mt_reg);
}
