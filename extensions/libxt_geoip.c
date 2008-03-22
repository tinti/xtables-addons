/* Shared library add-on to iptables to add geoip match support.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Copyright (c) 2004, 2005, 2006, 2007, 2008
 * Samuel Jean & Nicolas Bouliane
 *
 * For comments, bugs or suggestions, please contact
 * Samuel Jean       <peejix@people.netfilter.org>
 * Nicolas Bouliane  <peejix@people.netfilter.org>
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xtables.h>
#include "xt_geoip.h"
#define GEOIP_DB_DIR "/var/geoip"

static void geoip_help(void)
{
	printf (
	"geoip match options:\n"
	"[!] --src-cc, --source-country country[,country...]\n"
	"	Match packet coming from (one of) the specified country(ies)\n"
	"[!] --dst-cc, --destination-country country[,country...]\n"
	"	Match packet going to (one of) the specified country(ies)\n"
	"\n"
	"NOTE: The country is inputed by its ISO3166 code.\n"
	"\n"
	);
}

static struct option geoip_opts[] = {
	{.name = "dst-cc",              .has_arg = true, .val = '2'},
	{.name = "destination-country", .has_arg = true, .val = '2'},
	{.name = "src-cc",              .has_arg = true, .val = '1'},
	{.name = "source-country",      .has_arg = true, .val = '1'},
	{NULL},
};

static struct geoip_subnet *geoip_get_subnets(const char *code, uint32_t *count)
{
	struct geoip_subnet *subnets;
	struct stat sb;
	char buf[256];
	int fd;

	/* Use simple integer vector files */
#if __BYTE_ORDER == _BIG_ENDIAN
	snprintf(buf, sizeof(buf), GEOIP_DB_DIR "/BE/%s.iv0", code);
#else
	snprintf(buf, sizeof(buf), GEOIP_DB_DIR "/LE/%s.iv0", code);
#endif

	if ((fd = open(buf, O_RDONLY)) < 0) {
		fprintf(stderr, "Could not open %s: %s\n", buf, strerror(errno));
		exit_error(OTHER_PROBLEM, "Could not read geoip database");
	}

	fstat(fd, &sb);
	if (sb.st_size % sizeof(struct geoip_subnet) != 0)
		exit_error(OTHER_PROBLEM, "Database file %s seems to be "
		           "corrupted", buf);
	subnets = malloc(sb.st_size);
	if (subnets == NULL)
		exit_error(OTHER_PROBLEM, "geoip: insufficient memory");
	read(fd, subnets, sb.st_size);
	close(fd);
	*count = sb.st_size / sizeof(struct geoip_subnet);
	return subnets;
}
 
static struct geoip_country_user *geoip_load_cc(const char *code,
    unsigned short cc)
{
	struct geoip_country_user *ginfo;
	ginfo = malloc(sizeof(struct geoip_country_user));

	if (!ginfo)
		return NULL;

	ginfo->subnets = (unsigned long)geoip_get_subnets(code, &ginfo->count);
	ginfo->cc = cc;

	return ginfo;
}

static u_int16_t
check_geoip_cc(char *cc, u_int16_t cc_used[], u_int8_t count)
{
	u_int8_t i;
	u_int16_t cc_int16;

	if (strlen(cc) != 2) /* Country must be 2 chars long according
													 to the ISO3166 standard */
		exit_error(PARAMETER_PROBLEM,
			"geoip: invalid country code '%s'", cc);

	// Verification will fail if chars aren't uppercased.
	// Make sure they are..
	for (i = 0; i < 2; i++)
		if (isalnum(cc[i]) != 0)
			cc[i] = toupper(cc[i]);
		else
			exit_error(PARAMETER_PROBLEM,
				"geoip:  invalid country code '%s'", cc);

	/* Convert chars into a single 16 bit integer.
	 * FIXME:	This assumes that a country code is
	 *			 exactly 2 chars long. If this is
	 *			 going to change someday, this whole
	 *			 match will need to be rewritten, anyway.
	 *											 - SJ  */
	cc_int16 = (cc[0] << 8) | cc[1];

	// Check for presence of value in cc_used
	for (i = 0; i < count; i++)
		if (cc_int16 == cc_used[i])
			return 0; // Present, skip it!

	return cc_int16;
}

static unsigned int parse_geoip_cc(const char *ccstr, uint16_t *cc,
    union geoip_country_group *mem)
{
	char *buffer, *cp, *next;
	u_int8_t i, count = 0;
	u_int16_t cctmp;

	buffer = strdup(ccstr);
	if (!buffer)
		exit_error(OTHER_PROBLEM,
			"geoip: insufficient memory available");

	for (cp = buffer, i = 0; cp && i < XT_GEOIP_MAX; cp = next, i++)
	{
		next = strchr(cp, ',');
		if (next) *next++ = '\0';

		if ((cctmp = check_geoip_cc(cp, cc, count)) != 0) {
			if ((mem[count++].user = (unsigned long)geoip_load_cc(cp, cctmp)) == 0)
				exit_error(OTHER_PROBLEM,
					"geoip: insufficient memory available");
			cc[count-1] = cctmp;
		}
	}

	if (cp)
		exit_error(PARAMETER_PROBLEM,
			"geoip: too many countries specified");
	free(buffer);

	if (count == 0)
		exit_error(PARAMETER_PROBLEM,
			"geoip: don't know what happened");

	return count;
}

static int geoip_parse(int c, char **argv, int invert, unsigned int *flags,
    const void *entry, struct xt_entry_match **match)
{
	struct xt_geoip_match_info *info = (void *)(*match)->data;

	switch(c) {
		case '1':
		// Ensure that XT_GEOIP_SRC *OR* XT_GEOIP_DST haven't been used yet.
		if (*flags & (XT_GEOIP_SRC | XT_GEOIP_DST))
			exit_error(PARAMETER_PROBLEM,
				"geoip: only use --source-country *OR* --destination-country once!");

		*flags |= XT_GEOIP_SRC;
		break;

	case '2':
		// Ensure that XT_GEOIP_SRC *OR* XT_GEOIP_DST haven't been used yet.
		if (*flags & (XT_GEOIP_SRC | XT_GEOIP_DST))
			exit_error(PARAMETER_PROBLEM,
				"geoip: only use --source-country *OR* --destination-country once!");

		*flags |= XT_GEOIP_DST;
		break;

	default:
		return 0;
	}

	if (invert)
		*flags |= XT_GEOIP_INV;

	info->count = parse_geoip_cc(argv[optind-1], info->cc, info->mem);
	info->flags = *flags;
	return 1;
}

static void
geoip_final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			"geoip: missing arguments");
}

static void
geoip_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_geoip_match_info *info = (void*)match->data;

	u_int8_t i;

	if (info->flags & XT_GEOIP_SRC)
		printf("Source ");
	else
		printf("Destination ");

	if (info->count > 1)
		printf("countries: ");
	else
		printf("country: ");

	if (info->flags & XT_GEOIP_INV)
		printf("! ");

	for (i = 0; i < info->count; i++)
		 printf("%s%c%c", i ? "," : "", COUNTRY(info->cc[i]));
	printf(" ");
}

static void
geoip_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_geoip_match_info *info = (void *)match->data;
	u_int8_t i;

	if (info->flags & XT_GEOIP_INV)
		printf("! ");

	if (info->flags & XT_GEOIP_SRC)
		printf("--source-country ");
	else
		printf("--destination-country ");

	for (i = 0; i < info->count; i++)
		printf("%s%c%c", i ? "," : "", COUNTRY(info->cc[i]));
	printf(" ");
}

static struct xtables_match geoip_match = {
	 .family        = AF_INET,
	 .name          = "geoip",
	 .version       = XTABLES_VERSION,
	 .size          = XT_ALIGN(sizeof(struct xt_geoip_match_info)),
	 .userspacesize = XT_ALIGN(offsetof(struct xt_geoip_match_info, mem)),
	 .help          = geoip_help,
	 .parse	        = geoip_parse,
	 .final_check   = geoip_final_check,
	 .print         = geoip_print,
	 .save          = geoip_save,
	 .extra_opts    = geoip_opts,
};

static void _init(void)
{
	xtables_register_match(&geoip_match);
}
