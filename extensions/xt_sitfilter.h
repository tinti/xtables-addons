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

#ifndef _XT_SITFILTER_H
#define _XT_SITFILTER_H

enum {
	XT_SITFILTER_IPV4    = 1 << 0,
	XT_SITFILTER_IPV6    = 1 << 1,
	XT_SITFILTER_BITLEN  = 1 << 2,
};

struct xt_sitfilter_mtinfo {
	uint8_t ipv4_start;
	uint8_t ipv6_start;
	uint8_t bit_len;
};

#endif /* _XT_SITFILTER_H */
