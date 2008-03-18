/* ipt_geoip.h header file for libipt_geoip.c and ipt_geoip.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Copyright (c) 2004, 2005, 2006, 2007, 2008
 *
 * Samuel Jean
 * Nicolas Bouliane
 */
#ifndef _LINUX_NETFILTER_XT_GEOIP_H
#define _LINUX_NETFILTER_XT_GEOIP_H 1

#define XT_GEOIP_SRC         0x01     /* Perform check on Source IP */
#define XT_GEOIP_DST         0x02     /* Perform check on Destination IP */
#define XT_GEOIP_INV         0x04     /* Negate the condition */

#define XT_GEOIP_MAX         15       /* Maximum of countries */

struct geoip_subnet {
	u_int32_t begin;
	u_int32_t end;
};

struct geoip_country_user {
	aligned_u64 subnets;
	u_int32_t count;
	u_int16_t cc;
};

struct geoip_country_kernel;

union geoip_country_group {
	aligned_u64 user;
	struct geoip_country_kernel *kernel;
};

struct xt_geoip_match_info {
	u_int8_t flags;
	u_int8_t count;
	u_int16_t cc[XT_GEOIP_MAX];

	/* Used internally by the kernel */
	union geoip_country_group mem[XT_GEOIP_MAX];
};

#define COUNTRY(cc) (cc >> 8), (cc & 0x00FF)

#endif /* _LINUX_NETFILTER_XT_GEOIP_H */
