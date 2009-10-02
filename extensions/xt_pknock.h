/*
 * Kernel module to implement Port Knocking and SPA matching support.
 *
 * (C) 2006-2008 J. Federico Hernandez <fede.hernandez@gmail.com>
 * (C) 2006 Luis Floreani <luis.floreani@gmail.com>
 *
 * $Id$
 *
 * This program is released under the terms of GNU GPL version 2.
 */
#ifndef _XT_PKNOCK_H
#define _XT_PKNOCK_H

#define PKNOCK "xt_pknock: "

#define IPT_PKNOCK_KNOCKPORT	0x01
#define IPT_PKNOCK_TIME			0x02
#define IPT_PKNOCK_NAME			0x04
#define IPT_PKNOCK_STRICT		0x08
#define IPT_PKNOCK_CHECKIP		0x10
#define IPT_PKNOCK_OPENSECRET	0x20
#define IPT_PKNOCK_CLOSESECRET	0x40

#define IPT_PKNOCK_MAX_PORTS		15
#define IPT_PKNOCK_MAX_BUF_LEN		31
#define IPT_PKNOCK_MAX_PASSWD_LEN	31

#define DEBUG 1

struct xt_pknock_mtinfo {
	char		rule_name[IPT_PKNOCK_MAX_BUF_LEN + 1];
	uint32_t			rule_name_len;
	char		open_secret[IPT_PKNOCK_MAX_PASSWD_LEN + 1];
	uint32_t			open_secret_len;
	char		close_secret[IPT_PKNOCK_MAX_PASSWD_LEN + 1];
	uint32_t			close_secret_len;
	uint8_t	option;		/* --time, --knock-port, ... */
	uint8_t	ports_count;	/* number of ports */
	uint16_t	port[IPT_PKNOCK_MAX_PORTS]; /* port[,port,port,...] */
	uint32_t	max_time;	/* max matching time between ports */
};

struct xt_pknock_nl_msg {
	char		rule_name[IPT_PKNOCK_MAX_BUF_LEN + 1];
	uint32_t	peer_ip;
};

#endif /* _XT_PKNOCK_H */
