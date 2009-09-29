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
#ifndef _IPT_PKNOCK_H
#define _IPT_PKNOCK_H

#define PKNOCK "ipt_pknock: "

#define IPT_PKNOCK_KNOCKPORT	0x01
#define IPT_PKNOCK_TIME			0x02
#define IPT_PKNOCK_NAME			0x04
#define IPT_PKNOCK_STRICT		0x08
#define IPT_PKNOCK_CHECKIP		0x10
#define IPT_PKNOCK_OPENSECRET	0x20
#define IPT_PKNOCK_CLOSESECRET	0x40

#define IPT_PKNOCK_MAX_PORTS		15
#define IPT_PKNOCK_MAX_BUF_LEN		32
#define IPT_PKNOCK_MAX_PASSWD_LEN	32

#define DEBUG 1

struct ipt_pknock {
	char		rule_name[IPT_PKNOCK_MAX_BUF_LEN + 1];
	int			rule_name_len;
	char		open_secret[IPT_PKNOCK_MAX_PASSWD_LEN + 1];
	int			open_secret_len;
	char		close_secret[IPT_PKNOCK_MAX_PASSWD_LEN + 1];
	int			close_secret_len;
	uint8_t	ports_count;	/* number of ports */
	uint16_t	port[IPT_PKNOCK_MAX_PORTS]; /* port[,port,port,...] */
	unsigned long	max_time;	/* max matching time between ports */
	uint8_t	option;		/* --time, --knock-port, ... */
};

struct ipt_pknock_nl_msg {
	char		rule_name[IPT_PKNOCK_MAX_BUF_LEN + 1];
	uint32_t	peer_ip;
};

enum status {ST_INIT=1, ST_MATCHING, ST_ALLOWED};

#ifdef __KERNEL__
#include <linux/list.h>
#include <linux/spinlock.h>

struct peer {
	struct list_head head;
	uint32_t		ip;
	uint8_t		proto;
	uint32_t		id_port_knocked;
	enum status		status;
	unsigned long	timestamp;
	int				login_min;	/* the login epoch minute */
};

#include <linux/proc_fs.h>

struct ipt_pknock_rule {
	struct list_head	head;
	char				rule_name[IPT_PKNOCK_MAX_BUF_LEN + 1];
	int					rule_name_len;
	unsigned int		ref_count;
	struct timer_list	timer;		/* garbage collector timer */
	struct list_head	*peer_head;
	struct proc_dir_entry	*status_proc;
	unsigned long		max_time; /* max matching time between ports */
};

#include <linux/crypto.h>

struct ipt_pknock_crypto {
	char				*algo;
	struct crypto_hash	*tfm;
	int					size;
	struct hash_desc	desc;
};

struct transport_data {
	uint8_t	proto;
	uint16_t	port;	/* destination port */
	int			payload_len;
	unsigned char	*payload;
};

#endif /* __KERNEL__ */
#endif /* _IPT_PKNOCK_H */
