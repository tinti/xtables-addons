/* Copyright 2007-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 2 as 
 * published by the Free Software Foundation.
 */
#include <assert.h>				/* assert */
#include <errno.h>				/* errno */
#include <stdint.h>
#include <stdlib.h>				/* calloc, free */
#include <time.h>				/* time */
#include <arpa/inet.h>				/* hto* */

#include <libipset/linux_ip_set.h>		/* enum ipset_cmd */
#include <libipset/debug.h>			/* D() */
#include <libipset/session.h>			/* ipset_session_handle */
#include <libipset/ui.h>			/* IPSET_ENV_EXIST */
#include <libipset/utils.h>			/* UNUSED */
#include <libipset/mnl.h>			/* prototypes */

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>

#ifndef NFNL_SUBSYS_IPSET
#define NFNL_SUBSYS_IPSET	6
#endif

/* Internal data structure for the kernel-userspace communication parameters */
struct ipset_handle {
	struct mnl_socket *h;		/* the mnl socket */
	unsigned int seq;		/* netlink message sequence number */
	unsigned int portid;		/* the socket port identifier */
	mnl_cb_t *cb_ctl;		/* control block callbacks */
	void *data;			/* data pointer */
	unsigned int genl_id;		/* genetlink ID of ip_set */
};

/* Netlink flags of the commands */
static const uint16_t cmdflags[] = {
	[IPSET_CMD_CREATE-1]	= NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL,
	[IPSET_CMD_DESTROY-1]	= NLM_F_REQUEST|NLM_F_ACK,
	[IPSET_CMD_FLUSH-1]	= NLM_F_REQUEST|NLM_F_ACK,
	[IPSET_CMD_RENAME-1]	= NLM_F_REQUEST|NLM_F_ACK,
	[IPSET_CMD_SWAP-1]	= NLM_F_REQUEST|NLM_F_ACK,
	[IPSET_CMD_LIST-1]	= NLM_F_REQUEST,
	[IPSET_CMD_SAVE-1]	= NLM_F_REQUEST,
	[IPSET_CMD_ADD-1]	= NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL,
	[IPSET_CMD_DEL-1]	= NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL,
	[IPSET_CMD_TEST-1]	= NLM_F_REQUEST|NLM_F_ACK,
	[IPSET_CMD_HEADER-1]	= NLM_F_REQUEST,
	[IPSET_CMD_TYPE-1]	= NLM_F_REQUEST,
	[IPSET_CMD_PROTOCOL-1]	= NLM_F_REQUEST,
};

/**
 * ipset_get_nlmsg_type - get ipset netlink message type
 * @nlh: pointer to the netlink message header
 *
 * Returns the ipset netlink message type, i.e. the ipset command.
 */
int
ipset_get_nlmsg_type(const struct nlmsghdr *nlh)
{
	const struct genlmsghdr *ghdr = mnl_nlmsg_get_payload(nlh);

	return ghdr->cmd;
}

static void
ipset_mnl_fill_hdr(struct ipset_handle *handle, enum ipset_cmd cmd,
		   void *buffer, size_t len UNUSED, uint8_t envflags)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;

	assert(handle);
	assert(buffer);
	assert(cmd > IPSET_CMD_NONE && cmd < IPSET_MSG_MAX);

	nlh = mnl_nlmsg_put_header(buffer);
	nlh->nlmsg_type = handle->genl_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	if (cmdflags[cmd-1] & NLM_F_ACK)
		nlh->nlmsg_flags |= NLM_F_ACK;
	nlh->nlmsg_seq = handle->seq = time(NULL);

	ghdr = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	ghdr->cmd = cmd;
	/* (ge)netlink is dumb, NLM_F_CREATE and NLM_F_DUMP overlap, get misinterpreted. */
	ghdr->reserved = cmdflags[cmd-1];
	if (envflags & IPSET_ENV_EXIST)
		ghdr->reserved &= ~NLM_F_EXCL;
}

static int
ipset_mnl_query(struct ipset_handle *handle, void *buffer, size_t len)
{
	struct nlmsghdr *nlh = buffer;
	int ret;

	assert(handle);
	assert(buffer);

	if (mnl_socket_sendto(handle->h, nlh, nlh->nlmsg_len) < 0)
		return -ECOMM;

	D("message sent");
	ret = mnl_socket_recvfrom(handle->h, buffer, len);
	D("message received, ret: %d", ret);
	while (ret > 0) {
		ret = mnl_cb_run2(buffer, ret,
				  handle->seq, handle->portid,
				  handle->cb_ctl[NLMSG_MIN_TYPE],
				  handle->data,
				  handle->cb_ctl, NLMSG_MIN_TYPE);
		D("nfln_cb_run2, ret: %d", ret);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(handle->h, buffer, len);
		D("message received, ret: %d", ret);
	}
	return ret > 0 ? 0 : ret;
}

static int ipset_mnl_getid_acb(const struct nlattr *attr, void *datap)
{
	const struct nlattr **tb = datap;
	uint16_t type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
		return MNL_CB_OK;
	tb[type] = attr;
	return MNL_CB_OK;
}

static int ipset_mnl_getid_cb(const struct nlmsghdr *nlhdr, void *datap)
{
	struct ipset_handle *h = datap;
	const struct nlattr *tb[CTRL_ATTR_MAX+1] = {0};
	const struct genlmsghdr *ghdr = mnl_nlmsg_get_payload(nlhdr);
	int ret;

	ret = mnl_attr_parse(nlhdr, sizeof(*ghdr), ipset_mnl_getid_acb, tb);
	if (ret != MNL_CB_OK)
		return ret;
	if (tb[CTRL_ATTR_FAMILY_ID] != NULL)
		h->genl_id = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
	return MNL_CB_OK;
}

/**
 * Look up the GENL identifier for the ip_set subsystem, and store it in
 * @h->genl_id. On success, 0 is returned, otherwise error encoded as
 * negative number.
 */
static int ipset_mnl_getid(struct ipset_handle *h, bool modprobe)
{
	size_t buf_size = 8192; //MNL_SOCKET_BUFFER_SIZE;
	struct nlmsghdr *nlhdr;
	struct genlmsghdr *ghdr;
	char *buf;
	int ret = -ENOENT;

	h->genl_id = 0;

	if (modprobe) {
		/* genetlink has no autoloading like nfnetlink... */
		system("/sbin/modprobe -q ip_set");
	}

	buf = malloc(buf_size);
	if (buf == NULL)
		return -errno;

	nlhdr = mnl_nlmsg_put_header(buf);
	nlhdr->nlmsg_type = GENL_ID_CTRL;
	nlhdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	ghdr = mnl_nlmsg_put_extra_header(nlhdr, sizeof(struct genlmsghdr));
	ghdr->cmd = CTRL_CMD_GETFAMILY;
	ghdr->version = 2;
	if (!mnl_attr_put_strz_check(nlhdr, buf_size,
	    CTRL_ATTR_FAMILY_NAME, "ip_set"))
		goto out;

	ret = mnl_socket_sendto(h->h, buf, nlhdr->nlmsg_len);
	if (ret < 0)
		goto out;
	ret = mnl_socket_recvfrom(h->h, buf, buf_size);
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, 0, ipset_mnl_getid_cb, h);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(h->h, buf, buf_size);
	}
	if (h->genl_id == 0 && !modprobe)
		/* Redo, with modprobe this time. */
		ret = ipset_mnl_getid(h, true);
	if (h->genl_id > 0)
		ret = 0;
 out:
	free(buf);
	return ret;
}

static struct ipset_handle *
ipset_mnl_init(mnl_cb_t *cb_ctl, void *data)
{	
	struct ipset_handle *handle;
	
	assert(cb_ctl);
	assert(data);

	handle = calloc(1, sizeof(*handle));
	if (!handle)
		return NULL;
		
	handle->h = mnl_socket_open(NETLINK_GENERIC);
	if (!handle->h)
		goto free_handle;
	
	if (mnl_socket_bind(handle->h, 0, MNL_SOCKET_AUTOPID) < 0)
		goto close_nl;
	
	handle->portid = mnl_socket_get_portid(handle->h);
	handle->cb_ctl = cb_ctl;
	handle->data = data;
	
	if (ipset_mnl_getid(handle, false) < 0)
		goto close_nl;
	return handle;

close_nl:
	mnl_socket_close(handle->h);
free_handle:
	free(handle);

   	return NULL;
}

static int
ipset_mnl_fini(struct ipset_handle *handle)
{
	assert(handle);

	if (handle->h)
		mnl_socket_close(handle->h);

	free(handle);
	return 0;
}

const struct ipset_transport ipset_mnl_transport = {
	.init	= ipset_mnl_init,
	.fini	= ipset_mnl_fini,
	.fill_hdr = ipset_mnl_fill_hdr,
	.query	= ipset_mnl_query,
};
