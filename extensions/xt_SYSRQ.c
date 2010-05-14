/*
 *	"SYSRQ" target extension for Netfilter
 *	Copyright © Jan Engelhardt <jengelh [at] medozas de>, 2008 - 2010
 *
 *	Based upon the ipt_SYSRQ idea by Marek Zalem <marek [at] terminus sk>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	version 2 or 3 as published by the Free Software Foundation.
 */
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/sysrq.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <net/ip.h>
#include "compat_xtables.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19) && \
    (defined(CONFIG_CRYPTO) || defined(CONFIG_CRYPTO_MODULE))
#	define WITH_CRYPTO 1
#endif
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#	define WITH_IPV6 1
#endif

static bool sysrq_once;
static char sysrq_password[64];
static char sysrq_hash[16] = "sha1";
static long sysrq_seqno;
static int sysrq_debug;
module_param_string(password, sysrq_password, sizeof(sysrq_password),
	S_IRUSR | S_IWUSR);
module_param_string(hash, sysrq_hash, sizeof(sysrq_hash), S_IRUSR);
module_param_named(seqno, sysrq_seqno, long, S_IRUSR | S_IWUSR);
module_param_named(debug, sysrq_debug, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(password, "password for remote sysrq");
MODULE_PARM_DESC(hash, "hash algorithm, default sha1");
MODULE_PARM_DESC(seqno, "sequence number for remote sysrq");
MODULE_PARM_DESC(debug, "debugging: 0=off, 1=on");

#ifdef WITH_CRYPTO
static struct crypto_hash *sysrq_tfm;
static int sysrq_digest_size;
static unsigned char *sysrq_digest_password;
static unsigned char *sysrq_digest;
static char *sysrq_hexdigest;

/*
 * The data is of the form "<requests>,<seqno>,<salt>,<hash>" where <requests>
 * is a series of sysrq requests; <seqno> is a sequence number that must be
 * greater than the last sequence number; <salt> is some random bytes; and
 * <hash> is the hash of everything up to and including the preceding ","
 * together with the password.
 *
 * For example
 *
 *   salt=$RANDOM
 *   req="s,$(date +%s),$salt"
 *   echo "$req,$(echo -n $req,secret | sha1sum | cut -c1-40)"
 *
 * You will want a better salt and password than that though :-)
 */
static unsigned int sysrq_tg(const void *pdata, uint16_t len)
{
	const char *data = pdata;
	int i, n;
	struct scatterlist sg[2];
	struct hash_desc desc;
	int ret;
	long new_seqno = 0;

	if (*sysrq_password == '\0') {
		if (!sysrq_once)
			printk(KERN_INFO KBUILD_MODNAME ": No password set\n");
		sysrq_once = true;
		return NF_DROP;
	}
	if (len == 0)
		return NF_DROP;

	for (i = 0; sysrq_password[i] != '\0' &&
	     sysrq_password[i] != '\n'; ++i)
		/* loop */;
	sysrq_password[i] = '\0';

	i = 0;
	for (n = 0; n < len - 1; ++n) {
		if (i == 1 && '0' <= data[n] && data[n] <= '9')
			new_seqno = 10L * new_seqno + data[n] - '0';
		if (data[n] == ',' && ++i == 3)
			break;
	}
	++n;
	if (i != 3) {
		if (sysrq_debug)
			printk(KERN_WARNING KBUILD_MODNAME
				": badly formatted request\n");
		return NF_DROP;
	}
	if (sysrq_seqno >= new_seqno) {
		if (sysrq_debug)
			printk(KERN_WARNING KBUILD_MODNAME
				": old sequence number ignored\n");
		return NF_DROP;
	}

	desc.tfm   = sysrq_tfm;
	desc.flags = 0;
	ret = crypto_hash_init(&desc);
	if (ret != 0)
		goto hash_fail;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	sg_init_table(sg, 2);
#endif
	sg_set_buf(&sg[0], data, n);
	strcpy(sysrq_digest_password, sysrq_password);
	i = strlen(sysrq_digest_password);
	sg_set_buf(&sg[1], sysrq_digest_password, i);
	ret = crypto_hash_digest(&desc, sg, n + i, sysrq_digest);
	if (ret != 0)
		goto hash_fail;

	for (i = 0; i < sysrq_digest_size; ++i) {
		sysrq_hexdigest[2*i] =
			"0123456789abcdef"[(sysrq_digest[i] >> 4) & 0xf];
		sysrq_hexdigest[2*i+1] =
			"0123456789abcdef"[sysrq_digest[i] & 0xf];
	}
	sysrq_hexdigest[2*sysrq_digest_size] = '\0';
	if (len - n < sysrq_digest_size) {
		if (sysrq_debug)
			printk(KERN_INFO KBUILD_MODNAME ": Short digest,"
			       " expected %s\n", sysrq_hexdigest);
		return NF_DROP;
	}
	if (strncmp(data + n, sysrq_hexdigest, sysrq_digest_size) != 0) {
		if (sysrq_debug)
			printk(KERN_INFO KBUILD_MODNAME ": Bad digest,"
			       " expected %s\n", sysrq_hexdigest);
		return NF_DROP;
	}

	/* Now we trust the requester */
	sysrq_seqno = new_seqno;
	for (i = 0; i < len && data[i] != ','; ++i) {
		printk(KERN_INFO KBUILD_MODNAME ": SysRq %c\n", data[i]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
		handle_sysrq(data[i], NULL);
#else
		handle_sysrq(data[i], NULL, NULL);
#endif
	}
	return NF_ACCEPT;

 hash_fail:
	printk(KERN_WARNING KBUILD_MODNAME ": digest failure\n");
	return NF_DROP;
}
#else
static unsigned int sysrq_tg(const void *pdata, uint16_t len)
{
	const char *data = pdata;
	char c;

	if (*sysrq_password == '\0') {
		if (!sysrq_once)
			printk(KERN_INFO KBUILD_MODNAME "No password set\n");
		sysrq_once = true;
		return NF_DROP;
	}

	if (len == 0)
		return NF_DROP;

	c = *data;
	if (strncmp(&data[1], sysrq_password, len - 1) != 0) {
		printk(KERN_INFO KBUILD_MODNAME "Failed attempt - "
		       "password mismatch\n");
		return NF_DROP;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
	handle_sysrq(c, NULL);
#else
	handle_sysrq(c, NULL, NULL);
#endif
	return NF_ACCEPT;
}
#endif

static unsigned int
sysrq_tg4(struct sk_buff **pskb, const struct xt_action_param *par)
{
	struct sk_buff *skb = *pskb;
	const struct iphdr *iph;
	const struct udphdr *udph;
	uint16_t len;

	if (skb_linearize(skb) < 0)
		return NF_DROP;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_UDPLITE)
		return NF_DROP;

	udph = (const void *)iph + ip_hdrlen(skb);
	len  = ntohs(udph->len) - sizeof(struct udphdr);

	if (sysrq_debug)
		printk(KERN_INFO KBUILD_MODNAME
		       ": " NIPQUAD_FMT ":%u -> :%u len=%u\n",
		       NIPQUAD(iph->saddr), htons(udph->source),
		       htons(udph->dest), len);
	return sysrq_tg((void *)udph + sizeof(struct udphdr), len);
}

#ifdef WITH_IPV6
static unsigned int
sysrq_tg6(struct sk_buff **pskb, const struct xt_action_param *par)
{
	struct sk_buff *skb = *pskb;
	const struct ipv6hdr *iph;
	const struct udphdr *udph;
	unsigned short frag_off;
	unsigned int th_off;
	uint16_t len;

	if (skb_linearize(skb) < 0)
		return NF_DROP;

	iph = ipv6_hdr(skb);
	if (ipv6_find_hdr(skb, &th_off, IPPROTO_UDP, &frag_off) < 0 ||
	    frag_off > 0)
		return NF_DROP;

	udph = (const void *)iph + th_off;
	len  = ntohs(udph->len) - sizeof(struct udphdr);

	if (sysrq_debug)
		printk(KERN_INFO KBUILD_MODNAME
		       ": " NIP6_FMT ":%hu -> :%hu len=%u\n",
		       NIP6(iph->saddr), ntohs(udph->source),
		       ntohs(udph->dest), len);
	return sysrq_tg(udph + sizeof(struct udphdr), len);
}
#endif

static int sysrq_tg_check(const struct xt_tgchk_param *par)
{
	if (par->target->family == NFPROTO_IPV4) {
		const struct ipt_entry *entry = par->entryinfo;

		if ((entry->ip.proto != IPPROTO_UDP &&
		    entry->ip.proto != IPPROTO_UDPLITE) ||
		    entry->ip.invflags & XT_INV_PROTO)
			goto out;
	} else if (par->target->family == NFPROTO_IPV6) {
		const struct ip6t_entry *entry = par->entryinfo;

		if ((entry->ipv6.proto != IPPROTO_UDP &&
		    entry->ipv6.proto != IPPROTO_UDPLITE) ||
		    entry->ipv6.invflags & XT_INV_PROTO)
			goto out;
	}

	return 0;

 out:
	printk(KERN_ERR KBUILD_MODNAME ": only available for UDP and UDP-Lite");
	return -EINVAL;
}

static struct xt_target sysrq_tg_reg[] __read_mostly = {
	{
		.name       = "SYSRQ",
		.revision   = 1,
		.family     = NFPROTO_IPV4,
		.target     = sysrq_tg4,
		.checkentry = sysrq_tg_check,
		.me         = THIS_MODULE,
	},
#ifdef WITH_IPV6
	{
		.name       = "SYSRQ",
		.revision   = 1,
		.family     = NFPROTO_IPV6,
		.target     = sysrq_tg6,
		.checkentry = sysrq_tg_check,
		.me         = THIS_MODULE,
	},
#endif
};

static void sysrq_crypto_exit(void)
{
#ifdef WITH_CRYPTO
	if (sysrq_tfm)
		crypto_free_hash(sysrq_tfm);
	if (sysrq_digest)
		kfree(sysrq_digest);
	if (sysrq_hexdigest)
		kfree(sysrq_hexdigest);
	if (sysrq_digest_password)
		kfree(sysrq_digest_password);
#endif
}

static int __init sysrq_crypto_init(void)
{
#if defined(WITH_CRYPTO)
	struct timeval now;
	int ret;

	sysrq_tfm = crypto_alloc_hash(sysrq_hash, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(sysrq_tfm)) {
		printk(KERN_WARNING KBUILD_MODNAME
			": Error: Could not find or load %s hash\n",
			sysrq_hash);
		sysrq_tfm = NULL;
		ret = PTR_ERR(sysrq_tfm);
		goto fail;
	}
	sysrq_digest_size = crypto_hash_digestsize(sysrq_tfm);
	sysrq_digest = kmalloc(sysrq_digest_size, GFP_KERNEL);
	ret = -ENOMEM;
	if (sysrq_digest == NULL)
		goto fail;
	sysrq_hexdigest = kmalloc(2 * sysrq_digest_size + 1, GFP_KERNEL);
	if (sysrq_hexdigest == NULL)
		goto fail;
	sysrq_digest_password = kmalloc(sizeof(sysrq_password), GFP_KERNEL);
	if (sysrq_digest_password == NULL)
		goto fail;
	do_gettimeofday(&now);
	sysrq_seqno = now.tv_sec;
	ret = xt_register_targets(sysrq_tg_reg, ARRAY_SIZE(sysrq_tg_reg));
	if (ret < 0)
		goto fail;
	return ret;

 fail:
	sysrq_crypto_exit();
	return ret;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	printk(KERN_WARNING "xt_SYSRQ does not provide crypto for < 2.6.19\n");
#endif
	return -EINVAL;
}

static int __init sysrq_tg_init(void)
{
	if (sysrq_crypto_init() < 0)
		printk(KERN_WARNING "xt_SYSRQ starting without crypto\n");
	return xt_register_targets(sysrq_tg_reg, ARRAY_SIZE(sysrq_tg_reg));
}

static void __exit sysrq_tg_exit(void)
{
	sysrq_crypto_exit();
	xt_unregister_targets(sysrq_tg_reg, ARRAY_SIZE(sysrq_tg_reg));
}

module_init(sysrq_tg_init);
module_exit(sysrq_tg_exit);
MODULE_DESCRIPTION("Xtables: triggering SYSRQ remotely");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_SYSRQ");
MODULE_ALIAS("ip6t_SYSRQ");
