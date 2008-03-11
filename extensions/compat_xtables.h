#ifndef _XTABLES_COMPAT_H
#define _XTABLES_COMPAT_H 1

#include <linux/version.h>
#include "compat_skbuff.h"
#include "compat_xtnu.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
#	warning Kernels below 2.6.18 not supported.
#endif

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#	if !defined(CONFIG_NF_CONNTRACK_MARK) || !defined(CONFIG_NF_CONNTRACK_SECMARK)
#		warning You have CONFIG_NF_CONNTRACK enabled, but CONFIG_NF_CONNTRACK_MARK or CONFIG_NF_CONNTRACK_SECMARK are not (please enable).
#	endif
#	include <net/netfilter/nf_conntrack.h>
#elif defined(CONFIG_IP_NF_CONNTRACK) || defined(CONFIG_IP_NF_CONNTRACK_MODULE)
#	if !defined(CONFIG_IP_NF_CONNTRACK_MARK) || !defined(CONFIG_IP_NF_CONNTRACK_SECMARK)
#		warning You have CONFIG_IP_NF_CONNTRACK enabled, but CONFIG_IP_NF_CONNTRACK_MARK or CONFIG_IP_NF_CONNTRACK_SECMARK are not (please enable).
#	endif
#	include <linux/netfilter_ipv4/ip_conntrack.h>
#	define nf_conn ip_conntrack
#	define nf_ct_get ip_conntrack_get
#	define nf_conntrack_untracked ip_conntrack_untracked
#else
#	warning You need either CONFIG_NF_CONNTRACK or CONFIG_IP_NF_CONNTRACK.
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19)
#	define neigh_hh_output xtnu_neigh_hh_output
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
#	define NF_INET_PRE_ROUTING  NF_IP_PRE_ROUTING
#	define NF_INET_LOCAL_IN     NF_IP_LOCAL_IN
#	define NF_INET_FORWARD      NF_IP_FORWARD
#	define NF_INET_LOCAL_OUT    NF_IP_LOCAL_OUT
#	define NF_INET_POST_ROUTING NF_IP_POST_ROUTING
#	define ip_local_out         xtnu_ip_local_out
#	define ip_route_output_key  xtnu_ip_route_output_key
#	include "compat_nfinetaddr.h"
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
#	define init_net               xtnu_ip_route_output_key /* yes */
#	define init_net__loopback_dev (&loopback_dev)
#else
#	define init_net__loopback_dev init_net.loopback_dev
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
#	define xt_match              xtnu_match
#	define xt_register_match     xtnu_register_match
#	define xt_unregister_match   xtnu_unregister_match
#	define xt_register_matches   xtnu_register_matches
#	define xt_unregister_matches xtnu_unregister_matches
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23)
#	define xt_target             xtnu_target
#	define ip_route_me_harder    xtnu_ip_route_me_harder
#	define xt_register_target    xtnu_register_target
#	define xt_unregister_target  xtnu_unregister_target
#	define xt_register_targets   xtnu_register_targets
#	define xt_unregister_targets xtnu_unregister_targets
#endif

#define xt_request_find_match xtnu_request_find_match

#endif /* _XTABLES_COMPAT_H */
