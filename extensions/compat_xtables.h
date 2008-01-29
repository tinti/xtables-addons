#ifndef _XTABLES_COMPAT_H
#define _XTABLES_COMPAT_H 1

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
#	define NF_INET_PRE_ROUTING  NF_IP_PRE_ROUTING
#	define NF_INET_LOCAL_IN     NF_IP_LOCAL_IN
#	define NF_INET_FORWARD      NF_IP_FORWARD
#	define NF_INET_LOCAL_OUT    NF_IP_LOCAL_OUT
#	define NF_INET_POST_ROUTING NF_IP_POST_ROUTING
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
#	include "compat_nfinetaddr.h"
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
#endif

#include "compat_xtnu.h"

#endif /* _XTABLES_COMPAT_H */
