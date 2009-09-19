# -*- Makefile -*-

AM_CFLAGS       = ${regular_CFLAGS} -DIPSET_LIB_DIR=\"${xtlibdir}\"

sbin_PROGRAMS = ipset
pkglibexec_LTLIBRARIES = \
	libipset_iphash.la \
	libipset_ipmap.la \
	libipset_ipporthash.la \
	libipset_ipportiphash.la \
	libipset_ipportnethash.la \
	libipset_iptree.la \
	libipset_iptreemap.la \
	libipset_macipmap.la \
	libipset_nethash.la \
	libipset_portmap.la \
	libipset_setlist.la

ipset_LDADD   = -ldl
ipset_LDFLAGS = -rdynamic

module_flags = -avoid-version -module

libipset_iphash_la_SOURCES        = ipset_iphash.c
libipset_iphash_la_LDFLAGS        = ${module_flags}
libipset_ipmap_la_SOURCES         = ipset_ipmap.c
libipset_ipmap_la_LDFLAGS         = ${module_flags}
libipset_ipporthash_la_SOURCES    = ipset_ipporthash.c
libipset_ipporthash_la_LDFLAGS    = ${module_flags}
libipset_ipportiphash_la_SOURCES  = ipset_ipportiphash.c
libipset_ipportiphash_la_LDFLAGS  = ${module_flags}
libipset_ipportnethash_la_SOURCES = ipset_ipportnethash.c
libipset_ipportnethash_la_LDFLAGS = ${module_flags}
libipset_iptree_la_SOURCES        = ipset_iptree.c
libipset_iptree_la_LDFLAGS        = ${module_flags}
libipset_iptreemap_la_SOURCES     = ipset_iptreemap.c
libipset_iptreemap_la_LDFLAGS     = ${module_flags}
libipset_macipmap_la_SOURCES      = ipset_macipmap.c
libipset_macipmap_la_LDFLAGS      = ${module_flags}
libipset_nethash_la_SOURCES       = ipset_nethash.c
libipset_nethash_la_LDFLAGS       = ${module_flags}
libipset_portmap_la_SOURCES       = ipset_portmap.c
libipset_portmap_la_LDFLAGS       = ${module_flags}
libipset_setlist_la_SOURCES       = ipset_setlist.c
libipset_setlist_la_LDFLAGS       = ${module_flags}
