# -*- Makefile -*-

AM_CPPFLAGS = -I${srcdir}/include
AM_CFLAGS = ${regular_CFLAGS} ${libmnl_CFLAGS}

include ../../Makefile.extra

lib_LTLIBRARIES = libipset.la
libipset_la_SOURCES = libipset/data.c libipset/icmp.c libipset/icmpv6.c \
                      libipset/mnl.c libipset/parse.c libipset/print.c \
                      libipset/session.c libipset/types.c
libipset_la_LIBADD  = ${libmnl_LIBS}
libipset_la_LDFLAGS = -version-info 1:0:0

sbin_PROGRAMS = ipset
ipset_SOURCES = src/ipset.c src/errcode.c src/ui.c src/ipset_bitmap_ip.c \
                src/ipset_bitmap_ipmac.c src/ipset_bitmap_port.c \
                src/ipset_hash_ip.c src/ipset_hash_ipport.c \
                src/ipset_hash_ipportip.c src/ipset_hash_ipportnet.c \
                src/ipset_hash_net.c src/ipset_hash_netport.c \
                src/ipset_list_set.c
ipset_LDADD   = libipset.la

man_MANS      = ipset.8
