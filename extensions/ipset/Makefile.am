# -*- Makefile -*-

AM_CFLAGS = ${regular_CFLAGS} -DIPSET_LIB_DIR=\"${xtlibdir}\" \
            -DIP_NF_SET_HASHSIZE=1024

include ../../Makefile.extra

sbin_PROGRAMS = ipset
ipset_LDADD   = -ldl
ipset_LDFLAGS = -rdynamic

man_MANS      = ipset.8
