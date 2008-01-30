# -*- Makefile -*-

AUTOMAKE_OPTIONS = foreign subdir-objects
abssrcdir        = $(shell readlink -f ${srcdir})

regular_CFLAGS  := @regular_CFLAGS@
iptables_CFLAGS := @iptables_CFLAGS@
kinclude_CFLAGS := @kinclude_CFLAGS@
AM_CFLAGS        = ${regular_CFLAGS} ${iptables_CFLAGS} ${kinclude_CFLAGS} \
                   -D_INIT=$*_init
AM_LDFLAGS       = -module -avoid-version
ipt_LTLIBRARIES  = \
	libxt_LOGMARK.la \
	libxt_TARPIT.la \
	libxt_TEE.la

#
#	Call out to kbuild
#
.PHONY: modules modules_install clean_modules

all-local: modules

install-exec-local: modules_install

clean-local: clean_modules

modules:
	make -C ${kbuilddir} M=${abssrcdir} modules;

modules_install:
	make -C ${kbuilddir} M=${abssrcdir} INSTALL_MOD_PATH=${DESTDIR} modules_install;

clean_modules:
	make -C ${kbuilddir} M=${abssrcdir} clean;
