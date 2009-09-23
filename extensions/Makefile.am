# -*- Makefile -*-
# AUTOMAKE

# Not having Kbuild in Makefile.extra because it will already recurse
.PHONY: modules modules_install clean_modules

_kcall = ${MAKE} -C ${kbuilddir} M=${abs_srcdir}

modules:
	${AM_V_silent}if [ -n "${kbuilddir}" ]; then ${_kcall} modules; fi;

modules_install:
	${AM_V_silent}if [ -n "${kbuilddir}" ]; then ${_kcall} INSTALL_MOD_PATH=${DESTDIR} modules_install; fi;

clean_modules:
	${AM_V_silent}if [ -n "${kbuilddir}" ]; then ${_kcall} clean; fi;

all-local: modules

install-exec-local: modules_install

clean-local: clean_modules

include ../Makefile.extra
