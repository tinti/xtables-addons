# -*- Makefile -*-

ACLOCAL_AMFLAGS  = -I m4
SUBDIRS          = extensions

man_MANS := xtables-addons.8

.PHONY: FORCE
FORCE:

xtables-addons.8: FORCE
	${MAKE} -f Makefile.mans all;

install-exec-hook:
	depmod -a || :;

config.status: Makefile.iptrules.in

.PHONY: tarball
tarball:
	rm -Rf /tmp/xtables-addons-${PACKAGE_VERSION};
	pushd ${top_srcdir} && git archive --prefix=xtables-addons-${PACKAGE_VERSION}/ HEAD | tar -C /tmp -x && popd;
	pushd /tmp/xtables-addons-${PACKAGE_VERSION} && ./autogen.sh && popd;
	tar -C /tmp -cjf xtables-addons-${PACKAGE_VERSION}.tar.bz2 --owner=root --group=root xtables-addons-${PACKAGE_VERSION}/;
	rm -Rf /tmp/xtables-addons-${PACKAGE_VERSION};
