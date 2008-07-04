# -*- Makefile -*-

AUTOMAKE_OPTIONS = foreign subdir-objects
SUBDIRS          = extensions extensions/ipset

man_MANS := xtables-addons.8

xtables-addons.8: ${srcdir}/xtables-addons.8.in extensions/matches.man extensions/targets.man
	${AM_VERBOSE_GEN} sed -e '/@MATCHES@/ r extensions/matches.man' -e '/@TARGET@/ r extensions/targets.man' $< >$@;

extensions/%:
	${MAKE} ${AM_MAKEFLAGS} -C $(@D) $(@F)

.PHONY: tarball
tarball:
	rm -Rf /tmp/xtables-addons-${PACKAGE_VERSION};
	pushd ${top_srcdir} && git-archive --prefix=xtables-addons-${PACKAGE_VERSION}/ HEAD | tar -C /tmp -x && popd;
	pushd /tmp/xtables-addons-${PACKAGE_VERSION} && ./autogen.sh && popd;
	tar -C /tmp -cjf xtables-addons-${PACKAGE_VERSION}.tar.bz2 --owner=root --group=root xtables-addons-${PACKAGE_VERSION}/;
	rm -Rf /tmp/xtables-addons-${PACKAGE_VERSION};
