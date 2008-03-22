# -*- Makefile -*-

AUTOMAKE_OPTIONS = foreign subdir-objects
SUBDIRS          = extensions

.PHONY: tarball
tarball:
	rm -Rf /tmp/xtables-addons-${PACKAGE_VERSION};
	pushd ${top_srcdir} && git-archive --prefix=xtables-addons-${PACKAGE_VERSION}/ HEAD | tar -C /tmp -x && popd;
	pushd /tmp/xtables-addons-${PACKAGE_VERSION} && ./autogen.sh && popd;
	tar -C /tmp -cjf xtables-addons-${PACKAGE_VERSION}.tar.bz2 --owner=root --group=root xtables-addons-${PACKAGE_VERSION}/;
	rm -Rf /tmp/xtables-addons-${PACKAGE_VERSION};
