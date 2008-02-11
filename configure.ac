
AC_INIT([xtables-addons], [1.5.0])
AC_CONFIG_HEADERS([config.h])
AC_PROG_INSTALL
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

kbuilddir="/lib/modules/$(uname -r)/build";
ksourcedir="/lib/modules/$(uname -r)/source";
AC_ARG_WITH([kbuild],
	AS_HELP_STRING([--with-kbuild=PATH],
	[Path to kernel build directory [[/lib/modules/CURRENT/build]]]),
	[kbuilddir="$withval"])
AC_ARG_WITH([ksource],
	AS_HELP_STRING([--with-ksource=PATH],
	[Path to kernel source directory [[/lib/modules/CURRENT/source]]]),
	[ksourcedir="$withval"])
AC_ARG_WITH([xtables],
	AS_HELP_STRING([--with-xtables=PATH],
	[Path to the Xtables includes [[none]]]),
	[xtables_location="$withval"])
AC_ARG_WITH([xtlibdir],
	AS_HELP_STRING([--with-xtlibdir=PATH],
	[Path where to install Xtables extensions [[LIBEXECDIR/xtables]]]),
	[xtlibdir="$withval"],
	[xtlibdir='${libexecdir}/xtables'])

AC_CHECK_HEADER([netinet/ip6.h], [], [AC_MSG_ERROR(but we need that for IPv6)])

AC_MSG_CHECKING([xtables.h presence])
if [[ -n "$xtables_location" ]]; then
	if [[ -f "$xtables_location/xtables.h" ]]; then
		AC_MSG_RESULT([$xtables_location/xtables.h])
		xtables_CFLAGS="-I $xtables_location";
	elif [[ -f "$xtables_location/include/xtables.h" ]]; then
		AC_MSG_RESULT([$xtables_location/include/xtables.h])
		xtables_CFLAGS="-I $xtables_location/include";
	fi;
fi;
if [[ -z "$xtables_CFLAGS" ]]; then
	if [[ -f "$includedir/xtables.h" ]]; then
		AC_MSG_RESULT([$includedir/xtables.h])
	else
		AC_MSG_RESULT([no])
	fi;
fi;

regular_CFLAGS="-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe -DIPTABLES_VERSION=\\\"$PACKAGE_VERSION\\\" \
	-DXTABLES_LIBDIR=\\\"\${xtlibdir}\\\"";
kinclude_CFLAGS="-I $kbuilddir/include -I $ksourcedir/include";

AC_SUBST([regular_CFLAGS xtables_CFLAGS kinclude_CFLAGS])
AC_SUBST([kbuilddir])
AC_SUBST([ksourcedir])
AC_SUBST([xtlibdir])
AC_OUTPUT([Makefile extensions/Makefile])
