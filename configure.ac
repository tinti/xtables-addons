
AC_INIT([iptables-addons], [1.4.1])
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
AC_ARG_WITH([iptables],
	AS_HELP_STRING([--with-iptables=PATH],
	[Path to the iptables includes [[PREFIX/include]]]),
	[iptables_location="$withval"])
AC_ARG_WITH([iptdir],
	AS_HELP_STRING([--with-iptdir=PATH],
	[Path to iptables modules [[LIBEXECDIR/iptables]]]),
	[iptdir="$withval"],
	[iptdir='${libexecdir}/iptables'])

AC_CHECK_HEADER([netinet/ip6.h], [], [AC_MSG_ERROR(but we need that for IPv6)])

AC_MSG_CHECKING([xtables.h presence])
if [[ -n "$iptables_location" ]]; then
	if [[ -f "$iptables_location/xtables.h" ]]; then
		AC_MSG_RESULT([$iptables_location/xtables.h])
		iptables_CFLAGS="-I$iptables_location";
	elif [[ -f "$iptables_location/include/xtables.h" ]]; then
		AC_MSG_RESULT([$iptables_location/include/xtables.h])
		iptables_CFLAGS="-I$iptables_location/include";
	fi;
fi;
if [[ -z "$iptables_CFLAGS" ]]; then
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
	-DIPT_LIB_DIR=\\\"\${iptdir}\\\" -DIP6T_LIB_DIR=\\\"\${iptdir}\\\"";
kinclude_CFLAGS="-I\"$kbuilddir/include\" -I\"$ksourcedir/include\"";

AC_SUBST([regular_CFLAGS iptables_CFLAGS kinclude_CFLAGS])
AC_SUBST([kbuilddir])
AC_SUBST([ksourcedir])
AC_SUBST([iptdir])
AC_OUTPUT([Makefile extensions/Makefile])
