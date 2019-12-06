#
# Copyright (c) 2014-2015 Brent Cook
# Parts based on configure.ac from Portable OpenNTPD:
# Copyright (c) 2004-2008 Darren Tucker
# which itself was based on configure.ac from OpenSSH:
# Copyright (c) 1999-2004 Damien Miller
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

AC_INIT([OpenNTPD], m4_esyscmd([tr -d '\n' < VERSION]))

AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([subdir-objects foreign])
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
LT_INIT
AC_PROG_YACC

DISABLE_COMPILER_WARNINGS

CHECK_OS_OPTIONS

CHECK_CRYPTO_COMPAT

# check functions that are expected to be in libc
AC_CHECK_FUNCS([asprintf closefrom daemon freezero memmem poll reallocarray recallocarray])
AC_CHECK_FUNCS([setproctitle setgroups])
AC_CHECK_FUNCS([setregid setresgid setreuid setresuid])
AC_CHECK_FUNCS([strlcat strlcpy strtonum sysconf])

# check auxiliary libraries that might contain other functions
AC_SEARCH_LIBS([arc4random], [crypto])
AC_SEARCH_LIBS([ibuf_open], [util])

AC_CHECK_FUNCS([ibuf_open])

# time-specific system functions
AC_SEARCH_LIBS([clock_getres],[rt posix4])
AC_SEARCH_LIBS([clock_gettime],[rt posix4])
AC_CHECK_FUNCS([adjfreq ntp_adjtime adjtimex])
AC_CHECK_FUNCS([clock_gettime clock_getres])
AM_CONDITIONAL([HAVE_ADJFREQ], [test "x$ac_cv_func_adjfreq" = xyes])
AM_CONDITIONAL([HAVE_CLOCK_GETRES], [test "x$ac_cv_func_clock_getres" = xyes])
AM_CONDITIONAL([HAVE_CLOCK_GETTIME], [test "x$ac_cv_func_clock_gettime" = xyes])

# check for libtls
AC_SEARCH_LIBS([tls_config_set_ca_mem],[tls],
	       [LIBS="$LIBS -ltls -lssl -lcrypto"],,[-lssl -lcrypto])
AC_CHECK_FUNCS([tls_config_set_ca_mem])

# check if libtls uses 3-argument tls_write
AC_CACHE_CHECK([if tls_write takes 3 arguments], ac_cv_have_tls_write_3_arg, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <tls.h>
size_t outlen;
		]], [[ tls_write(NULL, NULL, 0); ]])],
	[ ac_cv_have_tls_write_3_arg="yes" ],
	[ ac_cv_have_tls_write_3_arg="no"
	])
])

AC_ARG_ENABLE([https-constraint],
	AS_HELP_STRING([--disable-https-constraint],
		[Disable HTTPS Constraint Functionality]))

AM_CONDITIONAL([HAVE_LIBTLS],
	[test "x$ac_cv_func_tls_config_set_ca_mem" = xyes \
	  -a "x$ac_cv_have_tls_write_3_arg" = xyes \
	  -a "x$enable_https_constraint" != xno])

if test "x$ac_cv_func_tls_config_set_ca_mem" = xyes \
	-a "x$ac_cv_have_tls_write_3_arg" = xyes \
	-a "x$enable_https_constraint" != xno; then
        AC_DEFINE([HAVE_LIBTLS], [yes])
fi

# Share test results with automake
AM_CONDITIONAL([HAVE_ASPRINTF], [test "x$ac_cv_func_asprintf" = xyes])
AM_CONDITIONAL([HAVE_CLOSEFROM], [test "x$ac_cv_func_closefrom" = xyes])
AM_CONDITIONAL([HAVE_DAEMON], [test "x$ac_cv_func_daemon" = xyes])
AM_CONDITIONAL([HAVE_EXPLICIT_BZERO], [test "x$ac_cv_func_explicit_bzero" = xyes])
AM_CONDITIONAL([HAVE_FREEZERO], [test "x$ac_cv_func_freezero" = xyes])
AM_CONDITIONAL([HAVE_IFADDRS_H], [test "x$ac_cv_header_ifaddrs_h" = xyes])
AM_CONDITIONAL([HAVE_IMSG], [test "x$ac_cv_func_ibuf_open" = xyes])
AM_CONDITIONAL([HAVE_MEMMEM], [test "x$ac_cv_func_memmem" = xyes])
AM_CONDITIONAL([HAVE_POLL], [test "x$ac_cv_func_poll" = xyes])
AM_CONDITIONAL([HAVE_REALLOCARRAY], [test "x$ac_cv_func_reallocarray" = xyes])
AM_CONDITIONAL([HAVE_RECALLOCARRAY], [test "x$ac_cv_func_recallocarray" = xyes])
AM_CONDITIONAL([HAVE_SETGROUPS], [test "x$ac_cv_func_setgroups" = xyes])
AM_CONDITIONAL([HAVE_SETRESGID], [test "x$ac_cv_func_setresgid" = xyes])
AM_CONDITIONAL([HAVE_SETRESUID], [test "x$ac_cv_func_setresuid" = xyes])
AM_CONDITIONAL([HAVE_SETPROCTITLE], [test "x$ac_cv_func_setproctitle" = xyes])
AM_CONDITIONAL([HAVE_STRLCAT], [test "x$ac_cv_func_strlcat" = xyes])
AM_CONDITIONAL([HAVE_STRLCPY], [test "x$ac_cv_func_strlcpy" = xyes])
AM_CONDITIONAL([HAVE_STRTONUM], [test "x$ac_cv_func_strtonum" = xyes])
AM_CONDITIONAL([HAVE_SYSCONF], [test "x$ac_cv_func_sysconf" = xyes])

CHECK_PROGNAME
CHECK_VA_COPY

AC_CHECK_HEADERS([sys/sysctl.h err.h ifaddrs.h paths.h])

AC_CHECK_HEADERS([sys/sensors.h],
	AM_CONDITIONAL(HAVE_SENSORS, true),
	AM_CONDITIONAL(HAVE_SENSORS, false)
)

AC_CHECK_MEMBERS([struct sockaddr_in.sin_len], , ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)

AC_ARG_WITH([privsep-user],
	AS_HELP_STRING([--with-privsep-user=user],
		       [Privilege separation user for ntpd to use]),
	PRIVSEP_USER="$withval",
	PRIVSEP_USER="_ntp"
)
AC_DEFINE_UNQUOTED(NTPD_USER, "$PRIVSEP_USER", [Unprivileged user])
AC_SUBST(PRIVSEP_USER)

AC_ARG_WITH([privsep-path],
	AS_HELP_STRING([--with-privsep-path=path],
		       [Privilege separation chroot path to check on install]),
	PRIVSEP_PATH="$withval",
	PRIVSEP_PATH="/var/empty"
)
AC_SUBST(PRIVSEP_PATH)

AC_ARG_WITH([cacert],
	AS_HELP_STRING([--with-cacert=path],
		       [CA certificate location for HTTPS constraint validation]),
	CONSTRAINT_CA="$withval",
	CONSTRAINT_CA="/etc/ssl/cert.pem"
)
AC_DEFINE_UNQUOTED(CONSTRAINT_CA, "$CONSTRAINT_CA", [CA certificate path])

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	compat/Makefile
	src/Makefile
])

AC_OUTPUT
