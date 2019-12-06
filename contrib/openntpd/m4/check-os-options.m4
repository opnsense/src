AC_DEFUN([CHECK_OS_OPTIONS], [

CFLAGS="$CFLAGS -Wall -std=gnu99 -fno-strict-aliasing"

case $host_os in
	*aix*)
		HOST_OS=aix
		if test "`echo $CC | cut -d ' ' -f 1`" != "gcc" ; then
			CFLAGS="-qnoansialias $USER_CFLAGS"
		fi
		AC_SUBST([PLATFORM_LDADD], ['-lperfstat -lpthread'])
		;;
	*cygwin*)
		HOST_OS=cygwin
		;;
	*darwin*)
		HOST_OS=darwin
		HOST_ABI=macosx
		# weak seed on failure to open /dev/random, based on latest
		# public source:
		# http://www.opensource.apple.com/source/Libc/Libc-997.90.3/gen/FreeBSD/arc4random.c
		USE_BUILTIN_ARC4RANDOM=yes
		AC_DEFINE(SETEUID_BREAKS_SETUID,[],[setuid after seteuid does not work])
		AC_DEFINE(BROKEN_SETREUID,[], [Broken setreuid])
		AC_DEFINE(BROKEN_SETREGID,[], [Broken setregid])
		AC_DEFINE(YYSTYPE_IS_DECLARED,[], [Broken bison])
		AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV])
		;;
	*freebsd*)
		HOST_OS=freebsd
		HOST_ABI=elf
		# fork detection missing, weak seed on failure
		# https://svnweb.freebsd.org/base/head/lib/libc/gen/arc4random.c?revision=268642&view=markup
		USE_BUILTIN_ARC4RANDOM=yes
		AC_SUBST([PROG_LDADD], ['-lthr'])
		;;
	*hpux*)
		HOST_OS=hpux;
		if test "`echo $CC | cut -d ' ' -f 1`" = "gcc" ; then
			CFLAGS="$CFLAGS -mlp64"
		else
			CFLAGS="-g -O2 +DD64 +Otype_safety=off $USER_CFLAGS"
		fi
		CPPFLAGS="$CPPFLAGS -D_XOPEN_SOURCE=600 -D__STRICT_ALIGNMENT"
		AC_SUBST([PLATFORM_LDADD], ['-lpthread'])
		;;
	*linux*)
		HOST_OS=linux
		HOST_ABI=elf
		CPPFLAGS="$CPPFLAGS -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_POSIX_SOURCE -D_GNU_SOURCE"
		AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV])
		;;
	*netbsd*)
		HOST_OS=netbsd
		HOST_ABI=elf
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/param.h>
#if __NetBSD_Version__ < 700000001
        undefined
#endif
                       ]], [[]])],
                       [ USE_BUILTIN_ARC4RANDOM=no ],
                       [ USE_BUILTIN_ARC4RANDOM=yes ]
		)
		CPPFLAGS="$CPPFLAGS -D_OPENBSD_SOURCE"
		;;
	*openbsd* | *bitrig*)
		HOST_OS=openbsd
		HOST_ABI=elf
		AC_DEFINE([HAVE_ATTRIBUTE__BOUNDED__], [1], [OpenBSD gcc has bounded])
		AC_DEFINE([HAVE_ATTRIBUTE__DEAD], [1], [OpenBSD gcc has __dead])
		;;
	*solaris*)
		HOST_OS=solaris
		HOST_ABI=elf
		CPPFLAGS="$CPPFLAGS -D__EXTENSIONS__ -D_XOPEN_SOURCE=600 -DBSD_COMP"
		AC_SUBST([PLATFORM_LDADD], ['-lnsl -lsocket'])
		;;
	*) ;;
esac

AM_CONDITIONAL([HOST_AIX],     [test x$HOST_OS = xaix])
AM_CONDITIONAL([HOST_CYGWIN],  [test x$HOST_OS = xcygwin])
AM_CONDITIONAL([HOST_DARWIN],  [test x$HOST_OS = xdarwin])
AM_CONDITIONAL([HOST_FREEBSD], [test x$HOST_OS = xfreebsd])
AM_CONDITIONAL([HOST_HPUX],    [test x$HOST_OS = xhpux])
AM_CONDITIONAL([HOST_LINUX],   [test x$HOST_OS = xlinux])
AM_CONDITIONAL([HOST_NETBSD],  [test x$HOST_OS = xnetbsd])
AM_CONDITIONAL([HOST_OPENBSD], [test x$HOST_OS = xopenbsd])
AM_CONDITIONAL([HOST_SOLARIS], [test x$HOST_OS = xsolaris])
])
