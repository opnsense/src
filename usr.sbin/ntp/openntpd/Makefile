#	$OpenBSD: Makefile,v 1.16 2015/11/20 18:53:42 tedu Exp $

OPENNTPD_SRC=	${.CURDIR}/../../../contrib/openntpd/src

PROG=	ntpd
# compat
SRCS=	freezero.c imsg.c imsg-buffer.c adjfreq_freebsd.c \
	progname.c setproctitle.c
# Imported from OpenBSD src makefile
SRCS+=	ntpd.c log.c ntp.c ntp_msg.c parse.y config.c \
	server.c client.c fake-sensors.c util.c ntp_dns.c \
	control.c constraint.c
CFLAGS+= -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
# Add includes and defines
CFLAGS+= -I${OPENNTPD_SRC}
CFLAGS+= -I${OPENNTPD_SRC}/../include
CFLAGS+= -DHAVE_CLOSEFROM=1
CFLAGS+= -DHAVE_LIBTLS=yes
CFLAGS+= -DHAVE___PROGNAME=1
CFLAGS+= -DHAVE_SETPROCTITLE=1

LIBADD+=	m md util tls ssl crypto
LINKS=	${BINDIR}/ntpd ${BINDIR}/ntpctl
MAN5=	ntpd.conf.5
MAN8=	ntpd.8 ntpctl.8

CONFS=		ntpd.conf
CONFSDIR=	/etc
CONFSMODE=	644

.PATH:	${OPENNTPD_SRC}/../compat ${OPENNTPD_SRC}

.include <bsd.prog.mk>
