# $FreeBSD$

.PATH: ${SRCTOP}/contrib/netcat

PROG=	nc
SRCS=	netcat.c atomicio.c socks.c

CFLAGS+=-DIPSEC
LIBADD=	ipsec

CFI_OVERRIDE=-fno-sanitize=cfi-icall

WARNS?=	2

.include <bsd.prog.mk>
