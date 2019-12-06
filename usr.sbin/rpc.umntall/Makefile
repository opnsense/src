#	@(#)Makefile	8.4 (Berkeley) 6/22/95
# $FreeBSD$

PROG=	rpc.umntall
MAN=	rpc.umntall.8
SRCS=	rpc.umntall.c mounttab.c

WARNS?= 3

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>
