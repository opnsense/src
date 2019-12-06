#	from: @(#)Makefile	5.2 (Berkeley) 5/11/90
# $FreeBSD$

PROG=	rpcinfo
SRCS=	rpcinfo.c
MAN=	rpcinfo.8

CFLAGS+= -DPORTMAP

WARNS?=	2

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>
