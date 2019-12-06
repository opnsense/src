# $FreeBSD$

MK_BIND_NOW=	no

CFLAGS+=	${CFLAGS_NO_SIMD} -msoft-float
