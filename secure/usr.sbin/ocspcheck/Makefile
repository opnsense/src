#	$OpenBSD: Makefile,v 1.2 2017/01/24 09:25:27 deraadt Exp $

.include "../../lib/libcrypto/Makefile.inc.libressl"

PROG=	ocspcheck
MAN8=	ocspcheck.8

LIBADD=	 tls ssl crypto

CFLAGS+= -Wall -Werror
CFLAGS+= -Wformat
CFLAGS+= -Wformat-security
CFLAGS+= -Wimplicit
CFLAGS+= -Wreturn-type
CFLAGS+= -Wshadow
CFLAGS+= -Wtrigraphs
CFLAGS+= -Wuninitialized
CFLAGS+= -Wunused

CFLAGS+= -DLIBRESSL_INTERNAL

SRCS=	ocspcheck.c http.c

.include <bsd.prog.mk>

.PATH:  ${LIBRESSL_SRC}/apps/ocspcheck
