#	$OpenBSD: Makefile,v 1.22 2015/10/07 23:33:38 beck Exp $

.include "../libcrypto/Makefile.inc.libressl"

.if exists(Makefile.man)
.include "Makefile.man"
.endif

CFLAGS+= -Wall -Werror -Wimplicit
CFLAGS+= -DLIBRESSL_INTERNAL

LIB=	tls
SHLIB_MAJOR=	16

LTLS_SRC=	${LIBRESSL_SRC}/tls

LIBADD= crypto ssl

INCS=	tls.h

SRCS=	tls.c \
	tls_bio_cb.c \
	tls_client.c \
	tls_config.c \
	tls_conninfo.c \
	tls_peer.c \
	tls_server.c \
	tls_util.c \
	tls_ocsp.c \
	tls_verify.c

.PATH: ${LTLS_SRC} \
	${LIBRESSL_SRC}/include \
	${LIBRESSL_SRC}/man

.include <bsd.lib.mk>
