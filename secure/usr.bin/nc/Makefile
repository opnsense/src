#	$OpenBSD: Makefile,v 1.7 2015/09/11 21:07:01 beck Exp $

.include "../../lib/libcrypto/Makefile.inc.libressl"

PROG=	nc
SRCS=	netcat.c atomicio.c socks.c
LIBADD+= tls ssl crypto

# Reset man-dir set for LibreSSL
MANDIR=	${SHAREDIR}/man/man
MAN1=	nc.1

.PATH:	${LIBRESSL_SRC}/apps/nc

.include <bsd.prog.mk>
