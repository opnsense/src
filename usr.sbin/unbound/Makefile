# $FreeBSD$
.include <src.opts.mk>

SUBDIR=	daemon anchor checkconf control host
SUBDIR+= setup
SUBDIR_PARALLEL=

.if ${MK_LIBRESSL} != "no"
CFLAGS+= -DHAVE_LIBRESSL=1
.endif

.include <bsd.subdir.mk>
