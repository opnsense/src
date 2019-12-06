# $FreeBSD$

DO32=1

.include <bsd.init.mk>

MK_SPECTREV1_FIX=no

LIB=sa32
LIBSA_CPUARCH=${MACHINE_CPUARCH:C/amd64/i386/}

.PATH:	${SASRC}
.include "${SASRC}/Makefile"
