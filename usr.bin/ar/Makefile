# $FreeBSD$

.include <src.opts.mk>

PROG=	elftc-ar
SRCS=	ar.c acplex.l acpyacc.y read.c util.c write.c y.tab.h
MAN=	ar.1

LIBADD=	archive elf

NO_WMISSING_VARIABLE_DECLARATIONS=

CFLAGS+=-I. -I${.CURDIR}

.if ${MK_SHARED_TOOLCHAIN} == "no"
NO_SHARED?=	yes
.endif

.if ${MK_LLVM_AR_IS_AR} == "no"
SYMLINKS=	${BINDIR}/elftc-ar ${BINDIR}/ranlib \
    ${BINDIR}/elftc-ar ${BINDIR}/ar
.else
SYMLINKS=	${BINDIR}/elftc-ar ${BINDIR}/elftc-ranlib
.endif

MLINKS= ar.1 ranlib.1

.include <bsd.prog.mk>
