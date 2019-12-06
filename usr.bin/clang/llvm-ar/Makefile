# $FreeBSD$

.include <src.opts.mk>

PROG_CXX=	llvm-ar

SRCDIR=		tools/llvm-ar
SRCS+=		llvm-ar.cpp

LIBADD+=	z

LINKS+=		${BINDIR}/llvm-ar ${BINDIR}/llvm-ranlib

.if ${MK_LLVM_AR_IS_AR} != "no"
SYMLINKS=	${BINDIR}/llvm-ar ${BINDIR}/ar \
    ${BINDIR}/llvm-ar ${BINDIR}/ranlib
.endif

.include "../llvm.prog.mk"
