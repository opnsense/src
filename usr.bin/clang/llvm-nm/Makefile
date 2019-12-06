# $FreeBSD$

.include <src.opts.mk>

PROG_CXX=	llvm-nm

SRCDIR=		tools/llvm-nm
SRCS+=		llvm-nm.cpp

LIBADD+=	z

.if ${MK_LLVM_NM_IS_NM} != "no"
SYMLINKS=	${BINDIR}/llvm-nm ${BINDIR}/nm
.endif

.include "../llvm.prog.mk"
