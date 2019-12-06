# $FreeBSD$

.include <src.opts.mk>

PROG_CXX=	llvm-objdump

SRCDIR=		tools/llvm-objdump
SRCS+=		COFFDump.cpp
SRCS+=		ELFDump.cpp
SRCS+=		MachODump.cpp
SRCS+=		WasmDump.cpp
SRCS+=		llvm-objdump.cpp

LIBADD+=	z

.if ${MK_LLVM_OBJDUMP_IS_OBJDUMP} != "no"
SYMLINKS=	${BINDIR}/llvm-objdump \
    ${BINDIR}/objdump
.endif

.include "../llvm.prog.mk"
