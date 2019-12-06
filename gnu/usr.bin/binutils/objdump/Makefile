# $FreeBSD$

.include "../Makefile.inc0"
.include <src.opts.mk>

.PATH: ${SRCDIR}/binutils ${SRCDIR}/binutils/doc

PROG=	gnu-objdump
SRCS=	objdump.c prdbg.c
CFLAGS+= -D_GNU_SOURCE
CFLAGS+= -I${.CURDIR}/${GNURELTOP}/libbinutils
CFLAGS+= -I${SRCDIR}/binutils
CFLAGS+= -DBFD_VERSION_STRING=\"${VERSION}\"
DPADD=	${GNURELTOP}/libbinutils/libbinutils.a
DPADD+=	${GNURELTOP}/libopcodes/libopcodes.a
DPADD+=	${GNURELTOP}/libbfd/libbfd.a
DPADD+=	${GNURELTOP}/libiberty/libiberty.a
LDADD=	${DPADD}
MAN=	objdump.1

.if ${MK_LLVM_OBJDUMP_IS_OBJDUMP} != "yes"
SYMLINKS+=	${BINDIR}/gnu-objdump ${BINDIR}/objdump
.endif

.include <bsd.prog.mk>
