# $FreeBSD$

.include <src.opts.mk>

SUBDIR= 
.if ${MK_OPENSSL} != "no"
.  if ${MK_LIBRESSL} != "no"
SUBDIR+=ocspcheck
.  endif
.endif
.if ${MK_OPENSSH} != "no"
SUBDIR+=sshd
.endif

SUBDIR.${MK_TESTS}+= tests

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
