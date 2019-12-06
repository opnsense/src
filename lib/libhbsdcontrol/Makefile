.include <bsd.own.mk>

PACKAGE=lib${LIB}
SHLIBDIR?= /lib

LIB=	hbsdcontrol
SHLIB_MAJOR=	0

.PATH: ${SRCTOP}/contrib/hardenedbsd/hbsdcontrol
CFLAGS+=-I${.CURDIR}

SRCS=	libhbsdcontrol.c
INCS=	libhbsdcontrol.h
MAN+=	libhbsdcontrol.3
MLINKS+=	libhbsdcontrol.3	hbsdcontrol_set_extattr.3
MLINKS+=	libhbsdcontrol.3	hbsdcontrol_rm_extattr.3
MLINKS+=	libhbsdcontrol.3	hbsdcontrol_set_feature_state.3
MLINKS+=	libhbsdcontrol.3	hbsdcontrol_rm_feature_state.3

.include <bsd.lib.mk>
