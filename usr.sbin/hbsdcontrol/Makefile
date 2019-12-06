PACKAGE=hardenedbsd

PROG=hbsdcontrol

.PATH: ${SRCTOP}/contrib/hardenedbsd/hbsdcontrol
CFLAGS+= -I${HBSDCONTROL_DIR}

LIBADD= sbuf hbsdcontrol

SRCS= main.c
SRCS+= cmd_pax.c

MAN= hbsdcontrol.8

.include <bsd.prog.mk>
