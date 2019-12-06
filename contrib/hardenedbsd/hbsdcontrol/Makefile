PROG=	hbsdcontrol
MAN=	hbsdcontrol.8

SRCS=	main.c cmd_pax.c
SRCS+=	libhbsdcontrol.c

INCS=	hbsdcontrol.h cmd_pax.h
INCS+=	libhbsdcontrol.h

LIBADD=	sbuf
LDADD=  -lsbuf

.include <bsd.prog.mk>
