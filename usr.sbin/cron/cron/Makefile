# $FreeBSD$

CONFS=	crontab
PROG=	cron
MAN=	cron.8
SRCS=	cron.c database.c do_command.c job.c user.c popen.c

NOCFI=	yes

CFLAGS+= -DLOGIN_CAP -DPAM

LIBADD=	cron pam util

WARNS?=	2

.include <bsd.prog.mk>
