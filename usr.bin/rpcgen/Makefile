# $FreeBSD$

PROG=	rpcgen
SRCS=	rpc_main.c  rpc_clntout.c rpc_cout.c rpc_hout.c rpc_parse.c \
	rpc_sample.c rpc_scan.c rpc_svcout.c rpc_tblout.c rpc_util.c

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>
