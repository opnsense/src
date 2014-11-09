/*
 * Copyright (c) 2013 Ermal Lu‡i
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet/ip_fw.h>

#include "ipfw2.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <string.h>
#include <errno.h>
#include <err.h>

extern int ipfw_socket;

int
ipfw_context_handler(int ac, char **av)
{
        ip_fw3_opheader *op3;
	int error = 0;
	uint32_t action = 0;
	socklen_t len, nlen;
	char *ifname;

	av++;
	ac--;
	NEED1("bad arguments, for usage summary ``ipfw''");

	if (!strncmp(*av, "list", strlen(*av))) {
		action = IP_FW_CTX_GET;
		av++;
		ac--;
		if (ac > 0)
			errx(EX_DATAERR, "list: does not take any extra arguments.");

	} else {
		co.ctx = atoi(*av);

		av++;
		ac--;
		NEED1("bad arguments, for usage summary ``ipfw''");

		if (!strncmp(*av, "create", strlen(*av)))
			action = IP_FW_CTX_ADD;
		else if (!strncmp(*av, "destroy", strlen(*av)))
			action = IP_FW_CTX_DEL;
		else {
			if (!strncmp(*av, "madd", strlen(*av)))
				action = IP_FW_CTX_ADDMEMBER;
			else if (!strncmp(*av, "mdel", strlen(*av)))
				action = IP_FW_CTX_DELMEMBER;
			else
				errx(EX_DATAERR, "Wrong parameters passed");

			av++;
			ac--;
			NEED1("bad arguments, for usage summary ``ipfw''");

			ifname = *av;
		}

		ac--;
		if (ac > 0)
			errx(EX_DATAERR, "context handling: Too many arguments passed");

	}

        if (co.test_only)
                return (0);

        if (ipfw_socket < 0)
                ipfw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (ipfw_socket < 0)
                err(EX_UNAVAILABLE, "socket");

	switch (action) {
	case IP_FW_CTX_ADD:
	case IP_FW_CTX_DEL:
	case IP_FW_CTX_SET:
		len = sizeof(ip_fw3_opheader);
		op3 = alloca(len);
		/* Zero reserved fields */
		memset(op3, 0, sizeof(ip_fw3_opheader));
		op3->opcode = action;
		op3->ctxid = co.ctx;
		error = setsockopt(ipfw_socket, IPPROTO_IP, IP_FW3, op3, len);
		break;
	case IP_FW_CTX_ADDMEMBER:
	case IP_FW_CTX_DELMEMBER:
		len = sizeof(ip_fw3_opheader) + strlen(ifname) + 1;
		op3 = alloca(len);
		/* Zero reserved fields */
		memset(op3, 0, sizeof(ip_fw3_opheader));
		memcpy((op3 + 1), ifname, strlen(ifname));
		op3->opcode = action;
		op3->ctxid = co.ctx;
		error = setsockopt(ipfw_socket, IPPROTO_IP, IP_FW3, op3, len);
		break;
	case IP_FW_CTX_GET:
		len = sizeof(ip_fw3_opheader) + 1000;
		nlen = len;
		do {
			if (nlen > len) {
				len = nlen;
			}
			op3 = alloca(len);
			/* Zero reserved fields */
			memset(op3, 0, sizeof(ip_fw3_opheader));
			op3->opcode = action;
			op3->ctxid = co.ctx;
			nlen = len;
			error = getsockopt(ipfw_socket, IPPROTO_IP, IP_FW3, op3, &nlen);
		} while (nlen > len && !error);

		if (!error) {
			if (nlen == 0)
				printf("There are no contextes defined\n");
			else
				printf("Currently defined contextes and their members:\n%s\n", (char *)op3);
		} else
			err(EX_UNAVAILABLE, "Error returned: %s\n", strerror(error));

		break;
	}

	return (error);
}
