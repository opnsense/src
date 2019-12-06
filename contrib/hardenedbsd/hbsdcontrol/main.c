/*-
 * Copyright (c) 2015-2018 Oliver Pinter <oliver.pinter@HardenedBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Warning: currently this file is just a thin wrapper around libhbsdcontrol!
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "cmd_pax.h"
#include "hbsdcontrol.h"
#include "libhbsdcontrol.h"

#define	HBSDCONTROL_VERSION	"v000"

static bool flag_force = false;
static int flag_debug = 0;
static bool flag_immutable = false;
static bool flag_keepgoing = false;
static bool flag_usage= false;
static bool flag_version = false;

static void usage(void);

struct hbsdcontrol_command_entry {
	const char	*cmd;
	const int	 min_argc;
	int		(*fn)(int *, char ***);
	void		(*usage)(bool);
};

static const struct hbsdcontrol_command_entry hbsdcontrol_commands[] = {
	{"pax",		3,	pax_cmd,	pax_usage},
	{NULL,		0,	NULL,		NULL},
};


static void
usage(void)
{
	int i;

	for (i = 0; hbsdcontrol_commands[i].cmd != NULL; i++) {
		hbsdcontrol_commands[i].usage(false);
	}

	exit(-1);
}

static void
version(void)
{

	printf("hbsdcontrol version: %s\n", HBSDCONTROL_VERSION);
	printf("libhbsdcontrol version: %s\n", hbsdcontrol_get_version());
}


int
main(int argc, char **argv)
{
	int i;
	int ch;

	if (argc == 1)
		usage();

	while ((ch = getopt(argc, argv, "dfhikv")) != -1) {
		switch (ch) {
		case 'd':
			flag_debug++;
			break;
		case 'f':
			flag_force = true;
			break;
		case 'h':
			flag_usage = true;
			break;
		case 'i':
			flag_immutable = true;
			break;
		case 'k':
			flag_keepgoing = true;
			break;
		case 'v':
			flag_version = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (flag_debug > 0) {
		hbsdcontrol_set_debug(flag_debug);
	}

	if (flag_version) {
		version();
		exit(0);
	}

	if (flag_usage) {
		if (flag_debug) {
			version();
		}
		usage();
	}

	if (getuid() != 0) {
		errx(-1, "Running this program requires root privileges.");
	}

	while (argc > 0) {
		for (i = 0; hbsdcontrol_commands[i].cmd != NULL; i++) {
			if (!strcmp(argv[0], hbsdcontrol_commands[i].cmd)) {
				argv++;
				argc--;

				if (hbsdcontrol_commands[i].fn(&argc, &argv) != 0) {
					if (hbsdcontrol_commands[i].usage)
						hbsdcontrol_commands[i].usage(flag_keepgoing ? false : true);
				}
			}
		}

		argv++;
		argc--;
	}

	if (flag_debug > 0)
		printf("argc at the end: %i\n", argc);

	return (0);
}

