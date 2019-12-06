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

#include <sys/types.h>
#include <sys/sbuf.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <err.h>
#include <errno.h>

#include "cmd_pax.h"
#include "hbsdcontrol.h"
#include "libhbsdcontrol.h"

static int pax_enable_cb(int *argc, char ***argv);
static int pax_disable_cb(int *argc, char ***argv);
static int pax_reset_cb(int *argc, char ***argv);
static int pax_list_cb(int *argc, char ***argv);

static int dummy_cb(int *argc __unused, char ***argv __unused) __unused;

static const struct hbsdcontrol_action_entry hbsdcontrol_pax_actions[] = {
	{"enable",	3,	pax_enable_cb},
	{"disable",	3,	pax_disable_cb},
//	{"status",	3,	dummy_cb},
	{"reset",	3,	pax_reset_cb},
	{"sysdef",	3,	pax_reset_cb},
//	{"reset-all",	2,	dummy_cb},
	{"list",	2,	pax_list_cb},
	{NULL,		0,	NULL}
};

static int
dummy_cb(int *argc __unused, char ***argv __unused)
{

	errx(-1, "dummy_cb");
}

static int
enable_disable(int *argc, char ***argv, int state)
{
	char *feature;
	char *file;
	struct stat st;

	if (*argc < 3)
		pax_usage(true);


	feature = (*argv)[1];
	file = (*argv)[2];

	*argc -= 2;
	*argv += 2;

	if (lstat(file, &st)) {
		fprintf(stderr, "missing file: %s\n", file);
		return (1);
	}

	hbsdcontrol_set_feature_state(file, feature, state);

	return (0);
}

static int
pax_list(int *argc, char ***argv)
{
	char *file;
	char *features;
	struct stat st;

	if (*argc < 2)
		err(-1, "bar");


	file = (*argv)[1];

	features = NULL;

	(*argc)--;
	(*argv)--;

	if (lstat(file, &st)) {
		fprintf(stderr, "missing file: %s\n", file);
		return (1);
	}

	hbsdcontrol_list_features(file, &features);
	printf("%s", features);
	hbsdcontrol_free_features(&features);

	return (0);
}

static int
pax_enable_cb(int *argc, char ***argv)
{

	return (enable_disable(argc, argv, enable));
}

static int
pax_disable_cb(int *argc, char ***argv)
{

	return (enable_disable(argc, argv, disable));
}

static int
pax_rm_fsea(int *argc, char ***argv)
{
	char *feature;
	char *file;

	if (*argc < 3)
		pax_usage(true);

	feature = (*argv)[1];
	file = (*argv)[2];

	(*argc) -= 2;
	*argv += 2;

	return (hbsdcontrol_rm_feature_state(file, feature));
}

static int
pax_reset_cb(int *argc, char ***argv)
{

	return (pax_rm_fsea(argc, argv));
}

static int
pax_list_cb(int *argc, char ***argv)
{

	return (pax_list(argc, argv));
}


void
pax_usage(bool terminate)
{
	int i;

	fprintf(stderr, "usage:\n");
	for (i = 0; hbsdcontrol_pax_actions[i].action != NULL; i++) {
		if (hbsdcontrol_pax_actions[i].min_argc == 2)
			fprintf(stderr, "\thbsdcontrol pax %s file\n",
			    hbsdcontrol_pax_actions[i].action);
		else
			fprintf(stderr, "\thbsdcontrol pax %s feature file\n",
			    hbsdcontrol_pax_actions[i].action);
	}

	if (terminate)
		exit(-1);
}

int
pax_cmd(int *argc, char ***argv)
{
	int i;

	if (*argc < 2)
		return (1);

	for (i = 0; hbsdcontrol_pax_actions[i].action != NULL; i++) {
		if (!strcmp(*argv[0], hbsdcontrol_pax_actions[i].action)) {
			if (*argc < hbsdcontrol_pax_actions[i].min_argc)
				pax_usage(true);

			return (hbsdcontrol_pax_actions[i].fn(argc, argv));
		}
	}

	return (1);
}
