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

#include <sys/param.h>
#include <sys/sbuf.h>
#include <sys/uio.h>
#include <sys/extattr.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <libgen.h>
#include <libutil.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "libhbsdcontrol.h"

static const char *hbsdcontrol_version = "v001";

static int hbsdcontrol_validate_state(struct pax_feature_state *feature_state);
static const char * hbsdcontrol_get_state_string(const struct pax_feature_state *feature_state);
static int hbsdcontrol_get_all_feature_state(const char *file, struct pax_feature_state **feature_states);
static void hbsdcontrol_free_all_feature_state(struct pax_feature_state **feature_states);

static int hbsdcontrol_debug_flag;

const struct pax_feature_entry pax_features[] = {
	{
		.feature = "pageexec",
		.extattr = {
			[disable] = "hbsd.pax.nopageexec",
			[enable]  = "hbsd.pax.pageexec",
		},
	},
	{
		.feature = "mprotect",
		.extattr = {
			[disable] = "hbsd.pax.nomprotect",
			[enable]  = "hbsd.pax.mprotect",
		},
	},
	{
		.feature = "segvguard",
		.extattr = {
			[disable] = "hbsd.pax.nosegvguard",
			[enable]  = "hbsd.pax.segvguard",
		},
	},
	{
		.feature = "aslr",
		.extattr = {
			[disable] = "hbsd.pax.noaslr",
			[enable]  = "hbsd.pax.aslr",
		},
	},
	{
		.feature = "shlibrandom",
		.extattr = {
			[disable] = "hbsd.pax.noshlibrandom",
			[enable]  = "hbsd.pax.shlibrandom",
		},
	},
	{
		.feature = "disallow_map32bit",
		.extattr = {
			[disable] = "hbsd.pax.nodisallow_map32bit",
			[enable]  = "hbsd.pax.disallow_map32bit",
		},
	},
	/* Terminating NULL entry, DO NOT REMOVE! */
	{NULL, {0, 0}}
};


const char *
hbsdcontrol_get_version(void)
{

	return hbsdcontrol_version;
}

int
hbsdcontrol_extattr_set_attr(const char *file, const char *attr, const int val)
{
	int	error;
	int	len;
	int	attrnamespace;
	struct sbuf *attrval = NULL;

	error = extattr_string_to_namespace("system", &attrnamespace);
	if (error)
		err(-1, "%s", "system");

	attrval = sbuf_new_auto();
	sbuf_printf(attrval, "%d", val);
	sbuf_finish(attrval);

	len = extattr_set_file(file, attrnamespace, attr,
	    sbuf_data(attrval), sbuf_len(attrval));
	if (len >= 0 && hbsdcontrol_debug_flag)
		warnx("%s: %s@%s = %s", file, "system", attr, sbuf_data(attrval));

	sbuf_delete(attrval);

	if (len == -1) {
		perror(__func__);
		errx(-1, "abort");
	}

	return (0);
}

int
hbsdcontrol_extattr_get_attr(const char *file, const char *attr, int *val)
{
	int	error;
	int	len;
	int	attrnamespace;
	char	*attrval = NULL;

	if (val == NULL)
		err(-1, "%s", "val");

	error = extattr_string_to_namespace("system", &attrnamespace);
	if (error)
		err(-1, "%s", "system");

	len = extattr_get_file(file, attrnamespace, attr, NULL, 0);
	if (len < 0) {
		perror(__func__);
		errx(-1, "abort");
	}

#if 0
	if (len >= 0 && hbsdcontrol_debug_flag)
		warnx("%s: %s@%s = %s", file, "system", attr, sbuf_data(attrval));
#endif

	attrval = calloc(sizeof(char), len);
	if (attrval == NULL) {
		perror(__func__);
		errx(-1, "abort");
	}

	len = extattr_get_file(file, attrnamespace, attr, attrval, len);
	if (len == -1) {
		perror(__func__);
		errx(-1, "abort");
	}

	// XXXOP: strtol?
	*val = *attrval - '0';

	free(attrval);

	return (0);
}


int
hbsdcontrol_extattr_rm_attr(const char *file, const char *attr)
{
	int error;
	int attrnamespace;

	error = extattr_string_to_namespace("system", &attrnamespace);
	if (error)
		err(-1, "%s", "system");

	if (hbsdcontrol_debug_flag)
		printf("reset attr: %s on file: %s\n", attr, file);

	error = extattr_delete_file(file, attrnamespace, attr);

	return (error);
}


int
hbsdcontrol_extattr_list_attrs(const char *file, char ***attrs)
{
	char *data;
	int error;
	int attrnamespace;
	ssize_t nbytes;
	ssize_t pos;
	uint8_t len;
	unsigned int fpos;

	nbytes = 0;
	data = NULL;
	pos = 0;
	fpos = 0;

	if (attrs == NULL)
		err(-1, "%s", "attrs");

	error = extattr_string_to_namespace("system", &attrnamespace);
	if (error)
		err(-1, "%s", "system");

	if (hbsdcontrol_debug_flag)
		printf("list attrs on file: %s\n", file);

	nbytes = extattr_list_file(file, attrnamespace, NULL, 0);
	if (nbytes < 0) {
		error = EFAULT;
		goto out;
	}

	data = calloc(sizeof(char), nbytes);
	if (data == NULL) {
		error = ENOMEM;
		goto out;
	}

	*attrs = (char **)calloc(sizeof(char *), nitems(pax_features) * nitems(pax_features[0].extattr));
	if (*attrs == NULL) {
		error = ENOMEM;
		goto out;
	}

	nbytes = extattr_list_file(file, attrnamespace, data, nbytes);
	if (nbytes == -1) {
		error = EFAULT;
		goto out;
	}

	pos = 0;
	while (pos < nbytes) {
		size_t attr_len;

		assert(fpos < nitems(pax_features) * nitems(pax_features[0].extattr));

		/* see EXTATTR(2) about the data structure */
		len = data[pos++];

		for (int feature = 0; pax_features[feature].feature != NULL; feature++) {
			/* The value 2 comes from enum pax_attr_state's size */
			for (pax_feature_state_t state = 0; state < 2; state++) {
				attr_len = strlen(pax_features[feature].extattr[state]);
				if (attr_len != len) {
					/* Fast path, skip if the size of attribute differs. */
					continue;
				}

				if (!memcmp(pax_features[feature].extattr[state], &data[pos], attr_len)) {
					if (hbsdcontrol_debug_flag)
						printf("%s:\tfound attribute: %s\n",
						    __func__, pax_features[feature].extattr[state]);
					(*attrs)[fpos] = strdup(pax_features[feature].extattr[state]);
					fpos++;
				}
			}
		}

		pos += len;
	}

	/* NULL terminate the attrs array. */
	(*attrs)[fpos] = NULL;

out:
	free(data);
	if (error)
		hbsdcontrol_free_attrs(attrs);

	return (error);
}


void
hbsdcontrol_free_attrs(char ***attrs)
{
	if (*attrs == NULL)
		return;

	for (int attr = 0; (*attrs)[attr] != NULL; attr++) {
		free((*attrs)[attr]);
		(*attrs)[attr] = NULL;
	}
	free(*attrs);
	*attrs = NULL;
}


int
hbsdcontrol_set_feature_state(const char *file, const char *feature, pax_feature_state_t state)
{
	int i;
	int error;

	error = 0;

	for (i = 0; pax_features[i].feature != NULL; i++) {
		if (strcmp(pax_features[i].feature, feature) == 0) {
			if (hbsdcontrol_debug_flag) {
				printf("%s:\t%s %s on %s\n",
				    __func__,
				    state ? "enable" : "disable",
				    pax_features[i].feature, file);
			}

			error = hbsdcontrol_extattr_set_attr(file, pax_features[i].extattr[disable], !state);
			error |= hbsdcontrol_extattr_set_attr(file, pax_features[i].extattr[enable], state);

			break;
		}
	}

	return (error);
}


int
hbsdcontrol_rm_feature_state(const char *file, const char *feature)
{
	int i;
	int error;

	error = 0;

	for (i = 0; pax_features[i].feature != NULL; i++) {
		if (!strcmp(pax_features[i].feature, feature)) {
			if (hbsdcontrol_debug_flag)
				printf("%s:\treset %s on %s\n",
				    __func__,
				    pax_features[i].feature, file);
			error = hbsdcontrol_extattr_rm_attr(file, pax_features[i].extattr[disable]);
			error |= hbsdcontrol_extattr_rm_attr(file, pax_features[i].extattr[enable]);

			break;
		}
	}

	return (error);
}


static int
hbsdcontrol_get_all_feature_state(const char *file, struct pax_feature_state **feature_states)
{
	int error;
	char **attrs;
	int val;
	bool found = false;

	error = 0;
	attrs = NULL;

	assert(feature_states != NULL);

	*feature_states = calloc(sizeof(struct pax_feature_state), nitems(pax_features));

	assert(*feature_states != NULL);

	error = hbsdcontrol_extattr_list_attrs(file, &attrs);
	if (attrs == NULL)
		err(-1, "attrs == NULL");

	for (int feature = 0; pax_features[feature].feature != NULL; feature++) {
		for (int attr = 0; attrs[attr] != NULL; attr++) {
			for (pax_feature_state_t state = 0; state < 2; state++) {
				if (!strcmp(pax_features[feature].extattr[state], attrs[attr])) {
					hbsdcontrol_extattr_get_attr(file, attrs[attr], &val);

					if (hbsdcontrol_debug_flag)
						printf("%s:\t%s (%s: %d)\n",
						    __func__,
						    pax_features[feature].feature, attrs[attr], val);

					if ((*feature_states)[feature].feature == NULL)
						(*feature_states)[feature].feature = strdup(pax_features[feature].feature);
					(*feature_states)[feature].internal[state].state = val;
					(*feature_states)[feature].internal[state].extattr = strdup(pax_features[feature].extattr[state]);
					found = true;
				}
			}
		}
		if (found) {
			(*feature_states)[feature].state = hbsdcontrol_validate_state(&(*feature_states)[feature]);
			found = false;
		} else {
			(*feature_states)[feature].feature = strdup(pax_features[feature].feature);
			(*feature_states)[feature].state = sysdef;
		}
	}

	hbsdcontrol_free_attrs(&attrs);

	return (error);
}


static void
hbsdcontrol_free_all_feature_state(struct pax_feature_state **feature_states)
{
	if (*feature_states == NULL)
		return;

	for (unsigned int feature = 0; feature < nitems(pax_features); feature++) {
		free((*feature_states)[feature].feature);
		(*feature_states)[feature].feature = NULL;
		for (pax_feature_state_t state = 0; state < 2; state++) {
			free((*feature_states)[feature].internal[state].extattr);
			(*feature_states)[feature].internal[state].extattr = NULL;
		}
	}
}

/*
 * XXXOP: currently this returns one string with all of the
 * features and its state. In the future it would be better
 * to return an array of strings with the {feature, value}
 * pairs.
 */
int
hbsdcontrol_list_features(const char *file, char **features)
{
	struct pax_feature_state	*feature_states;
	struct sbuf *list = NULL;

	assert(*features == NULL);

	if (hbsdcontrol_get_all_feature_state(file, &feature_states) != 0)
		return (1);

	list = sbuf_new_auto();
	for (unsigned int feature = 0; feature < nitems(pax_features); feature++) {
		if (feature_states[feature].feature == NULL)
			continue;

		sbuf_printf(list, "%s:\t%s\n",
		    feature_states[feature].feature,
		    hbsdcontrol_get_state_string(&feature_states[feature]));
	}
	sbuf_finish(list);
	asprintf(features, "%s", sbuf_data(list));

	hbsdcontrol_free_all_feature_state(&feature_states);

	return (0);
}

void
hbsdcontrol_free_features(char **features)
{

	free(*features);
	*features = NULL;
}

static int
hbsdcontrol_validate_state(struct pax_feature_state *feature_state)
{
	int state = -1;
	pax_feature_state_t negated_feature, feature;

	assert(feature_state != NULL);

	negated_feature = feature_state->internal[disable].state;
	feature = feature_state->internal[enable].state;

	if (negated_feature == disable && feature == disable)
		state = conflict;
	else if (negated_feature == disable && feature == enable)
		state = enable;
	else if (negated_feature == enable && feature == disable)
		state = disable;
	else if (negated_feature == enable && feature == enable)
		state = conflict;
	else
		assert(false);

	return (state);
}

static const char *
hbsdcontrol_get_state_string(const struct pax_feature_state *feature_state)
{

	switch (feature_state->state) {
	case enable:
		return "enabled";
	case disable:
		return "disabled";
	case conflict:
		return "conflict";
	case sysdef:
		return "sysdef";
	}

	return "unknown";
}

int
hbsdcontrol_set_debug(const int level)
{

	hbsdcontrol_debug_flag = level;

	return (hbsdcontrol_debug_flag);
}
