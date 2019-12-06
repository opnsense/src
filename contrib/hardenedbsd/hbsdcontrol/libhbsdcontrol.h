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

#ifndef __LIBHBSDCONTROL_H
#define	__LIBHBSDCONTROL_H

enum feature_state {
	conflict = -2,
	sysdef = -1,
	disable = 0,
	enable = 1,
};

typedef enum feature_state pax_feature_state_t;

struct pax_feature_entry {
	const char	*feature;
	const char	*extattr[2];
};

struct pax_feature_state {
	char	*feature;
	struct {
		char	*extattr;
		pax_feature_state_t	 state;
	} internal[2];
	int	state;
};

extern const struct pax_feature_entry pax_features[];

int hbsdcontrol_extattr_get_attr(const char *file, const char *attr, int *val);
int hbsdcontrol_extattr_set_attr(const char *file, const char *attr, const int val);
int hbsdcontrol_extattr_rm_attr(const char *file, const char *attr);
int hbsdcontrol_extattr_list_attrs(const char *file, char ***attrs);
void hbsdcontrol_free_attrs(char ***attrs);

int hbsdcontrol_get_feature_state(const char *file, const char *feature, pax_feature_state_t *state);
int hbsdcontrol_set_feature_state(const char *file, const char *feature, pax_feature_state_t state);
int hbsdcontrol_rm_feature_state(const char *file, const char *feature);
int hbsdcontrol_list_features(const char *file, char **features);
void hbsdcontrol_free_features(char **features);

int hbsdcontrol_set_debug(const int level);

const char *hbsdcontrol_get_version(void);

#endif /* __LIBHBSDCONTROL_H */
