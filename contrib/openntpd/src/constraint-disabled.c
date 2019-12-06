/*	$OpenBSD: constraint.c,v 1.5 2015/02/22 14:55:41 jsing Exp $	*/

/*
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ntpd.h"

u_int constraint_cnt = 0;

int
constraint_init(struct constraint *cstr)
{
	return (0);
}

int
constraint_query(struct constraint *cstr)
{
	return (-1);
}

void
priv_constraint_child(const char *pw_dir, uid_t pw_uid, gid_t pw_gid)
{
}

void
priv_constraint_check_child(pid_t pid, int status)
{
}

void
priv_constraint_kill(u_int32_t id)
{
}

void
priv_constraint_msg(u_int32_t id, u_int8_t *data, size_t len, int argc,
    char **argv)
{
}

void
constraint_purge(void)
{
}

void
constraint_add(struct constraint *cstr)
{
}

void
constraint_msg_dns(u_int32_t id, u_int8_t *data, size_t len)
{
}

void
constraint_msg_result(u_int32_t id, u_int8_t *data, size_t len)
{
}

void
constraint_msg_close(u_int32_t id, u_int8_t *data, size_t len)
{
}

int
priv_constraint_dispatch(struct pollfd *pfd)
{
	return (0);
}

int
constraint_check(double val)
{
	return (-1);
}
