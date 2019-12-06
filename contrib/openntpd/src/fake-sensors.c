/*
 * Copyright (c) 2006 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2014 Brent Cook <bcook@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ntpd.h"

/*
 * These stubs indicate that no sensors exist on systems without a sensor framework.
 */
void
sensor_init(void)
{
}

int
sensor_scan(void)
{
	return 0;
}

void
sensor_query(struct ntp_sensor *s)
{
}

int
sensor_hotplugfd(void)
{
	return (-1);
}

void
sensor_hotplugevent(int fd)
{
}
