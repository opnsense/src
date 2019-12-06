/*
 * Copyright (c) 1999-2004 Damien Miller <djm@mindrot.org>
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
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <mach/mach_time.h>
#include <sys/time.h>

#include <stdint.h>
#include <time.h>

int
clock_gettime(clockid_t clk_id, struct timespec *ts)
{
	static uint64_t timebase_scale = 0;
	mach_timebase_info_data_t timebase_info;
	uint64_t nsec;

	/*
	 * Only CLOCK_MONOTONIC is needed by ntpd
	 */
        if (clk_id != CLOCK_MONOTONIC)
                return -1;

	if (timebase_scale == 0) {
		if (mach_timebase_info(&timebase_info))
			return -1;
		timebase_scale = timebase_info.numer / timebase_info.denom;
	}

	nsec = mach_absolute_time() * timebase_scale;
	ts->tv_sec  = nsec / 1000000000UL;
	ts->tv_nsec = nsec % 1000000000UL;

	return 0;
}
