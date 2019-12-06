/*
 * Copyright (c) 1999-2004 Damien Miller <djm@mindrot.org>
 * Copyright (c) 2004 Darren Tucker <dtucker at zip com au>
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

#include <sys/time.h>

#ifdef HAVE_ADJTIMEX
#include <sys/timex.h>
#endif

int
clock_getres(clockid_t clk_id, struct timespec *tp)
{
# ifdef HAVE_ADJTIMEX
        struct timex tmx;
# endif

        if (clk_id != CLOCK_REALTIME)
                return -1;      /* not implemented */

        tp->tv_sec = 0;

# ifdef HAVE_ADJTIMEX
        tmx.modes = 0;
        if (adjtimex(&tmx) == -1)
                return -1;
        else
                tp->tv_nsec = tmx.precision * 1000;     /* usec -> nsec */
# else
        /* assume default 10ms tick */
        tp->tv_nsec = 10000000;
# endif
        return 0;
}
