/*
 * Copyright (c) 2007 Sebastian Benoit <benoit-lists@fb12.de>
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

#include <sys/types.h>
# include <sys/timex.h>

#include <unistd.h>

#include <ntp.h>
#include <ntpd.h>

/*
 * adjfreq (old)freq = nanosec. per seconds shifted left 32 bits
 * timex.freq is ppm / left shifted by SHIFT_USEC (16 bits), defined in timex.h
 */

int
adjfreq(const int64_t *freq, int64_t *oldfreq)
{
	struct timex txc = { 0 };
	int64_t newfreq;

	if (freq != NULL) {
		txc.modes = MOD_FREQUENCY;
		txc.freq = *freq / 1e3 / (1LL << 16);

		if ((ntp_adjtime(&txc)) == -1)
			log_warn("ntp_adjtime (2) failed");

		log_debug("ntp_adjtime adjusted frequency by %fppm",
			  ((txc.freq * 1e3) *  (1LL<<16) / 1e3 / (1LL << 32)));
	}
	if (oldfreq != NULL) {
		txc.modes = 0;
		if ((ntp_adjtime(&txc)) == -1) {
			log_warn("ntp_adjtime (1) failed");
			return -1;
		}
		newfreq = (txc.freq * 1e3) *  (1LL<<16);
		log_debug("ntp_adjtime returns frequency of %fppm",
			  newfreq / 1e3 / (1LL << 32));
		*oldfreq = newfreq;
	}

	return 0;
}

/*
 * The RTC is only updated if the clock is not marked as unsynced.
 */

void
update_time_sync_status(int synced)
{
	struct timex txc = { 0 };

	txc.modes = MOD_STATUS;
	if (synced) {
		txc.modes |= MOD_MAXERROR;
		txc.maxerror = 0;
	} else
		txc.status = STA_UNSYNC;
	if (ntp_adjtime(&txc) == -1)
		log_warn("ntp_adjtime (3) failed");
	return;
}
