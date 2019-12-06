/*
 * Public domain
 * sys/time.h compatibility shim
 */

#ifndef LIBCOMPAT_SYS_TIME_H
#define LIBCOMPAT_SYS_TIME_H

#include_next <sys/time.h>

#include <stdint.h>

int adjfreq(const int64_t *freq, int64_t *oldfreq);

#ifdef __sun
static inline int sun_adjtime(struct timeval *delta, struct timeval *olddelta)
{
	struct timeval zero = {0};
	int rc;

	/*
	 * adjtime on Solaris appears to handle a NULL delta differently than
	 * other OSes. Fill in a dummy value as necessary.
	 */
	if (delta)
		rc = adjtime(delta, olddelta);
	else
		rc = adjtime(&zero, olddelta);

	/*
	 * Old delta on Solaris frequently gets stuck with 1 ms left.
	 * Round down to 0 in this case so we do not get flapping clock sync.
	 */
	if (rc == 0 && olddelta &&
	    olddelta->tv_sec == 0 && olddelta->tv_usec == 1)
		olddelta->tv_usec = 0;

	return rc;
}
#define adjtime(d, o) sun_adjtime(d, o)
#endif

#endif
