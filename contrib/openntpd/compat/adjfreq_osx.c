/*
 * This file is in the public domain.
 *
 * OS X does not appear to provide a mechanism to adjust the time frequency, or
 * at least not one that is easy to discover. Always fail here until a suitable
 * implementation is found.
 */

#include <sys/time.h>
#include <sys/types.h>

#include <errno.h>

int
adjfreq(const int64_t *freq, int64_t *oldfreq)
{
	errno = ENOSYS;
	return -1;
}

void
update_time_sync_status(int synced)
{
}
