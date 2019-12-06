/*
 * Public domain
 * time.h compatibility shim
 */

#include_next <time.h>

#ifndef LIBCOMPAT_TIME_H
#define LIBCOMPAT_TIME_H

#ifndef CLOCK_REALTIME
typedef int clockid_t;
#define CLOCK_REALTIME  1
#define CLOCK_MONOTONIC 2	
#endif

#ifndef HAVE_CLOCK_GETRES
int clock_getres(clockid_t clk_id, struct timespec *res);
#endif

#ifndef HAVE_CLOCK_GETTIME
int clock_gettime(clockid_t clk_id, struct timespec *ts);
#endif

#endif
