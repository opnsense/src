/*
 * stdlib.h compatibility shim
 * Public domain
 */

#include_next <stdlib.h>

#ifndef LIBCOMPAT_STDLIB_H
#define LIBCOMPAT_STDLIB_H

#include <sys/stat.h>
#include <sys/time.h>
#include <stdint.h>

#ifndef HAVE_ARC4RANDOM_
uint32_t arc4random(void);
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif

#ifndef HAVE_FREEZERO
void freezero(void *ptr, size_t sz);
#endif

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
void *recallocarray(void *, size_t, size_t, size_t);
#endif

#ifndef HAVE_SETPROCTITLE
void compat_init_setproctitle(int argc, char *argv[]);
void setproctitle(const char *fmt, ...);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(const char *nptr, long long minval,
		long long maxval, const char **errstr);
#endif

#endif
