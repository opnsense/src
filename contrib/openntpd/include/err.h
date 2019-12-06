/*
 * Public domain
 * err.h compatibility shim
 */

#ifdef HAVE_ERR_H

#include_next <err.h>

#else

#ifndef LIBCOMPAT_ERR_H
#define LIBCOMPAT_ERR_H

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

extern char *__progname;

static inline void _warn(int err, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

static inline void _warn(int err, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	fprintf(stderr, "%s: ", __progname);
	if (format != NULL) {
		vfprintf(stderr, format, args);
		if (err)
			fprintf(stderr, ": ");
	}
	if (err)
		fprintf(stderr, "%s", strerror(err));
	fprintf(stderr, "\n");
	va_end(args);
}

#define err(exitcode, format, args...) \
  do { warn(format, ## args); exit(exitcode); } while (0)

#define errx(exitcode, format, args...) \
  do { warnx(format, ## args); exit(exitcode); } while (0)

#define warn(format, args...) \
  _warn(errno, format, ## args)

#define warnx(format, args...) \
  _warn(0, format, ## args)

#endif

#endif
