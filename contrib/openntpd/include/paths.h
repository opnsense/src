/*
 * paths.h compatibility shim
 */

#ifdef HAVE_PATHS_H

#include_next <paths.h>

#else

#ifndef LIBCOMPAT_PATHS_H
#define LIBCOMPAT_PATHS_H

#define    _PATH_DEVNULL   "/dev/null"

#endif

#endif
