/*
 * Public domain
 * sys/cdefs.h compatibility shim
 */

#include_next <sys/cdefs.h>

#ifndef LIBCOMPAT_SYS_CDEFS_H
#define LIBCOMPAT_SYS_CDEFS_H

#if !defined(HAVE_ATTRIBUTE__DEAD) && !defined(__dead)
#define __dead          __attribute__((__noreturn__))
#define __pure          __attribute__((__const__))
#endif

#endif
