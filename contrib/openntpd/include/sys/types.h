/*
 * Public domain
 * sys/types.h compatibility shim
 */

#include_next <sys/types.h>

#ifndef LIBCOMPAT_SYS_TYPES_H
#define LIBCOMPAT_SYS_TYPES_H

#include <stdint.h>

#ifdef __MINGW32__
#include <_bsd_types.h>
#endif

#if !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#endif

/*
 * Define BSD-style unsigned bits types for systems that do not have them.
 */
typedef uint8_t     u_int8_t;
typedef uint16_t    u_int16_t;
typedef uint32_t    u_int32_t;
typedef uint64_t    u_int64_t;

#ifndef BYTE_ORDER
#include <machine/endian.h>
#endif

#endif
