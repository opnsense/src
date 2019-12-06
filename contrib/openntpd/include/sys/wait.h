/*
 * Public domain
 * sys/wait.h compatibility shim
 */

#include_next <sys/wait.h>

#ifndef LIBCOMPAT_SYS_WAIT_H
#define LIBCOMPAT_SYS_WAIT_H

#ifndef WAIT_ANY
#define WAIT_ANY (-1) /* Any process. */
#endif

#endif
