/*
 * Public domain
 * poll.h compatibility shim
 */

#include_next <poll.h>

#ifndef LIBCOMPAT_POLL_H
#define LIBCOMPAT_POLL_H

#ifndef INFTIM
#define INFTIM          (-1)
#endif

#endif
