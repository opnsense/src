/*
 * Copyright (c) 2004-2005, 2007, 2010, 2012-2014
 *	Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef OPEN_MAX
#define OPEN_MAX 256
#endif

/*
 * Close all file descriptors greater than or equal to lowfd.
 * This is the expensive (fallback) method.
 */
int
closefrom(int lowfd)
{
    long fd, maxfd;

    /*
     * Fall back on sysconf() or getdtablesize().  We avoid checking
     * resource limits since it is possible to open a file descriptor
     * and then drop the rlimit such that it is below the open fd.
     */
#ifdef HAVE_SYSCONF
    maxfd = sysconf(_SC_OPEN_MAX);
#else
    maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
    if (maxfd < 0)
	maxfd = OPEN_MAX;

    for (fd = lowfd; fd < maxfd; fd++) {
#ifdef __APPLE__
	/* Avoid potential libdispatch crash when we close its fds. */
	(void) fcntl((int) fd, F_SETFD, FD_CLOEXEC);
#else
	(void) close((int) fd);
#endif
    }

    return 0;
}
