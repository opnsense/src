/*
 * Public domain
 * unistd.h compatibility shim
 */

#include_next <unistd.h>

#ifndef LIBCOMPAT_UNISTD_H
#define LIBCOMPAT_UNISTD_H

#define pledge(request, paths) 0

#ifndef HAVE_GETENTROPY
int getentropy(void *buf, size_t buflen);
#endif

#include <grp.h>

#ifndef HAVE_CLOSEFROM
int closefrom(int fd);
#endif

#ifndef HAVE_SETGROUPS
int setgroups(int ngroups, const gid_t *gidset);
#endif

#ifndef HAVE_SETRESGID
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
#endif

#ifndef HAVE_SETRESUID
int setresuid(uid_t ruid, uid_t euid, uid_t suid);
#endif

#endif
