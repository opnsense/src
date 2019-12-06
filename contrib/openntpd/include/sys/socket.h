/*
 * Public domain
 * sys/socket.h compatibility shim
 */

#include_next <sys/socket.h>

#ifndef SA_LEN
#define SA_LEN(X) \
	(((struct sockaddr*)(X))->sa_family == AF_INET ? sizeof(struct sockaddr_in) : \
	 ((struct sockaddr*)(X))->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : \
	 ((struct sockaddr*)(X))->sa_family == AF_UNSPEC ? sizeof(struct sockaddr) : \
	   sizeof(struct sockaddr))
#endif

#if !defined(SOCK_NONBLOCK) || !defined(SOCK_CLOEXEC)
#define NEED_SOCKET_FLAGS
int _socket(int domain, int type, int protocol);
#ifndef SOCKET_FLAGS_PRIV
#define socket(d, t, p) _socket(d, t, p)
#endif
#endif

/*
 * Prevent Solaris 10 system header leakage
 */
#ifdef MODEMASK
#undef MODEMASK
#endif

#ifndef SOCK_NONBLOCK
#define	SOCK_NONBLOCK		0x4000	/* set O_NONBLOCK */
#endif

#ifndef SOCK_CLOEXEC
#define	SOCK_CLOEXEC		0x8000	/* set FD_CLOEXEC */
#endif
