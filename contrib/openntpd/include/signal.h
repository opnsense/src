/*
 * Public domain
 * signal.h compatibility shim
 */

#include_next <signal.h>

#ifndef SIGINFO
#define SIGINFO SIGUSR1
#endif

#ifndef _NSIG
#define _NSIG NSIG
#endif
