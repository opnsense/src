/*-
 * Copyright (c) 2014, by Shawn Webb <shawn.webb at hardenedbsd.org>
 * Copyright (c) 2014-2017, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"
#include "opt_pax.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/jail.h>
#include <sys/ktr.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/sysctl.h>

#include "hbsd_pax_internal.h"

FEATURE(hbsd_hardening, "Various hardening features.");

#if __FreeBSD_version < 1100000
#define	kern_unsetenv	unsetenv
#endif

#ifdef PAX_HARDENING
static int pax_procfs_harden_global = PAX_FEATURE_SIMPLE_ENABLED;
static int pax_randomize_pids_global = PAX_FEATURE_SIMPLE_ENABLED;
static int pax_init_hardening_global = PAX_FEATURE_SIMPLE_ENABLED;
#else
static int pax_procfs_harden_global = PAX_FEATURE_SIMPLE_DISABLED;
static int pax_randomize_pids_global = PAX_FEATURE_SIMPLE_DISABLED;
static int pax_init_hardening_global = PAX_FEATURE_SIMPLE_DISABLED;
#endif

TUNABLE_INT("hardening.procfs_harden", &pax_procfs_harden_global);
TUNABLE_INT("hardening.randomize_pids", &pax_randomize_pids_global);

#ifdef PAX_SYSCTLS
SYSCTL_HBSD_2STATE(pax_procfs_harden_global, pr_hbsd.hardening.procfs_harden,
    _hardening, procfs_harden,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_SECURE,
    "Harden procfs, disabling write of /proc/pid/mem");
#endif

#if 0
#ifdef PAX_JAIL_SUPPORT
SYSCTL_JAIL_PARAM(hardening, procfs_harden,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "disabling write of /proc/pid/mem");
#endif
#endif

static void
pax_hardening_sysinit(void)
{
	pax_state_t old_state;

	old_state = pax_procfs_harden_global;
	if (!pax_feature_simple_validate_state(&pax_procfs_harden_global)) {
		printf("[HBSD HARDENING] WARNING, invalid settings in loader.conf!"
		    " (hardening.procfs_harden = %d)\n", old_state);
	}
	if (bootverbose) {
		printf("[HBSD HARDENING] procfs hardening: %s\n",
		    pax_status_simple_str[pax_procfs_harden_global]);
	}

	old_state = pax_randomize_pids_global;
	if (!pax_feature_simple_validate_state(&pax_randomize_pids_global)) {
		printf("[HBSD HARDENING] WARNING, invalid settings in loader.conf!"
		    " (hardening.randomize_pids = %d)\n", old_state);
	}
	if (bootverbose) {
		printf("[HBSD HARDENING] randomize pids: %s\n",
		    pax_status_simple_str[pax_randomize_pids_global]);
	}

	(void)pax_feature_simple_validate_state(&pax_init_hardening_global);
	if (bootverbose) {
		printf("[HBSD HARDENING] unset insecure init variables: %s\n",
		    pax_status_simple_str[pax_init_hardening_global]);
	}
}
SYSINIT(pax_hardening, SI_SUB_PAX, SI_ORDER_SECOND, pax_hardening_sysinit, NULL);

int
pax_hardening_init_prison(struct prison *pr, struct vfsoptlist *opts)
{
	struct prison *pr_p;
#if 0
	int error;
#endif

	CTR2(KTR_PAX, "%s: Setting prison %s PaX variables\n",
	    __func__, pr->pr_name);

	if (pr == &prison0) {
		/* prison0 has no parent, use globals */
		pr->pr_hbsd.hardening.procfs_harden =
		    pax_procfs_harden_global;
		pr->pr_allow &= ~(PR_ALLOW_UNPRIV_DEBUG);
	} else {
		KASSERT(pr->pr_parent != NULL,
		   ("%s: pr->pr_parent == NULL", __func__));
		pr_p = pr->pr_parent;

		pr->pr_hbsd.hardening.procfs_harden =
		    pr_p->pr_hbsd.hardening.procfs_harden;
#if 0
		error = pax_handle_prison_param(opts, "hardening.procfs_harden",
		    &pr->pr_hbsd.hardening.procfs_harden);
		if (error != 0)
			return (error);
#endif
	}

	return (0);
}

int
pax_procfs_harden(struct thread *td)
{
	struct prison *pr;

	pr = pax_get_prison_td(td);

	return (pr->pr_hbsd.hardening.procfs_harden ? EPERM : 0);
}


extern int randompid;

static void
pax_randomize_pids(void *dummy __unused)
{
	int modulus;

	if (pax_randomize_pids_global == PAX_FEATURE_SIMPLE_DISABLED)
		return;

	modulus = pid_max - 200;

	sx_xlock(&allproc_lock);
	randompid = arc4random() % modulus + 100;
	sx_xunlock(&allproc_lock);
}
SYSINIT(pax_randomize_pids, SI_SUB_KTHREAD_INIT, SI_ORDER_MIDDLE+1,
    pax_randomize_pids, NULL);


static void
pax_init_hardening(void *dummy __unused)
{
	/*
	 * Never should be made available from the loader / outside
	 * the pax_init_hardening_global variable.
	 */
	if (pax_init_hardening_global == PAX_FEATURE_SIMPLE_DISABLED)
		return;

	kern_unsetenv("init_chroot");
	kern_unsetenv("init_exec");
	kern_unsetenv("init_path");
	kern_unsetenv("init_script");
	kern_unsetenv("init_shell");
}
SYSINIT(pax_init_hardening, SI_SUB_PAX, SI_ORDER_ANY,
    pax_init_hardening, NULL);

