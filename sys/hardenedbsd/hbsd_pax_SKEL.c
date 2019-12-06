/*-
 * Copyright (c) 2016-2017, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
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
#include <sys/sx.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include "hbsd_pax_internal.h"


FEATURE(hbsd_SKEL, "SKEL features.");

#if __FreeBSD_version < 1100000
#define	kern_unsetenv	unsetenv
#endif

#ifdef PAX_SKEL
static int pax_SKEL_status = PAX_FEATURE_SIMPLE_ENABLED;
#else
static int pax_SKEL_status = PAX_FEATURE_SIMPLE_DISABLED;
#endif

#ifdef PAX_SYSCTLS
static int sysctl_pax_SKEL(SYSCTL_HANDLER_ARGS);

SYSCTL_NODE(_hardening_pax, OID_AUTO, SKEL, CTLFLAG_RD, 0,
    "SKEL feature.");

SYSCTL_HBSD_4STATE(pax_SKEL_status, pr_hbsd.SKEL.status, _hardening_pax_SKEL, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_SECURE);
#endif

TUNABLE_INT("hardening.SKEL.state", &pax_SKEL_status);

#ifdef PAX_JAIL_SUPPORT
SYSCTL_JAIL_PARAM_SUBNODE(hardening, SKEL, "SKEL");
SYSCTL_JAIL_PARAM(_hardening_SKEL, status,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "SKEL status");
#endif

static void
pax_SKEL_sysinit(void)
{
	pax_state_t old_state;

	old_state = pax_SKEL_status;
	if (!pax_feature_simple_validate_state(&pax_SKEL_status)) {
		printf("[HBSD SKEL] WARNING, invalid settings in loader.conf!"
		    " (hardening.SKEL.status = %d)\n", old_state);
	}
	if (bootverbose) {
		printf("[HBSD SKEL] skel status: %s\n",
		    pax_status_simple_str[pax_SKEL_status]);
	}
}
SYSINIT(pax_SKEL, SI_SUB_PAX, SI_ORDER_SECOND, pax_SKEL_sysinit, NULL);

int
pax_SKEL_init_prison(struct prison *pr, struct vfsoptlist *opts)
{
	struct prison *pr_p;
	int error;

	CTR2(KTR_PAX, "%s: Setting prison %s PaX variables\n",
	    __func__, pr->pr_name);

	if (pr == &prison0) {
		/* prison0 has no parent, use globals */
		pr->pr_hbsd.SKEL.status = pax_SKEL_status;
	} else {
		KASSERT(pr->pr_parent != NULL,
		   ("%s: pr->pr_parent == NULL", __func__));
		pr_p = pr->pr_parent;

		pr->pr_hbsd.SKEL.status = pr_p->pr_hbsd.SKEL.status;
		error = pax_handle_prison_param(opts, "hardening.pax.SKEL.status",
		    &pr->pr_hbsd.SKEL.status);
		if (error != 0)
			return (error);
	}

	return (0);
}

pax_flag_t
pax_SKEL_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode)
{
	struct prison *pr;
	pax_flag_t flags;
	uint32_t status;

	KASSERT(imgp->proc == td->td_proc,
	    ("%s: imgp->proc != td->td_proc", __func__));

	flags = 0;
	status = 0;

	pr = pax_get_prison_td(td);
	status = pr->pr_hbsd.SKEL.status;

	if (status == PAX_FEATURE_DISABLED) {
		flags &= ~PAX_NOTE_SKEL;
		flags |= PAX_NOTE_NOSKEL;

		return (flags);
	}

	if (status == PAX_FEATURE_FORCE_ENABLED) {
		flags &= ~PAX_NOTE_NOSKEL;
		flags |= PAX_NOTE_SKEL;

		return (flags);
	}

	if (status == PAX_FEATURE_OPTIN) {
		if (mode & PAX_NOTE_SKEL) {
			flags |= PAX_NOTE_SKEL;
			flags &= ~PAX_NOTE_NOSKEL;
		} else {
			flags &= ~PAX_NOTE_SKEL;
			flags |= PAX_NOTE_NOSKEL;
		}

		return (flags);
	}

	if (status == PAX_FEATURE_OPTOUT) {
		if (mode & PAX_NOTE_NOSKEL) {
			flags |= PAX_NOTE_NOSKEL;
			flags &= ~PAX_NOTE_SKEL;
		} else {
			flags &= ~PAX_NOTE_NOSKEL;
			flags |= PAX_NOTE_SKEL;
		}

		return (flags);
	}

	/* Unknown status, force SKEL restriction. */
	flags |= PAX_NOTE_SKEL;
	flags &= ~PAX_NOTE_NOSKEL;
#endif

	return (flags);
}
