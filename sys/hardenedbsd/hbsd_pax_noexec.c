/*-
 * Copyright (c) 2006 Elad Efrat <elad@NetBSD.org>
 * Copyright (c) 2013-2017, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
 * Copyright (c) 2014, by Shawn Webb <lattera at gmail.com>
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

#include "opt_pax.h"

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/jail.h>
#include <sys/kthread.h>
#include <sys/ktr.h>
#include <sys/libkern.h>
#include <sys/libkern.h>
#include <sys/mman.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>

#include "hbsd_pax_internal.h"

FEATURE(hbsd_noexec, "PAX PAGEEXEC and MPROTECT hardening");


static pax_flag_t pax_pageexec_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode);
static pax_flag_t pax_mprotect_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t flags, pax_flag_t mode);

#ifdef PAX_HARDENING
static int pax_pageexec_status = PAX_FEATURE_OPTOUT;
static int pax_mprotect_status = PAX_FEATURE_OPTOUT;
#else /* !PAX_HARDENING */
static int pax_pageexec_status = PAX_FEATURE_OPTIN;
static int pax_mprotect_status = PAX_FEATURE_OPTIN;
#endif /* PAX_HARDENING */

TUNABLE_INT("hardening.pax.pageexec.status", &pax_pageexec_status);
TUNABLE_INT("hardening.pax.mprotect.status", &pax_mprotect_status);

#ifdef PAX_SYSCTLS
SYSCTL_DECL(_hardening_pax);
SYSCTL_NODE(_hardening_pax, OID_AUTO, pageexec, CTLFLAG_RD, 0,
    "Remove WX pages from user-space.");
SYSCTL_NODE(_hardening_pax, OID_AUTO, mprotect, CTLFLAG_RD, 0,
    "MPROTECT hardening - enforce W^X.");

SYSCTL_HBSD_4STATE(pax_pageexec_status, pr_hbsd.noexec.pageexec_status,
    _hardening_pax_pageexec, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE);

SYSCTL_HBSD_4STATE(pax_mprotect_status, pr_hbsd.noexec.mprotect_status,
    _hardening_pax_mprotect, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE);

#endif /* PAX_SYSCTLS */

#ifdef PAX_JAIL_SUPPORT
SYSCTL_DECL(_security_jail_param_hardening_pax);

SYSCTL_JAIL_PARAM_SUBNODE(hardening_pax, pageexec, "mprotect");
SYSCTL_JAIL_PARAM(_hardening_pax_pageexec, status,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "pageexec");
SYSCTL_JAIL_PARAM_SUBNODE(hardening_pax, mprotect, "mprotect");
SYSCTL_JAIL_PARAM(_hardening_pax_mprotect, status,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "mprotect");
#endif /* PAX_JAIL_SUPPORT */


/*
 * PaX PAGEEXEC functions
 */

static void
pax_noexec_sysinit(void)
{
	pax_state_t old_state;

	old_state = pax_pageexec_status;
	if (!pax_feature_validate_state(&pax_pageexec_status)) {
		printf("[HBSD PAGEEXEC] WARNING, invalid PAX settings in loader.conf!"
		    " (hardening.pax.pageexec.status = %d)\n", old_state);
	}
	if (bootverbose) {
		printf("[HBSD PAGEEXEC] status: %s\n",
		    pax_status_str[pax_pageexec_status]);
	}

	old_state = pax_mprotect_status;
	if (!pax_feature_validate_state(&pax_mprotect_status)) {
		printf("[HBSD MPROTECT] WARNING, invalid PAX settings in loader.conf!"
		    " (hardening.pax.mprotect.status = %d)\n", old_state);
	}
	if (bootverbose) {
		printf("[HBSD MPROTECT] status: %s\n",
		    pax_status_str[pax_mprotect_status]);
	}
}
SYSINIT(pax_noexec, SI_SUB_PAX, SI_ORDER_SECOND, pax_noexec_sysinit, NULL);

int
pax_noexec_init_prison(struct prison *pr, struct vfsoptlist *opts)
{
	struct prison *pr_p;
	int error;

	CTR2(KTR_PAX, "%s: Setting prison %s PaX variables\n",
	    __func__, pr->pr_name);

	if (pr == &prison0) {
		/* prison0 has no parent, use globals */
		pr->pr_hbsd.noexec.pageexec_status = pax_pageexec_status;
		pr->pr_hbsd.noexec.mprotect_status = pax_mprotect_status;
	} else {
		KASSERT(pr->pr_parent != NULL,
		   ("%s: pr->pr_parent == NULL", __func__));
		pr_p = pr->pr_parent;

		pr->pr_hbsd.noexec.pageexec_status =
		    pr_p->pr_hbsd.noexec.pageexec_status;
		error = pax_handle_prison_param(opts, "hardening.pax.pageexec.status",
		    &pr->pr_hbsd.noexec.pageexec_status);
		if (error != 0)
			return (error);

		pr->pr_hbsd.noexec.mprotect_status =
		    pr_p->pr_hbsd.noexec.mprotect_status;
		error = pax_handle_prison_param(opts, "hardening.pax.mprotect.status",
		    &pr->pr_hbsd.noexec.mprotect_status);
		if (error != 0)
			return (error);
	}

	return (0);
}

static pax_flag_t
pax_pageexec_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode)
{
	struct prison *pr;
	pax_flag_t flags;
	u_int status;

	KASSERT(imgp->proc == td->td_proc,
	    ("%s: imgp->proc != td->td_proc", __func__));

	flags = 0;
	status = 0;

	pr = pax_get_prison_td(td);
	status = pr->pr_hbsd.noexec.pageexec_status;

	if (status == PAX_FEATURE_DISABLED) {
		flags &= ~PAX_NOTE_PAGEEXEC;
		flags |= PAX_NOTE_NOPAGEEXEC;

		return (flags);
	}

	if (status == PAX_FEATURE_FORCE_ENABLED) {
		flags |= PAX_NOTE_PAGEEXEC;
		flags &= ~PAX_NOTE_NOPAGEEXEC;

		return (flags);
	}

	if (status == PAX_FEATURE_OPTIN) {
		if (mode & PAX_NOTE_PAGEEXEC) {
			flags |= PAX_NOTE_PAGEEXEC;
			flags &= ~PAX_NOTE_NOPAGEEXEC;
		} else {
			flags &= ~PAX_NOTE_PAGEEXEC;
			flags |= PAX_NOTE_NOPAGEEXEC;
		}

		return (flags);
	}

	if (status == PAX_FEATURE_OPTOUT) {
		if (mode & PAX_NOTE_NOPAGEEXEC) {
			flags &= ~PAX_NOTE_PAGEEXEC;
			flags |= PAX_NOTE_NOPAGEEXEC;
		} else {
			flags |= PAX_NOTE_PAGEEXEC;
			flags &= ~PAX_NOTE_NOPAGEEXEC;
		}

		return (flags);
	}

	/*
	 * unknown status, force PAGEEXEC
	 */
	flags |= PAX_NOTE_PAGEEXEC;
	flags &= ~PAX_NOTE_NOPAGEEXEC;

	return (flags);
}

/*
 * PAGEEXEC
 */

bool
pax_pageexec_active(struct proc *p)
{
	pax_flag_t flags;

	pax_get_flags(p, &flags);

	CTR3(KTR_PAX, "%s: pid = %d p_pax = %x",
	    __func__, p->p_pid, flags);

	if ((flags & PAX_NOTE_PAGEEXEC) == PAX_NOTE_PAGEEXEC)
		return (true);

	if ((flags & PAX_NOTE_NOPAGEEXEC) == PAX_NOTE_NOPAGEEXEC)
		return (false);

	return (true);
}

void
pax_pageexec(struct proc *p, vm_prot_t *prot, vm_prot_t *maxprot)
{

	if (!pax_pageexec_active(p)) {
		return;
	}

	CTR3(KTR_PAX, "%s: pid = %d prot = %x",
	    __func__, p->p_pid, *prot);

	if ((*prot & (VM_PROT_WRITE|VM_PROT_EXECUTE)) != VM_PROT_EXECUTE) {
		*prot &= ~VM_PROT_EXECUTE;
	} else {
		*prot &= ~VM_PROT_WRITE;
	}
}

/*
 * MPROTECT
 */

bool
pax_mprotect_active(struct proc *p)
{
	pax_flag_t flags;

	pax_get_flags(p, &flags);

	CTR3(KTR_PAX, "%s: pid = %d p_pax = %x",
	    __func__, p->p_pid, flags);

	if ((flags & PAX_NOTE_MPROTECT) == PAX_NOTE_MPROTECT)
		return (true);

	if ((flags & PAX_NOTE_NOMPROTECT) == PAX_NOTE_NOMPROTECT)
		return (false);

	return (true);
}

static pax_flag_t
pax_mprotect_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t flags, pax_flag_t mode)
{
	struct prison *pr;
	uint32_t status;

	status = 0;

	pr = pax_get_prison_td(td);
	status = pr->pr_hbsd.noexec.mprotect_status;

	if (status == PAX_FEATURE_DISABLED) {
		flags &= ~PAX_NOTE_MPROTECT;
		flags |= PAX_NOTE_NOMPROTECT;

		return (flags);
	}

	if (status == PAX_FEATURE_FORCE_ENABLED) {
		flags |= (PAX_NOTE_MPROTECT | PAX_NOTE_PAGEEXEC);
		flags &= ~(PAX_NOTE_NOMPROTECT | PAX_NOTE_NOPAGEEXEC);

		return (flags);
	}

	if (status == PAX_FEATURE_OPTIN) {
		if (mode & PAX_NOTE_MPROTECT) {
			flags |= (PAX_NOTE_MPROTECT | PAX_NOTE_PAGEEXEC);
			flags &= ~(PAX_NOTE_NOMPROTECT | PAX_NOTE_NOPAGEEXEC);
		} else {
			flags &= ~PAX_NOTE_MPROTECT;
			flags |= PAX_NOTE_NOMPROTECT;
		}

		return (flags);
	}

	if (status == PAX_FEATURE_OPTOUT) {
		if (mode & PAX_NOTE_NOMPROTECT) {
			flags &= ~PAX_NOTE_MPROTECT;
			flags |= PAX_NOTE_NOMPROTECT;
		} else {
			flags |= (PAX_NOTE_MPROTECT | PAX_NOTE_PAGEEXEC);
			flags &= ~(PAX_NOTE_NOMPROTECT | PAX_NOTE_NOPAGEEXEC);
		}

		return (flags);
	}

	/*
	 * unknown status, force MPROTECT
	 */
	flags |= (PAX_NOTE_MPROTECT | PAX_NOTE_PAGEEXEC);
	flags &= ~(PAX_NOTE_NOMPROTECT | PAX_NOTE_NOPAGEEXEC);

	return (flags);
}

void
pax_mprotect(struct proc *p, vm_prot_t *prot, vm_prot_t *maxprot)
{

	if (!pax_mprotect_active(p))
		return;

	CTR3(KTR_PAX, "%s: pid = %d maxprot = %x",
	    __func__, p->p_pid, *maxprot);

	if ((*maxprot & (VM_PROT_WRITE|VM_PROT_EXECUTE)) != VM_PROT_EXECUTE &&
	    (*prot & VM_PROT_EXECUTE) != VM_PROT_EXECUTE)
		*maxprot &= ~VM_PROT_EXECUTE;
	else
		*maxprot &= ~VM_PROT_WRITE;
}

int
pax_mprotect_enforce(struct proc *p, vm_map_t map, vm_prot_t old_prot, vm_prot_t new_prot)
{

	if (!pax_mprotect_active(p))
		return (0);

	if ((new_prot & VM_PROT_EXECUTE) == VM_PROT_EXECUTE &&
	    ((old_prot & VM_PROT_EXECUTE) != VM_PROT_EXECUTE)) {
		pax_log_mprotect(p, PAX_LOG_P_COMM,
		    "prevented to introduce new RWX page...");
		vm_map_unlock(map);
		return (KERN_PROTECTION_FAILURE);
	}

	return (0);
}

pax_flag_t
pax_noexec_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode)
{
	pax_flag_t	flags;

	flags = pax_pageexec_setup_flags(imgp, td, mode);
	flags = pax_mprotect_setup_flags(imgp, td, flags, mode);

	return (flags);
}


/*
 * @brief Removes VM_PROT_EXECUTE from prot and maxprot.
 *
 * Mainly used to remove exec protection from data, stack, and other sections.
 *
 * @param p		The controlled vmspace's process proc pointer.
 * @param prot
 * @param maxprot
 *
 * @return		none
 */
void
pax_noexec_nx(struct proc *p, vm_prot_t *prot, vm_prot_t *maxprot)
{

	CTR4(KTR_PAX, "%s: before - pid = %d prot = %x maxprot = %x",
	    __func__, p->p_pid, *prot, *maxprot);

	if (pax_pageexec_active(p)) {
		*prot &= ~VM_PROT_EXECUTE;

		if (pax_mprotect_active(p))
			*maxprot &= ~VM_PROT_EXECUTE;
	}

	CTR4(KTR_PAX, "%s: after - pid = %d prot = %x maxprot = %x",
	    __func__, p->p_pid, *prot, *maxprot);
}

/*
 * @brief Removes VM_PROT_WRITE from prot and maxprot.
 *
 * Mainly used to remove write protection from TEXT sections.
 *
 * @param p		The controlled vmspace's process proc pointer.
 * @param prot
 * @param maxprot
 *
 * @return		none
 */
void
pax_noexec_nw(struct proc *p, vm_prot_t *prot, vm_prot_t *maxprot)
{

	CTR4(KTR_PAX, "%s: before - pid = %d prot = %x maxprot = %x",
	    __func__, p->p_pid, *prot, *maxprot);

	if (pax_pageexec_active(p)) {
		*prot &= ~VM_PROT_WRITE;

		if (pax_mprotect_active(p))
			*maxprot &= ~VM_PROT_WRITE;
	}

	CTR4(KTR_PAX, "%s: after - pid = %d prot = %x maxprot = %x",
	    __func__, p->p_pid, *prot, *maxprot);
}

