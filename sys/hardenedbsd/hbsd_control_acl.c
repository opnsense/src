/*-
 * Copyright (c) 2015-2017 Oliver Pinter <oliver.pinter@HardenedBSD.org>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_pax.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/ktr.h>
#include <sys/libkern.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

FEATURE(hbsd_control_acl, "HardenedBSD's ACL based control subsystem.");

static int pax_control_acl_status = PAX_FEATURE_SIMPLE_ENABLED;
TUNABLE_INT("hardening.control.acl.status", &pax_control_acl_status);

static bool pax_control_acl_active(void);

#ifdef PAX_SYSCTLS
SYSCTL_DECL(_hardening_control);

SYSCTL_NODE(_hardening_control, OID_AUTO, acl, CTLFLAG_RD, 0,
    "ACL based control subsystem.");

SYSCTL_INT(_hardening_control_acl, OID_AUTO, status,
    CTLFLAG_RDTUN|CTLFLAG_SECURE,
    &pax_control_acl_status, 0,
    "status: "
    "0 - disabled, "
    "1 - enabled");
#endif /* PAX_SYSCTLS */

int
pax_control_acl_set_flags(struct thread *td, struct image_params *imgp, const pax_flag_t req_flags)
{

	if (!pax_control_acl_active()) {
		imgp->pax.req_acl_flags = 0;
		return (0);
	}

	imgp->pax.req_acl_flags = req_flags;

	return (0);
}

static bool
pax_control_acl_active(void)
{

	if ((pax_control_acl_status & PAX_FEATURE_SIMPLE_ENABLED) == PAX_FEATURE_SIMPLE_ENABLED)
		return (true);

	if ((pax_control_acl_status & PAX_FEATURE_SIMPLE_DISABLED) == PAX_FEATURE_SIMPLE_DISABLED)
		return (false);

	return (true);
}

static void
pax_control_acl_sysinit(void)
{
	pax_state_t old_state;

	old_state = pax_control_acl_status;
	if (!pax_feature_simple_validate_state(&pax_control_acl_status)) {
		printf("[HBSD CONTROL / ACL] WARNING, invalid settings in loader.conf!"
		    " (pax_hbsdcontrol_status = %d)\n", old_state);
	}

	if (bootverbose) {
		printf("[HBSD CONTROL / ACL] status: %s\n",
		    pax_status_simple_str[pax_control_acl_status]);
	}
}
SYSINIT(pax_control_acl, SI_SUB_PAX, SI_ORDER_SECOND + 1, pax_control_acl_sysinit, NULL);

