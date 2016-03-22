/*-
 * Copyright (c) 2006 Elad Efrat <elad@NetBSD.org>
 * Copyright (c) 2013-2016, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
 * Copyright (c) 2014-2015, by Shawn Webb <shawn.webb@hardenedbsd.org>
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
#include <sys/elf_common.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/jail.h>
#include <sys/ktr.h>
#include <sys/libkern.h>
#include <sys/mman.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>

#include "hbsd_pax_internal.h"

#ifndef PAX_ASLR_DELTA
#define	PAX_ASLR_DELTA(delta, lsb, len)	\
	(((delta) & ((1UL << (len)) - 1)) << (lsb))
#endif /* PAX_ASLR_DELTA */

/*-
 * generic ASLR values
 *
 *  		| 32 bit | 64 bit | compat |
 * 	+-------+--------+--------+--------+
 * 	| MMAP	| 14 bit | 30 bit | 14 bit |
 * 	+-------+--------+--------+--------+
 * 	| STACK	| 10 bit | 42 bit | 10 bit |
 * 	+-------+--------+--------+--------+
 * 	| EXEC	| 14 bit | 30 bit | 14 bit |
 * 	+-------+--------+--------+--------+
 * 	| VDSO	| 10 bit | 28 bit | 10 bit |
 * 	+-------+--------+--------+--------+
 * 	| M32B	|  N.A.  | 18 bit |  N.A.  |
 * 	+-------+--------+--------+--------+
 *
 */

#ifndef PAX_ASLR_DELTA_MMAP_LSB
#define PAX_ASLR_DELTA_MMAP_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_DELTA_MMAP_LSB */

#ifndef PAX_ASLR_DELTA_STACK_LSB
#define	PAX_ASLR_DELTA_STACK_LSB	PAGE_SHIFT
#endif /* PAX_ASLR_DELTA_STACK_LSB */

#ifndef PAX_ASLR_DELTA_STACK_WITH_GAP_LSB
#define	PAX_ASLR_DELTA_STACK_WITH_GAP_LSB	3
#endif /* PAX_ASLR_DELTA_STACK_WITH_GAP_LSB */

#ifndef PAX_ASLR_DELTA_EXEC_LSB
#define	PAX_ASLR_DELTA_EXEC_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_DELTA_EXEC_LSB */

#ifndef PAX_ASLR_DELTA_VDSO_LSB
#define	PAX_ASLR_DELTA_VDSO_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_DELTA_VDSO_LSB */

#ifdef MAP_32BIT
#ifndef PAX_ASLR_DELTA_MAP32BIT_LSB
#define	PAX_ASLR_DELTA_MAP32BIT_LSB	PAGE_SHIFT
#endif /* PAX_ASLR_DELTA_MAP32BIT_LSB */
#endif /* MAP_32BIT */

/*
 * ASLR default values for native host
 */
#ifdef __LP64__

#ifndef PAX_ASLR_DELTA_MMAP_DEF_LEN
#define	PAX_ASLR_DELTA_MMAP_DEF_LEN	30
#endif /* PAX_ASLR_DELTA_MMAP_DEF_LEN */

#ifndef PAX_ASLR_DELTA_STACK_DEF_LEN
#define	PAX_ASLR_DELTA_STACK_DEF_LEN	42
#endif /* PAX_ASLR_DELTA_STACK_DEF_LEN */

#ifndef PAX_ASLR_DELTA_EXEC_DEF_LEN
#define	PAX_ASLR_DELTA_EXEC_DEF_LEN	30
#endif /* PAX_ASLR_DELTA_EXEC_DEF_LEN */

#ifndef PAX_ASLR_DELTA_VDSO_DEF_LEN
#define	PAX_ASLR_DELTA_VDSO_DEF_LEN	28
#endif /* PAX_ASLR_DELTA_VDSO_DEF_LEN */

#ifdef MAP_32BIT
#ifndef PAX_ASLR_DELTA_MAP32BIT_DEF_LEN
#define	PAX_ASLR_DELTA_MAP32BIT_DEF_LEN	18
#endif /* PAX_ASLR_DELTA_MAP32BIT_DEF_LEN */
#endif /* MAP_32BIT */

#else /* ! __LP64__ */

#ifndef PAX_ASLR_DELTA_MMAP_DEF_LEN
#define	PAX_ASLR_DELTA_MMAP_DEF_LEN	14
#endif /* PAX_ASLR_DELTA_MMAP_DEF_LEN */

#ifndef PAX_ASLR_DELTA_STACK_DEF_LEN
#define	PAX_ASLR_DELTA_STACK_DEF_LEN	10
#endif /* PAX_ASLR_DELTA_STACK_DEF_LEN */

#ifndef PAX_ASLR_DELTA_EXEC_DEF_LEN
#define	PAX_ASLR_DELTA_EXEC_DEF_LEN	14
#endif /* PAX_ASLR_DELTA_EXEC_DEF_LEN */

#ifndef PAX_ASLR_DELTA_VDSO_DEF_LEN
#define	PAX_ASLR_DELTA_VDSO_DEF_LEN	10
#endif /* PAX_ASLR_DELTA_VDSO_DEF_LEN */

#endif /* __LP64__ */

/*
 * ASLR values for COMPAT_FREEBSD32, COMPAT_LINUX and MAP_32BIT
 */
#if defined(COMPAT_LINUX) || defined(COMPAT_FREEBSD32) || defined(MAP_32BIT)
#ifndef PAX_ASLR_COMPAT_DELTA_MMAP_LSB
#define PAX_ASLR_COMPAT_DELTA_MMAP_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_COMPAT_DELTA_MMAP_LSB */

#ifndef PAX_ASLR_COMPAT_DELTA_STACK_LSB
#define PAX_ASLR_COMPAT_DELTA_STACK_LSB		3
#endif /* PAX_ASLR_COMPAT_DELTA_STACK_LSB */

#ifndef PAX_ASLR_COMPAT_DELTA_EXEC_LSB
#define PAX_ASLR_COMPAT_DELTA_EXEC_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_COMPAT_DELTA_EXEC_LSB */

#ifndef PAX_ASLR_COMPAT_DELTA_VDSO_LSB
#define PAX_ASLR_COMPAT_DELTA_VDSO_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_COMPAT_DELTA_VDSO_LSB */

#ifndef PAX_ASLR_COMPAT_DELTA_MMAP_DEF_LEN
#define	PAX_ASLR_COMPAT_DELTA_MMAP_DEF_LEN	14
#endif /* PAX_ASLR_COMPAT_DELTA_MMAP_DEF_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_STACK_DEF_LEN
#define	PAX_ASLR_COMPAT_DELTA_STACK_DEF_LEN	10
#endif /* PAX_ASLR_COMPAT_DELTA_STACK_DEF_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_EXEC_DEF_LEN
#define	PAX_ASLR_COMPAT_DELTA_EXEC_DEF_LEN	14
#endif /* PAX_ASLR_COMPAT_DELTA_EXEC_DEF_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_VDSO_DEF_LEN
#define	PAX_ASLR_COMPAT_DELTA_VDSO_DEF_LEN	10
#endif /* PAX_ASLR_COMPAT_DELTA_VDSO_DEF_LEN */

#endif

FEATURE(hbsd_aslr, "Address Space Layout Randomization.");

static int pax_aslr_status = PAX_FEATURE_OPTOUT;
static int pax_aslr_mmap_len = PAX_ASLR_DELTA_MMAP_DEF_LEN;
static int pax_aslr_stack_len = PAX_ASLR_DELTA_STACK_DEF_LEN;
static int pax_aslr_exec_len = PAX_ASLR_DELTA_EXEC_DEF_LEN;
static int pax_aslr_vdso_len = PAX_ASLR_DELTA_VDSO_DEF_LEN;
#ifdef MAP_32BIT
static int pax_aslr_map32bit_len = PAX_ASLR_DELTA_MAP32BIT_DEF_LEN;
#ifdef PAX_HARDENING
static int pax_disallow_map32bit_status_global = PAX_FEATURE_OPTOUT;
#else
static int pax_disallow_map32bit_status_global = PAX_FEATURE_OPTIN;
#endif
#endif

#ifdef COMPAT_FREEBSD32
static int pax_aslr_compat_status = PAX_FEATURE_OPTOUT;
static int pax_aslr_compat_mmap_len = PAX_ASLR_COMPAT_DELTA_MMAP_DEF_LEN;
static int pax_aslr_compat_stack_len = PAX_ASLR_COMPAT_DELTA_STACK_DEF_LEN;
static int pax_aslr_compat_exec_len = PAX_ASLR_COMPAT_DELTA_EXEC_DEF_LEN;
static int pax_aslr_compat_vdso_len = PAX_ASLR_COMPAT_DELTA_VDSO_DEF_LEN;
#endif /* COMPAT_FREEBSD32 */

TUNABLE_INT("hardening.pax.aslr.status", &pax_aslr_status);
TUNABLE_INT("hardening.pax.aslr.mmap_len", &pax_aslr_mmap_len);
TUNABLE_INT("hardening.pax.aslr.stack_len", &pax_aslr_stack_len);
TUNABLE_INT("hardening.pax.aslr.exec_len", &pax_aslr_exec_len);
TUNABLE_INT("hardening.pax.aslr.vdso_len", &pax_aslr_vdso_len);
#ifdef MAP_32BIT
TUNABLE_INT("hardening.pax.aslr.map32bit_len", &pax_aslr_map32bit_len);
TUNABLE_INT("hardening.pax.disallow_map32bit.status", &pax_disallow_map32bit_status_global);
#endif
#ifdef COMPAT_FREEBSD32
TUNABLE_INT("hardening.pax.aslr.compat.status", &pax_aslr_compat_status);
TUNABLE_INT("hardening.pax.aslr.compat.mmap_len", &pax_aslr_compat_mmap_len);
TUNABLE_INT("hardening.pax.aslr.compat.stack_len", &pax_aslr_compat_stack_len);
TUNABLE_INT("hardening.pax.aslr.compat.exec_len", &pax_aslr_compat_exec_len);
TUNABLE_INT("hardening.pax.aslr.compat.vdso_len", &pax_aslr_compat_vdso_len);
#endif

#ifdef PAX_SYSCTLS
SYSCTL_DECL(_hardening_pax);

SYSCTL_NODE(_hardening_pax, OID_AUTO, aslr, CTLFLAG_RD, 0,
    "Address Space Layout Randomization.");
SYSCTL_HBSD_4STATE(pax_aslr_status, pr_hbsd.aslr.status,
    _hardening_pax_aslr, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE);

/* COMPAT_FREEBSD32 and linuxulator. */
#ifdef COMPAT_FREEBSD32
SYSCTL_NODE(_hardening_pax_aslr, OID_AUTO, compat, CTLFLAG_RD, 0,
    "Settings for COMPAT_FREEBSD32 and linuxulator.");
SYSCTL_HBSD_4STATE(pax_aslr_compat_status, pr_hbsd.aslr.compat_status,
    _hardening_pax_aslr_compat, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON);
#endif /* COMPAT_FREEBSD32 */

#ifdef MAP_32BIT
SYSCTL_NODE(_hardening_pax, OID_AUTO, disallow_map32bit, CTLFLAG_RD, 0,
    "Disallow MAP_32BIT mode mmap(2) calls.");
SYSCTL_HBSD_4STATE(pax_disallow_map32bit_status_global, pr_hbsd.aslr.disallow_map32bit_status,
    _hardening_pax_disallow_map32bit, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE);
#endif	/* MAP_32BIT */

#endif /* PAX_SYSCTLS */


/*
 * ASLR functions
 */

static void
pax_aslr_sysinit(void)
{

	switch (pax_aslr_status) {
	case PAX_FEATURE_DISABLED:
	case PAX_FEATURE_OPTIN:
	case PAX_FEATURE_OPTOUT:
	case PAX_FEATURE_FORCE_ENABLED:
		break;
	default:
		printf("[HBSD ASLR] WARNING, invalid PAX settings in loader.conf!"
		    " (pax_aslr_status = %d)\n", pax_aslr_status);
		pax_aslr_status = PAX_FEATURE_FORCE_ENABLED;
		break;
	}
	printf("[HBSD ASLR] status: %s\n", pax_status_str[pax_aslr_status]);
	printf("[HBSD ASLR] mmap: %d bit\n", pax_aslr_mmap_len);
	printf("[HBSD ASLR] exec base: %d bit\n", pax_aslr_exec_len);
	printf("[HBSD ASLR] stack: %d bit\n", pax_aslr_stack_len);
	printf("[HBSD ASLR] vdso: %d bit\n", pax_aslr_vdso_len);
#ifdef MAP_32BIT
	printf("[HBSD ASLR] map32bit: %d bit\n", pax_aslr_map32bit_len);

	switch (pax_disallow_map32bit_status_global) {
	case PAX_FEATURE_DISABLED:
	case PAX_FEATURE_OPTIN:
	case PAX_FEATURE_OPTOUT:
	case PAX_FEATURE_FORCE_ENABLED:
		break;
	default:
		printf("[HBSD ASLR] WARNING, invalid settings in loader.conf!"
		    " (hardening.pax.disallow_map32bit.status = %d)\n",
		    pax_disallow_map32bit_status_global);
		pax_disallow_map32bit_status_global = PAX_FEATURE_FORCE_ENABLED;
	}
	printf("[HBSD ASLR] disallow MAP_32BIT mode mmap: %s\n",
	    pax_status_str[pax_disallow_map32bit_status_global]);
#endif
}
SYSINIT(pax_aslr, SI_SUB_PAX, SI_ORDER_SECOND, pax_aslr_sysinit, NULL);

bool
pax_aslr_active(struct proc *p)
{
	pax_flag_t flags;

	pax_get_flags(p, &flags);

	CTR3(KTR_PAX, "%s: pid = %d p_pax = %x",
	    __func__, p->p_pid, flags);

	if ((flags & PAX_NOTE_ASLR) == PAX_NOTE_ASLR)
		return (true);

	if ((flags & PAX_NOTE_NOASLR) == PAX_NOTE_NOASLR)
		return (false);

	return (true);
}

void
pax_aslr_init_vmspace(struct proc *p)
{
	struct vmspace *vm;
	unsigned long rand_buf;
	int try;

	vm = p->p_vmspace;
	KASSERT(vm != NULL, ("%s: vm is null", __func__));

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_mmap = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_DELTA_MMAP_LSB,
	    pax_aslr_mmap_len);

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_exec = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_DELTA_EXEC_LSB,
	    pax_aslr_exec_len);

	try = 3;
try_again:
	/*
	 * In stack case we generate a bigger random, which consists
	 * of two parts.
	 * The first upper part [pax_aslr_stack_len .. PAGE_SHIFT+1]
	 * applied to mapping, the second lower part [PAGE_SHIFT .. 3]
	 * applied in the mapping as gap.
	 */
	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_stack = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_DELTA_STACK_WITH_GAP_LSB,
	    pax_aslr_stack_len);
	vm->vm_aslr_delta_stack = ALIGN(vm->vm_aslr_delta_stack);

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	rand_buf = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_DELTA_VDSO_LSB,
	    pax_aslr_vdso_len);

	/*
	 * Place the vdso between the stacktop and
	 * vm_max_user-PAGE_SIZE.
	 *
	 * In future this will change, to place them between the 
	 * stack and heap.
	 */

	/* 
	 * This check required to handle the case 
	 * when PAGE_ALIGN(vm->vm_aslr_delta_stack) == 0.
	 */
	if ((vm->vm_aslr_delta_stack & (-1UL << PAX_ASLR_DELTA_VDSO_LSB)) != 0) {
		if (rand_buf > vm->vm_aslr_delta_stack) {
			rand_buf = rand_buf %
			    ((unsigned long)vm->vm_aslr_delta_stack &
			    (-1UL << PAX_ASLR_DELTA_STACK_LSB));
			rand_buf &= (-1UL << PAX_ASLR_DELTA_VDSO_LSB);
		}
	} else if (try > 0) {
		try--;
		goto try_again;
	} else {
		/* XXX: Instead of 0, should we place them at the end of heap? */
		pax_log_aslr(p, PAX_LOG_DEFAULT, "%s check your /boot/loader.conf ...", __func__);
		rand_buf = 0;
	}
	vm->vm_aslr_delta_vdso = rand_buf;

#ifdef MAP_32BIT
	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_map32bit = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_DELTA_MAP32BIT_LSB,
	    pax_aslr_map32bit_len);
#endif

	CTR2(KTR_PAX, "%s: vm_aslr_delta_mmap=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_mmap);
	CTR2(KTR_PAX, "%s: vm_aslr_delta_stack=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_stack);
	CTR2(KTR_PAX, "%s: vm_aslr_delta_exec=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_exec);
	CTR2(KTR_PAX, "%s: vm_aslr_delta_vdso=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_vdso);
#ifdef MAP_32BIT
	CTR2(KTR_PAX, "%s: vm_aslr_delta_map32bit=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_map32bit);
#endif
}

#ifdef COMPAT_FREEBSD32
static void
pax_compat_aslr_sysinit(void)
{

	switch (pax_aslr_compat_status) {
	case PAX_FEATURE_DISABLED:
	case PAX_FEATURE_OPTIN:
	case PAX_FEATURE_OPTOUT:
	case PAX_FEATURE_FORCE_ENABLED:
		break;
	default:
		printf("[HBSD ASLR (compat)] WARNING, invalid PAX settings in loader.conf! "
		    "(pax_aslr_compat_status = %d)\n", pax_aslr_compat_status);
		pax_aslr_compat_status = PAX_FEATURE_FORCE_ENABLED;
		break;
	}
	printf("[HBSD ASLR (compat)] status: %s\n", pax_status_str[pax_aslr_compat_status]);
	printf("[HBSD ASLR (compat)] mmap: %d bit\n", pax_aslr_compat_mmap_len);
	printf("[HBSD ASLR (compat)] exec base: %d bit\n", pax_aslr_compat_exec_len);
	printf("[HBSD ASLR (compat)] stack: %d bit\n", pax_aslr_compat_stack_len);
	printf("[HBSD ASLR (compat)] vdso: %d bit\n", pax_aslr_compat_vdso_len);
}
SYSINIT(pax_compat_aslr, SI_SUB_PAX, SI_ORDER_SECOND, pax_compat_aslr_sysinit, NULL);

void
pax_aslr_init_vmspace32(struct proc *p)
{
	struct vmspace *vm;
	long rand_buf;

	vm = p->p_vmspace;
	KASSERT(vm != NULL, ("%s: vm is null", __func__));

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_mmap = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_COMPAT_DELTA_MMAP_LSB,
	    pax_aslr_compat_mmap_len);

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_stack = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_COMPAT_DELTA_STACK_LSB,
	    pax_aslr_compat_stack_len);
	vm->vm_aslr_delta_stack = ALIGN(vm->vm_aslr_delta_stack);

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_exec = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_COMPAT_DELTA_EXEC_LSB,
	    pax_aslr_compat_exec_len);

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_vdso = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_COMPAT_DELTA_VDSO_LSB,
	    pax_aslr_compat_vdso_len);

	CTR2(KTR_PAX, "%s: vm_aslr_delta_mmap=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_mmap);
	CTR2(KTR_PAX, "%s: vm_aslr_delta_stack=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_stack);
	CTR2(KTR_PAX, "%s: vm_aslr_delta_exec=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_exec);
	CTR2(KTR_PAX, "%s: vm_aslr_delta_vdso=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_vdso);
}
#endif	/* COMPAT_FREEBSD32 */

void
pax_aslr_init(struct image_params *imgp)
{
	struct proc *p;

	KASSERT(imgp != NULL, ("%s: imgp is null", __func__));
	p = imgp->proc;

	if (!pax_aslr_active(p))
		return;

	if (imgp->sysent->sv_pax_aslr_init != NULL)
		imgp->sysent->sv_pax_aslr_init(p);
}

void
pax_aslr_init_prison(struct prison *pr)
{
	struct prison *pr_p;

	CTR2(KTR_PAX, "%s: Setting prison %s PaX variables\n",
	    __func__, pr->pr_name);

	if (pr == &prison0) {
		/* prison0 has no parent, use globals */
		pr->pr_hbsd.aslr.status = pax_aslr_status;
#ifdef MAP_32BIT
		pr->pr_hbsd.aslr.disallow_map32bit_status =
		    pax_disallow_map32bit_status_global;
#endif
	} else {
		KASSERT(pr->pr_parent != NULL,
		   ("%s: pr->pr_parent == NULL", __func__));
		pr_p = pr->pr_parent;

		pr->pr_hbsd.aslr.status = pr_p->pr_hbsd.aslr.status;
#ifdef MAP_32BIT
		pr->pr_hbsd.aslr.disallow_map32bit_status =
		    pr_p->pr_hbsd.aslr.disallow_map32bit_status;
#endif
	}
}

#ifdef COMPAT_FREEBSD32
void
pax_aslr_init_prison32(struct prison *pr)
{
	struct prison *pr_p;

	CTR2(KTR_PAX, "%s: Setting prison %s PaX variables\n",
	    __func__, pr->pr_name);

	if (pr == &prison0) {
		/* prison0 has no parent, use globals */

		pr->pr_hbsd.aslr.compat_status = pax_aslr_compat_status;
	} else {
		KASSERT(pr->pr_parent != NULL,
		   ("%s: pr->pr_parent == NULL", __func__));
		pr_p = pr->pr_parent;

		pr->pr_hbsd.aslr.compat_status = pr_p->pr_hbsd.aslr.compat_status;
	}
}
#endif /* COMPAT_FREEBSD32 */

void
pax_aslr_mmap(struct proc *p, vm_offset_t *addr, vm_offset_t orig_addr, int mmap_flags)
{

	PROC_LOCK_ASSERT(p, MA_OWNED);

#ifdef MAP_32BIT
	if (((mmap_flags & MAP_32BIT) == MAP_32BIT) || !pax_aslr_active(p))
#else
	if (!pax_aslr_active(p))
#endif
		return;

#ifdef MAP_32BIT
	KASSERT((mmap_flags & MAP_32BIT) != MAP_32BIT,
	    ("%s: we can't handle MAP_32BIT mapping here", __func__));
#endif
	KASSERT((mmap_flags & MAP_FIXED) != MAP_FIXED,
	    ("%s: we can't randomize MAP_FIXED mapping", __func__));

	/*
	 * From original PaX doc:
	 *
	 * PaX applies randomization (delta_mmap) to TASK_UNMAPPED_BASE in bits 12-27
	 * (16 bits) and ignores the hint for file mappings (unfortunately there is
	 * a 'feature' in linuxthreads where the thread stack mappings do not specify
	 * MAP_FIXED but still expect that behaviour so the hint cannot be overriden
	 * for anonymous mappings).
	 *
	 * https://github.com/HardenedBSD/pax-docs-mirror/blob/master/randmmap.txt#L30
	 */
	if ((orig_addr == 0) || !(mmap_flags & MAP_ANON)) {
		CTR4(KTR_PAX, "%s: applying to %p orig_addr=%p mmap_flags=%x\n",
		    __func__, (void *)*addr, (void *)orig_addr, mmap_flags);
		*addr += p->p_vmspace->vm_aslr_delta_mmap;
		CTR2(KTR_PAX, "%s: result %p\n", __func__, (void *)*addr);
	} else
		CTR4(KTR_PAX, "%s: not applying to %p orig_addr=%p mmap_flags=%x\n",
		    __func__, (void *)*addr, (void *)orig_addr, mmap_flags);
}

void
pax_aslr_rtld(struct proc *p, u_long *addr)
{

	PROC_LOCK_ASSERT(p, MA_OWNED);

	if (!pax_aslr_active(p))
		return;

	*addr += p->p_vmspace->vm_aslr_delta_mmap;
	CTR2(KTR_PAX, "%s: result %p\n", __func__, (void *)*addr);
}

void
pax_aslr_stack(struct proc *p, vm_offset_t *addr)
{
	uintptr_t orig_addr;
	uintptr_t random;

	if (!pax_aslr_active(p))
		return;

	orig_addr = *addr;

	/*
	 * Apply the random offset to the mapping.
	 * This should page aligned.
	 */
	random = p->p_vmspace->vm_aslr_delta_stack;
	random &= (-1UL << PAX_ASLR_DELTA_STACK_LSB);
	*addr -= random;

	CTR3(KTR_PAX, "%s: orig_addr=%p, new_addr=%p\n",
	    __func__, (void *)orig_addr, (void *)*addr);
}

void
pax_aslr_stack_with_gap(struct proc *p, vm_offset_t *addr)
{
	uintptr_t orig_addr;
	uintptr_t random;

	if (!pax_aslr_active(p))
		return;

	orig_addr = *addr;
	/*
	 * Apply the random gap offset withing the page.
	 */
	random = p->p_vmspace->vm_aslr_delta_stack;
	*addr -= random;

	CTR3(KTR_PAX, "%s: orig_addr=%p, new_addr=%p\n",
	    __func__, (void *)orig_addr, (void *)*addr);
}

void
pax_aslr_execbase(struct proc *p, u_long *et_dyn_addrp)
{

	if (!pax_aslr_active(p))
		return;

	*et_dyn_addrp += p->p_vmspace->vm_aslr_delta_exec;
}

void
pax_aslr_vdso(struct proc *p, vm_offset_t *addr)
{
	uintptr_t orig_addr;

	if (!pax_aslr_active(p))
		return;

	orig_addr = *addr;
	*addr -= p->p_vmspace->vm_aslr_delta_vdso;

	CTR3(KTR_PAX, "%s: orig_addr=%p, new_addr=%p\n",
	    __func__, (void *)orig_addr, (void *)*addr);
}

pax_flag_t
pax_aslr_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode)
{
	struct prison *pr;
	pax_flag_t flags;
	uint32_t status;

	KASSERT(imgp->proc == td->td_proc,
	    ("%s: imgp->proc != td->td_proc", __func__));

	flags = 0;
	status = 0;

	pr = pax_get_prison_td(td);
	status = pr->pr_hbsd.aslr.status;

	if (status == PAX_FEATURE_DISABLED) {
		flags &= ~PAX_NOTE_ASLR;
		flags |= PAX_NOTE_NOASLR;

		return (flags);
	}

	if (status == PAX_FEATURE_FORCE_ENABLED) {
		flags |= PAX_NOTE_ASLR;
		flags &= ~PAX_NOTE_NOASLR;

		return (flags);
	}

	if (status == PAX_FEATURE_OPTIN) {
		if (mode & PAX_NOTE_ASLR) {
			flags |= PAX_NOTE_ASLR;
			flags &= ~PAX_NOTE_NOASLR;
		} else {
			flags &= ~PAX_NOTE_ASLR;
			flags |= PAX_NOTE_NOASLR;
		}

		return (flags);
	}

	if (status == PAX_FEATURE_OPTOUT) {
		if (mode & PAX_NOTE_NOASLR) {
			flags &= ~PAX_NOTE_ASLR;
			flags |= PAX_NOTE_NOASLR;
		} else {
			flags |= PAX_NOTE_ASLR;
			flags &= ~PAX_NOTE_NOASLR;
		}

		return (flags);
	}

	/*
	 * Unknown status, force ASLR.
	 */
	flags |= PAX_NOTE_ASLR;
	flags &= ~PAX_NOTE_NOASLR;

	return (flags);
}

#ifdef MAP_32BIT
void
pax_aslr_mmap_map_32bit(struct proc *p, vm_offset_t *addr, vm_offset_t orig_addr, int mmap_flags)
{

	PROC_LOCK_ASSERT(p, MA_OWNED);

	if (((mmap_flags & MAP_32BIT) != MAP_32BIT) || !pax_aslr_active(p))
		return;

	KASSERT((mmap_flags & MAP_32BIT) == MAP_32BIT,
	    ("%s: we can't handle not MAP_32BIT mapping here", __func__));
	KASSERT((mmap_flags & MAP_FIXED) != MAP_FIXED,
	    ("%s: we can't randomize MAP_FIXED mapping", __func__));

	/*
	 * From original PaX doc:
	 *
	 * PaX applies randomization (delta_mmap) to TASK_UNMAPPED_BASE in bits 12-27
	 * (16 bits) and ignores the hint for file mappings (unfortunately there is
	 * a 'feature' in linuxthreads where the thread stack mappings do not specify
	 * MAP_FIXED but still expect that behaviour so the hint cannot be overriden
	 * for anonymous mappings).
	 *
	 * https://github.com/HardenedBSD/pax-docs-mirror/blob/master/randmmap.txt#L30
	 */
	if ((orig_addr == 0) || !(mmap_flags & MAP_ANON)) {
		CTR4(KTR_PAX, "%s: applying to %p orig_addr=%p mmap_flags=%x\n",
				__func__, (void *)*addr, (void *)orig_addr, mmap_flags);

		*addr += p->p_vmspace->vm_aslr_delta_map32bit;
		CTR2(KTR_PAX, "%s: result %p\n", __func__, (void *)*addr);
	}
}

bool
pax_disallow_map32bit_active(struct thread *td, int mmap_flags)
{
	pax_flag_t flags;

	if ((mmap_flags & MAP_32BIT) != MAP_32BIT)
		/*
		 * Fast path, the mmap request does not
		 * contains MAP_32BIT flag.
		 */
		return (false);

	pax_get_flags_td(td, &flags);

	CTR3(KTR_PAX, "%S: pid = %d p_pax = %x",
	    __func__, td->td_proc->p_pid, flags);

	if ((flags & PAX_NOTE_DISALLOWMAP32BIT) == PAX_NOTE_DISALLOWMAP32BIT)
		return (true);

	if ((flags & PAX_NOTE_NODISALLOWMAP32BIT) == PAX_NOTE_NODISALLOWMAP32BIT)
		return (false);

	return (true);
}

pax_flag_t
pax_disallow_map32bit_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode)
{
	struct prison *pr;
	pax_flag_t flags;
	uint32_t  status;

	KASSERT(imgp->proc == td->td_proc,
	    ("%s: imgp->proc != td->td_proc", __func__));

	flags = 0;
	status = 0;

	pr = pax_get_prison_td(td);
	status = pr->pr_hbsd.aslr.disallow_map32bit_status;

	if (status == PAX_FEATURE_DISABLED) {
		flags &= ~PAX_NOTE_DISALLOWMAP32BIT;
		flags |= PAX_NOTE_NODISALLOWMAP32BIT;

		return (flags);
	}

	if (status == PAX_FEATURE_FORCE_ENABLED) {
		flags &= ~PAX_NOTE_NODISALLOWMAP32BIT;
		flags |= PAX_NOTE_DISALLOWMAP32BIT;

		return (flags);
	}

	if (status == PAX_FEATURE_OPTIN) {
		if (mode & PAX_NOTE_DISALLOWMAP32BIT) {
			flags |= PAX_NOTE_DISALLOWMAP32BIT;
			flags &= ~PAX_NOTE_NODISALLOWMAP32BIT;
		} else {
			flags &= ~PAX_NOTE_DISALLOWMAP32BIT;
			flags |= PAX_NOTE_NODISALLOWMAP32BIT;
		}

		return (flags);
	}

	if (status == PAX_FEATURE_OPTOUT) {
		if (mode & PAX_NOTE_NODISALLOWMAP32BIT) {
			flags |= PAX_NOTE_NODISALLOWMAP32BIT;
			flags &= ~PAX_NOTE_DISALLOWMAP32BIT;
		} else {
			flags &= ~PAX_NOTE_NODISALLOWMAP32BIT;
			flags |= PAX_NOTE_DISALLOWMAP32BIT;
		}

		return (flags);
	}

	/* Unknown status, force MAP32 restriction. */
	flags |= PAX_NOTE_DISALLOWMAP32BIT;
	flags &= ~PAX_NOTE_NODISALLOWMAP32BIT;

	return (flags);
}
#endif	/* MAP_32BIT */

