/*-
 * Copyright (c) 2006 Elad Efrat <elad@NetBSD.org>
 * Copyright (c) 2013-2017, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
 * Copyright (c) 2014-2015 by Shawn Webb <shawn.webb@hardenedbsd.org>
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

#ifndef	_SYS_PAX_H
#define	_SYS_PAX_H

#define	__HardenedBSD_version	1100056UL

#if defined(_KERNEL) || defined(_WANT_PRISON)
typedef	uint32_t	pax_state_t;

struct hbsd_features {
	struct hbsd_aslr {
		pax_state_t	 status;	/* (p) PaX ASLR enabled */
		pax_state_t	 compat_status;	/* (p) PaX ASLR enabled (compat32) */
		pax_state_t	 disallow_map32bit_status; /* (p) MAP_32BIT protection (__LP64__ only) */
	} aslr;
	struct hbsd_segvguard {
		pax_state_t	 status;       /* (p) PaX segvguard enabled */
		pax_state_t	 expiry;       /* (p) num of seconds to expire an entry */
		pax_state_t	 suspension;   /* (p) num of seconds to suspend an application */
		pax_state_t	 maxcrashes;   /* (p) Maximum number of crashes before suspending application */
	} segvguard;
	struct hbsd_noexec {
		pax_state_t	 pageexec_status;	/* (p) Remove WX pages from user-space */
		pax_state_t	 mprotect_status;	/* (p) Enforce W^X mappings */
	} noexec;
	struct hbsd_hardening {
		pax_state_t	 procfs_harden;		/* (p) Harden procfs */
	} hardening;
	struct hbsd_log {
		pax_state_t	log;		/* (p) Per-jail logging status */
		pax_state_t	ulog;		/* (p) Per-jail user visible logging status */
	} log;
};
#endif

#ifdef _KERNEL

#include <vm/vm.h>

/*
 *  These are internal macros, which are used to enforce the correct
 *  kernel API version from external modules like secadm.
 */
#define	__HBSD_KPI_FREEBSD_VERSION	__CONCAT(__FBSD_KPI, __FreeBSD_version)
#define	__HBSD_KPI_HARDENEDBSD_VERSION	__CONCAT(__HBSD_KPI, __HardenedBSD_version)
#define	__HBSD_KPI_VERSION	__CONCAT(__HBSD_KPI_FREEBSD_VERSION, __HBSD_KPI_HARDENEDBSD_VERSION)

struct image_params;
struct prison;
struct proc;
struct thread;
struct vfsoptlist;
struct vm_offset_t;
struct vnode;

typedef	uint32_t	pax_flag_t;

/*
 * used in sysctl handler
 */
#define	PAX_FEATURE_DISABLED		0
#define	PAX_FEATURE_OPTIN		1
#define	PAX_FEATURE_OPTOUT		2
#define	PAX_FEATURE_FORCE_ENABLED	3

extern const char *pax_status_str[];

#define PAX_FEATURE_SIMPLE_DISABLED	0
#define PAX_FEATURE_SIMPLE_ENABLED	1

extern const char *pax_status_simple_str[];

/*
 * generic pax functions
 */
uint64_t pax_get_hardenedbsd_version(void);
#ifndef	pax_elf
/*
 * This macro is used to enforce the correct KPI version.
 */
#define pax_elf	__CONCAT(pax_elf, __HBSD_KPI_VERSION)
#endif
int pax_elf(struct thread *td, struct image_params *imgp);
void pax_get_flags(struct proc *p, pax_flag_t *flags);
void pax_get_flags_td(struct thread *td, pax_flag_t *flags);
struct prison *pax_get_prison_td(struct thread *td);
bool pax_init_prison(struct prison *pr, struct vfsoptlist *opts);
int pax_handle_prison_param(struct vfsoptlist *opts, const char *mib, pax_state_t *status);
void pax_print_hbsd_context(void);
bool pax_feature_validate_state(pax_state_t *state);
bool pax_feature_simple_validate_state(pax_state_t *state);

/*
 * HardenedBSD's hbsdcontol related functions
 */
int pax_control_acl_set_flags(struct thread *td, struct image_params *imgp, const pax_flag_t req_flags);
int pax_control_extattr_parse_flags(struct thread *td, struct image_params *imgp);

/*
 * ASLR related functions
 */
bool pax_aslr_active(struct proc *p);
#ifdef PAX_ASLR
int pax_aslr_init_prison(struct prison *pr, struct vfsoptlist *opts);
int pax_aslr_init_prison32(struct prison *pr, struct vfsoptlist *opts);
void pax_aslr_init_vmspace(struct proc *p);
void pax_aslr_init_vmspace32(struct proc *p);
#else
#define	pax_aslr_init_prison(pr, opts)	({ 0; })
#define	pax_aslr_init_prison32(pr, opts)	({ 0; })
#define	pax_aslr_init_vmspace		NULL
#define	pax_aslr_init_vmspace32		NULL
#endif
void pax_aslr_init(struct image_params *imgp);
void pax_aslr_execbase(struct proc *p, u_long *et_dyn_addrp);
void pax_aslr_mmap(struct proc *p, vm_offset_t *addr, vm_offset_t orig_addr, int mmap_flags);
void pax_aslr_mmap_map_32bit(struct proc *p, vm_offset_t *addr, vm_offset_t orig_addr, int mmap_flags);
void pax_aslr_rtld(struct proc *p, u_long *addr);
pax_flag_t pax_aslr_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode);
void pax_aslr_stack(struct proc *p, vm_offset_t *addr);
void pax_aslr_stack_with_gap(struct proc *p, vm_offset_t *addr);
void pax_aslr_vdso(struct proc *p, vm_offset_t *addr);
pax_flag_t pax_disallow_map32bit_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode);
bool pax_disallow_map32bit_active(struct thread *td, int mmap_flags);

/*
 * Log related functions
 */

typedef	uint64_t	pax_log_settings_t;

#define	PAX_LOG_DEFAULT		0x00000000
#define	PAX_LOG_SKIP_DETAILS	0x00000001
#define	PAX_LOG_NO_NEWLINE	0x00000002
#define	PAX_LOG_P_COMM		0x00000004
#define	PAX_LOG_NO_P_PAX	0x00000008
#define	PAX_LOG_NO_INDENT	0x00000010

int pax_log_init_prison(struct prison *pr, struct vfsoptlist *opts);
void pax_printf_flags(struct proc *p, pax_log_settings_t flags);
void pax_printf_flags_td(struct thread *td, pax_log_settings_t flags);
void pax_db_printf_flags(struct proc *p, pax_log_settings_t flags);
void pax_db_printf_flags_td(struct thread *td, pax_log_settings_t flags);
int hbsd_uprintf(const char *fmt, ...) __printflike(1, 2);
void pax_log_internal(struct proc *, pax_log_settings_t flags, const char *fmt, ...) __printflike(3, 4);
void pax_log_internal_imgp(struct image_params *imgp, pax_log_settings_t flags, const char* fmt, ...) __printflike(3, 4);
void pax_ulog_internal(const char *fmt, ...) __printflike(1, 2);
void pax_log_aslr(struct proc *, pax_log_settings_t flags, const char *fmt, ...) __printflike(3, 4);
void pax_ulog_aslr(const char *fmt, ...) __printflike(1, 2);
void pax_log_pageexec(struct proc *, pax_log_settings_t flags, const char *fmt, ...) __printflike(3, 4);
void pax_ulog_pageexec(const char *fmt, ...) __printflike(1, 2);
void pax_log_mprotect(struct proc *, pax_log_settings_t flags, const char *fmt, ...) __printflike(3, 4);
void pax_ulog_mprotect(const char *fmt, ...) __printflike(1, 2);
void pax_log_segvguard(struct proc *, pax_log_settings_t flags, const char *fmt, ...) __printflike(3, 4);
void pax_ulog_segvguard(const char *fmt, ...) __printflike(1, 2);

/*
 * SegvGuard related functions
 */
#ifdef PAX_SEGVGUARD
int pax_segvguard_init_prison(struct prison *pr, struct vfsoptlist *opts);
#else
#define	pax_segvguard_init_prison(pr, opts)	({ 0; })
#endif
int pax_segvguard_check(struct thread *, struct vnode *, const char *);
int pax_segvguard_segfault(struct thread *, const char *);
void pax_segvguard_remove(struct thread *td, struct vnode *vn);
pax_flag_t pax_segvguard_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode);

/*
 * PAX PAGEEXEC and MPROTECT hardening
 */
#ifdef PAX_NOEXEC
int pax_noexec_init_prison(struct prison *pr, struct vfsoptlist *opts);
#else
#define	pax_noexec_init_prison(pr, opts)	({ 0; })
#endif
pax_flag_t pax_noexec_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode);
void pax_noexec_nw(struct proc *p, vm_prot_t *prot, vm_prot_t *maxprot);
void pax_noexec_nx(struct proc *p, vm_prot_t *prot, vm_prot_t *maxprot);
bool pax_pageexec_active(struct proc *p);
bool pax_mprotect_active(struct proc *p);
void pax_pageexec(struct proc *p, vm_prot_t *prot, vm_prot_t *maxprot);
void pax_mprotect(struct proc *p, vm_prot_t *prot, vm_prot_t *maxprot);
int pax_mprotect_enforce(struct proc *p, vm_map_t map, vm_prot_t old_prot, vm_prot_t new_prot);

/*
 * Hardening related functions
 */
#ifdef PAX_HARDENING
int pax_hardening_init_prison(struct prison *pr, struct vfsoptlist *opts);
#else
#define	pax_hardening_init_prison(pr, opts)	({ 0; })
#endif
int pax_procfs_harden(struct thread *td);

#define	PAX_NOTE_PAGEEXEC	0x00000001
#define	PAX_NOTE_NOPAGEEXEC	0x00000002
#define	PAX_NOTE_MPROTECT	0x00000004
#define	PAX_NOTE_NOMPROTECT	0x00000008
#define	PAX_NOTE_SEGVGUARD	0x00000010
#define	PAX_NOTE_NOSEGVGUARD	0x00000020
#define	PAX_NOTE_ASLR		0x00000040
#define	PAX_NOTE_NOASLR		0x00000080
#define	PAX_NOTE_SHLIBRANDOM	0x00000100
#define	PAX_NOTE_NOSHLIBRANDOM	0x00000200
#define	PAX_NOTE_DISALLOWMAP32BIT	0x00000400
#define	PAX_NOTE_NODISALLOWMAP32BIT	0x00000800

#define	PAX_NOTE_RESERVED0	0x40000000
#define	PAX_NOTE_PREFER_ACL	0x80000000

#define PAX_NOTE_ALL_ENABLED	\
    (PAX_NOTE_PAGEEXEC | PAX_NOTE_MPROTECT | PAX_NOTE_SEGVGUARD | \
    PAX_NOTE_ASLR | PAX_NOTE_SHLIBRANDOM | PAX_NOTE_DISALLOWMAP32BIT)
#define PAX_NOTE_ALL_DISABLED	\
    (PAX_NOTE_NOPAGEEXEC | PAX_NOTE_NOMPROTECT | \
    PAX_NOTE_NOSEGVGUARD | PAX_NOTE_NOASLR | PAX_NOTE_NOSHLIBRANDOM | \
    PAX_NOTE_NODISALLOWMAP32BIT)
#define PAX_NOTE_ALL	(PAX_NOTE_ALL_ENABLED | PAX_NOTE_ALL_DISABLED | PAX_NOTE_PREFER_ACL)

#endif /* _KERNEL */

#define	PAX_HARDENING_SHLIBRANDOM	0x00000100
#define	PAX_HARDENING_NOSHLIBRANDOM	0x00000200

#endif /* !_SYS_PAX_H */
