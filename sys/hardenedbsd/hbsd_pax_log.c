/*-
 * Copyright (c) 2014, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
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

#include "opt_pax.h"
#include "opt_ddb.h"

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/imgact.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/jail.h>
#include <machine/stdarg.h>

#ifdef DDB
#include <ddb/ddb.h>
#endif

#include "hbsd_pax_internal.h"

static void pax_log_log(struct proc *p, struct thread *td, pax_log_settings_t flags,
    const char *prefix, const char *fmt, va_list ap);
static void pax_log_ulog(const char *prefix, const char *fmt, va_list ap);

#define PAX_LOG_FEATURES_STRING		\
		    "\020"		\
		    "\001PAGEEXEC"	\
		    "\002NOPAGEEXEC"	\
		    "\003MPROTECT"	\
		    "\004NOMPROTECT"	\
		    "\005SEGVGUARD"	\
		    "\006NOSEGVGUARD"	\
		    "\007ASLR"		\
		    "\010NOASLR"	\
		    "\011SHLIBRANDOM"	\
		    "\012NOSHLIBRANDOM"		\
		    "\013DISALLOWMAP32BIT"	\
		    "\014NODISALLOWMAP32BIT"	\
		    "\015<f12>"		\
		    "\016<f13>"		\
		    "\017<f14>"		\
		    "\020<f15>"		\
		    "\021<f16>"		\
		    "\022<f17>"		\
		    "\023<f18>"		\
		    "\024<f19>"		\
		    "\025<f20>"		\
		    "\026<f21>"		\
		    "\027<f22>"		\
		    "\030<f23>"		\
		    "\031<f24>"		\
		    "\032<f25>"		\
		    "\033<f26>"		\
		    "\034<f27>"		\
		    "\035<f28>"		\
		    "\036<f29>"		\
		    "\037<f30>"		\
		    "\040<f31>"

#define __HARDENING_LOG_TEMPLATE(MAIN, SUBJECT, prefix, name)		\
void									\
prefix##_log_##name(struct proc *p, pax_log_settings_t flags,		\
    const char* fmt, ...)						\
{									\
	const char *prefix = "["#MAIN" "#SUBJECT"]";			\
	va_list args;							\
									\
	if (hardening_log_log == 0)					\
		return;							\
									\
	va_start(args, fmt);						\
	pax_log_log(p, NULL, flags, prefix, fmt, args);			\
	va_end(args);							\
}									\
									\
void									\
prefix##_ulog_##name(const char* fmt, ...)				\
{									\
	const char *prefix = "["#MAIN" "#SUBJECT"]";			\
	va_list args;							\
									\
	if (hardening_log_ulog == 0)					\
		return;							\
									\
	va_start(args, fmt);						\
	pax_log_ulog(prefix, fmt, args);				\
	va_end(args);							\
}

static int hardening_log_log = PAX_FEATURE_SIMPLE_ENABLED;
static int hardening_log_ulog = PAX_FEATURE_SIMPLE_DISABLED;

TUNABLE_INT("hardening.log.log", &hardening_log_log);
TUNABLE_INT("hardening.log.ulog", &hardening_log_ulog);

#ifdef PAX_SYSCTLS
SYSCTL_NODE(_hardening, OID_AUTO, log, CTLFLAG_RD, 0,
    "Hardening related logging facility.");

SYSCTL_HBSD_2STATE(hardening_log_log, pr_hbsd.log.log, _hardening_log, log,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    "log to syslog ");

SYSCTL_HBSD_2STATE(hardening_log_ulog, pr_hbsd.log.ulog, _hardening_log, ulog,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    "log to syslog ");
#endif


static void
hardening_log_sysinit(void)
{
	switch (hardening_log_log) {
	case PAX_FEATURE_SIMPLE_DISABLED:
	case PAX_FEATURE_SIMPLE_ENABLED:
		break;
	default:
		printf("[HBSD LOG] WARNING, invalid settings in loader.conf!"
		    " (hardening.log.log = %d)\n", hardening_log_log);
		hardening_log_log = PAX_FEATURE_SIMPLE_ENABLED;
	}
	printf("[HBSD LOG] logging to system: %s\n",
	    pax_status_simple_str[hardening_log_log]);

	switch (hardening_log_ulog) {
	case PAX_FEATURE_SIMPLE_DISABLED:
	case PAX_FEATURE_SIMPLE_ENABLED:
		break;
	default:
		printf("[HBSD LOG] WARNING, invalid settings in loader.conf!"
		    " (hardening.log.ulog = %d)\n", hardening_log_ulog);
		hardening_log_ulog = PAX_FEATURE_SIMPLE_ENABLED;
	}
	printf("[HBSD LOG] logging to user: %s\n",
	    pax_status_simple_str[hardening_log_ulog]);
}
SYSINIT(hardening_log, SI_SUB_PAX, SI_ORDER_SECOND, hardening_log_sysinit, NULL);

void
pax_log_init_prison(struct prison *pr)
{
	struct prison *pr_p;

	CTR2(KTR_PAX, "%s: Setting prison %s PaX variables\n",
	    __func__, pr->pr_name);

	if (pr == &prison0) {
		/* prison0 has no parent, use globals */
		pr->pr_hbsd.log.log = hardening_log_log;
		pr->pr_hbsd.log.ulog = hardening_log_ulog;
	} else {
		KASSERT(pr->pr_parent != NULL,
		   ("%s: pr->pr_parent == NULL", __func__));
		pr_p = pr->pr_parent;

		pr->pr_hbsd.log.log = pr_p->pr_hbsd.log.log;
		pr->pr_hbsd.log.ulog = pr_p->pr_hbsd.log.ulog;
	}
}

static void
_pax_log_prefix(struct sbuf *sb, pax_log_settings_t flags, const char *prefix)
{

	sbuf_printf(sb, "%s ", prefix);
}

static void
_pax_log_indent(struct sbuf *sb, pax_log_settings_t flags)
{

	if ((flags & PAX_LOG_NO_INDENT) != PAX_LOG_NO_INDENT)
		sbuf_printf(sb, "\n -> ");
}

static void
_pax_log_proc_details(struct sbuf *sb, pax_log_settings_t flags, struct proc *p)
{

	if (p != NULL) {
		if ((flags & PAX_LOG_P_COMM) == PAX_LOG_P_COMM)
			sbuf_printf(sb, "p_comm: %s ", p->p_comm);

		sbuf_printf(sb, "pid: %d ", p->p_pid);
		sbuf_printf(sb, "ppid: %d ", p->p_pptr->p_pid);

		if ((flags & PAX_LOG_NO_P_PAX) != PAX_LOG_NO_P_PAX)
			sbuf_printf(sb, "p_pax: 0x%b ", p->p_pax, PAX_LOG_FEATURES_STRING);
	}
}

static void
_pax_log_thread_details(struct sbuf *sb, pax_log_settings_t flags, struct thread *td)
{

	if (td != NULL) {
		sbuf_printf(sb, "tid: %d ", td->td_tid);
	}
}

static void
_pax_log_details_end(struct sbuf *sb)
{

	sbuf_printf(sb, "\n");
}

static void
_pax_log_imgp_details(struct sbuf *sb, pax_log_settings_t flags, struct image_params *imgp)
{

	if (imgp != NULL && imgp->args != NULL)
		if (imgp->args->fname != NULL)
			sbuf_printf(sb, "fname: %s ",
			    imgp->args->fname);
}


static void
pax_log_log(struct proc *p, struct thread *td, pax_log_settings_t flags,
    const char *prefix, const char *fmt, va_list ap)
{
	struct sbuf *sb;

	sb = sbuf_new_auto();
	if (sb == NULL)
		panic("%s: Could not allocate memory", __func__);

	_pax_log_prefix(sb, flags, prefix);

	sbuf_vprintf(sb, fmt, ap);
	if ((flags & PAX_LOG_SKIP_DETAILS) != PAX_LOG_SKIP_DETAILS) {
		_pax_log_indent(sb, flags);
		_pax_log_proc_details(sb, flags, p);
		_pax_log_thread_details(sb, flags, td);
		_pax_log_details_end(sb);
	}

	if (sbuf_finish(sb) != 0)
		panic("%s: Could not generate message", __func__);

	printf("%s", sbuf_data(sb));
	sbuf_delete(sb);
}

static void
pax_log_ulog(const char *prefix, const char *fmt, va_list ap)
{
	struct sbuf *sb;

	sb = sbuf_new_auto();
	if (sb == NULL)
		panic("%s: Could not allocate memory", __func__);

	if (prefix != NULL)
		sbuf_printf(sb, "%s ", prefix);
	sbuf_vprintf(sb, fmt, ap);
	if (sbuf_finish(sb) != 0)
		panic("%s: Could not generate message", __func__);

	hbsd_uprintf("%s", sbuf_data(sb));				\
	sbuf_delete(sb);
}

void
pax_printf_flags(struct proc *p, pax_log_settings_t flags)
{

	if (p != NULL) {
		printf("pax flags: 0x%b%c", p->p_pax, PAX_LOG_FEATURES_STRING,
		    ((flags & PAX_LOG_NO_NEWLINE) == PAX_LOG_NO_NEWLINE) ?
		    ' ' : '\n');
	}
}

void
pax_printf_flags_td(struct thread *td, pax_log_settings_t flags)
{

	if (td != NULL) {
		printf("pax flags: 0x%b%c", td->td_pax, PAX_LOG_FEATURES_STRING,
		    ((flags & PAX_LOG_NO_NEWLINE) == PAX_LOG_NO_NEWLINE) ?
		    ' ' : '\n');
	}
}

#ifdef DDB
void
pax_db_printf_flags(struct proc *p, pax_log_settings_t flags)
{

	if (p != NULL) {
		db_printf(" pax flags: 0x%b%c", p->p_pax, PAX_LOG_FEATURES_STRING,
		    ((flags & PAX_LOG_NO_NEWLINE) == PAX_LOG_NO_NEWLINE) ?
		    ' ' : '\n');
	}
}

void
pax_db_printf_flags_td(struct thread *td, pax_log_settings_t flags)
{

	if (td != NULL) {
		db_printf(" pax flags: 0x%b%c", td->td_pax, PAX_LOG_FEATURES_STRING,
		    ((flags & PAX_LOG_NO_NEWLINE) == PAX_LOG_NO_NEWLINE) ?
		    ' ' : '\n');
	}
}
#endif

__HARDENING_LOG_TEMPLATE(HBSD, INTERNAL, pax, internal);
__HARDENING_LOG_TEMPLATE(HBSD, ASLR, pax, aslr);

void
pax_log_internal_imgp(struct image_params *imgp, pax_log_settings_t flags, const char* fmt, ...)
{
	const char *prefix = "[HBSD INTERNAL]";
	struct sbuf *sb;
	va_list args;

	KASSERT(imgp != NULL, ("%s: imgp == NULL", __func__));

	if (hardening_log_log == 0)
		return;

	sb = sbuf_new_auto();
	if (sb == NULL)
		panic("%s: Could not allocate memory", __func__);

	_pax_log_prefix(sb, flags, prefix);

	va_start(args, fmt);
	sbuf_vprintf(sb, fmt, args);
	va_end(args);

	if ((flags & PAX_LOG_SKIP_DETAILS) != PAX_LOG_SKIP_DETAILS) {
		_pax_log_indent(sb, flags);
		_pax_log_imgp_details(sb, flags, imgp);
		_pax_log_indent(sb, flags);
		_pax_log_proc_details(sb, flags, imgp->proc);
		_pax_log_details_end(sb);
	}

	if (sbuf_finish(sb) != 0)
		panic("%s: Could not generate message", __func__);

	printf("%s", sbuf_data(sb));
	sbuf_delete(sb);
}
