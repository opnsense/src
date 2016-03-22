/*-
 * Copyright (c) 2016, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
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

#ifndef __HBSD_PAX_INTERNAL_H
#define __HBSD_PAX_INTERNAL_H

#define SYSCTL_HBSD_2STATE(g_status, pr_status, parent, name, access, desc)	\
	static int sysctl ## parent ## _ ## name (SYSCTL_HANDLER_ARGS);	\
	SYSCTL_PROC(parent, OID_AUTO, name, access, 			\
	    NULL, 0, sysctl ## parent ## _ ## name, "I",		\
	    desc " status: "				\
	    "0 - disabled, "						\
	    "1 - enabled");						\
									\
	static int							\
	sysctl ## parent ## _ ## name (SYSCTL_HANDLER_ARGS)		\
	{								\
		struct prison *pr;					\
		int err, val;						\
									\
		pr = pax_get_prison_td(req->td);			\
									\
		val = pr->pr_status;					\
		err = sysctl_handle_int(oidp, &val, sizeof(int), req);	\
		if (err || (req->newptr == NULL))			\
			return (err);					\
									\
		switch (val) {						\
		case PAX_FEATURE_SIMPLE_DISABLED:			\
		case PAX_FEATURE_SIMPLE_ENABLED:			\
			if (pr == &prison0)				\
				g_status = val;				\
			pr->pr_status = val;				\
			break;						\
		default:						\
			return (EINVAL);				\
		}							\
									\
		return (0);						\
	}

#define SYSCTL_HBSD_4STATE(g_status, pr_status, parent, name, access)	\
	static int sysctl ## parent ## _ ## name (SYSCTL_HANDLER_ARGS);	\
	SYSCTL_PROC(parent, OID_AUTO, name, access, 			\
	    NULL, 0, sysctl ## parent ## _ ## name, "I",		\
	    "Restrictions status: "					\
	    "0 - disabled, "						\
	    "1 - opt-in,  "						\
	    "2 - opt-out, "						\
	    "3 - force enabled");					\
									\
	static int							\
	sysctl ## parent ## _ ## name (SYSCTL_HANDLER_ARGS)		\
	{								\
		struct prison *pr;					\
		int err, val;						\
									\
		pr = pax_get_prison_td(req->td);			\
									\
		val = pr->pr_status;					\
		err = sysctl_handle_int(oidp, &val, sizeof(int), req);	\
		if (err || (req->newptr == NULL))			\
			return (err);					\
									\
		switch (val) {						\
		case PAX_FEATURE_DISABLED:				\
		case PAX_FEATURE_OPTIN:					\
		case PAX_FEATURE_OPTOUT:				\
		case PAX_FEATURE_FORCE_ENABLED:				\
			if (pr == &prison0)				\
				g_status = val;				\
			pr->pr_status = val;				\
			break;						\
		default:						\
			return (EINVAL);				\
		}							\
									\
		return (0);						\
	}

#endif /* __HBSD_PAX_INTERNAL_H */
