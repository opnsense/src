/*	$FreeBSD$	*/
/*	$KAME: if_stf.c,v 1.73 2001/12/03 11:08:30 keiichi Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 2000 WIDE Project.
 * Copyright (c) 2010 Hiroki Sato <hrs@FreeBSD.org>
 * Copyright (c) 2013 Ermal Luçi <eri@FreeBSD.org>
 * Copyright (c) 2017 Rubicon Communications, LLC (Netgate)
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * 6to4 interface, based on RFC3056 + 6rd (RFC5569) support.
 *
 * 6to4 interface is NOT capable of link-layer (I mean, IPv4) multicasting.
 * There is no address mapping defined from IPv6 multicast address to IPv4
 * address.  Therefore, we do not have IFF_MULTICAST on the interface.
 *
 * Due to the lack of address mapping for link-local addresses, we cannot
 * throw packets toward link-local addresses (fe80::x).  Also, we cannot throw
 * packets to link-local multicast addresses (ff02::x).
 *
 * Here are interesting symptoms due to the lack of link-local address:
 *
 * Unicast routing exchange:
 * - RIPng: Impossible.  Uses link-local multicast packet toward ff02::9,
 *   and link-local addresses as nexthop.
 * - OSPFv6: Impossible.  OSPFv6 assumes that there's link-local address
 *   assigned to the link, and makes use of them.  Also, HELLO packets use
 *   link-local multicast addresses (ff02::5 and ff02::6).
 * - BGP4+: Maybe.  You can only use global address as nexthop, and global
 *   address as TCP endpoint address.
 *
 * Multicast routing protocols:
 * - PIM: Hello packet cannot be used to discover adjacent PIM routers.
 *   Adjacent PIM routers must be configured manually (is it really spec-wise
 *   correct thing to do?).
 *
 * ICMPv6:
 * - Redirects cannot be used due to the lack of link-local address.
 *
 * stf interface does not have, and will not need, a link-local address.
 * It seems to have no real benefit and does not help the above symptoms much.
 * Even if we assign link-locals to interface, we cannot really
 * use link-local unicast/multicast on top of 6to4 cloud (since there's no
 * encapsulation defined for link-local address), and the above analysis does
 * not change.  RFC3056 does not mandate the assignment of link-local address
 * either.
 *
 * 6to4 interface has security issues.  Refer to
 * http://playground.iijlab.net/i-d/draft-itojun-ipv6-transition-abuse-00.txt
 * for details.  The code tries to filter out some of malicious packets.
 * Note that there is no way to be 100% secure.
 *
 * 6rd (RFC5569 & RFC5969) extension is enabled when an IPv6 GUA other than
 * 2002::/16 is assigned.  The stf(4) recognizes a 32-bit just after
 * prefixlen as the IPv4 address of the 6rd customer site.  The
 * prefixlen must be shorter than 32.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rmlock.h>
#include <sys/sysctl.h>
#include <machine/cpu.h>

#include <sys/malloc.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/route.h>
#include <net/route/nhop.h>
#include <net/netisr.h>
#include <net/if_types.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_fib.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>
#include <net/if_stf.h>

#include <netinet/ip6.h>
#include <netinet6/in6_fib.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip_ecn.h>

#include <netinet/ip_encap.h>

#include <machine/stdarg.h>

#include <net/bpf.h>

#include <security/mac/mac_framework.h>

#define	STF_DEBUG	1
#if STF_DEBUG > 3
#define	ip_sprintf(buf, a)						\
	sprintf(buf, "%u.%u.%u.%u",					\
		(ntohl((a)->s_addr)>>24)&0xFF,				\
		(ntohl((a)->s_addr)>>16)&0xFF,				\
		(ntohl((a)->s_addr)>>8)&0xFF,				\
		(ntohl((a)->s_addr))&0xFF);
#endif

#if STF_DEBUG
#define	DEBUG_PRINTF(a, ...)						\
	do {								\
		if (V_stf_debug >= a)					\
		printf(__VA_ARGS__);					\
	} while (0)
#else
#define DEBUG_PRINTF(a, ...)
#endif

SYSCTL_DECL(_net_link);
static SYSCTL_NODE(_net_link, IFT_STF, stf, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "6to4 Interface");

#if STF_DEBUG
VNET_DEFINE_STATIC(int, stf_debug) = 0;
#define	V_stf_debug	VNET(stf_debug)
SYSCTL_INT(_net_link_stf, OID_AUTO, stf_debug, CTLFLAG_VNET | CTLFLAG_RW,
    &VNET_NAME(stf_debug), 0,
    "Enable displaying debug messages of stf interfaces");
#endif

static int stf_permit_rfc1918 = 0;
SYSCTL_INT(_net_link_stf, OID_AUTO, permit_rfc1918, CTLFLAG_RWTUN,
    &stf_permit_rfc1918, 0, "Permit the use of private IPv4 addresses");

#define IN6_IS_ADDR_6TO4(x)	(ntohs((x)->s6_addr16[0]) == 0x2002)

/*
 * XXX: Return a pointer with 16-bit aligned.  Don't cast it to
 * struct in_addr *; use bcopy() instead.
 */
#define GET_V4(x)	(&(x)->s6_addr16[1])

struct stf_softc {
	struct ifnet	*sc_ifp;
	in_addr_t	inaddr;
	in_addr_t	dstv4_addr;
	in_addr_t	srcv4_addr;
	u_int	v4prefixlen;
	u_int	sc_fibnum;
	const struct encaptab *encap_cookie;
	LIST_ENTRY(stf_softc) stf_list;
};
#define STF2IFP(sc)	((sc)->sc_ifp)

static const char stfname[] = "stf";

VNET_DEFINE_STATIC(struct mtx, stf_mtx);
#define	V_stf_mtx	VNET(stf_mtx)
static MALLOC_DEFINE(M_STF, stfname, "6to4 Tunnel Interface");
VNET_DEFINE_STATIC(LIST_HEAD(, stf_softc), stf_softc_list);
#define	V_stf_softc_list	VNET(stf_softc_list)

static const int ip_stf_ttl = 40;

static int in_stf_input(struct mbuf *, int, int, void *);

static int stfmodevent(module_t, int, void *);
static int stf_encapcheck(const struct mbuf *, int, int, void *);
static int stf_getsrcifa6(struct ifnet *, struct in6_addr *, struct in6_addr *);
static int stf_output(struct ifnet *, struct mbuf *, const struct sockaddr *,
	struct route *);
static int isrfc1918addr(struct in_addr *);
static int stf_checkaddr4(struct stf_softc *, struct in_addr *,
	struct ifnet *);
static int stf_checkaddr6(struct stf_softc *, struct in6_addr *,
	struct ifnet *);
static struct sockaddr_in *stf_getin4addr_in6(struct stf_softc *,
	struct sockaddr_in *, struct in6_addr, struct in6_addr,
	struct in6_addr);
static struct sockaddr_in *stf_getin4addr(struct stf_softc *,
	struct sockaddr_in *, struct in6_addr, struct in6_addr);
static int stf_ioctl(struct ifnet *, u_long, caddr_t);

static int stf_clone_create(struct if_clone *, int, caddr_t);
static void stf_clone_destroy(struct ifnet *);
VNET_DEFINE_STATIC(struct if_clone *, stf_cloner);
#define V_stf_cloner	VNET(stf_cloner)

static const struct encap_config ipv4_encap_cfg = {
	.proto = IPPROTO_IPV6,
	.min_length = sizeof(struct ip),
	.exact_match = (sizeof(in_addr_t) << 3) + 8,
	.check = stf_encapcheck,
	.input = in_stf_input
};

static int
stf_clone_create(struct if_clone *ifc, int unit, caddr_t params)
{
	struct stf_softc *sc;
	struct ifnet *ifp;

	sc = malloc(sizeof(struct stf_softc), M_STF, M_WAITOK | M_ZERO);
	ifp = STF2IFP(sc) = if_alloc(IFT_STF);
	if (ifp == NULL) {
		free(sc, M_STF);
		return (ENOSPC);
	}
	ifp->if_softc = sc;
	sc->sc_fibnum = curthread->td_proc->p_fibnum;
	if_initname(ifp, stfname, unit);

	sc->encap_cookie = ip_encap_attach(&ipv4_encap_cfg, sc, M_WAITOK);
	if (sc->encap_cookie == NULL) {
		if_printf(ifp, "attach failed\n");
		if_free(ifp);
		free(sc, M_STF);
		return (ENOMEM);
	}

	ifp->if_mtu    = IPV6_MMTU;
	ifp->if_ioctl  = stf_ioctl;
	ifp->if_output = stf_output;
	ifp->if_snd.ifq_maxlen = ifqmaxlen;
	if_attach(ifp);
	bpfattach(ifp, DLT_NULL, sizeof(u_int32_t));

	mtx_lock(&V_stf_mtx);
	LIST_INSERT_HEAD(&V_stf_softc_list, sc, stf_list);
	mtx_unlock(&V_stf_mtx);

	return (0);
}

static void
stf_clone_destroy(struct ifnet *ifp)
{
	struct stf_softc *sc = ifp->if_softc;
	int err __unused;

	mtx_lock(&V_stf_mtx);
	LIST_REMOVE(sc, stf_list);
	mtx_unlock(&V_stf_mtx);

	err = ip_encap_detach(sc->encap_cookie);
	KASSERT(err == 0, ("Unexpected error detaching encap_cookie"));
	bpfdetach(ifp);
	if_detach(ifp);
	if_free(ifp);

	free(sc, M_STF);
}

static void
vnet_stf_init(const void *unused __unused)
{
	mtx_init(&V_stf_mtx, "stf_mtx", NULL, MTX_DEF);
	V_stf_cloner = if_clone_simple(stfname, stf_clone_create,
	    stf_clone_destroy, 0);
}
VNET_SYSINIT(vnet_stf_init, SI_SUB_PSEUDO, SI_ORDER_ANY, vnet_stf_init, NULL);

static void
vnet_stf_uninit(const void *unused __unused)
{
	if_clone_detach(V_stf_cloner);
	V_stf_cloner = NULL;
	mtx_destroy(&V_stf_mtx);
}
VNET_SYSUNINIT(vnet_stf_uninit, SI_SUB_PSEUDO, SI_ORDER_ANY, vnet_stf_uninit,
    NULL);

static int
stfmodevent(module_t mod, int type, void *data)
{

	switch (type) {
	case MOD_LOAD:
		/* Done in vnet_stf_init() */
		break;
	case MOD_UNLOAD:
		/* Done in vnet_stf_uninit() */
		break;
	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t stf_mod = {
	"if_stf",
	stfmodevent,
	0
};

DECLARE_MODULE(if_stf, stf_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(if_stf, 1);

static int
stf_encapcheck(const struct mbuf *m, int off, int proto, void *arg)
{
	struct ip ip;
	struct stf_softc *sc;
	struct in6_addr addr6, mask6;
	struct sockaddr_in sin4addr, sin4mask;

	DEBUG_PRINTF(1, "%s: enter\n", __func__);
	sc = (struct stf_softc *)arg;
	if (sc == NULL)
		return (0);

	if ((STF2IFP(sc)->if_flags & IFF_UP) == 0)
		return (0);

	/* IFF_LINK0 means "no decapsulation" */
	if ((STF2IFP(sc)->if_flags & IFF_LINK0) != 0)
		return (0);

	if (proto != IPPROTO_IPV6)
		return (0);

	m_copydata(m, 0, sizeof(ip), (caddr_t)&ip);

	if (ip.ip_v != 4)
		return (0);

	if (stf_getsrcifa6(STF2IFP(sc), &addr6, &mask6) != 0)
		return (0);

	if (sc->srcv4_addr != INADDR_ANY) {
		sin4addr.sin_addr.s_addr = sc->srcv4_addr;
		sin4addr.sin_family = AF_INET;
	} else
		if (stf_getin4addr(sc, &sin4addr, addr6, mask6) == NULL)
			return (0);

#if STF_DEBUG > 3
	{
		char buf[INET6_ADDRSTRLEN + 1];
		memset(&buf, 0, sizeof(buf));

		ip6_sprintf(buf, &addr6);
		DEBUG_PRINTF(1, "%s: addr6 = %s\n", __func__, buf);
		ip6_sprintf(buf, &mask6);
		DEBUG_PRINTF(1, "%s: mask6 = %s\n", __func__, buf);

		ip_sprintf(buf, &sin4addr.sin_addr);
		DEBUG_PRINTF(1, "%s: sin4addr.sin_addr = %s\n", __func__, buf);
		ip_sprintf(buf, &ip.ip_src);
		DEBUG_PRINTF(1, "%s: ip.ip_src = %s\n", __func__, buf);
		ip_sprintf(buf, &ip.ip_dst);
		DEBUG_PRINTF(1, "%s: ip.ip_dst = %s\n", __func__, buf);
	}
#endif

	/*
	 * check if IPv4 dst matches the IPv4 address derived from the
	 * local 6to4 address.
	 * success on: dst = 10.1.1.1, ia6->ia_addr = 2002:0a01:0101:...
	 */
	if (sin4addr.sin_addr.s_addr != ip.ip_dst.s_addr) {
		DEBUG_PRINTF(1,
		    "%s: IPv4 dst address do not match the encoded address.  "
		    "Ignore this packet.\n", __func__);
		return (0);
	}

	if (IN6_IS_ADDR_6TO4(&addr6)) {
		/*
		 * 6to4 (RFC 3056).
		 * Check if IPv4 src matches the IPv4 address derived
		 * from the local 6to4 address masked by prefixmask.
		 * success on: src = 10.1.1.1, ia6->ia_addr = 2002:0a00:.../24
		 * fail on: src = 10.1.1.1, ia6->ia_addr = 2002:0b00:.../24
		 */

		memcpy(&sin4mask.sin_addr, GET_V4(&mask6), sizeof(sin4mask.sin_addr));
#if STF_DEBUG > 3
		{
			char buf[INET6_ADDRSTRLEN + 1];
			memset(&buf, 0, sizeof(buf));

			ip_sprintf(buf, &sin4addr.sin_addr);
			DEBUG_PRINTF(1, "%s: sin4addr = %s\n",
			    __func__, buf);
			ip_sprintf(buf, &ip.ip_src);
			DEBUG_PRINTF(1, "%s: ip.ip_src = %s\n",
			    __func__, buf);
			ip_sprintf(buf, &sin4mask.sin_addr);
			DEBUG_PRINTF(1, "%s: sin4mask = %s\n",
			    __func__, buf);
		}
#endif

		if ((sin4addr.sin_addr.s_addr & sin4mask.sin_addr.s_addr) !=
		    (ip.ip_src.s_addr & sin4mask.sin_addr.s_addr)) {
			DEBUG_PRINTF(1,
			    "%s: v4 address do not match expected address.  "
			    "Ignore this packet.\n", __func__);
			return (0);
		}
	} else {
		/* 6rd (RFC 5569) */
		/*
		 * No restriction on the src address in the case of
		 * 6rd because the stf(4) interface always has a
		 * prefix which covers whole of IPv4 src address
		 * range.  So, stf_output() will catch all of
		 * 6rd-capsuled IPv4 traffic with suspicious inner dst
		 * IPv4 address (i.e. the IPv6 destination address is
		 * one the admin does not like to route to outside),
		 * and then it discard them silently.
		 */
	}

	/* stf interface makes single side match only */
	return (32);
}

static int
stf_getsrcifa6(struct ifnet *ifp, struct in6_addr *addr, struct in6_addr *mask)
{
	struct rm_priotracker in_ifa_tracker;
	struct ifaddr *ia;
	struct in_ifaddr *ia4;
	struct in6_addr addr6, mask6;
	struct in6_ifaddr *ia6;
	struct sockaddr_in sin4;
	struct stf_softc *sc;
	struct in_addr in;

	NET_EPOCH_ASSERT();

	sc = ifp->if_softc;

	CK_STAILQ_FOREACH(ia, &ifp->if_addrhead, ifa_link) {
		if (ia->ifa_addr->sa_family != AF_INET6)
			continue;
		ia6 = (struct in6_ifaddr *)ia;
		*&addr6 = ((struct sockaddr_in6 *)ia->ifa_addr)->sin6_addr;
		*&mask6 = ia6->ia_prefixmask.sin6_addr;
		if (sc->srcv4_addr != INADDR_ANY)
			bcopy(&sc->srcv4_addr, &in, sizeof(in));
		else {
			if (stf_getin4addr(sc, &sin4, addr6, mask6) == NULL)
				continue;
			bcopy(&sin4.sin_addr, &in, sizeof(in));
		}

		IN_IFADDR_RLOCK(&in_ifa_tracker);
		LIST_FOREACH(ia4, INADDR_HASH(in.s_addr), ia_hash)
			if (ia4->ia_addr.sin_addr.s_addr == in.s_addr)
				break;
		IN_IFADDR_RUNLOCK(&in_ifa_tracker);
		if (ia4 == NULL)
			continue;

#if STF_DEBUG > 3
	{
		char buf[INET6_ADDRSTRLEN + 1];
		memset(&buf, 0, sizeof(buf));

		ip6_sprintf(buf, &((struct sockaddr_in6 *)ia->ifa_addr)->sin6_addr);
		DEBUG_PRINTF(1, "%s: ia->ifa_addr->sin6_addr = %s\n",
			__func__, buf);
		ip_sprintf(buf, &ia4->ia_addr.sin_addr);
		DEBUG_PRINTF(1, "%s: ia4->ia_addr.sin_addr = %s\n",
		    __func__, buf);
	}
#endif

		*addr = addr6;
		*mask = mask6;
		return (0);
	}

	return (ENOENT);
}

static int
stf_output(struct ifnet *ifp, struct mbuf *m, const struct sockaddr *dst,
    struct route *ro)
{
	struct stf_softc *sc;
	const struct sockaddr_in6 *dst6;
	struct sockaddr_in dst4, src4;
	u_int8_t tos;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct in6_addr addr6, mask6;
	int error;

#ifdef MAC
	error = mac_ifnet_check_transmit(ifp, m);
	if (error) {
		m_freem(m);
		return (error);
	}
#endif

	sc = ifp->if_softc;
	dst6 = (const struct sockaddr_in6 *)dst;

	/* just in case */
	if ((ifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		return (ENETDOWN);
	}

	/*
	 * If we don't have an ip4 address that match my inner ip6 address,
	 * we shouldn't generate output.  Without this check, we'll end up
	 * using wrong IPv4 source.
	 */
	if (stf_getsrcifa6(ifp, &addr6, &mask6) != 0) {
		m_freem(m);
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		return (ENETDOWN);
	}

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m) {
			if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
			return (ENOBUFS);
		}
	}
	ip6 = mtod(m, struct ip6_hdr *);
	tos = IPV6_TRAFFIC_CLASS(ip6);

	/*
	 * Pickup the right outer dst addr from the list of candidates.
	 * ip6_dst has priority as it may be able to give us shorter IPv4 hops.
	 */
	DEBUG_PRINTF(1, "%s: dst addr selection\n", __func__);
	if (stf_getin4addr_in6(sc, &dst4, addr6, mask6,
	    ip6->ip6_dst) == NULL) {
		if (sc->dstv4_addr != INADDR_ANY)
			dst4.sin_addr.s_addr = sc->dstv4_addr;
		else if (stf_getin4addr_in6(sc, &dst4, addr6, mask6,
		    dst6->sin6_addr) == NULL) {
			m_freem(m);
			if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
			return (ENETUNREACH);
		}
	}
#if STF_DEBUG > 3
	{
		char buf[INET6_ADDRSTRLEN + 1];
		memset(&buf, 0, sizeof(buf));

		ip_sprintf(buf, &dst4.sin_addr);
		DEBUG_PRINTF(1, "%s: ip_dst = %s\n", __func__, buf);
	}
#endif
	if (bpf_peers_present(ifp->if_bpf)) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer a to it).
		 */
		u_int af = AF_INET6;
		bpf_mtap2(ifp->if_bpf, &af, sizeof(af), m);
	}

	M_PREPEND(m, sizeof(struct ip), M_NOWAIT);
	if (m == NULL) {
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		return (ENOBUFS);
	}
	ip = mtod(m, struct ip *);

	bzero(ip, sizeof(*ip));

	if (sc->srcv4_addr != INADDR_ANY)
		src4.sin_addr.s_addr = sc->srcv4_addr;
	else if (stf_getin4addr(sc, &src4, addr6, mask6) == NULL) {
		m_freem(m);
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		return (ENETUNREACH);
	}
	bcopy(&src4.sin_addr, &ip->ip_src, sizeof(ip->ip_src));
#if STF_DEBUG > 3
	{
		char buf[INET6_ADDRSTRLEN + 1];
		memset(&buf, 0, sizeof(buf));

		ip_sprintf(buf, &ip->ip_src);
		DEBUG_PRINTF(1, "%s: ip_src = %s\n", __func__, buf);
	}
#endif
	bcopy(&dst4.sin_addr, &ip->ip_dst, sizeof(ip->ip_dst));
	ip->ip_p = IPPROTO_IPV6;
	ip->ip_ttl = ip_stf_ttl;
	ip->ip_len = htons(m->m_pkthdr.len);
	if (ifp->if_flags & IFF_LINK1)
		ip_ecn_ingress(ECN_ALLOWED, &ip->ip_tos, &tos);
	else
		ip_ecn_ingress(ECN_NOCARE, &ip->ip_tos, &tos);

	M_SETFIB(m, sc->sc_fibnum);
	if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
	error = ip_output(m, NULL, NULL, 0, NULL, NULL);

	return (error);
}

static int
isrfc1918addr(struct in_addr *in)
{
	/*
	 * returns 1 if private address range:
	 * 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
	 */
	if (stf_permit_rfc1918 == 0 && (
	    (ntohl(in->s_addr) & 0xff000000) >> 24 == 10 ||
	    (ntohl(in->s_addr) & 0xfff00000) >> 16 == 172 * 256 + 16 ||
	    (ntohl(in->s_addr) & 0xffff0000) >> 16 == 192 * 256 + 168))
		return (1);

	return (0);
}

static int
stf_checkaddr4(struct stf_softc *sc, struct in_addr *in, struct ifnet *inifp)
{
	struct rm_priotracker in_ifa_tracker;
	struct in_ifaddr *ia4;

	/*
	 * reject packets with the following address:
	 * 224.0.0.0/4 0.0.0.0/8 127.0.0.0/8 255.0.0.0/8
	 */
	if (IN_MULTICAST(ntohl(in->s_addr)))
		return (-1);
	switch ((ntohl(in->s_addr) & 0xff000000) >> 24) {
	case 0: case 127: case 255:
		return (-1);
	}

	/*
	 * reject packets with broadcast
	 */
	IN_IFADDR_RLOCK(&in_ifa_tracker);
	CK_STAILQ_FOREACH(ia4, &V_in_ifaddrhead, ia_link) {
		if ((ia4->ia_ifa.ifa_ifp->if_flags & IFF_BROADCAST) == 0)
			continue;
		if (in->s_addr == ia4->ia_broadaddr.sin_addr.s_addr) {
			IN_IFADDR_RUNLOCK(&in_ifa_tracker);
			return (-1);
		}
	}
	IN_IFADDR_RUNLOCK(&in_ifa_tracker);

	/*
	 * perform ingress filter
	 */
	if (sc && (STF2IFP(sc)->if_flags & IFF_LINK2) == 0 && inifp) {
		struct nhop_object *nh;

		NET_EPOCH_ASSERT();
		nh = fib4_lookup(sc->sc_fibnum, *in, 0, 0, 0);
		if (nh == NULL)
			return (-1);

		if (nh->nh_ifp != inifp)
			return (-1);
	}

	return (0);
}

static int
stf_checkaddr6(struct stf_softc *sc, struct in6_addr *in6, struct ifnet *inifp)
{
	/*
	 * check 6to4 addresses
	 */
	if (IN6_IS_ADDR_6TO4(in6)) {
		struct in_addr in4;
		bcopy(GET_V4(in6), &in4, sizeof(in4));
		return (stf_checkaddr4(sc, &in4, inifp));
	}

	/*
	 * reject anything that look suspicious.  the test is implemented
	 * in ip6_input too, but we check here as well to
	 * (1) reject bad packets earlier, and
	 * (2) to be safe against future ip6_input change.
	 */
	if (IN6_IS_ADDR_V4COMPAT(in6) || IN6_IS_ADDR_V4MAPPED(in6))
		return (-1);

	return (0);
}

static int
in_stf_input(struct mbuf *m, int off, int proto, void *arg)
{
	struct stf_softc *sc = arg;
	struct ip *ip;
	struct ip6_hdr *ip6;
	u_int8_t otos, itos;
	struct ifnet *ifp;
	struct nhop_object *nh;

	NET_EPOCH_ASSERT();

	if (proto != IPPROTO_IPV6) {
		m_freem(m);
		return (IPPROTO_DONE);
	}

	ip = mtod(m, struct ip *);
	if (sc == NULL || (STF2IFP(sc)->if_flags & IFF_UP) == 0) {
		m_freem(m);
		return (IPPROTO_DONE);
	}

	ifp = STF2IFP(sc);

#ifdef MAC
	mac_ifnet_create_mbuf(ifp, m);
#endif

#if STF_DEBUG > 3
	{
		char buf[INET6_ADDRSTRLEN + 1];
		memset(&buf, 0, sizeof(buf));

		ip_sprintf(buf, &ip->ip_dst);
		DEBUG_PRINTF(1, "%s: ip->ip_dst = %s\n", __func__, buf);
		ip_sprintf(buf, &ip->ip_src);
		DEBUG_PRINTF(1, "%s: ip->ip_src = %s\n", __func__, buf);
	}
#endif
	/*
	 * perform sanity check against outer src/dst.
	 * for source, perform ingress filter as well.
	 */
	if (stf_checkaddr4(sc, &ip->ip_dst, NULL) < 0 ||
	    stf_checkaddr4(sc, &ip->ip_src, m->m_pkthdr.rcvif) < 0) {
		m_freem(m);
		return (IPPROTO_DONE);
	}

	otos = ip->ip_tos;
	m_adj(m, off);

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m)
			return (IPPROTO_DONE);
	}
	ip6 = mtod(m, struct ip6_hdr *);

#if STF_DEBUG > 3
	{
		char buf[INET6_ADDRSTRLEN + 1];
		memset(&buf, 0, sizeof(buf));

		ip6_sprintf(buf, &ip6->ip6_dst);
		DEBUG_PRINTF(1, "%s: ip6->ip6_dst = %s\n", __func__, buf);
		ip6_sprintf(buf, &ip6->ip6_src);
		DEBUG_PRINTF(1, "%s: ip6->ip6_src = %s\n", __func__, buf);
	}
#endif
	/*
	 * perform sanity check against inner src/dst.
	 * for source, perform ingress filter as well.
	 */
	if (stf_checkaddr6(sc, &ip6->ip6_dst, NULL) < 0 ||
	    stf_checkaddr6(sc, &ip6->ip6_src, m->m_pkthdr.rcvif) < 0) {
		m_freem(m);
		return (IPPROTO_DONE);
	}

	/*
	 * reject packets with private address range.
	 * (requirement from RFC3056 section 2 1st paragraph)
	 */
	if ((IN6_IS_ADDR_6TO4(&ip6->ip6_src) && isrfc1918addr(&ip->ip_src)) ||
	    (IN6_IS_ADDR_6TO4(&ip6->ip6_dst) && isrfc1918addr(&ip->ip_dst))) {
		m_freem(m);
		return (IPPROTO_DONE);
	}

	/*
	 * Ignore if the destination is the same stf interface because
	 * all of valid IPv6 outgoing traffic should go interfaces
	 * except for it.
	 */
	if ((nh = fib6_lookup(sc->sc_fibnum, &ip6->ip6_dst, 0, 0, 0)) == NULL) {
		DEBUG_PRINTF(1, "%s: no IPv6 dst.  Ignored.\n", __func__);
		m_free(m);
		return (IPPROTO_DONE);
	}
	if (nh->nh_ifp == ifp && nh->nh_flags & NHF_GATEWAY &&
	    !IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, &nh->gw6_sa.sin6_addr)) {
		DEBUG_PRINTF(1, "%s: IPv6 dst is the same stf.  Ignored.\n",
		    __func__);
		m_free(m);
		return (IPPROTO_DONE);
	}

	itos = IPV6_TRAFFIC_CLASS(ip6);
	if ((ifp->if_flags & IFF_LINK1) != 0)
		ip_ecn_egress(ECN_ALLOWED, &otos, &itos);
	else
		ip_ecn_egress(ECN_NOCARE, &otos, &itos);
	ip6->ip6_flow &= ~htonl(0xff << 20);
	ip6->ip6_flow |= htonl((u_int32_t)itos << 20);

	m->m_pkthdr.rcvif = ifp;

	if (bpf_peers_present(ifp->if_bpf)) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer a to it).
		 */
		u_int32_t af = AF_INET6;
		bpf_mtap2(ifp->if_bpf, &af, sizeof(af), m);
	}

	DEBUG_PRINTF(1, "%s: netisr_dispatch(NETISR_IPV6)\n", __func__);
	/*
	 * Put the packet to the network layer input queue according to the
	 * specified address family.
	 * See net/if_gif.c for possible issues with packet processing
	 * reorder due to extra queueing.
	 */
	if_inc_counter(ifp, IFCOUNTER_IPACKETS, 1);
	if_inc_counter(ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);
	M_SETFIB(m, ifp->if_fib);
	netisr_dispatch(NETISR_IPV6, m);
	return (IPPROTO_DONE);
}

static struct sockaddr_in *
stf_getin4addr_in6(struct stf_softc *sc, struct sockaddr_in *sin,
    struct in6_addr addr6, struct in6_addr mask6, struct in6_addr in6)
{
	int i;

#if STF_DEBUG > 3
	{
		char buf[INET6_ADDRSTRLEN + 1];
		memset(&buf, 0, sizeof(buf));

		ip6_sprintf(buf, &in6);
		DEBUG_PRINTF(1, "%s: in6 = %s\n", __func__, buf);
		ip6_sprintf(buf, &addr6);
		DEBUG_PRINTF(1, "%s: addr6 = %s\n", __func__, buf);
		ip6_sprintf(buf, &mask6);
		DEBUG_PRINTF(1, "%s: mask6 = %s\n", __func__, buf);
	}
#endif

	/*
	 * When (src addr & src mask) != (in6 & src mask),
	 * the dst is not in the 6rd domain.  The IPv4 address must
	 * not be used.
	 */
	for (i = 0; i < sizeof(addr6); i++) {
		if ((((u_char *)&addr6)[i] & ((u_char *)&mask6)[i]) !=
		    (((u_char *)&in6)[i] & ((u_char *)&mask6)[i]))
			return (NULL);
	}

	/* After the mask check, use in6 instead of addr6. */
	return (stf_getin4addr(sc, sin, in6, mask6));
}

static struct sockaddr_in *
stf_getin4addr(struct stf_softc *sc, struct sockaddr_in *sin,
    struct in6_addr addr6, struct in6_addr mask6)
{
	struct in_addr *in;

	DEBUG_PRINTF(1, "%s: enter.\n", __func__);
#if STF_DEBUG > 3
	{
		char tmpbuf[INET6_ADDRSTRLEN + 1];
		memset(&tmpbuf, 0, INET6_ADDRSTRLEN);

		ip6_sprintf(tmpbuf, &addr6);
		DEBUG_PRINTF(1, "%s: addr6 = %s\n", __func__, tmpbuf);
	}
#endif
	memset(sin, 0, sizeof(*sin));
	in = &sin->sin_addr;
	if (IN6_IS_ADDR_6TO4(&addr6)) {
		/* 6to4 (RFC 3056) */
		bcopy(GET_V4(&addr6), in, sizeof(*in));
		if (isrfc1918addr(in))
			return (NULL);
	} else {
		/* 6rd (RFC 5569) */
		struct in6_addr buf;
		u_char *p = (u_char *)&buf;
		u_char *q = (u_char *)&in->s_addr;
		u_int residue = 0, v4residue = 0;
		u_char mask, v4mask = 0;
		int i, j;
		u_int plen, loop;

		/*
		 * 6rd-relays IPv6 prefix is located at a 32-bit just
		 * after the prefix edge.
		 */
		plen = in6_mask2len(&mask6, NULL);
		if (64 < plen) {
			DEBUG_PRINTF(1, "prefixlen is %d\n", plen);
			return (NULL);
		}

		loop = 4;	/* Normal 6rd operation */
		memcpy(&buf, &addr6, sizeof(buf));
		if (sc->v4prefixlen != 0 && sc->v4prefixlen != 32)
			v4residue = sc->v4prefixlen % 8;
		p += plen / 8;
		//plen -= 32;

		residue = plen % 8;
		mask = ((u_char)(-1) >> (8 - residue));
		if (v4residue) {
			loop++;
			v4mask = ((u_char)(-1) << v4residue);
		}
		/*
		 * The p points head of the IPv4 address part in
		 * bytes.  The residue is a bit-shift factor when
		 * prefixlen is not a multiple of 8.
		 */
		DEBUG_PRINTF(2, "residue = %d 0x%x\n", residue, mask);
		for (j = (loop - (sc->v4prefixlen / 8)),
		     i = (loop - (sc->v4prefixlen / 8));
		     i < loop; j++, i++) {
			if (residue) {
				q[i] = ((p[j] & mask) << (8 - residue));
				q[i] |=  ((p[j + 1] >> residue) & mask);
				DEBUG_PRINTF(2,
				    "FINAL i = %d  q[%d] - p[%d/%d] %x\n",
				    i, q[i], p[j], p[j + 1] >> residue, q[i]);
			} else {
				q[i] = p[j];
				DEBUG_PRINTF(2,
				    "FINAL i = %d q[%d] - p[%d] %x\n",
				    i, q[i], p[j], q[i]);
			}
		}
		if (v4residue)
		 	q[loop - (sc->v4prefixlen / 8)] &= v4mask;

		if (sc->v4prefixlen > 0 && sc->v4prefixlen < 32)
			in->s_addr |= sc->inaddr &
			    ((uint32_t)(-1) >> (32 - sc->v4prefixlen));
	}

#if STF_DEBUG > 3
	{
		char tmpbuf[INET6_ADDRSTRLEN + 1];
		memset(&tmpbuf, 0, INET_ADDRSTRLEN);

		ip_sprintf(tmpbuf, in);
		DEBUG_PRINTF(1, "%s: in->in_addr = %s\n", __func__, tmpbuf);
	}
#endif

	return (sin);
}

static int
stf_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifaddr *ifa;
	struct ifdrv *ifd;
	struct ifreq *ifr;
	struct sockaddr_in sin4;
	struct stf_softc *sc, *sc_cur;
	struct stfv4args args;
	struct in6_addr addr6, mask6;
	int error, mtu;

	error = 0;
	sc_cur = ifp->if_softc;

	switch (cmd) {
	case SIOCSDRVSPEC:
		ifd = (struct ifdrv *)data;
		error = priv_check(curthread, PRIV_NET_ADDIFADDR);
		if (error)
			break;
		if (ifd->ifd_cmd == STF_SV4NET) {
			if (ifd->ifd_len != sizeof(args)) {
				error = EINVAL;
				break;
			}
			mtx_lock(&V_stf_mtx);
			LIST_FOREACH(sc, &V_stf_softc_list, stf_list) {
				if (sc == sc_cur)
					continue;
				if (sc->inaddr == 0 || sc->v4prefixlen == 0)
					continue;

				if ((ntohl(sc->inaddr) &
				    ((uint32_t)(-1) << sc_cur->v4prefixlen)) ==
				    ntohl(sc_cur->inaddr)) {
					error = EEXIST;
					mtx_unlock(&V_stf_mtx);
					return (error);
				}
				if ((ntohl(sc_cur->inaddr) &
				    ((uint32_t)(-1) << sc->v4prefixlen)) ==
				    ntohl(sc->inaddr)) {
					error = EEXIST;
					mtx_unlock(&V_stf_mtx);
					return (error);
				}
			}
			mtx_unlock(&V_stf_mtx);
			bzero(&args, sizeof args);
			error = copyin(ifd->ifd_data, &args, ifd->ifd_len);
			if (error)
				break;

			sc_cur->srcv4_addr = args.inaddr.s_addr;
			sc_cur->inaddr = ntohl(args.inaddr.s_addr);
			sc_cur->inaddr &= ((uint32_t)(-1) << args.prefix);
			sc_cur->inaddr = htonl(sc_cur->inaddr);
			sc_cur->v4prefixlen = args.prefix;
		} else if (ifd->ifd_cmd == STF_SDSTV4) {
			if (ifd->ifd_len != sizeof(args)) {
				error = EINVAL;
				break;
			}
			bzero(&args, sizeof args);
			error = copyin(ifd->ifd_data, &args, ifd->ifd_len);
			if (error)
				break;
			sc_cur->dstv4_addr = args.dstv4_addr.s_addr;
		} else
			error = EINVAL;
		break;
	case SIOCGDRVSPEC:
		ifd = (struct ifdrv *)data;
		if (ifd->ifd_len != sizeof(args)) {
			error = EINVAL;
			break;
		}
		if (ifd->ifd_cmd != STF_GV4NET) {
			error = EINVAL;
			break;
		}
		bzero(&args, sizeof args);
		args.inaddr.s_addr = sc_cur->srcv4_addr;
		args.dstv4_addr.s_addr = sc_cur->dstv4_addr;
		args.prefix = sc_cur->v4prefixlen;
		error = copyout(&args, ifd->ifd_data, ifd->ifd_len);
		break;
	case SIOCSIFADDR:
		ifa = (struct ifaddr *)data;
		if (ifa == NULL || ifa->ifa_addr->sa_family != AF_INET6) {
			error = EAFNOSUPPORT;
			break;
		}
		if (stf_getin4addr(sc_cur, &sin4,
		    satosin6(ifa->ifa_addr)->sin6_addr,
		    satosin6(ifa->ifa_netmask)->sin6_addr) == NULL) {
			error = EINVAL;
			break;
		}
		/*
		 * Sanity check: if more than two interfaces have IFF_UP, do
		 * if_down() for all of them except for the specified one.
		 */
		mtx_lock(&V_stf_mtx);
		LIST_FOREACH(sc, &V_stf_softc_list, stf_list) {
			if (sc == sc_cur)
				continue;
			if (stf_getsrcifa6(ifp, &addr6, &mask6) != 0)
				continue;
			if (IN6_ARE_ADDR_EQUAL(&addr6,
			    &ifatoia6(ifa)->ia_addr.sin6_addr)) {
				error = EEXIST;
				break;
			}
		}
		mtx_unlock(&V_stf_mtx);

		ifp->if_flags |= IFF_UP;
		ifp->if_drv_flags |= IFF_DRV_RUNNING;
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		ifr = (struct ifreq *)data;
		if (ifr && ifr->ifr_addr.sa_family == AF_INET6)
			;
		else
			error = EAFNOSUPPORT;
		break;

	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP)
			ifp->if_drv_flags |= IFF_DRV_RUNNING;
		else
			ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
		break;

	case SIOCGIFMTU:
		break;

	case SIOCSIFMTU:
		ifr = (struct ifreq *)data;
		mtu = ifr->ifr_mtu;
		/* RFC 4213 3.2 ideal world MTU */
		if (mtu < IPV6_MINMTU || mtu > IF_MAXMTU - 20)
			return (EINVAL);
		ifp->if_mtu = mtu;
		break;

	default:
		error = EINVAL;
		break;
	}

	return (error);
}
