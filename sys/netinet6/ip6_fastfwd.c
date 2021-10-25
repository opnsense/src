/*-
 * Copyright (c) 2014-2016 Andrey V. Elsukov <ae@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet6.h"
#include "opt_ipstealth.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/route/nhop.h>
#include <net/pfil.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_kdtrace.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_fib.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>

static int
ip6_findroute(struct nhop_object **pnh, const struct sockaddr_in6 *dst,
    struct mbuf *m)
{
	struct nhop_object *nh;

	nh = fib6_lookup(M_GETFIB(m), &dst->sin6_addr,
	    dst->sin6_scope_id, NHR_NONE, m->m_pkthdr.flowid);
       if (nh == NULL) {
		IP6STAT_INC(ip6s_noroute);
		IP6STAT_INC(ip6s_cantforward);
		icmp6_error(m, ICMP6_DST_UNREACH,
		    ICMP6_DST_UNREACH_NOROUTE, 0);
		return (EHOSTUNREACH);
	}
	if (nh->nh_flags & NHF_BLACKHOLE) {
		IP6STAT_INC(ip6s_cantforward);
		m_freem(m);
		return (EHOSTUNREACH);
	}

	if (nh->nh_flags & NHF_REJECT) {
		IP6STAT_INC(ip6s_cantforward);
		icmp6_error(m, ICMP6_DST_UNREACH,
		    ICMP6_DST_UNREACH_REJECT, 0);
		return (EHOSTUNREACH);
	}

	*pnh = nh;

	return (0);
}

struct mbuf*
ip6_tryforward(struct mbuf *m)
{
	struct sockaddr_in6 dst;
	struct nhop_object *nh = NULL;
	struct ip6_hdr *ip6;
	struct ifnet *rcvif, *nifp = NULL;
	uint32_t plen;
	int error, mtu = 0;

	/*
	 * Fallback conditions to ip6_input for slow path processing.
	 */
	ip6 = mtod(m, struct ip6_hdr *);
	if ((m->m_flags & (M_BCAST | M_MCAST)) != 0 ||
	    ip6->ip6_nxt == IPPROTO_HOPOPTS ||
	    IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) ||
	    IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst) ||
	    IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) ||
	    in6_localip(&ip6->ip6_dst))
		return (m);
	/*
	 * Check that the amount of data in the buffers
	 * is as at least much as the IPv6 header would have us expect.
	 * Trim mbufs if longer than we expect.
	 * Drop packet if shorter than we expect.
	 */
	rcvif = m->m_pkthdr.rcvif;
	plen = ntohs(ip6->ip6_plen);
	if (plen == 0) {
		/*
		 * Jumbograms must have hop-by-hop header and go via
		 * slow path.
		 */
		IP6STAT_INC(ip6s_badoptions);
		goto dropin;
	}
	if (m->m_pkthdr.len - sizeof(struct ip6_hdr) < plen) {
		IP6STAT_INC(ip6s_tooshort);
		in6_ifstat_inc(rcvif, ifs6_in_truncated);
		goto dropin;
	}
	if (m->m_pkthdr.len > sizeof(struct ip6_hdr) + plen) {
		if (m->m_len == m->m_pkthdr.len) {
			m->m_len = sizeof(struct ip6_hdr) + plen;
			m->m_pkthdr.len = sizeof(struct ip6_hdr) + plen;
		} else
			m_adj(m, sizeof(struct ip6_hdr) + plen -
			    m->m_pkthdr.len);
	}

	/*
	 * Hop limit.
	 */
#ifdef IPSTEALTH
	if (!V_ip6stealth)
#endif
	if (ip6->ip6_hlim <= IPV6_HLIMDEC) {
		icmp6_error(m, ICMP6_TIME_EXCEEDED,
		    ICMP6_TIME_EXCEED_TRANSIT, 0);
		m = NULL;
		goto dropin;
	}

	bzero(&dst, sizeof(dst));
	dst.sin6_family = AF_INET6;
	dst.sin6_len = sizeof(dst);
	dst.sin6_addr = ip6->ip6_dst;

	/*
	 * Incoming packet firewall processing.
	 */
	if (!PFIL_HOOKED_IN(V_inet6_pfil_head))
		goto passin;
	if (pfil_run_hooks(V_inet6_pfil_head, &m, rcvif, PFIL_IN, NULL) !=
	    PFIL_PASS)
		goto dropin;
	/*
	 * If packet filter sets the M_FASTFWD_OURS flag, this means
	 * that new destination or next hop is our local address.
	 * So, we can just go back to ip6_input.
	 * XXX: should we decrement ip6_hlim in such case?
	 */
	if (m->m_flags & M_FASTFWD_OURS)
		return (m);

	ip6 = mtod(m, struct ip6_hdr *);
	if (IP6_HAS_NEXTHOP(m) && !ip6_get_fwdtag(m, &dst, &nifp)) {
		/*
		 * Now we will find route to forwarded by pfil destination.
		 */
		ip6_flush_fwdtag(m);
	} else {
		/* Update dst since pfil could change it */
		dst.sin6_addr = ip6->ip6_dst;
	}
passin:
	/*
	 * Find route to destination.
	 */
	if (!nifp && ip6_findroute(&nh, &dst, m) != 0) {
		m = NULL;
		in6_ifstat_inc(rcvif, ifs6_in_noroute);
		goto dropin;
	}
	if (!nifp)
		nifp = nh->nh_ifp;
	mtu = IN6_LINKMTU(nifp);
	if (!PFIL_HOOKED_OUT(V_inet6_pfil_head)) {
		if (m->m_pkthdr.len > mtu) {
			in6_ifstat_inc(nifp, ifs6_in_toobig);
			icmp6_error(m, ICMP6_PACKET_TOO_BIG, 0, mtu);
			m = NULL;
			goto dropout;
		}
		goto passout;
	}

	/*
	 * Outgoing packet firewall processing.
	 */
	if (pfil_run_hooks(V_inet6_pfil_head, &m, nifp, PFIL_OUT |
	    PFIL_FWD, NULL) != PFIL_PASS)
		goto dropout;

	/*
	 * We used slow path processing for packets with scoped addresses.
	 * So, scope checks aren't needed here.
	 *
	 * XXX this one is rather strange. Shouldn't we switch nh first?
	 */
	if (m->m_pkthdr.len > mtu) {
		in6_ifstat_inc(nifp, ifs6_in_toobig);
		icmp6_error(m, ICMP6_PACKET_TOO_BIG, 0, mtu);
		m = NULL;
		goto dropout;
	}

	/*
	 * If packet filter sets the M_FASTFWD_OURS flag, this means
	 * that new destination or next hop is our local address.
	 * So, we can just go back to ip6_input.
	 */
	if (m->m_flags & M_FASTFWD_OURS) {
		/*
		 * XXX: we did one hop and should decrement hop limit. But
		 * now we are the destination and just don't pay attention.
		 */
		return (m);
	}
	/*
	 * Again. A packet filter could change the destination address.
	 */
	ip6 = mtod(m, struct ip6_hdr *);
	if (IP6_HAS_NEXTHOP(m) ||
	    !IN6_ARE_ADDR_EQUAL(&dst.sin6_addr, &ip6->ip6_dst)) {
		struct ifnet *nnifp = NULL;
		if (!ip6_get_fwdtag(m, &dst, &nnifp))
			ip6_flush_fwdtag(m);
		else
			dst.sin6_addr = ip6->ip6_dst;
		/*
		 * Redo route lookup with new destination address
		 */
		if (!nnifp && ip6_findroute(&nh, &dst, m) != 0) {
			m = NULL;
			goto dropout;
		}
		nifp = nnifp ? nnifp : nh->nh_ifp;
	}
passout:
#ifdef IPSTEALTH
	if (!V_ip6stealth)
#endif
	{
		ip6->ip6_hlim -= IPV6_HLIMDEC;
	}

	m_clrprotoflags(m);	/* Avoid confusing lower layers. */
	IP_PROBE(send, NULL, NULL, ip6, nifp, NULL, ip6);

	if (nh && nh->nh_ifp == nifp && nh->nh_flags & NHF_GATEWAY)
		dst.sin6_addr = nh->gw6_sa.sin6_addr;
	error = (*nifp->if_output)(nifp, m, (struct sockaddr *)&dst, NULL);
	if (error != 0) {
		in6_ifstat_inc(nifp, ifs6_out_discard);
		IP6STAT_INC(ip6s_cantforward);
	} else {
		in6_ifstat_inc(nifp, ifs6_out_forward);
		IP6STAT_INC(ip6s_forward);
	}
	return (NULL);
dropin:
	in6_ifstat_inc(rcvif, ifs6_in_discard);
	goto drop;
dropout:
	in6_ifstat_inc(nifp, ifs6_out_discard);
drop:
	if (m != NULL)
		m_freem(m);
	return (NULL);
}
