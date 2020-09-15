/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2020 Giuseppe Lettieri. All rights reserved.
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
 */

/*
 * $FreeBSD$
 *
 * netmap support for: tun
 *
 * The actual support comes from the netmap generic driver. The purpose of these
 * functions is to make the tun device similar to an ethernet device, just enough
 * for the generic driver to work with it.
 *
 * Two adjustments are needed:
 *
 * - In tunwrite(), when in netmap mode, we prepend a fake ethernet header that contains the family
 * (AF_INET or AF_INET6) and then call the (overriden) if_input method;
 *
 * - We also provide the if_input method called by netmap when trying to inject packets
 *   into the host stack
 */

#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <net/ethernet.h>
#include <dev/netmap/netmap_kern.h>

static void
netmap_tuninput(struct ifnet *ifp, struct mbuf *m)
{
	struct ether_header *eh;
	u_short etype;
	int isr;

	if (m->m_len < ETHER_HDR_LEN) {
		nm_prlim(5, "discarding malformed mbuf (m->m_len == %d)", m->m_len);
		goto error;
	}
	eh = mtod(m, struct ether_header *);
	etype = ntohs(eh->ether_type);
	switch (etype) {
	case ETHERTYPE_IP:
		isr = NETISR_IP;
		break;
	case ETHERTYPE_IPV6:
		isr = NETISR_IPV6;
		break;
	default:
		nm_prlim(5, "discarding packet with ethertype %02x", etype);
		goto error;
	}
	m_adj(m, ETHER_HDR_LEN);
	if_inc_counter(ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);
	if_inc_counter(ifp, IFCOUNTER_IPACKETS, 1);
	m->m_pkthdr.rcvif = ifp;
	CURVNET_SET(ifp->if_vnet);
	M_SETFIB(m, ifp->if_fib);
	netisr_dispatch(isr, m);
	CURVNET_RESTORE();

	return;

error:
	if_inc_counter(ifp, IFCOUNTER_IERRORS, 1);
	m_free(m);
	return;
}

static int
netmap_tuncapture(struct ifnet *ifp, int isr, struct mbuf *m)
{
	struct netmap_adapter *na = NA(ifp);
	struct ether_header *eh;

	if (!nm_netmap_on(na))
		return 0;

	M_PREPEND(m, ETHER_HDR_LEN, M_NOWAIT);
	if (m == NULL) {
		nm_prlim(5, "failed to prepend fake ethernet header, skipping");
		return 0;
	}
	eh = mtod(m, struct ether_header *);
	eh->ether_type = htons(isr == AF_INET6 ? ETHERTYPE_IPV6 : ETHERTYPE_IP);
	memcpy(eh->ether_shost, "\x02\x02\x02\x02\x02\x02", ETHER_ADDR_LEN);
	memcpy(eh->ether_dhost, "\x06\x06\x06\x06\x06\x06", ETHER_ADDR_LEN);
	(*ifp->if_input)(ifp, m);
	return 1; /* stolen */
}

/* end of file */
