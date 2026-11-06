/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * CAKE - Common Applications Kept Enhanced, for dummynet
 *
 * Copyright (c) 2026 Tim Pletcher
 *
 * Derived in part from the Linux sch_cake qdisc (net/sched/sch_cake.c),
 * used under the BSD-3-Clause option of its GPL-2.0 OR BSD-3-Clause
 * license:
 * Copyright (C) 2014-2018 Jonathan Morton <chromatix99@gmail.com>
 * Copyright (C) 2015-2018 Toke Hoiland-Jorgensen <toke@toke.dk>
 * Copyright (C) 2014-2018 Dave Taht <dave.taht@gmail.com>
 * Copyright (C) 2015-2018 Sebastian Moeller <moeller0@gmx.de>
 * (C) 2015-2018 Kevin Darbyshire-Bryant <kevin@darbyshire-bryant.me.uk>
 * Copyright (C) 2017-2018 Ryan Mounce <ryan@mounce.com.au>
 *
 * The dummynet scheduler glue follows dn_sched_fq_codel.c:
 * Copyright (C) 2016 Centre for Advanced Internet Architectures,
 *  Swinburne University of Technology, Melbourne, Australia.
 * Implemented by Rasool Al-Saadi <ralsaadi@swin.edu.au>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * CAKE as a dummynet scheduler:
 *  - diffserv tins (besteffort, diffserv3, diffserv4, diffserv8,
 *    precedence): a tin within its rate share is served by priority, tins
 *    over it share by rate; WDRR between tins when the pipe has no rate
 *  - 8-way set-associative flow hashing per tin, with flow and host
 *    isolation (flows, srchost, dsthost, hosts, dual-*, triple-isolate)
 *  - DRR between flows with sparse (new) / bulk (old) flow lists
 *  - COBALT AQM (CoDel + BLUE) per flow, ECN aware
 *  - drop from the fattest flow over the packet or byte limit
 *  - link-layer overhead compensation (overhead, mpu, ATM, PTM)
 *  - ACK filter, DSCP wash and ingress mode
 *
 * Rate limiting is still done by the dummynet pipe the scheduler is
 * attached to; its bandwidth is used for the tin rate shares and per-tin
 * AQM parameters.
 */

#ifdef _KERNEL
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/time.h>
#include <sys/sbuf.h>
#include <sys/ucred.h>
#include <sys/jail.h>		/* TD_TO_VNET */
#include <net/vnet.h>
#include <sys/libkern.h>
#include <sys/endian.h>
#include <net/if.h>	/* IFNAMSIZ */
#include <netinet/in.h>
#include <netinet/ip_var.h>		/* ipfw_rule_ref */
#include <netinet/ip_fw.h>	/* flow_id */
#include <netinet/ip_dummynet.h>

#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>

#include <netpfil/ipfw/ip_fw_private.h>
#include <sys/sysctl.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/udp.h>
#include <sys/queue.h>
#include <sys/hash.h>

#include <netpfil/ipfw/dn_heap.h>
#include <netpfil/ipfw/ip_dn_private.h>

#include <netpfil/ipfw/dn_aqm.h>
#include <netpfil/ipfw/dn_sched.h>
#include "dn_sched_cake.h"

#else
#include <dn_test.h>
#endif

#define CAKE_MTU		1514	/* used for AQM rate scaling */
/*
 * The pipe's clock: its credit is in bits * DN_CREDIT_HZ, and it releases
 * packets at most DN_RELEASE_NS apart. A stock dummynet does both by the
 * tick; a dummynet with a finer release clock defines them.
 */
#ifndef DN_CREDIT_HZ
#define DN_CREDIT_HZ		hz
#define DN_RELEASE_NS		(1000000000ULL / hz)
#endif
/* how far apart its releases can be, which widens a tin's target */
#ifndef DN_RELEASE_GRAIN_NS
#define DN_RELEASE_GRAIN_NS	((uint64_t)tick * 1000)
#endif
#define CAKE_TIN_QUANTUM_SHIFT	4	/* tin quantum = quantum << 4 >> weight */
#define COBALT_CACHE		16	/* cached 1/sqrt(count) values */

static struct dn_alg cake_desc;
static void cake_reconfig(struct cake_si *si, struct cake_schk *schk);

/*
 * The instance needs cake_reconfig(): the scheduler was reconfigured, or
 * the pipe's rate changed, which dummynet does not tell the scheduler.
 */
#define	CAKE_STALE(si, schk)	((si)->gen != (schk)->gen ||		\
	(si)->bw != (si)->_si.sched->link.bandwidth)
static int cake_ecn_mark(struct mbuf *m);
static void cake_heapify(struct cake_si *si, uint32_t i);
static __inline void cake_charge_tin(struct cake_tin *tin, int len,
    uint64_t now);
static __inline uint64_t cake_link_now(struct cake_si *si, uint64_t now,
    int decide);
static __inline uint64_t cake_link_dur(struct cake_si *si, uint32_t len);

/* cake default parameters */
static struct dn_sch_cake_parms
cake_sysctl = {5000, 100000, CAKE_ECN_ENABLED, CAKE_DIFFSERV_DIFFSERV3,
	1514, 10240, 1024, CAKE_FLOW_TRIPLE, 0, 0, CAKE_ATM_NONE, 0};

/* host isolation within flow isolation: share a source/destination host's
 * quantum between its bulk flows */
#define	cake_dsrc(mode)	(((mode) & CAKE_FLOW_DUAL_SRC) == CAKE_FLOW_DUAL_SRC)
#define	cake_ddst(mode)	(((mode) & CAKE_FLOW_DUAL_DST) == CAKE_FLOW_DUAL_DST)

/*
 * DSCP to tin maps, following the tin definitions in tc-cake(8).
 * Unlisted code points map to tin 0, Best Effort.
 */
static const uint8_t cake_besteffort[64] = { 0 };

/* 0- Best Effort, 1- Bulk, 2- Voice */
static const uint8_t cake_diffserv3[64] = {
	[1] = 1, [8] = 1,			/* LE, CS1 */
	[4] = 2, [44] = 2, [46] = 2,		/* TOS4, VA, EF */
	[48] = 2, [56] = 2,			/* CS6, CS7 */
};

/* 0- Best Effort, 1- Bulk, 2- Video, 3- Voice */
static const uint8_t cake_diffserv4[64] = {
	[1] = 1, [8] = 1,			/* LE, CS1 */
	[4] = 2,				/* TOS4 */
	[16] = 2, [18] = 2, [20] = 2, [22] = 2,	/* CS2, AF2x */
	[24] = 2, [26] = 2, [28] = 2, [30] = 2,	/* CS3, AF3x */
	[34] = 2, [36] = 2, [38] = 2,		/* AF4x */
	[32] = 3, [40] = 3, [44] = 3, [46] = 3,	/* CS4, CS5, VA, EF */
	[48] = 3, [56] = 3,			/* CS6, CS7 */
};

/*
 * 0- Background (LE), 1- High Throughput (AF1x, TOS2, CS1), 2- Best
 * Effort, 3- Low Latency (AF2x, TOS4), 4- Video (AF4x, AF3x, CS3),
 * 5- Interactive (CS2), 6- Minimum Latency (EF, VA, CS5, CS4),
 * 7- Network Control (CS6, CS7); the table is sch_cake's diffserv8[]
 */
static const uint8_t cake_diffserv8[64] = {
	2, 0, 1, 2, 4, 2, 2, 2,
	1, 2, 1, 2, 1, 2, 1, 2,
	5, 2, 4, 2, 4, 2, 4, 2,
	3, 2, 3, 2, 3, 2, 3, 2,
	6, 2, 3, 2, 3, 2, 3, 2,
	6, 2, 2, 2, 6, 2, 6, 2,
	7, 2, 2, 2, 2, 2, 2, 2,
	7, 2, 2, 2, 2, 2, 2, 2,
};

/* one tin per IP precedence value, the top three DSCP bits */
static const uint8_t cake_precedence[64] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 4, 4, 4,
	5, 5, 5, 5, 5, 5, 5, 5,
	6, 6, 6, 6, 6, 6, 6, 6,
	7, 7, 7, 7, 7, 7, 7, 7,
};

static const uint8_t *cake_dscp_maps[] = {
	cake_besteffort, cake_diffserv3, cake_diffserv4, cake_diffserv8,
	cake_precedence
};

static const uint32_t cake_tin_cnt[] = { 1, 3, 4, 8, 8 };

/*
 * Per-tin rate share and WDRR weight, Q16 of the link rate: 1/16 for
 * Bulk, 1/2 for Video and 1/4 for Voice, and for the eight tin modes 7/8
 * of the tin below, as sch_cake computes them.
 */
static const uint32_t cake_tin_share[][CAKE_MAX_TINS] = {
	{ 65536 },
	{ 65536, 4096, 16384 },
	{ 65536, 4096, 32768, 16384 },
	{ 65536, 57344, 50176, 43904, 38416, 33614, 29412, 25735 },
	{ 65536, 57344, 50176, 43904, 38416, 33614, 29412, 25735 },
};

/*
 * 1/sqrt(count) for small counts, Q0.32, as sch_cake's inv_sqrt_cache:
 * a single Newton step is not accurate enough there. Entries 0 and 1 are
 * as close to 1.0 as Q0.32 gets.
 */
static const uint32_t cobalt_rec_inv_sqrt_cache[COBALT_CACHE] = {
		~0U,         ~0U, 3037000500, 2479700525,
	2147483647, 1920767767, 1753413056, 1623345051,
	1518500250, 1431655765, 1358187914, 1294981364,
	1239850263, 1191209601, 1147878294, 1108955788
};

static int
cake_sysctl_interval_handler(SYSCTL_HANDLER_ARGS)
{
	int error;
	long  value;

	value = cake_sysctl.interval;
	error = sysctl_handle_long(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 1 || value > 100 * AQM_TIME_1S)
		return (EINVAL);
	cake_sysctl.interval = value;

	return (0);
}

static int
cake_sysctl_target_handler(SYSCTL_HANDLER_ARGS)
{
	int error;
	long  value;

	value = cake_sysctl.target;
	error = sysctl_handle_long(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 1 || value > 5 * AQM_TIME_1S)
		return (EINVAL);
	cake_sysctl.target = value;

	return (0);
}

SYSBEGIN(f4)

SYSCTL_DECL(_net_inet);
SYSCTL_DECL(_net_inet_ip);
SYSCTL_DECL(_net_inet_ip_dummynet);
static SYSCTL_NODE(_net_inet_ip_dummynet, OID_AUTO, cake,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "CAKE");

#ifdef SYSCTL_NODE

SYSCTL_PROC(_net_inet_ip_dummynet_cake, OID_AUTO, target,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
    NULL, 0, cake_sysctl_target_handler, "L",
    "CAKE target in microsecond");
SYSCTL_PROC(_net_inet_ip_dummynet_cake, OID_AUTO, interval,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
    NULL, 0, cake_sysctl_interval_handler, "L",
    "CAKE interval in microsecond");

SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, diffserv,
	CTLFLAG_RW, &cake_sysctl.diffserv, CAKE_DIFFSERV_DIFFSERV3,
	"CAKE diffserv mode (0 besteffort, 1 diffserv3, 2 diffserv4, "
	"3 diffserv8, 4 precedence)");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, flags,
	CTLFLAG_RW, &cake_sysctl.flags, CAKE_ECN_ENABLED,
	"CAKE flags (1 ecn, 2 wash, 4 ack-filter, 8 aggressive, 16 ingress)");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, memlimit,
	CTLFLAG_RW, &cake_sysctl.memlimit, 0,
	"CAKE byte limit in KB, 0 for 4 x rate x interval, at least 4 MB");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, quantum,
	CTLFLAG_RW, &cake_sysctl.quantum, 1514, "CAKE quantum");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, flows,
	CTLFLAG_RW, &cake_sysctl.flows_cnt, 1024,
	"Number of queues per tin for CAKE");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, limit,
	CTLFLAG_RW, &cake_sysctl.limit, 10240, "CAKE queues size limit");
SYSCTL_INT(_net_inet_ip_dummynet_cake, OID_AUTO, overhead,
	CTLFLAG_RW, &cake_sysctl.overhead, 0,
	"CAKE bytes added to each packet for the link layer (-64 to 256)");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, mpu,
	CTLFLAG_RW, &cake_sysctl.mpu, 0,
	"CAKE minimum packet size on the link, bytes");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, atm,
	CTLFLAG_RW, &cake_sysctl.atm, CAKE_ATM_NONE,
	"CAKE link framing (0 none, 1 ATM cells, 2 PTM 64b/65b)");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, flowmode,
	CTLFLAG_RW, &cake_sysctl.flow_mode, CAKE_FLOW_TRIPLE,
	"CAKE flow isolation (0 flowblind, 1 srchost, 2 dsthost, 3 hosts, "
	"4 flows, 5 dual-srchost, 6 dual-dsthost, 7 triple-isolate)");
#endif

/*
 * dummynet only advances its clock once per tick, which is too coarse
 * for sojourn times at the default 5ms target, so COBALT and the tin
 * clocks use the uptime clock, in nanoseconds as sch_cake does.
 */
static __inline uint64_t
cake_now_ns(void)
{
	return (sbttons(sbinuptime()));
}

/*
 * The deficit dither and BLUE's drop draw need a number per refill, not
 * an unpredictable one: arc4random(), ChaCha20 per call, took about 12% of
 * a CPU at 300 Mbit/s each way on an Atom. sch_cake has the per-CPU
 * get_random_u16()/u32(); here a 64-bit LCG (Knuth's MMIX constants),
 * its high half, seeded from arc4random() by each new instance. Callers
 * hold dn_uh; a lost update between vnets only repeats a number.
 */
static uint64_t cake_rng;

static __inline uint32_t
cake_random(void)
{
	cake_rng = cake_rng * 6364136223846793005ULL + 1442695040888963407ULL;
	return (cake_rng >> 32);
}

/*
 * COBALT: CoDel and BLUE, as in sch_cake.
 */

/* one Newton-Raphson step towards 1/sqrt(count), Q0.32 */
static void
cobalt_newton_step(struct cobalt_vars *v)
{
	uint32_t invsqrt, invsqrt2;
	uint64_t val;

	invsqrt = v->rec_inv_sqrt;
	invsqrt2 = ((uint64_t)invsqrt * invsqrt) >> 32;
	val = (3ULL << 32) - ((uint64_t)v->count * invsqrt2);

	val >>= 2; /* avoid overflow in following multiply */
	val = (val * invsqrt) >> (32 - 2 + 1);

	v->rec_inv_sqrt = val;
}

static void
cobalt_invsqrt(struct cobalt_vars *v)
{
	if (v->count < COBALT_CACHE)
		v->rec_inv_sqrt = cobalt_rec_inv_sqrt_cache[v->count];
	else
		cobalt_newton_step(v);
}

/*
 * t + interval / sqrt(count). Split so that it cannot overflow: the
 * interval grows with the MTU time on very slow pipes. Below 2^32 us it
 * is sch_cake's reciprocal_scale().
 */
static __inline uint64_t
cobalt_control(uint64_t t, uint64_t interval, uint32_t rec_inv_sqrt)
{
	return (t + (interval >> 32) * rec_inv_sqrt +
	    (((interval & 0xffffffffULL) * rec_inv_sqrt) >> 32));
}

static void
cobalt_vars_init(struct cobalt_vars *v)
{
	memset(v, 0, sizeof(*v));
	/*
	 * Start at 1/sqrt(1), so the first signal is one interval after the
	 * flow first exceeds the target, as sch_cake's comments intend. Its
	 * cobalt_vars_init() leaves 0, so there a flow that has never been
	 * signalled is signalled on its second packet over the target.
	 */
	v->rec_inv_sqrt = ~0U;
}

/*
 * The flow overflowed: raise the BLUE drop probability. Return 1 if BLUE
 * was quiescent before and is active now.
 */
static int
cobalt_queue_full(struct cobalt_vars *v, struct cobalt_params *p,
	uint64_t now)
{
	int up = 0;

	if (now - v->blue_timer > p->target) {
		up = !v->p_drop;
		v->p_drop += p->p_inc;
		if (v->p_drop < p->p_inc)
			v->p_drop = ~0U;
		v->blue_timer = now;
	}
	v->dropping = 1;
	v->drop_next = now;
	if (!v->count)
		v->count = 1;
	return (up);
}

/*
 * The flow was found empty: decay BLUE and leave CoDel dropping state.
 * Return 1 if BLUE was active before and is quiescent now.
 */
static int
cobalt_queue_empty(struct cobalt_vars *v, struct cobalt_params *p,
	uint64_t now)
{
	int down = 0;

	if (v->p_drop && now - v->blue_timer > p->target) {
		if (v->p_drop < p->p_dec)
			v->p_drop = 0;
		else
			v->p_drop -= p->p_dec;
		v->blue_timer = now;
		down = !v->p_drop;
	}
	v->dropping = 0;

	if (v->count && (int64_t)(now - v->drop_next) >= 0) {
		v->count--;
		cobalt_invsqrt(v);
		v->drop_next = cobalt_control(v->drop_next, p->interval,
		    v->rec_inv_sqrt);
	}
	return (down);
}

/*
 * Decide whether to drop the packet just dequeued.
 * Return 1 to drop, 0 to send. ECN-capable packets are marked instead of
 * dropped by CoDel when ECN is enabled; BLUE always drops.
 */
static int
cobalt_should_drop(struct cobalt_vars *v, struct cobalt_params *p,
	uint64_t now, uint64_t enq_ts, struct mbuf *m, int ecn, int *marked,
	uint32_t bulk_flows)
{
	uint64_t sojourn;
	int64_t schedule;
	int drop = 0, next_due, over_target;

	*marked = 0;
	sojourn = now > enq_ts ? now - enq_ts : 0;
	schedule = (int64_t)(now - v->drop_next);
	/* in ingress mode, bulk flows share the link before the queue */
	over_target = sojourn > p->target &&
	    sojourn > p->mtu_time * bulk_flows * 2 &&
	    sojourn > p->mtu_time * 4;
	next_due = v->count && schedule >= 0;

	if (over_target) {
		if (!v->dropping) {
			v->dropping = 1;
			v->drop_next = cobalt_control(now, p->interval,
			    v->rec_inv_sqrt);
		}
		if (!v->count)
			v->count = 1;
	} else if (v->dropping) {
		v->dropping = 0;
	}

	if (next_due && v->dropping) {
		/* use ECN mark if possible, otherwise drop */
		if (ecn && cake_ecn_mark(m))
			*marked = 1;
		else
			drop = 1;

		v->count++;
		if (!v->count)
			v->count--;
		cobalt_invsqrt(v);
		v->drop_next = cobalt_control(v->drop_next, p->interval,
		    v->rec_inv_sqrt);
		schedule = (int64_t)(now - v->drop_next);
	} else {
		while (next_due) {
			v->count--;
			cobalt_invsqrt(v);
			v->drop_next = cobalt_control(v->drop_next,
			    p->interval, v->rec_inv_sqrt);
			schedule = (int64_t)(now - v->drop_next);
			next_due = v->count && schedule >= 0;
		}
	}

	/* simple BLUE; lack of ECN is deliberate */
	if (v->p_drop && !drop && cake_random() < v->p_drop)
		drop = 1;

	/* overload the drop_next field as an activity timeout */
	if (!v->count)
		v->drop_next = now + p->interval;
	else if (schedule > 0 && !drop)
		v->drop_next = now;

	return (drop);
}

/* Helper function to update flow, tin, main-queue and scheduler statistics.
 * negative len + drop -> drop
 * negative len -> dequeue
 * positive len -> enqueue
 * positive len + drop -> drop during enqueue
 */
static __inline void
cake_update_stats(struct cake_flow *q, struct cake_si *si, int len,
	int drop)
{
	int inc = 0;

	if (len < 0)
		inc = -1;
	else if (len > 0)
		inc = 1;

	if (drop) {
		si->main_q.ni.drops ++;
		q->stats.drops ++;
		si->_si.ni.drops ++;
		si->tins[q->tin].drops ++;
		V_dn_cfg.io_pkt_drop ++;
	}

	if (!drop || (drop && len < 0)) {
		/* Update stats for the main queue */
		si->main_q.ni.length += inc;
		si->main_q.ni.len_bytes += len;

		/* update sub-queue and tin stats */
		q->stats.length += inc;
		q->stats.len_bytes += len;
		si->tins[q->tin].backlog += inc;
		si->tins[q->tin].backlog_bytes += len;

		/* update scheduler instance stats */
		si->_si.ni.length += inc;
		si->_si.ni.len_bytes += len;
	}

	if (inc > 0) {
		si->main_q.ni.tot_bytes += len;
		si->main_q.ni.tot_pkts ++;

		q->stats.tot_bytes +=len;
		q->stats.tot_pkts++;

		si->_si.ni.tot_bytes +=len;
		si->_si.ni.tot_pkts ++;
	}
}

/*
 * Bytes a packet takes on the link, as sch_cake's cake_calc_overhead():
 * the network-layer length plus overhead, at least mpu, then ATM cell or
 * PTM framing. Without compensation configured it is the packet length,
 * as dummynet charges it.
 */
static __inline uint32_t
cake_wire_bytes(const struct dn_sch_cake_parms *cfg, struct mbuf *m)
{
	int len;

	if (cfg->overhead == 0 && cfg->mpu == 0 && cfg->atm == CAKE_ATM_NONE)
		return (m->m_pkthdr.len);

	len = m->m_pkthdr.len - dn_tag_get(m)->iphdr_off + cfg->overhead;
	len = MAX(len, (int)cfg->mpu);
	len = MAX(len, 1);
	if (cfg->atm == CAKE_ATM_ATM)
		len = (len + 47) / 48 * 53;
	else if (cfg->atm == CAKE_ATM_PTM)
		len += (len + 63) / 64;
	return (len);
}

#ifdef DN_WIRE_LEN
/* dn_alg wire_len: what the pipe charges for a dequeued packet */
static uint32_t
cake_wire_len(struct dn_sch_inst *_si, struct mbuf *m)
{
	return (cake_wire_bytes(&((struct cake_si *)_si)->cfg, m));
}
#endif

/*
 * Charge a packet that was dropped after crossing the link (ingress mode)
 * to the tin clock, the link clock and the pipe, as sch_cake does with
 * cake_advance_shaper() for its drops. As sch_cake's failsafe, which only
 * sends advance (cake_failsafe()), the pipe's debt from drops never
 * delays its next send past the failsafe time: so it sends at least 2/3
 * of the rate however much is dropped, at dequeue (COBALT) or at enqueue
 * (overflow). The debt is also capped at one interval of link time.
 */
static void
cake_charge_link(struct cake_si *si, struct cake_tin *tin, uint32_t len,
	uint64_t now_ns)
{
	uint64_t interval = tin->cparams.interval, last = tin->time_next;
	uint64_t link_ns;
	int64_t credit = si->_si.credit, debt, ahead, failsafe;

	if (!si->shaped)
		return;

	/* drops only add debt up to the cap, never take any away */
	link_ns = cake_link_now(si, now_ns, 0);
	cake_charge_tin(tin, len, link_ns);
	if (tin->time_next > link_ns + interval)
		tin->time_next = MAX(last, link_ns + interval);
	si->link_time = MAX(si->link_time, link_ns) + cake_link_dur(si, len);

	/* pipe credit is in bits * DN_CREDIT_HZ, gained at bw a second. The failsafe
	 * time ahead of now is debt drops may add; behind now, it is credit
	 * owed to sends, which drops may not take. Up to a second either
	 * way counts, which keeps the product in range. */
	debt = (int64_t)DN_CREDIT_HZ * si->_si.sched->link.bandwidth / 1000000 *
	    (interval / 1000);
	ahead = si->failsafe_time >= now_ns ?
	    (int64_t)MIN(si->failsafe_time - now_ns, 1000000000ULL) :
	    -(int64_t)MIN(now_ns - si->failsafe_time, 1000000000ULL);
	/* |ahead| / 1000 <= 10^6 us, bw / 1000 < 2^32 / 1000,
	 * DN_CREDIT_HZ <= 10^6: at most 4.3 * 10^18, within int64_t */
	failsafe = -(ahead / 1000) * (int64_t)(si->bw / 1000) * DN_CREDIT_HZ / 1000;
	si->_si.credit = MAX(credit - (int64_t)DN_CREDIT_HZ * 8 * len,
	    MIN(credit, MAX(-debt, failsafe)));
}

/*
 * Mark an ECN-capable packet CE for COBALT: 1 if it is marked now or was
 * already, 0 if it cannot be (not ECN-capable, or its header is not in
 * the first mbuf or not writable), and COBALT drops it instead. Unlike
 * dummynet's ecn_mark(), which writes at the recorded header offset
 * unchecked, so it could change data shared with other copies of the
 * packet; sch_cake's INET_ECN_set_ce() also checks the header bounds.
 */
static int
cake_ecn_mark(struct mbuf *m)
{
	struct ip *ip;
	struct ip6_hdr *ip6;
	uint32_t flow;
	uint16_t old;
	int off;

	off = dn_tag_get(m)->iphdr_off;
	if (m->m_len < off + (int)sizeof(struct ip))
		return (0);
	ip = mtodo(m, off);
	if (ip->ip_v == 4) {
		if ((ip->ip_tos & IPTOS_ECN_MASK) == IPTOS_ECN_NOTECT)
			return (0);
		if ((ip->ip_tos & IPTOS_ECN_MASK) == IPTOS_ECN_CE)
			return (1);
		if (!M_WRITABLE(m))
			return (0);
		old = *(uint16_t *)ip;
		ip->ip_tos |= IPTOS_ECN_CE;
		ip->ip_sum = cksum_adjust(ip->ip_sum, old, *(uint16_t *)ip);
		return (1);
	}
	if (ip->ip_v != 6 || m->m_len < off + (int)sizeof(struct ip6_hdr))
		return (0);
	ip6 = (struct ip6_hdr *)ip;
	flow = ntohl(ip6->ip6_flow);
	if ((flow & (IPTOS_ECN_MASK << 20)) == (IPTOS_ECN_NOTECT << 20))
		return (0);
	if ((flow & (IPTOS_ECN_MASK << 20)) == (IPTOS_ECN_CE << 20))
		return (1);
	if (!M_WRITABLE(m))
		return (0);
	ip6->ip6_flow = htonl(flow | (IPTOS_ECN_CE << 20));
	return (1);
}

/*
 * Clear the DSCP of a packet, keeping ECN, after it has been classified.
 * Packets whose header is not writable in the first mbuf keep it.
 */
static void
cake_wash(struct mbuf *m)
{
	struct ip *ip;
	struct ip6_hdr *ip6;
	uint16_t old;
	int off;

	off = dn_tag_get(m)->iphdr_off;
	if (!M_WRITABLE(m) || m->m_len < off + (int)sizeof(struct ip))
		return;
	ip = mtodo(m, off);
	if (ip->ip_v == 4) {
		old = *(uint16_t *)ip;
		ip->ip_tos &= IPTOS_ECN_MASK;
		ip->ip_sum = cksum_adjust(ip->ip_sum, old, *(uint16_t *)ip);
	} else if (ip->ip_v == 6 &&
	    m->m_len >= off + (int)sizeof(struct ip6_hdr)) {
		ip6 = (struct ip6_hdr *)ip;
		ip6->ip6_flow &= ~htonl(0x0fc00000);
	}
}

/*
 * ACK filter, as sch_cake's cake_ack_filter(): when a pure TCP ACK is
 * queued behind older pure ACKs of the same connection that it makes
 * redundant, drop one of those, so a congested uplink spends less of
 * itself on ACKs.
 */

/* TCP header flags, in the low 12 bits of header bytes 12-13 */
#define	CAKE_TH_SYN	0x002
#define	CAKE_TH_ACK	0x010
#define	CAKE_TH_ECE	0x040
#define	CAKE_TH_CWR	0x080
#define	CAKE_TH_ECN	(CAKE_TH_ECE | CAKE_TH_CWR)

/*
 * Packets of a flow the ACK filter looks at, from the head. sch_cake scans
 * the whole flow; a cap keeps the cost of one ACK bounded when an
 * unresponsive flow has thousands queued. (test/sched-diff.sh lifts it to
 * compare with sch_cake at any queue depth.)
 */
#ifndef CAKE_ACK_SCAN
#define	CAKE_ACK_SCAN	128
#endif

/* the TCP header of a packet, copied out of the mbuf chain if needed */
struct cake_tcp {
	const uint8_t	*th;		/* header with options */
	int		hlen;		/* header length */
	int		seglen;		/* header and payload */
	int		alen;		/* address length, 4 or 16 */
	uint8_t		addr[32];	/* source then destination */
	uint8_t		buf[60];
};

/* a pointer to 'len' bytes at 'off', or a copy in 'buf' */
static const void *
cake_hdr(struct mbuf *m, int off, int len, void *buf)
{
	if (off + len > m->m_pkthdr.len)
		return (NULL);
	if (off + len <= m->m_len)
		return (mtodo(m, off));
	m_copydata(m, off, len, buf);
	return (buf);
}

/*
 * Find the TCP header of an IPv4, IPv6 or 6in4 packet; 0 if there is
 * none, or the packet is a fragment.
 */
static int
cake_get_tcp(struct mbuf *m, struct cake_tcp *t)
{
	struct ip ipb;
	struct ip6_hdr ip6b;
	const struct ip *ip;
	const struct ip6_hdr *ip6;
	int off;

	off = dn_tag_get(m)->iphdr_off;
	ip = cake_hdr(m, off, sizeof(ipb), &ipb);
	if (ip == NULL)
		return (0);
	if (ip->ip_v == 4) {
		if (ip->ip_hl < sizeof(struct ip) >> 2 ||
		    (ip->ip_off & htons(IP_MF | IP_OFFMASK)))
			return (0);
		off += ip->ip_hl << 2;
		if (ip->ip_p == IPPROTO_TCP) {
			memcpy(t->addr, &ip->ip_src, 8);
			t->alen = 4;
			t->seglen = ntohs(ip->ip_len) - (ip->ip_hl << 2);
			goto tcp;
		}
		/* 6in4 tunnels are a common way to get IPv6 at home */
		if (ip->ip_p != IPPROTO_IPV6)
			return (0);
	} else if (ip->ip_v != 6)
		return (0);

	ip6 = cake_hdr(m, off, sizeof(ip6b), &ip6b);
	if (ip6 == NULL || ip6->ip6_nxt != IPPROTO_TCP)
		return (0);
	memcpy(t->addr, &ip6->ip6_src, 32);
	t->alen = 16;
	t->seglen = ntohs(ip6->ip6_plen);
	off += sizeof(*ip6);

tcp:
	t->th = cake_hdr(m, off, sizeof(struct tcphdr), t->buf);
	if (t->th == NULL || (t->th[12] >> 4) < 5)
		return (0);
	t->hlen = (t->th[12] >> 4) << 2;
	t->th = cake_hdr(m, off, t->hlen, t->buf);
	/* the IP length must cover the TCP header and fit in the packet
	 * (link layer padding may follow it) */
	return (t->th != NULL && t->seglen >= t->hlen &&
	    t->seglen <= m->m_pkthdr.len - off);
}

static __inline int
cake_th_flags(const struct cake_tcp *t)
{
	return (be16dec(t->th + 12) & 0x0fff);
}

static __inline uint32_t
cake_th_ack(const struct cake_tcp *t)
{
	return (be32dec(t->th + 8));
}

/* the contents of TCP option 'code' and its length, as cake_get_tcpopt() */
static const uint8_t *
cake_tcpopt(const struct cake_tcp *t, int code, int *oplen)
{
	const uint8_t *p = t->th + sizeof(struct tcphdr);
	int len = t->hlen - sizeof(struct tcphdr), op, size;

	while (len > 0) {
		op = *p++;
		if (op == TCPOPT_EOL)
			break;
		if (op == TCPOPT_NOP) {
			len--;
			continue;
		}
		if (len < 2)
			break;
		size = *p++;
		if (size < 2 || size > len)
			break;
		if (op == code) {
			*oplen = size;
			return (p);
		}
		p += size - 2;
		len -= size;
	}
	return (NULL);
}

static void
cake_tcp_tstamp(const struct cake_tcp *t, uint32_t *tsval, uint32_t *tsecr)
{
	const uint8_t *p;
	int size;

	p = cake_tcpopt(t, TCPOPT_TIMESTAMP, &size);
	if (p != NULL && size == TCPOLEN_TIMESTAMP) {
		*tsval = be32dec(p);
		*tsecr = be32dec(p + 4);
	}
}

/*
 * Whether a queued ACK may be dropped in favour of a newer one with the
 * given timestamps: only the ACK flag (ECN flags are compared by the
 * caller), and only options that carry no state, as cake_tcph_may_drop().
 */
static int
cake_tcp_may_drop(const struct cake_tcp *t, uint32_t tsval_new,
	uint32_t tsecr_new)
{
	const uint8_t *p = t->th + sizeof(struct tcphdr);
	int len = t->hlen - sizeof(struct tcphdr), op, size;

	if ((cake_th_flags(t) & ~CAKE_TH_ECN) != CAKE_TH_ACK)
		return (0);

	while (len > 0) {
		op = *p++;
		if (op == TCPOPT_EOL)
			break;
		if (op == TCPOPT_NOP) {
			len--;
			continue;
		}
		if (len < 2)
			break;
		size = *p++;
		if (size < 2 || size > len)
			break;

		switch (op) {
		case TCPOPT_SIGNATURE:	/* doesn't influence state */
			break;
		case TCPOPT_SACK:	/* compared by cake_tcp_sack_cmp() */
			if (size % 8 != 2)
				return (0);
			break;
		case TCPOPT_TIMESTAMP:	/* only drop older timestamps */
			if (size != TCPOLEN_TIMESTAMP ||
			    SEQ_GT(be32dec(p), tsval_new) ||
			    SEQ_GT(be32dec(p + 4), tsecr_new))
				return (0);
			break;
		default:		/* SYN-only or unknown options */
			return (0);
		}
		p += size - 2;
		len -= size;
	}
	return (1);
}

/*
 * Compare the SACK blocks of two ACKs, as cake_tcph_sack_compare(): -1
 * if A SACKs anything B does not (or has a DSACK), 1 if B SACKs more
 * bytes, 0 if they SACK the same.
 */
static int
cake_tcp_sack_cmp(const struct cake_tcp *a, const struct cake_tcp *b)
{
	const uint8_t *sa, *sb, *st;
	uint32_t ack_a = cake_th_ack(a), bytes_a = 0, bytes_b = 0;
	uint32_t start_a, end_a, start_b, end_b;
	int la = 0, lb = 0, lt, first = 1, found;

	sa = cake_tcpopt(a, TCPOPT_SACK, &la);
	sb = cake_tcpopt(b, TCPOPT_SACK, &lb);
	la -= 2;
	lb -= 2;
	if (sa == NULL)
		la = 0;
	if (sb == NULL)
		lb = 0;

	if (la >= 8 && lb < 8)
		return (-1);
	if (lb >= 8 && la < 8)
		return (1);
	if (la < 8 && lb < 8)
		return (0);

	for (; la >= 8; la -= 8, sa += 8) {
		start_a = be32dec(sa);
		end_a = be32dec(sa + 4);
		found = 0;

		/* DSACK; always considered greater to prevent dropping */
		if (SEQ_LT(start_a, ack_a))
			return (-1);
		bytes_a += end_a - start_a;

		for (st = sb, lt = lb; lt >= 8; lt -= 8, st += 8) {
			start_b = be32dec(st);
			end_b = be32dec(st + 4);
			if (first)
				bytes_b += end_b - start_b;
			if (!SEQ_GT(start_b, start_a) && !SEQ_LT(end_b, end_a)) {
				found = 1;
				if (!first)
					break;
			}
		}
		if (!found)
			return (-1);
		first = 0;
	}
	/* everything A SACKs, B does too */
	return (bytes_b > bytes_a ? 1 : 0);
}

/*
 * The packet at the tail of flow 'f' was just queued. If it is an ACK,
 * unlink and return a redundant pure ACK of the same connection: the
 * one nearest the head once two are eligible, or in aggressive mode a
 * single one right in front of it with the same ECN flags.
 */
static struct mbuf *
cake_ack_filter(struct cake_flow *f, int aggressive)
{
	struct cake_tcp t, c;
	struct mbuf *m, *chk, *prev = NULL, *elig = NULL, *elig_prev = NULL;
	uint32_t tsval = 0, tsecr = 0;
	int found = 0, elig_flags = 0, cmp, scan = CAKE_ACK_SCAN;

	m = f->mq.tail;
	if (f->mq.head == m || !cake_get_tcp(m, &t))
		return (NULL);
	cake_tcp_tstamp(&t, &tsval, &tsecr);
	if ((cake_th_flags(&t) & (CAKE_TH_ACK | CAKE_TH_SYN)) != CAKE_TH_ACK)
		return (NULL);

	for (chk = f->mq.head; chk != NULL && chk != m && scan-- > 0;
	    prev = chk, chk = chk->m_nextpkt) {
		/* same connection only: the flow may hold colliding ones */
		if (!cake_get_tcp(chk, &c) || c.alen != t.alen ||
		    memcmp(c.th, t.th, 4) != 0 ||
		    memcmp(c.addr, t.addr, 2 * t.alen) != 0)
			continue;

		/* changed ECN flags carry information: keep the older ACK */
		if (elig != NULL && (cake_th_flags(&c) & CAKE_TH_ECN) !=
		    elig_flags) {
			elig = NULL;
			elig_prev = NULL;
			found--;
		}

		/* pure ACKs, not acking beyond the new one */
		if (!cake_tcp_may_drop(&c, tsval, tsecr) ||
		    c.seglen != c.hlen ||
		    SEQ_GT(cake_th_ack(&c), cake_th_ack(&t)))
			continue;

		/* the new ACK must SACK more, or the same with a higher ack */
		cmp = cake_tcp_sack_cmp(&c, &t);
		if (cmp < 0 || (cake_th_ack(&c) == cake_th_ack(&t) && cmp == 0))
			continue;

		if (elig == NULL) {
			elig = chk;
			elig_prev = prev;
			elig_flags = cake_th_flags(&c) & CAKE_TH_ECN;
		}
		if (found++ > 0)
			goto drop;
	}

	if (elig == NULL || !aggressive || elig->m_nextpkt != m ||
	    elig_flags != (cake_th_flags(&t) & CAKE_TH_ECN))
		return (NULL);

drop:
	if (elig_prev != NULL)
		elig_prev->m_nextpkt = elig->m_nextpkt;
	else
		f->mq.head = elig->m_nextpkt;
	f->mq.count--;
	elig->m_nextpkt = NULL;
	return (elig);
}

/* Drop a packet from the head of a flow */
static void
cake_drop_head(struct cake_flow *q, struct cake_si *si)
{
	struct mbuf *m = q->mq.head;

	if (m == NULL)
		return;
	q->mq.head = m->m_nextpkt;
	q->mq.count--;

	cake_update_stats(q, si, -m->m_pkthdr.len, 1);

	if (si->main_q.ni.length == 0) /* queue is now idle */
		si->main_q.q_time = V_dn_cfg.curr_time;

	FREE_PKT(m);
}

/* Enqueue a packet 'm' to a flow 'q' and add timestamp to that packet.
 * Return 1 when unable to add timestamp, otherwise return 0
 */
static int
cake_flow_enqueue(struct cake_flow *q, struct mbuf *m, struct cake_si *si)
{
	struct m_tag *mtag;
	int len;

	len = m->m_pkthdr.len;

	/* Add timestamp to mbuf as MTAG. Reuse one the packet still carries
	 * (prepending it again would corrupt the tag list). It goes after
	 * dummynet's tag, which dn_tag_get() takes to be the first: in
	 * front, the ACK filter and the wire length of a queued packet
	 * would read the IP header offset past this tag's end.
	 */
	mtag = m_tag_locate(m, MTAG_ABI_COMPAT, DN_CAKE_MTAG_TS, NULL);
	if (mtag == NULL) {
		mtag = m_tag_alloc(MTAG_ABI_COMPAT, DN_CAKE_MTAG_TS,
		    sizeof(uint64_t), M_NOWAIT);
		if (mtag == NULL)
			goto drop;
		SLIST_INSERT_AFTER(m_tag_first(m), mtag, m_tag_link);
	}
	*(uint64_t *)(mtag + 1) = cake_now_ns();

	if (m->m_pkthdr.rcvif != NULL)
		m_rcvif_serialize(m);

	mq_append(&q->mq, m);
	cake_update_stats(q, si, len, 0);
	return 0;

drop:
	cake_update_stats(q, si, len, 1);
	m_freem(m);
	return 1;
}

/* extract the head of a flow, with its enqueue timestamp */
static struct mbuf *
cake_extract_head(struct cake_flow *q, struct cake_si *si, uint64_t *pkt_ts)
{
	struct m_tag *mtag;
	struct mbuf *m;

next:	m = q->mq.head;
	if (m == NULL)
		return m;
	q->mq.head = m->m_nextpkt;
	q->mq.count--;

	cake_update_stats(q, si, -m->m_pkthdr.len, 0);
	/* the flow's backlog shrank: keep a warm heap up to date, as
	 * cake_dequeue_one() does */
	if (si->overflow_timeout)
		cake_heapify(si, q->heap_idx);

	if (si->main_q.ni.length == 0) /* queue is now idle */
		si->main_q.q_time = V_dn_cfg.curr_time;

	/* extract packet timestamp */
	mtag = m_tag_locate(m, MTAG_ABI_COMPAT, DN_CAKE_MTAG_TS, NULL);
	if (mtag == NULL) {
		D("timestamp tag is not found!");
		*pkt_ts = 0;
	} else {
		*pkt_ts = *(uint64_t *)(mtag + 1);
		m_tag_delete(m, mtag);
	}
	/* the receiving interface has gone away: drop the packet */
	if (m->m_pkthdr.rcvif != NULL &&
	    __predict_false(m_rcvif_restore(m) == NULL)) {
		cake_update_stats(q, si, 0, 1);
		m_freem(m);
		goto next;
	}
	return m;
}

/*
 * Hash a packet with the Jenkins hash and extract its DSCP. The source and
 * destination host hashes go to *srch and *dsth. The flow hash covers the
 * 5-tuple with CAKE_FLOW_FLOWS, otherwise the hosts the mode isolates.
 * All fragments of a datagram hash to the same flow, without ports.
 */
static uint32_t
cake_hash_flow(struct mbuf *m, uint32_t perturbation, uint32_t mode,
	uint8_t *dscp, uint32_t *srch, uint32_t *dsth)
{
	struct ip *ip;
	struct ip6_hdr *ip6;
	/* 41 bytes hashed, rounded up to whole words: on an aligned key
	 * jenkins_hash() reads the last word whole and masks off the bytes
	 * past the end, which KASAN reports */
	uint8_t tuple[44];
	int off, len, portoff, ports, alen;
	uint8_t proto;
	uint32_t h;

	memset(tuple, 0, sizeof(tuple));
	memcpy(&tuple[1], &perturbation, sizeof(perturbation));

	/* the IP stack makes the header contiguous, but dummynet on layer 2
	 * can pass anything: short or non-IP packets go to one fixed flow */
	off = dn_tag_get(m)->iphdr_off;
	*dscp = 0;
	*srch = *dsth = 0;
	if (m->m_len < off + (int)sizeof(struct ip))
		return (0);
	ip = (struct ip *)mtodo(m, off);
	if ((ip->ip_v != 4 && ip->ip_v != 6) || (ip->ip_v == 4 &&
	    ip->ip_hl < sizeof(struct ip) >> 2) || (ip->ip_v == 6 &&
	    m->m_len < off + (int)sizeof(struct ip6_hdr)))
		return (0);

	if (ip->ip_v == 6) {
		ip6 = (struct ip6_hdr *)ip;
		*dscp = (ntohl(ip6->ip6_flow) >> 22) & 0x3f;
		proto = ip6->ip6_nxt;
		memcpy(&tuple[5], &ip6->ip6_src, 16);
		memcpy(&tuple[21], &ip6->ip6_dst, 16);
		off += sizeof(*ip6);
		portoff = 37;
		len = 41;
		alen = 16;
		ports = 1;
	} else {
		*dscp = ip->ip_tos >> 2;
		proto = ip->ip_p;
		memcpy(&tuple[5], &ip->ip_src, 4);
		memcpy(&tuple[9], &ip->ip_dst, 4);
		off += ip->ip_hl << 2;
		portoff = 13;
		len = 17;
		alen = 4;
		ports = !(ip->ip_off & htons(IP_MF | IP_OFFMASK));
	}
	tuple[0] = proto;

	*srch = jenkins_hash(&tuple[5], alen, perturbation);
	*dsth = jenkins_hash(&tuple[5 + alen], alen, perturbation);

	if ((mode & CAKE_FLOW_FLOWS) == 0) {
		h = 0;
		if (mode & CAKE_FLOW_SRC_IP)
			h ^= *srch;
		if (mode & CAKE_FLOW_DST_IP)
			h ^= *dsth;
		return (h);
	}

	/* source and destination ports are the first 4 bytes of both */
	if (ports && (proto == IPPROTO_TCP || proto == IPPROTO_UDP) &&
	    m->m_len >= off + 4)
		memcpy(&tuple[portoff], mtodo(m, off), 4);

	return (jenkins_hash(tuple, len, HASHINIT));
}

/*
 * Find the host slot for 'hash' in a tin's host table, set-associative
 * like the flows: the way holding the same host, else one no bulk flow
 * counts on. If every way is in use the hosts share the default way.
 */
static uint32_t
cake_host_slot(struct cake_host *hosts, uint32_t cnt, uint32_t hash, int dst)
{
	struct cake_host *h;
	uint32_t idx, base, i, k;

	idx = ((uint64_t)hash * cnt) >> 32;
	base = idx - idx % CAKE_SET_WAYS;

	k = idx % CAKE_SET_WAYS;
	for (i = 0; i < CAKE_SET_WAYS; i++, k = (k + 1) % CAKE_SET_WAYS) {
		h = &hosts[base + k];
		if ((dst ? h->dsthost_tag : h->srchost_tag) == hash)
			return (base + k);
	}
	for (i = 0; i < CAKE_SET_WAYS; i++, k = (k + 1) % CAKE_SET_WAYS) {
		h = &hosts[base + k];
		if (dst ? h->dsthost_bulk == 0 : h->srchost_bulk == 0) {
			if (dst)
				h->dsthost_tag = hash;
			else
				h->srchost_tag = hash;
			return (base + k);
		}
	}
	return (idx);
}

/* add (inc 1) or remove (inc -1) a bulk flow from its hosts' counts */
static __inline void
cake_host_bulk(struct cake_si *si, struct cake_flow *f, int inc)
{
	struct cake_host *hosts = &si->hosts[f->tin * si->flows_cnt];

	if (cake_dsrc(si->flow_mode))
		hosts[f->srchost].srchost_bulk += inc;
	if (cake_ddst(si->flow_mode))
		hosts[f->dsthost].dsthost_bulk += inc;
}

/*
 * Point a flow at its hosts' slots, moving its bulk count along if a hash
 * collision made the flow change hosts.
 */
static void
cake_set_hosts(struct cake_si *si, struct cake_flow *f, uint32_t srch,
	uint32_t dsth)
{
	struct cake_host *hosts = &si->hosts[f->tin * si->flows_cnt];

	if (f->set == CAKE_SET_BULK)
		cake_host_bulk(si, f, -1);
	if (cake_dsrc(si->flow_mode))
		f->srchost = cake_host_slot(hosts, si->flows_cnt, srch, 0);
	if (cake_ddst(si->flow_mode))
		f->dsthost = cake_host_slot(hosts, si->flows_cnt, dsth, 1);
	if (f->set == CAKE_SET_BULK)
		cake_host_bulk(si, f, 1);
}

/*
 * A flow's deficit refill: its tin's quantum shared between the bulk
 * flows of its busiest host, as cake_get_flow_quantum(): 65535 / load in
 * 16 bits, plus a random 16-bit dither so that the average refill is
 * exact. Under a heavy host load it can round down to 0; the flow then
 * waits for its next turn.
 */
static uint32_t
cake_flow_quantum(struct cake_si *si, struct cake_flow *f)
{
	struct cake_host *hosts = &si->hosts[f->tin * si->flows_cnt];
	uint32_t load = 1;

	if (cake_dsrc(si->flow_mode))
		load = MAX(load, hosts[f->srchost].srchost_bulk);
	if (cake_ddst(si->flow_mode))
		load = MAX(load, hosts[f->dsthost].dsthost_bulk);
	return ((si->tins[f->tin].flow_quantum * (65535 / load) +
	    (cake_random() & 0xffff)) >> 16);
}

/*
 * Find the flow for 'hash' in a tin, using an 8-way set-associative table
 * so that unrelated flows rarely share a queue: prefer the way holding
 * the same hash, then an idle way, and only then collide.
 */
static struct cake_flow *
cake_lookup_flow(struct cake_si *si, uint8_t tin, uint32_t hash)
{
	struct cake_flow *flows, *f;
	uint32_t idx, base, i, k;

	flows = &si->flows[tin * si->flows_cnt];
	idx = ((uint64_t)hash * si->flows_cnt) >> 32;
	base = idx - idx % CAKE_SET_WAYS;

	k = idx % CAKE_SET_WAYS;
	for (i = 0; i < CAKE_SET_WAYS; i++, k = (k + 1) % CAKE_SET_WAYS) {
		if (flows[base + k].tag == hash)
			return (&flows[base + k]);
	}

	for (i = 0; i < CAKE_SET_WAYS; i++, k = (k + 1) % CAKE_SET_WAYS) {
		f = &flows[base + k];
		if (!f->active) {
			f->tag = hash;
			cobalt_vars_init(&f->cvars);
			return (f);
		}
	}

	/* every way is busy: share the default way */
	si->tins[tin].way_collisions++;
	f = &flows[idx];
	f->tag = hash;
	return (f);
}

/*
 * The overflow heap, as sch_cake's: a max-heap of flow byte backlogs with
 * an entry for each flow of all CAKE_MAX_TINS tins, laid out as sch_cake
 * lays out its own (entry j * CAKE_MAX_TINS + t starts as flow j of tin
 * t), so that ties are broken the same way. Tins the diffserv mode does
 * not use have no flows and count as empty.
 */
#define	CAKE_HEAP_TIN(e)	((e) & (CAKE_MAX_TINS - 1))
#define	CAKE_HEAP_FLOW(e)	((e) >> 3)

static __inline uint32_t
cake_heap_backlog(struct cake_si *si, uint32_t i)
{
	uint32_t e = si->overflow_heap[i];

	return (CAKE_HEAP_TIN(e) < si->tin_cnt ?
	    si->flows[CAKE_HEAP_TIN(e) * si->flows_cnt +
	    CAKE_HEAP_FLOW(e)].stats.len_bytes : 0);
}

static void
cake_heap_swap(struct cake_si *si, uint32_t i, uint32_t j)
{
	uint32_t ii = si->overflow_heap[i], jj = si->overflow_heap[j];

	si->overflow_heap[i] = jj;
	si->overflow_heap[j] = ii;
	if (CAKE_HEAP_TIN(ii) < si->tin_cnt)
		si->flows[CAKE_HEAP_TIN(ii) * si->flows_cnt +
		    CAKE_HEAP_FLOW(ii)].heap_idx = j;
	if (CAKE_HEAP_TIN(jj) < si->tin_cnt)
		si->flows[CAKE_HEAP_TIN(jj) * si->flows_cnt +
		    CAKE_HEAP_FLOW(jj)].heap_idx = i;
}

/* sift entry i down, as cake_heapify() */
static void
cake_heapify(struct cake_si *si, uint32_t i)
{
	uint32_t a = CAKE_MAX_TINS * si->flows_cnt;
	uint32_t m = i, mb = cake_heap_backlog(si, i), l, r, lb, rb;

	while (m < a) {
		l = m + m + 1;
		r = l + 1;
		if (l < a) {
			lb = cake_heap_backlog(si, l);
			if (lb > mb) {
				m = l;
				mb = lb;
			}
		}
		if (r < a) {
			rb = cake_heap_backlog(si, r);
			if (rb > mb) {
				m = r;
				mb = rb;
			}
		}
		if (m == i)
			break;
		cake_heap_swap(si, i, m);
		i = m;
	}
}

/* move entry i up as its backlog grew, as cake_heapify_up() */
static void
cake_heapify_up(struct cake_si *si, uint32_t i)
{
	uint32_t p;

	while (i > 0 && i < CAKE_MAX_TINS * si->flows_cnt) {
		p = (i - 1) >> 1;
		if (cake_heap_backlog(si, i) <= cake_heap_backlog(si, p))
			break;
		cake_heap_swap(si, i, p);
		i = p;
	}
}

/*
 * Drop the head packet of the flow with the largest byte backlog, from
 * the heap as sch_cake's cake_drop(); 0 if nothing is queued.
 */
static int
cake_drop_fattest(struct cake_si *si, uint64_t now_ns)
{
	struct cake_flow *fat;
	uint32_t e, i, tries;

	for (tries = 0;; tries++) {
		/* as cake_drop(): a heap gone cold is rebuilt first */
		if (si->overflow_timeout == 0)
			for (i = CAKE_MAX_TINS * si->flows_cnt / 2; i-- > 0;)
				cake_heapify(si, i);
		si->overflow_timeout = 65535;

		e = si->overflow_heap[0];
		fat = CAKE_HEAP_TIN(e) < si->tin_cnt ?
		    &si->flows[CAKE_HEAP_TIN(e) * si->flows_cnt +
		    CAKE_HEAP_FLOW(e)] : NULL;
		if (fat != NULL && fat->mq.head != NULL)
			break;
		/* the heap went wrong (sch_cake rebuilds it on its next
		 * call): rebuild it now, or give up if nothing is queued */
		si->overflow_timeout = 0;
		if (tries > 0)
			return (0);
	}

	if (cobalt_queue_full(&fat->cvars, &si->tins[fat->tin].cparams,
	    now_ns))
		si->tins[fat->tin].unresponsive_flows++;
	if (si->cfg.flags & CAKE_INGRESS)
		cake_charge_link(si, &si->tins[fat->tin],
		    cake_wire_bytes(&si->cfg, fat->mq.head), now_ns);
	cake_drop_head(fat, si);
	cake_heapify(si, 0);
	return (1);
}

/* sch_cake's cake_ewma() */
static __inline uint64_t
cake_ewma(uint64_t avg, uint64_t sample, int shift)
{
	avg -= avg >> shift;
	avg += sample >> shift;
	return (avg);
}

/*
 * count a packet the tin sends, and its queue delay as sch_cake does: in
 * ns, as the averages move by 1/256 of a sample, and an average in us
 * would never fall to 255 us or below
 */
static __inline void
cake_tin_sent(struct cake_tin *tin, struct mbuf *m, uint64_t now_ns,
	uint64_t pkt_ts)
{
	uint64_t delay = now_ns > pkt_ts && pkt_ts != 0 ?
	    now_ns - pkt_ts : 0;

	tin->tx_pkts++;
	tin->tx_bytes += m->m_pkthdr.len;
	tin->avg_delay = cake_ewma(tin->avg_delay, delay, 8);
	tin->peak_delay = cake_ewma(tin->peak_delay, delay,
	    delay > tin->peak_delay ? 2 : 8);
	tin->base_delay = cake_ewma(tin->base_delay, delay,
	    delay < tin->base_delay ? 2 : 8);
}

/*
 * Dequeue from a flow, applying COBALT. Return NULL if the flow is empty,
 * or, in ingress mode, after a drop with *retry set: the drop used up
 * deficit, so the tin's DRR chooses a flow again, as in sch_cake.
 */
static struct mbuf *
cake_flow_dequeue(struct cake_flow *f, struct cake_si *si, uint64_t now_ns,
	int *retry)
{
	struct cake_tin *tin = &si->tins[f->tin];
	struct mbuf *m;
	uint64_t pkt_ts;
	uint32_t len;
	int drop, marked, ingress;

	ingress = (si->cfg.flags & CAKE_INGRESS) != 0;
	*retry = 0;
	while ((m = cake_extract_head(f, si, &pkt_ts)) != NULL) {
		drop = cobalt_should_drop(&f->cvars, &tin->cparams,
		    now_ns, pkt_ts, m, si->cfg.flags & CAKE_ECN_ENABLED,
		    &marked, ingress ? tin->bulk_flows : 0);
		if (marked)
			tin->ecn_marks++;

		/* last packet in queue may be marked, shouldn't be dropped */
		if (!drop || f->mq.head == NULL) {
			cake_tin_sent(tin, m, now_ns, pkt_ts);
			return m;
		}

		/* in ingress mode the dropped packet still used the link */
		if (ingress) {
			len = cake_wire_bytes(&si->cfg, m);
			cake_charge_link(si, tin, len, now_ns);
			f->deficit -= len;
			tin->tin_deficit -= len;
		}
		cake_update_stats(f, si, 0, 1);
		m_freem(m);
		if (ingress) {
			*retry = 1;
			return NULL;
		}
	}
	return NULL;
}

#ifdef CAKE_DEBUG
/*
 * Consistency checks for test builds (make CAKE_DEBUG=1): flow, tin and
 * instance counters must agree, every active flow must be on exactly one
 * list, in a state that fits it (decaying flows on the decaying list and
 * empty, the others on the new or old list), an inactive flow must hold
 * no packets (else it would never be served again), and the tin and host
 * flow counts must add up to the flows in each state. Violations are
 * counted and the first few are logged.
 */
static u_int cake_check_errors;
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, check_errors,
	CTLFLAG_RD, &cake_check_errors, 0, "CAKE_DEBUG consistency errors");

static void
cake_check(struct cake_si *si, const char *where)
{
	static u_int calls;
	struct cake_flow *f;
	struct mbuf *m;
	uint64_t pkts = 0, bytes = 0, tpkts, tbytes;
	uint32_t t, i, n, listed = 0, active = 0;
	int bad = 0;

	for (t = 0; t < si->tin_cnt; t++) {
		tpkts = tbytes = 0;
		TAILQ_FOREACH(f, &si->tins[t].newflows, flowchain) {
			listed++;
			tpkts += f->stats.length;
			tbytes += f->stats.len_bytes;
			if (!f->active || f->tin != t ||
			    f->set == CAKE_SET_DECAYING)
				bad |= 0x01;
		}
		TAILQ_FOREACH(f, &si->tins[t].oldflows, flowchain) {
			listed++;
			tpkts += f->stats.length;
			tbytes += f->stats.len_bytes;
			if (!f->active || f->tin != t ||
			    f->set == CAKE_SET_DECAYING)
				bad |= 0x01;
		}
		TAILQ_FOREACH(f, &si->tins[t].decayingflows, flowchain) {
			listed++;
			if (!f->active || f->tin != t ||
			    f->set != CAKE_SET_DECAYING || f->mq.head != NULL)
				bad |= 0x01;
		}
		if (tpkts != si->tins[t].backlog ||
		    tbytes != si->tins[t].backlog_bytes)
			bad |= 0x02;
		pkts += tpkts;
		bytes += tbytes;
	}
	if (pkts != si->main_q.ni.length || pkts != si->_si.ni.length)
		bad |= 0x04;
	if (bytes != si->main_q.ni.len_bytes || bytes != si->_si.ni.len_bytes)
		bad |= 0x08;

	/* full scan of the flow table now and then */
	if ((++calls & 63) == 0) {
		for (t = 0; t < si->tin_cnt; t++) {
			uint64_t nbulk = 0, nsparse = 0, ndecay = 0, nblue = 0;
			uint64_t src = 0, dst = 0;

			for (i = 0; i < si->flows_cnt; i++) {
				f = &si->flows[t * si->flows_cnt + i];
				if (f->set == CAKE_SET_BULK)
					nbulk++;
				else if (f->set == CAKE_SET_SPARSE ||
				    f->set == CAKE_SET_SPARSE_WAIT)
					nsparse++;
				else if (f->set == CAKE_SET_DECAYING)
					ndecay++;
				if (f->cvars.p_drop != 0)
					nblue++;
				src += si->hosts[t * si->flows_cnt + i].srchost_bulk;
				dst += si->hosts[t * si->flows_cnt + i].dsthost_bulk;
			}
			if (src != (cake_dsrc(si->flow_mode) ? nbulk : 0) ||
			    dst != (cake_ddst(si->flow_mode) ? nbulk : 0) ||
			    nbulk != si->tins[t].bulk_flows ||
			    nsparse != si->tins[t].sparse_flows ||
			    ndecay != si->tins[t].decaying_flows ||
			    nblue != si->tins[t].unresponsive_flows)
				bad |= 0x80;
		}
		for (i = 0; i < si->tin_cnt * si->flows_cnt; i++) {
			f = &si->flows[i];
			if (f->active != (f->set != CAKE_SET_NONE))
				bad |= 0x80;
			if (f->active)
				active++;
			else if (f->mq.head != NULL || f->stats.length != 0)
				bad |= 0x10;
			for (n = 0, m = f->mq.head; m != NULL; m = m->m_nextpkt)
				n++;
			if (n != f->stats.length)
				bad |= 0x20;
		}
		/* every flow knows its place in the overflow heap */
		for (i = 0; i < si->tin_cnt * si->flows_cnt; i++) {
			uint32_t e = si->overflow_heap[si->flows[i].heap_idx];

			if (CAKE_HEAP_TIN(e) * si->flows_cnt +
			    CAKE_HEAP_FLOW(e) != i)
				bad |= 0x100;
		}
		if (active != listed)
			bad |= 0x40;
	}

	if (bad) {
		cake_check_errors++;
		if (cake_check_errors <= 10)
			printf("cake_check %s: bad 0x%x pkts %ju/%u bytes %ju/%u\n",
			    where, bad, (uintmax_t)pkts, si->main_q.ni.length,
			    (uintmax_t)bytes, si->main_q.ni.len_bytes);
	}
}
#define	CAKE_CHECK(si, where)	cake_check(si, where)

/*
 * Allocation failure injection for test builds: fail_alloc fails the
 * table allocations whose bits are set, bit 0 the next one, and is
 * consumed one bit per allocation; fail_alloc_all fails all of them
 * while set, leaving fail_alloc for when it is cleared. rebuilds and
 * rebuild_failures count the outcomes of reconfigurations that need new
 * tables, adoptions the instances that took over a kept state.
 */
static u_int cake_fail_alloc, cake_fail_alloc_all;
static u_int cake_rebuilds, cake_rebuild_failures, cake_adoptions;
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, fail_alloc,
	CTLFLAG_RW, &cake_fail_alloc, 0, "CAKE_DEBUG allocations to fail");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, fail_alloc_all,
	CTLFLAG_RW, &cake_fail_alloc_all, 0, "CAKE_DEBUG fail all allocations");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, rebuilds,
	CTLFLAG_RD, &cake_rebuilds, 0, "CAKE_DEBUG table rebuilds");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, rebuild_failures,
	CTLFLAG_RD, &cake_rebuild_failures, 0, "CAKE_DEBUG failed rebuilds");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, adoptions,
	CTLFLAG_RD, &cake_adoptions, 0, "CAKE_DEBUG kept states adopted");

/*
 * The link clock's clamp (cake_link_now()): of its reads for a choice of
 * tin (enqueue and drops read it too, when it may run ahead), how many found
 * it more than a tick behind the real time (pulled forward) or ahead of
 * it (pulled back), and the largest correction each way, in us.
 */
static u_int cake_link_reads, cake_link_behind, cake_link_ahead;
static u_int cake_link_behind_max, cake_link_ahead_max;
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, link_reads,
	CTLFLAG_RW, &cake_link_reads, 0, "CAKE_DEBUG link clock reads");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, link_behind,
	CTLFLAG_RW, &cake_link_behind, 0, "CAKE_DEBUG link clock pulled forward");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, link_behind_max,
	CTLFLAG_RW, &cake_link_behind_max, 0, "CAKE_DEBUG largest pull forward, us");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, link_ahead,
	CTLFLAG_RW, &cake_link_ahead, 0, "CAKE_DEBUG link clock pulled back");
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, link_ahead_max,
	CTLFLAG_RW, &cake_link_ahead_max, 0, "CAKE_DEBUG largest pull back, us");

static void
cake_link_stat(uint64_t t, uint64_t lo, uint64_t now)
{
	u_int us;

	cake_link_reads++;
	if (t < lo) {
		cake_link_behind++;
		us = (u_int)MIN((lo - t) / 1000, UINT_MAX);
		cake_link_behind_max = MAX(cake_link_behind_max, us);
	} else if (t > now) {
		cake_link_ahead++;
		us = (u_int)MIN((t - now) / 1000, UINT_MAX);
		cake_link_ahead_max = MAX(cake_link_ahead_max, us);
	}
}
#define	CAKE_LINK_STAT(t, lo, now)	cake_link_stat(t, lo, now)

static void *
cake_alloc(size_t n, size_t size)
{
	if (cake_fail_alloc_all)
		return (NULL);
	if (cake_fail_alloc & 1) {
		cake_fail_alloc >>= 1;
		return (NULL);
	}
	cake_fail_alloc >>= 1;
	return (mallocarray(n, size, M_DUMMYNET, M_NOWAIT | M_ZERO));
}
#define	CAKE_COUNT(c)		((c)++)
#else
#define	CAKE_CHECK(si, where)	do { } while (0)
#define	cake_alloc(n, size)	mallocarray(n, size, M_DUMMYNET, M_NOWAIT | M_ZERO)
#define	CAKE_COUNT(c)		do { } while (0)
#define	CAKE_LINK_STAT(t, lo, now)	do { } while (0)
#endif

/*
 * Enqueue a packet into the flow selected by its tin and 5-tuple.
 */
static int
cake_enqueue(struct dn_sch_inst *_si, struct dn_queue *_q,
	struct mbuf *m)
{
	struct cake_si *si;
	struct cake_schk *schk;
	struct cake_tin *tin;
	struct cake_flow *f;
	struct mbuf *ack;
	uint64_t now_ns;
	uint32_t hash, srch, dsth;
	uint8_t dscp, t;

	si = (struct cake_si *)_si;
	schk = (struct cake_schk *)(si->_si.sched+1);
	now_ns = cake_now_ns();

	if (__predict_false(CAKE_STALE(si, schk)))
		cake_reconfig(si, schk);

	/* an empty packet would be queued but not counted, as the counters
	 * go by the length's sign (dummynet never passes one) */
	if (__predict_false(m->m_pkthdr.len <= 0)) {
		si->main_q.ni.drops++;
		si->_si.ni.drops++;
		V_dn_cfg.io_pkt_drop++;
		FREE_PKT(m);
		return 1;
	}

	hash = cake_hash_flow(m, si->perturbation, si->flow_mode, &dscp,
	    &srch, &dsth);
	t = si->dscp_map[dscp];
	tin = &si->tins[t];
	if ((si->cfg.flags & CAKE_WASH) && dscp != 0)
		cake_wash(m);
	f = cake_lookup_flow(si, t, hash);
	if (cake_dsrc(si->flow_mode) || cake_ddst(si->flow_mode))
		cake_set_hosts(si, f, srch, dsth);

	/* as sch_cake's shaper: an idle link without debt starts again now */
	if (si->main_q.ni.length == 0 && si->link_time < now_ns) {
		si->link_time = now_ns;
		si->failsafe_time = now_ns;
	}

	/* an idle tin's clock is stale: do not let it claim old credit, but
	 * let it be due on the link clock that cake_dequeue() goes by */
	if (si->shaped && tin->backlog == 0) {
		uint64_t link_ns = cake_link_now(si, now_ns, 0);

		if (tin->time_next < link_ns)
			tin->time_next = link_ns;
	}

	/* cake_flow_enqueue() only fails when it cannot timestamp a packet */
	if (cake_flow_enqueue(f, m, si)) {
		CAKE_CHECK(si, "enqueue drop");
		return 1;
	}

	/*
	 * An inactive or decaying flow goes to the tail of the tin's new
	 * (sparse) flows with a full quantum; a decaying one keeps its
	 * COBALT state. A flow that ran out of quantum while empty, still
	 * counted as sparse but in the old rotation, becomes bulk.
	 */
	if (!f->active || f->set == CAKE_SET_DECAYING) {
		if (f->active) {
			TAILQ_REMOVE(&tin->decayingflows, f, flowchain);
			tin->decaying_flows--;
		}
		TAILQ_INSERT_TAIL(&tin->newflows, f, flowchain);
		f->set = CAKE_SET_SPARSE;
		tin->sparse_flows++;
		f->deficit = cake_flow_quantum(si, f);
		f->active = 1;
	} else if (f->set == CAKE_SET_SPARSE_WAIT) {
		f->set = CAKE_SET_BULK;
		tin->sparse_flows--;
		tin->bulk_flows++;
		cake_host_bulk(si, f, 1);
	}

	if (si->cfg.flags & CAKE_ACK_FILTER) {
		ack = cake_ack_filter(f,
		    (si->cfg.flags & CAKE_ACK_AGGRESSIVE) != 0);
		if (ack != NULL) {
			tin->ack_drops++;
			if (si->cfg.flags & CAKE_INGRESS)
				cake_charge_link(si, tin,
				    cake_wire_bytes(&si->cfg, ack), now_ns);
			cake_update_stats(f, si, -ack->m_pkthdr.len, 1);
			FREE_PKT(ack);
		}
	}

	/* the flow's backlog grew: keep a warm heap up to date */
	if (si->overflow_timeout)
		cake_heapify_up(si, f->heap_idx);

	/* over the packet or byte limit: drop from the fattest flow, which
	 * is usually not the one this packet went to, so report the enqueue
	 * as a success.
	 */
	while (si->main_q.ni.length > si->cfg.limit ||
	    si->main_q.ni.len_bytes > si->buffer_limit)
		if (!cake_drop_fattest(si, now_ns))
			break;

	CAKE_CHECK(si, "enqueue");
	return 0;
}

/*
 * The link clock: dummynet asks for a tick's worth of packets at once,
 * all at the same time, where sch_cake's shaper asks for each when the
 * link is free. Tin selection and the tin clocks depend on that time:
 * with every tin over its threshold, the earliest clock sends and moves
 * to now plus the packet's time at the tin's rate, so in batches a tin
 * waits for the next tick where sch_cake would send it earlier (Bulk
 * against greedy Voice got 13% less at kern.hz=1000). So they use the
 * time each packet would leave a link paced at the pipe's rate: the
 * previous one's plus its own length at that rate (and in ingress mode
 * the drops', up to the failsafe), never ahead of now and at most one
 * release interval (a tick on a stock dummynet, DN_RELEASE_NS) behind
 * it, or, while the queue has been backlogged since the last send, as
 * far back as that send: a release that came late (a late tick) sends
 * what the link would have sent since. COBALT keeps the real time, as a
 * packet may have arrived after its slot on the link. link_clock=0 goes
 * back to dummynet's time.
 */
static u_int cake_link_clock = 1;
SYSCTL_UINT(_net_inet_ip_dummynet_cake, OID_AUTO, link_clock,
	CTLFLAG_RW, &cake_link_clock, 0,
	"Pace tin selection by the link's time, not dummynet's tick");

/* a packet's time on the link, at the pipe's rate, as sch_cake's shaper */
static __inline uint64_t
cake_link_dur(struct cake_si *si, uint32_t len)
{
	return (((uint64_t)len * si->link_rate_ns) >> si->link_rate_shft);
}

/* decide: a read for cake_dequeue()'s choice of tin, for CAKE_LINK_STAT */
static __inline uint64_t
cake_link_now(struct cake_si *si, uint64_t now, int decide)
{
	uint64_t window = DN_RELEASE_NS, t = si->link_time, lo;

	if (!cake_link_clock)
		return (now);
	if (si->cfg.flags & CAKE_INGRESS)
		t = MIN(t, si->failsafe_time);
	lo = now - MIN(now, window);
	/* backlogged since the pipe's previous release, the link could have
	 * sent ever since: a late release's batch covers that span */
	if (si->main_q.ni.length > 0 && si->link_prev != 0 && si->link_prev < lo)
		lo = si->link_prev;
	if (decide)
		CAKE_LINK_STAT(t, lo, now);
	return (MIN(MAX(t, lo), now));
}

/*
 * sch_cake's failsafe, for ingress mode, where drops charge the link: its
 * shaper sends at the earlier of the time the link is free, drops
 * included, and the failsafe time, which only sends advance, by 1.5 times
 * their duration. cake_charge_link() keeps the pipe's drop debt within it.
 * Sends advance it from their time on the link clock: from dummynet's,
 * a tick's batch would put it 1.5 ticks ahead, and the pipe would send
 * every other tick.
 */
static __inline void
cake_failsafe(struct cake_si *si, uint32_t len, uint64_t link_ns)
{
	uint64_t dur = cake_link_dur(si, len);

	si->failsafe_time = MAX(si->failsafe_time, link_ns) + dur + dur / 2;
}

/*
 * Select a tin when the pipe has a rate, as sch_cake does in shaped mode.
 * Tins are numbered in priority order (Best Effort < Bulk < Video < Voice,
 * as in sch_cake), so pick the highest-numbered tin whose virtual clock is
 * due, i.e. that is within its rate share; otherwise the tin with the
 * earliest clock, the last of equal ones. Bulk thus gets priority over
 * Best Effort up to its 1/16 share, and nothing beyond it. As in sch_cake,
 * a tin counts while it has sparse or bulk flows, even empty ones, so that
 * flows that emptied are visited and stop counting as bulk.
 */
static uint32_t
cake_select_tin(struct cake_si *si, uint64_t now)
{
	struct cake_tin *tin;
	int t, due = -1, earliest = -1;

	for (t = 0; t < (int)si->tin_cnt; t++) {
		tin = &si->tins[t];
		if (tin->sparse_flows + tin->bulk_flows == 0)
			continue;
		if (tin->time_next <= now)
			due = t;
		else if (earliest < 0 ||
		    tin->time_next <= si->tins[earliest].time_next)
			earliest = t;
	}
	if (due >= 0)
		return (due);
	return (earliest >= 0 ? earliest : 0);
}

/*
 * Advance a tin's virtual clock by a packet's time at the tin's rate, as
 * in sch_cake's cake_advance_shaper(): a clock behind now keeps its credit
 * while the tin stays backlogged, a clock ahead of now moves to at least
 * now + duration. cake_enqueue() resets the clock of a tin that was idle.
 */
static __inline void
cake_charge_tin(struct cake_tin *tin, int len, uint64_t now)
{
	uint64_t dur = ((uint64_t)len * tin->rate_ns) >> tin->rate_shft;

	if (tin->time_next < now)
		tin->time_next += dur;
	else if (tin->time_next < now + dur)
		tin->time_next = now + dur;
}

/*
 * Dequeue a packet: pick a tin (rate thresholds when the pipe has a rate,
 * WDRR otherwise), then DRR between the flows of that tin, new flows first.
 * As in sch_cake, the first flow visited in each call is a decaying one if
 * there is any, so that empty flows' COBALT state decays to rest.
 */
static struct mbuf *
cake_dequeue(struct dn_sch_inst *_si)
{
	struct cake_si *si;
	struct cake_schk *schk;
	struct cake_tin *tin;
	struct cake_flow *f;
	struct cake_flow_list *list;
	struct mbuf *m;
	uint64_t now_ns, link_ns = 0;
	uint32_t len, idle_tins = 0;
	int first_flow = 1, retry;

	si = (struct cake_si *)_si;
	schk = (struct cake_schk *)(si->_si.sched+1);
	now_ns = cake_now_ns();

	/* a rate change reaches a backlog without waiting for new packets */
	if (__predict_false(CAKE_STALE(si, schk)))
		cake_reconfig(si, schk);

	/* a new release: serve_sched() stamps each with its time */
	if (si->_si.sched_time != si->link_batch) {
		si->link_batch = si->_si.sched_time;
		si->link_prev = si->link_cur;
		si->link_cur = now_ns;
	}

	for (;;) {
		/* packets may have been dropped by COBALT on the way */
		if (si->main_q.ni.length == 0) {
			CAKE_CHECK(si, "dequeue empty");
			return NULL;
		}

		if (si->shaped) {
			link_ns = cake_link_now(si, now_ns, 1);
			si->cur_tin = cake_select_tin(si, link_ns);
			tin = &si->tins[si->cur_tin];
		} else {
			/* WDRR between the tins with flows, as sch_cake's
			 * unlimited mode: skip a tin while its deficit is
			 * negative, refilling it while not positive */
			tin = &si->tins[si->cur_tin];
			if (tin->tin_deficit < 0 ||
			    tin->sparse_flows + tin->bulk_flows == 0) {
				if (tin->tin_deficit <= 0)
					tin->tin_deficit += tin->tin_quantum;
				si->cur_tin = (si->cur_tin + 1) % si->tin_cnt;
				if (tin->sparse_flows + tin->bulk_flows == 0 &&
				    ++idle_tins > 2 * si->tin_cnt)
					return NULL;	/* no tin has flows */
				continue;
			}
		}

retry:
		/* select a list to start with */
		if (first_flow && !TAILQ_EMPTY(&tin->decayingflows))
			list = &tin->decayingflows;
		else if (!TAILQ_EMPTY(&tin->newflows))
			list = &tin->newflows;
		else
			list = &tin->oldflows;
		first_flow = 0;

		f = TAILQ_FIRST(list);
		if (f == NULL) {
			/* packets queued but no flows listed: stats are
			 * broken */
			D("tin %u has backlog %u but no flows", si->cur_tin,
			    tin->backlog);
			return NULL;
		}

		/* out of deficit: refill and move to the tail of old flows.
		 * A flow that used up a quantum and still has packets is bulk
		 * and counts against its hosts' share; one that is empty stays
		 * counted as sparse until it gets a packet (SPARSE_WAIT).
		 */
		if (f->deficit <= 0) {
			if (f->set == CAKE_SET_SPARSE) {
				if (f->mq.head != NULL) {
					f->set = CAKE_SET_BULK;
					tin->sparse_flows--;
					tin->bulk_flows++;
					cake_host_bulk(si, f, 1);
				} else
					f->set = CAKE_SET_SPARSE_WAIT;
			}
			f->deficit += cake_flow_quantum(si, f);
			TAILQ_REMOVE(list, f, flowchain);
			TAILQ_INSERT_TAIL(&tin->oldflows, f, flowchain);
			continue;
		}

		m = cake_flow_dequeue(f, si, now_ns, &retry);
		if (m == NULL && retry)
			goto retry;
		if (m == NULL) {
			/* The flow is empty. As in sch_cake, it stays on the
			 * decaying list while its COBALT state is not at rest
			 * (BLUE active, a drop count, or active within an
			 * interval), so that state carries over if it gets
			 * packets again and its hash slot is not reused;
			 * otherwise it is deactivated. Either way its next
			 * packet puts it among the new flows.
			 */
			if (cobalt_queue_empty(&f->cvars, &tin->cparams, now_ns))
				tin->unresponsive_flows--;
			TAILQ_REMOVE(list, f, flowchain);
			if (f->set == CAKE_SET_BULK) {
				tin->bulk_flows--;
				cake_host_bulk(si, f, -1);
			} else if (f->set == CAKE_SET_DECAYING)
				tin->decaying_flows--;
			else
				tin->sparse_flows--;
			if (f->cvars.p_drop || f->cvars.count ||
			    (int64_t)(now_ns - f->cvars.drop_next) < 0) {
				TAILQ_INSERT_TAIL(&tin->decayingflows, f,
				    flowchain);
				f->set = CAKE_SET_DECAYING;
				tin->decaying_flows++;
			} else {
				f->set = CAKE_SET_NONE;
				f->active = 0;
			}
			continue;
		}

		/* account in link bytes, as the pipe charges them */
		len = cake_wire_bytes(&si->cfg, m);
		f->deficit -= len;
		if (si->shaped) {
			cake_charge_tin(tin, len, link_ns);
			si->link_time = link_ns + cake_link_dur(si, len);
		} else
			tin->tin_deficit -= len;
#ifndef DN_WIRE_LEN
		/* the pipe charges the packet length; charge it the rest */
		if (si->shaped)
			si->_si.credit -= (int64_t)DN_CREDIT_HZ * 8 *
			    ((int64_t)len - m->m_pkthdr.len);
#endif
		if (si->shaped && (si->cfg.flags & CAKE_INGRESS))
			cake_failsafe(si, len, link_ns);
		/* a heap untouched for 65535 packets has gone cold */
		if (si->overflow_timeout)
			si->overflow_timeout--;
		CAKE_CHECK(si, "dequeue");
		return m;
	}

	/* unreachable point */
	return NULL;
}

/*
 * A share (of 65536) of the pipe's rate bw, in bit/s, as sch_cake's
 * cake_set_rate() keeps a rate: ns per byte, scaled to stay below 2^34.
 * Returns the rate in bytes per second, as sch_cake's.
 */
static uint64_t
cake_rate_ns(uint32_t bw, uint32_t share, uint64_t *ns, uint8_t *shft)
{
	uint64_t rate = MAX((((uint64_t)bw * share) >> 16) / 8, 64);

	*shft = 34;
	*ns = (1000000000ULL << 34) / rate;
	while (*ns >> 34) {
		*ns >>= 1;
		(*shft)--;
	}
	return (rate);
}

/* the link clock's rate: sch_cake's global shaper's, its full-rate tin's */
static void
cake_link_params(struct cake_si *si)
{
	si->link_rate_ns = 0;
	si->link_rate_shft = 0;
	if (si->bw != 0)
		cake_rate_ns(si->bw, 65536, &si->link_rate_ns,
		    &si->link_rate_shft);
}

/*
 * Set a tin's rate share, WDRR weight and COBALT parameters, at creation
 * and when the scheduler is reconfigured. As in sch_cake's
 * cake_set_rate(), target and interval are stretched when an MTU takes
 * longer than target to send at the tin's share of the link rate.
 * dummynet only releases packets once per tick (DN_RELEASE_GRAIN_NS;
 * a dummynet with a finer release clock sets it), so a tick longer than
 * target (e.g. kern.hz=100 in VMs) is treated the same way; otherwise
 * the batching delay alone looks like a standing queue to COBALT.
 */
static void
cake_tin_params(struct cake_si *si, uint32_t t, struct dn_sch_cake_parms *cfg,
	uint32_t bw)
{
	struct cake_tin *tin = &si->tins[t];
	struct cobalt_params *cp = &tin->cparams;
	uint32_t share = cake_tin_share[cfg->diffserv][t];
	uint64_t rate, granularity;

	tin->tin_quantum = ((uint64_t)(cfg->quantum << CAKE_TIN_QUANTUM_SHIFT) *
	    share) >> 16;
	tin->rate_ns = 0;
	tin->rate_shft = 0;
	tin->flow_quantum = cfg->quantum;

	cp->mtu_time = 0;
	if (bw != 0) {
		rate = cake_rate_ns(bw, share, &tin->rate_ns, &tin->rate_shft);
		cp->mtu_time = ((uint64_t)CAKE_MTU * tin->rate_ns) >>
		    tin->rate_shft;
		/* the tin's bytes per second over 4096, at least 300 and at
		 * most the configured quantum (sch_cake's is fixed at 1514),
		 * so slow tins interleave their flows in smaller pieces */
		tin->flow_quantum = MIN(MAX(rate >> 12, 300), cfg->quantum);
	}
	granularity = MAX(cp->mtu_time, DN_RELEASE_GRAIN_NS);
	cp->target = MAX(granularity * 3 / 2, cfg->target * 1000);
	cp->interval = MAX(cfg->interval * 1000 + cp->target -
	    cfg->target * 1000, cp->target * 2);
	cp->p_inc = 1 << 24;
	cp->p_dec = 1 << 20;
}

/*
 * The byte limit, as sch_cake's cake_reconfigure(): memlimit if set, else
 * four times what the link sends in an interval and at least 4 MB, but
 * not beyond what the packet limit allows unless memlimit says so.
 */
static void
cake_buffer_limit(struct cake_si *si, struct dn_sch_cake_parms *cfg,
	uint32_t bw)
{
	uint64_t limit, mem = (uint64_t)cfg->memlimit << 10;

	if (mem != 0)
		limit = mem;
	else if (bw != 0)
		limit = MAX((uint64_t)bw / 8 * cfg->interval * 4 / 1000000,
		    4ULL << 20);
	else
		limit = UINT64_MAX;
	si->buffer_limit = MIN(limit,
	    MAX((uint64_t)cfg->limit * CAKE_MTU, mem));
}

/*
 * Allocate and initialize an instance's flow and host tables and tins for
 * the scheduler's current configuration. The old tables, if any, are left
 * to the caller.
 */
static int
cake_new_tables(struct cake_si *si, struct cake_schk *schk)
{
	static struct timeval lastfail;
	static int failpps;
	struct dn_sch_cake_parms *cfg = &schk->cfg;
	struct cake_flow *flows;
	struct cake_host *hosts;
	uint32_t *heap;
	uint32_t i, j, n, bw;

	n = cake_tin_cnt[cfg->diffserv] * cfg->flows_cnt;
	flows = cake_alloc(n, sizeof(struct cake_flow));
	hosts = cake_alloc(n, sizeof(struct cake_host));
	heap = cake_alloc(CAKE_MAX_TINS * cfg->flows_cnt, sizeof(uint32_t));
	if (flows == NULL || hosts == NULL || heap == NULL) {
		/* a failed rebuild is retried on every packet */
		if (ppsratecheck(&lastfail, &failpps, 1))
			D("cannot allocate memory for cake flows");
		free(flows, M_DUMMYNET);
		free(hosts, M_DUMMYNET);
		free(heap, M_DUMMYNET);
		return ENOMEM ;
	}

	si->flows = flows;
	si->hosts = hosts;
	si->overflow_heap = heap;
	si->overflow_timeout = 0;
	si->tin_cnt = cake_tin_cnt[cfg->diffserv];
	si->flows_cnt = cfg->flows_cnt;
	si->dscp_map = cake_dscp_maps[cfg->diffserv];
	si->flow_mode = cfg->flow_mode;
	si->cur_tin = 0;
	si->cfg = *cfg;
	si->gen = schk->gen;

	bw = si->_si.sched->link.bandwidth;
	si->bw = bw;
	si->shaped = bw != 0;
	cake_link_params(si);
	cake_buffer_limit(si, cfg, bw);
	for (i = 0; i < si->tin_cnt; i++) {
		TAILQ_INIT(&si->tins[i].newflows);
		TAILQ_INIT(&si->tins[i].oldflows);
		TAILQ_INIT(&si->tins[i].decayingflows);
		si->tins[i].time_next = 0;
		si->tins[i].backlog = 0;
		si->tins[i].backlog_bytes = 0;
		si->tins[i].sparse_flows = 0;
		si->tins[i].bulk_flows = 0;
		si->tins[i].decaying_flows = 0;
		si->tins[i].unresponsive_flows = 0;
		cake_tin_params(si, i, cfg, bw);
		si->tins[i].tin_deficit = si->tins[i].tin_quantum;
	}

	for (i = 0; i < n; i++) {
		flows[i].tin = i / si->flows_cnt;
		cobalt_vars_init(&flows[i].cvars);
	}
	/* entry j * CAKE_MAX_TINS + t holds flow j of tin t, as in cake_init() */
	for (j = 0; j < si->flows_cnt; j++)
		for (i = 0; i < CAKE_MAX_TINS; i++) {
			heap[j * CAKE_MAX_TINS + i] = j << 3 | i;
			if (i < si->tin_cnt)
				flows[i * si->flows_cnt + j].heap_idx =
				    j * CAKE_MAX_TINS + i;
		}
	return 0;
}

/*
 * Drop every packet queued in replaced tables and free them. The tins
 * already belong to the new tables, so only the instance totals change.
 */
static void
cake_free_tables(struct cake_si *si, struct cake_flow *flows,
	struct cake_host *hosts, uint32_t *heap, uint32_t n)
{
	struct mbuf *m;
	uint32_t i;

	for (i = 0; i < n; i++) {
		while ((m = flows[i].mq.head) != NULL) {
			flows[i].mq.head = m->m_nextpkt;
			si->main_q.ni.length--;
			si->main_q.ni.len_bytes -= m->m_pkthdr.len;
			si->_si.ni.length--;
			si->_si.ni.len_bytes -= m->m_pkthdr.len;
			si->main_q.ni.drops++;
			si->_si.ni.drops++;
			V_dn_cfg.io_pkt_drop++;
			FREE_PKT(m);
		}
	}
	if (si->main_q.ni.length == 0)
		si->main_q.q_time = V_dn_cfg.curr_time;
	free(flows, M_DUMMYNET);
	free(hosts, M_DUMMYNET);
	free(heap, M_DUMMYNET);
}

/*
 * dummynet reconfigures a scheduler of unchanged type and mask in place
 * and keeps its instances, so bring an instance in line with the new
 * configuration (and pipe rate) when it next sees a packet. Rates and AQM
 * parameters change live; a new tin count, flow count or isolation mode
 * needs new tables, and the packets queued in the old ones are dropped.
 * If they cannot be allocated the instance keeps running on its old
 * tables and its own copy of the old configuration, and tries again.
 */
static void
cake_reconfig(struct cake_si *si, struct cake_schk *schk)
{
	struct dn_sch_cake_parms *cfg = &schk->cfg;
	struct cake_flow *flows = si->flows;
	struct cake_host *hosts = si->hosts;
	uint32_t *heap = si->overflow_heap;
	uint32_t i, n, bw;

	if (cake_tin_cnt[cfg->diffserv] == si->tin_cnt &&
	    cfg->flows_cnt == si->flows_cnt && cfg->flow_mode == si->flow_mode) {
		bw = si->_si.sched->link.bandwidth;
		si->bw = bw;
		si->shaped = bw != 0;
		cake_link_params(si);
		cake_buffer_limit(si, cfg, bw);
		for (i = 0; i < si->tin_cnt; i++)
			cake_tin_params(si, i, cfg, bw);
		si->cfg = *cfg;
		si->gen = schk->gen;
		return;
	}

	n = si->tin_cnt * si->flows_cnt;
	if (cake_new_tables(si, schk) != 0) {
		CAKE_COUNT(cake_rebuild_failures);
		return;		/* keep the old tables, try again later */
	}
	cake_free_tables(si, flows, hosts, heap, n);
	CAKE_COUNT(cake_rebuilds);
}

/*
 * Every CAKE instance and kept state, for net.inet.ip.dummynet.cake.stats.
 * The list has its own lock, as it spans every vnet's dummynet. Lock order:
 * dummynet's (DN_BH_WLOCK) first, then cake_instances_mtx; new_sched,
 * free_sched and destroy are called with dummynet's held, and the
 * statistics take both, so they copy counters no callback is changing.
 */
static LIST_HEAD(, cake_si) cake_instances =
    LIST_HEAD_INITIALIZER(cake_instances);
static LIST_HEAD(, cake_stash) cake_stashes =
    LIST_HEAD_INITIALIZER(cake_stashes);
static struct mtx cake_instances_mtx;
MTX_SYSINIT(cake_instances, &cake_instances_mtx, "dn_cake instances",
    MTX_DEF);

/*
 * Move tins with their flow lists, fixing the lists' back links to the
 * new heads.
 */
static void
cake_move_tins(struct cake_tin *dst, struct cake_tin *src, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		dst[i] = src[i];
		TAILQ_INIT(&dst[i].newflows);
		TAILQ_INIT(&dst[i].oldflows);
		TAILQ_INIT(&dst[i].decayingflows);
		TAILQ_CONCAT(&dst[i].newflows, &src[i].newflows, flowchain);
		TAILQ_CONCAT(&dst[i].oldflows, &src[i].oldflows, flowchain);
		TAILQ_CONCAT(&dst[i].decayingflows, &src[i].decayingflows,
		    flowchain);
	}
}

/* keep an idle instance's state with its scheduler */
static void
cake_stash(struct cake_si *si, struct cake_schk *schk)
{
	struct cake_stash *s = &schk->stash;

	s->flows = si->flows;
	s->hosts = si->hosts;
	s->overflow_heap = si->overflow_heap;
	s->overflow_timeout = si->overflow_timeout;
	cake_move_tins(s->tins, si->tins, si->tin_cnt);
	s->cfg = si->cfg;
	s->dscp_map = si->dscp_map;
	s->buffer_limit = si->buffer_limit;
	s->tin_cnt = si->tin_cnt;
	s->flows_cnt = si->flows_cnt;
	s->cur_tin = si->cur_tin;
	s->perturbation = si->perturbation;
	s->flow_mode = si->flow_mode;
	s->gen = si->gen;
	s->bw = si->bw;
	s->shaped = si->shaped;
	s->sched = si->_si.sched;
	s->vnet = si->vnet;
	si->flows = NULL;
	si->hosts = NULL;

	mtx_lock(&cake_instances_mtx);
	LIST_INSERT_HEAD(&cake_stashes, s, all);
	mtx_unlock(&cake_instances_mtx);
}

/*
 * Adopt the state kept with the scheduler. With a configuration changed
 * meanwhile, the generation differs and the next packet reconfigures it.
 */
static void
cake_adopt(struct cake_si *si, struct cake_schk *schk)
{
	struct cake_stash *s = &schk->stash;

	mtx_lock(&cake_instances_mtx);
	LIST_REMOVE(s, all);
	mtx_unlock(&cake_instances_mtx);

	si->flows = s->flows;
	si->hosts = s->hosts;
	si->overflow_heap = s->overflow_heap;
	si->overflow_timeout = s->overflow_timeout;
	cake_move_tins(si->tins, s->tins, s->tin_cnt);
	si->cfg = s->cfg;
	si->dscp_map = s->dscp_map;
	si->buffer_limit = s->buffer_limit;
	si->tin_cnt = s->tin_cnt;
	si->flows_cnt = s->flows_cnt;
	si->cur_tin = s->cur_tin;
	si->perturbation = s->perturbation;
	si->flow_mode = s->flow_mode;
	si->gen = s->gen;
	si->bw = s->bw;
	si->shaped = s->shaped;
	cake_link_params(si);
	s->flows = NULL;
	s->hosts = NULL;
	s->overflow_heap = NULL;
	CAKE_COUNT(cake_adoptions);
}

/*
 * Initialize cake scheduler instance.
 * also, allocate memory for flows array.
 */
static int
cake_new_sched(struct dn_sch_inst *_si)
{
	struct cake_si *si;
	struct dn_queue *q;
	struct cake_schk *schk;
	int error;

	si = (struct cake_si *)_si;
	schk = (struct cake_schk *)(_si->sched+1);

	if(si->flows) {
		D("si already configured!");
		return 0;
	}

	/* init the main queue */
	q = &si->main_q;
	set_oid(&q->ni.oid, DN_QUEUE, sizeof(*q));
	q->_si = _si;
	q->fs = _si->sched->fs;

	if (schk->stash.flows != NULL)
		cake_adopt(si, schk);
	else {
		/* init perturbation for this si */
		si->perturbation = random();
		cake_rng ^= (uint64_t)arc4random() << 32 | arc4random();

		error = cake_new_tables(si, schk);
		if (error != 0)
			return error;
	}

	si->vnet = curvnet;
	mtx_lock(&cake_instances_mtx);
	LIST_INSERT_HEAD(&cake_instances, si, all);
	si->listed = 1;
	mtx_unlock(&cake_instances_mtx);

	cake_desc.ref_count++;
	return 0;
}

/*
 * Free cake scheduler instance, including any packets still queued.
 */
static int
cake_free_sched(struct dn_sch_inst *_si)
{
	struct cake_si *si = (struct cake_si *)_si ;
	struct cake_schk *schk = (struct cake_schk *)(_si->sched+1);
	uint32_t i;

	if (si->listed) {
		mtx_lock(&cake_instances_mtx);
		LIST_REMOVE(si, all);
		si->listed = 0;
		mtx_unlock(&cake_instances_mtx);
	}
	/* an idle instance of a scheduler without a mask, as dummynet
	 * expires them: keep its state for the next instance */
	if (si->flows != NULL && si->main_q.ni.length == 0 &&
	    !(_si->sched->sch.flags & DN_HAVE_MASK) &&
	    schk->stash.flows == NULL) {
		cake_stash(si, schk);
		cake_desc.ref_count--;
	}
	if (si->flows != NULL) {
		for (i = 0; i < si->tin_cnt * si->flows_cnt; i++)
			dn_free_pkts(si->flows[i].mq.head);
		free(si->flows , M_DUMMYNET);
		free(si->hosts, M_DUMMYNET);
		free(si->overflow_heap, M_DUMMYNET);
		si->flows = NULL;
		si->hosts = NULL;
		si->overflow_heap = NULL;
		cake_desc.ref_count--;
	}

	return 0;
}

/*
 * Configure cake scheduler.
 * the configurations for the scheduler is passed from userland; an
 * unpatched ipfw(8) passes none, in which case the sysctl defaults apply.
 */
static int
cake_config(struct dn_schk *_schk)
{
	struct cake_schk *schk;
	struct dn_extra_parms *ep;
	struct dn_sch_cake_parms *cfg;
	uint32_t mask;

	schk = (struct cake_schk *)(_schk+1);
	ep = (struct dn_extra_parms *) _schk->cfg;
	cfg = &schk->cfg;

	/* dummynet refuses to unload a scheduler with references, but only
	 * instances take one; a configured scheduler without instances
	 * still points at this module, so it holds one too until destroyed */
	if (!schk->held) {
		schk->held = 1;
		cake_desc.ref_count++;
	}

	*cfg = cake_sysctl;
	schk->gen++;		/* instances pick the change up in enqueue */

	/* par array contains cake configuration as follow
	 * 0- target, 1- interval, 2- flags, 3- diffserv,
	 * 4- quantum, 5- limit, 6- flows, 7- flow mode,
	 * 8- overhead + 64, 9- mpu | framing << 16
	 */
	if (ep && ep->oid.len == sizeof(*ep) &&
		ep->oid.subtype == DN_SCH_PARAMS) {
		if (ep->par[0] >= 0)
			cfg->target = ep->par[0];
		if (ep->par[1] >= 0)
			cfg->interval = ep->par[1];
		if (ep->par[2] >= 0) {
			/* only the flags ipfw(8) was given; older ones send
			 * just ECN, without a mask */
			mask = (ep->par[2] >> CAKE_FLAGS_MASK_SHIFT) &
			    CAKE_FLAGS_ALL;
			if (mask == 0)
				mask = CAKE_ECN_ENABLED;
			cfg->flags = (cfg->flags & ~mask) | (ep->par[2] & mask);
		}
		if (ep->par[3] >= 0)
			cfg->diffserv = ep->par[3];
		if (ep->par[4] >= 0)
			cfg->quantum = ep->par[4];
		if (ep->par[5] >= 0) {
			if (ep->par[5] & 0xffffffff)
				cfg->limit = ep->par[5] & 0xffffffff;
			if (ep->par[5] >> 32)
				cfg->memlimit = ep->par[5] >> 32;
		}
		if (ep->par[6] >= 0)
			cfg->flows_cnt = ep->par[6];
		if (ep->par[7] >= 0)
			cfg->flow_mode = ep->par[7];
		if (ep->par[8] >= 0)
			cfg->overhead = ep->par[8] + CAKE_OVERHEAD_MIN;
		if (ep->par[9] >= 0) {
			cfg->mpu = ep->par[9] & 0xffff;
			cfg->atm = ep->par[9] >> 16;
		}
	}

	/* Bound the configurations */
	cfg->target = BOUND_VAR(cfg->target, 1, 5 * AQM_TIME_1S);
	cfg->interval = BOUND_VAR(cfg->interval, 1, 100 * AQM_TIME_1S);
	cfg->diffserv = BOUND_VAR(cfg->diffserv, 0, CAKE_DIFFSERV_MAX);
	cfg->flow_mode = BOUND_VAR(cfg->flow_mode, 0, CAKE_FLOW_MAX);
	cfg->overhead = BOUND_VAR(cfg->overhead, CAKE_OVERHEAD_MIN,
	    CAKE_OVERHEAD_MAX);
	cfg->mpu = BOUND_VAR(cfg->mpu, 0, CAKE_MPU_MAX);
	cfg->atm = BOUND_VAR(cfg->atm, 0, CAKE_ATM_MAX);
	cfg->flags &= CAKE_FLAGS_ALL;
	if (cfg->flags & CAKE_ACK_AGGRESSIVE)
		cfg->flags |= CAKE_ACK_FILTER;
	cfg->memlimit = BOUND_VAR(cfg->memlimit, 0, 4U << 20);	/* 4 GB */
	/* sch_cake's floor; a tiny quantum makes dequeue spin through
	 * many refill rounds per packet with the dummynet lock held */
	cfg->quantum = BOUND_VAR(cfg->quantum, 300, 9000);
	cfg->limit = BOUND_VAR(cfg->limit, 1, 65535);
	cfg->flows_cnt = BOUND_VAR(cfg->flows_cnt, CAKE_SET_WAYS, 65536);
	cfg->flows_cnt = roundup2(cfg->flows_cnt, CAKE_SET_WAYS);

	return 0;
}

/*
 * The scheduler is deleted, or changes type: drop its module reference.
 */
static int
cake_destroy(struct dn_schk *_schk)
{
	struct cake_schk *schk = (struct cake_schk *)(_schk+1);

	/* the instances are gone; free the state kept from the last one */
	if (schk->stash.flows != NULL) {
		mtx_lock(&cake_instances_mtx);
		LIST_REMOVE(&schk->stash, all);
		mtx_unlock(&cake_instances_mtx);
		free(schk->stash.flows, M_DUMMYNET);
		free(schk->stash.hosts, M_DUMMYNET);
		free(schk->stash.overflow_heap, M_DUMMYNET);
		schk->stash.flows = NULL;
		schk->stash.hosts = NULL;
		schk->stash.overflow_heap = NULL;
	}
	if (schk->held) {
		schk->held = 0;
		cake_desc.ref_count--;
	}
	return 0;
}

/*
 * net.inet.ip.dummynet.cake.stats: a line per tin of every CAKE instance
 * of the reader's vnet, for the plugin's statistics: the scheduler (pipe)
 * number, an instance number, the diffserv mode and tin, then the
 * counters as "name value" pairs. The snapshot is taken under dummynet's
 * lock, as dnctl's own statistics are, so it is consistent; it is
 * formatted and copied out after both locks are released, as that may
 * sleep. Its buffer is allocated with the locks released, so the entries
 * are counted again once they are held, and the allocation retried if
 * they no longer fit: nothing is left out.
 */
struct cake_tin_snap {
	uint32_t	sched, inst, diffserv, tin;
	uint64_t	rate;		/* bit/s, the tin's threshold; 0 unshaped */
	struct cake_tin	b;
};

static int
cake_sysctl_stats(SYSCTL_HANDLER_ARGS)
{
	struct cake_tin_snap *snap;
	struct cake_si *si;
	struct cake_stash *s;
	struct cake_tin *b;
	struct sbuf sb;
	u_int cap = 0, need, n = 0, inst = 0, i, t, tries;
	int error;

	snap = NULL;
	CURVNET_SET(TD_TO_VNET(curthread));
	for (tries = 0;; tries++) {
		DN_BH_WLOCK();
		mtx_lock(&cake_instances_mtx);
		need = 0;
		LIST_FOREACH(si, &cake_instances, all)
			if (si->vnet == curvnet)
				need += si->tin_cnt;
		LIST_FOREACH(s, &cake_stashes, all)
			if (s->vnet == curvnet)
				need += s->tin_cnt;
		if (snap != NULL && need <= cap)
			break;		/* it fits; both locks stay held */
		mtx_unlock(&cake_instances_mtx);
		DN_BH_WUNLOCK();
		free(snap, M_TEMP);
		if (tries == 10) {	/* instances keep appearing faster */
			CURVNET_RESTORE();
			return (EAGAIN);
		}
		/* with room for an instance or two created meanwhile */
		cap = need + 2 * CAKE_MAX_TINS;
		snap = malloc(cap * sizeof(*snap), M_TEMP, M_WAITOK);
	}

	LIST_FOREACH(si, &cake_instances, all) {
		if (si->vnet != curvnet)
			continue;
		for (t = 0; t < si->tin_cnt; t++, n++) {
			snap[n].sched = si->_si.sched->sch.sched_nr;
			snap[n].inst = inst;
			snap[n].diffserv = si->cfg.diffserv;
			snap[n].tin = t;
			snap[n].rate = ((uint64_t)si->_si.sched->link.bandwidth *
			    cake_tin_share[si->cfg.diffserv][t]) >> 16;
			snap[n].b = si->tins[t];
		}
		inst++;
	}
	/* kept from an expired instance: its counters, nothing queued */
	LIST_FOREACH(s, &cake_stashes, all) {
		if (s->vnet != curvnet)
			continue;
		for (t = 0; t < s->tin_cnt; t++, n++) {
			snap[n].sched = s->sched->sch.sched_nr;
			snap[n].inst = inst;
			snap[n].diffserv = s->cfg.diffserv;
			snap[n].tin = t;
			snap[n].rate = ((uint64_t)s->sched->link.bandwidth *
			    cake_tin_share[s->cfg.diffserv][t]) >> 16;
			snap[n].b = s->tins[t];
		}
		inst++;
	}
	mtx_unlock(&cake_instances_mtx);
	DN_BH_WUNLOCK();
	CURVNET_RESTORE();

	sbuf_new_for_sysctl(&sb, NULL, 512, req);
	for (i = 0; i < n; i++) {
		b = &snap[i].b;
		sbuf_printf(&sb, "sched %u inst %u diffserv %u tin %u "
		    "rate %ju target %ju interval %ju pkts %ju bytes %ju "
		    "drops %ju marks %ju ack_drops %ju backlog %u "
		    "backlog_bytes %ju sparse %u bulk %u decaying %u "
		    "unresponsive %u collisions %ju peak_delay %ju "
		    "avg_delay %ju base_delay %ju\n",
		    snap[i].sched, snap[i].inst, snap[i].diffserv, snap[i].tin,
		    (uintmax_t)snap[i].rate, (uintmax_t)b->cparams.target / 1000,
		    (uintmax_t)b->cparams.interval / 1000, (uintmax_t)b->tx_pkts,
		    (uintmax_t)b->tx_bytes, (uintmax_t)b->drops,
		    (uintmax_t)b->ecn_marks, (uintmax_t)b->ack_drops,
		    b->backlog, (uintmax_t)b->backlog_bytes, b->sparse_flows,
		    b->bulk_flows, b->decaying_flows, b->unresponsive_flows,
		    (uintmax_t)b->way_collisions, (uintmax_t)b->peak_delay / 1000,
		    (uintmax_t)b->avg_delay / 1000, (uintmax_t)b->base_delay / 1000);
	}
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	free(snap, M_TEMP);
	return (error);
}
SYSCTL_PROC(_net_inet_ip_dummynet_cake, OID_AUTO, stats,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    cake_sysctl_stats, "A", "CAKE per-tin statistics of every instance");

/*
 * Return cake scheduler configurations
 * the configurations for the scheduler is passed to userland.
 */
static int
cake_getconfig (struct dn_schk *_schk, struct dn_extra_parms *ep) {
	struct cake_schk *schk = (struct cake_schk *)(_schk+1);
	struct dn_sch_cake_parms *cfg;

	cfg = &schk->cfg;

	strcpy(ep->name, cake_desc.name);
	ep->par[0] = cfg->target;
	ep->par[1] = cfg->interval;
	ep->par[2] = cfg->flags;
	ep->par[3] = cfg->diffserv;
	ep->par[4] = cfg->quantum;
	ep->par[5] = cfg->limit | (int64_t)cfg->memlimit << 32;
	ep->par[6] = cfg->flows_cnt;
	ep->par[7] = cfg->flow_mode;
	ep->par[8] = cfg->overhead - CAKE_OVERHEAD_MIN;
	ep->par[9] = cfg->mpu | cfg->atm << 16;

	return 0;
}

/*
 * cake scheduler descriptor
 * contains the type of the scheduler, the name, the size of extra
 * data structures, and function pointers.
 */
static struct dn_alg cake_desc = {
	_SI( .type = )  DN_SCHED_CAKE,
	_SI( .name = ) "CAKE",
#ifdef DN_WIRE_LEN
	_SI( .flags = ) DN_WIRE_LEN,	/* overhead compensation */
#else
	_SI( .flags = ) 0,		/* dummynet without wire_len */
#endif

	_SI( .schk_datalen = ) sizeof(struct cake_schk),
	_SI( .si_datalen = ) sizeof(struct cake_si) - sizeof(struct dn_sch_inst),
	_SI( .q_datalen = ) 0,

	_SI( .enqueue = ) cake_enqueue,
	_SI( .dequeue = ) cake_dequeue,
	_SI( .config = ) cake_config, /* new sched i.e. sched X config ...*/
	_SI( .destroy = ) cake_destroy,  /*sched x delete */
	_SI( .new_sched = ) cake_new_sched, /* new schd instance */
	_SI( .free_sched = ) cake_free_sched,	/* delete schd instance */
	_SI( .new_fsk = ) NULL,
	_SI( .free_fsk = ) NULL,
	_SI( .new_queue = ) NULL,
	_SI( .free_queue = ) NULL,
	_SI( .getconfig = )  cake_getconfig,
	_SI( .ref_count = ) 0,
#ifdef DN_WIRE_LEN
	_SI( .wire_len = ) cake_wire_len,
#endif
};

DECLARE_DNSCHED_MODULE(dn_cake, &cake_desc);
