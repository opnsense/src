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
 * CAKE structures
 */

#ifndef _IP_DN_SCHED_CAKE_H
#define _IP_DN_SCHED_CAKE_H

#define DN_SCHED_CAKE	8	/* first type number not used in-tree */

#define CAKE_MAX_TINS	8
#define CAKE_SET_WAYS	8	/* set-associative flow hash */

#define DN_CAKE_MTAG_TS	55346	/* uint64_t enqueue timestamp, ns */

/*
 * flags, par[2]. ipfw(8) sends the bits it was given in the low 16 bits
 * and which bits those are in the next 16, so that e.g. "wash" alone
 * leaves ECN at its default; a mask of 0 is the older ECN-only form.
 */
enum {
	CAKE_ECN_ENABLED = 0x01,	/* ecn / noecn */
	CAKE_WASH = 0x02,		/* clear DSCP after classifying */
	CAKE_ACK_FILTER = 0x04,		/* drop redundant pure TCP ACKs */
	CAKE_ACK_AGGRESSIVE = 0x08,	/* ... also a lone redundant one */
	CAKE_INGRESS = 0x10,		/* drops still used the link */
	CAKE_FLAGS_ALL = 0x1f
};
#define	CAKE_FLAGS_MASK_SHIFT	16

/* diffserv modes, par[3] */
enum {
	CAKE_DIFFSERV_BESTEFFORT = 0,
	CAKE_DIFFSERV_DIFFSERV3 = 1,
	CAKE_DIFFSERV_DIFFSERV4 = 2,
	CAKE_DIFFSERV_DIFFSERV8 = 3,
	CAKE_DIFFSERV_PRECEDENCE = 4,
	CAKE_DIFFSERV_MAX = CAKE_DIFFSERV_PRECEDENCE
};

/*
 * flow isolation modes, par[7]; values and names as in sch_cake.
 * FLOWS hashes the 5-tuple, SRC_IP/DST_IP the hosts. With FLOWS, the host
 * bits instead share each host's quantum between its bulk flows.
 */
enum {
	CAKE_FLOW_NONE = 0,		/* flowblind */
	CAKE_FLOW_SRC_IP = 1,		/* srchost */
	CAKE_FLOW_DST_IP = 2,		/* dsthost */
	CAKE_FLOW_HOSTS = 3,		/* hosts */
	CAKE_FLOW_FLOWS = 4,		/* flows */
	CAKE_FLOW_DUAL_SRC = 5,		/* dual-srchost */
	CAKE_FLOW_DUAL_DST = 6,		/* dual-dsthost */
	CAKE_FLOW_TRIPLE = 7,		/* triple-isolate */
	CAKE_FLOW_MAX = CAKE_FLOW_TRIPLE
};

/* link-layer framing for overhead compensation */
enum {
	CAKE_ATM_NONE = 0,	/* noatm */
	CAKE_ATM_ATM = 1,	/* atm: 48 byte payload in 53 byte cells */
	CAKE_ATM_PTM = 2,	/* ptm: 64b/65b encoding */
	CAKE_ATM_MAX = CAKE_ATM_PTM
};

#define	CAKE_OVERHEAD_MIN	(-64)	/* as sch_cake */
#define	CAKE_OVERHEAD_MAX	256
#define	CAKE_MPU_MAX		256

/*
 * cake parameters, passed in dn_extra_parms.par[] as:
 * 0- target (us), 1- interval (us), 2- flags, 3- diffserv mode,
 * 4- quantum, 5- limit (packets) | memlimit (KB, 0 auto) << 32,
 * 6- flows per tin, 7- flow mode,
 * 8- overhead + 64 (bytes, so -1 can still mean unset),
 * 9- mpu (bytes) | framing << 16
 */
struct dn_sch_cake_parms {
	uint64_t	target;		/* CoDel target, us */
	uint64_t	interval;	/* CoDel interval, us */
	uint32_t	flags;
	uint32_t	diffserv;
	uint32_t	quantum;
	uint32_t	limit;		/* hard limit, packets, all tins */
	uint32_t	flows_cnt;	/* flows per tin, multiple of SET_WAYS */
	uint32_t	flow_mode;	/* CAKE_FLOW_* */
	int32_t		overhead;	/* bytes added per packet */
	uint32_t	mpu;		/* minimum packet size on the wire */
	uint32_t	atm;		/* CAKE_ATM_* */
	uint32_t	memlimit;	/* byte limit, KB; 0: from the rate */
};

/* per-tin COBALT parameters, derived from config and link rate */
struct cobalt_params {
	uint64_t	target;		/* ns */
	uint64_t	interval;	/* ns */
	uint64_t	mtu_time;	/* ns to send one MTU at tin rate */
	uint32_t	p_inc;		/* BLUE increment */
	uint32_t	p_dec;		/* BLUE decrement */
};

/* per-flow COBALT state (CoDel + BLUE) */
struct cobalt_vars {
	uint32_t	count;		/* CoDel drop count */
	uint32_t	rec_inv_sqrt;	/* 1/sqrt(count), Q0.32 */
	uint64_t	drop_next;	/* us */
	uint64_t	blue_timer;	/* us */
	uint32_t	p_drop;		/* BLUE drop probability, Q0.32 */
	uint16_t	dropping;	/* CoDel dropping state */
};

/* flow (sub-queue) stats */
struct cake_flow_stats {
	uint64_t tot_pkts;	/* statistics counters  */
	uint64_t tot_bytes;
	uint32_t length;	/* Queue length, in packets */
	uint32_t len_bytes;	/* Queue length, in bytes */
	uint32_t drops;
};

/* flow states, as sch_cake's */
enum {
	CAKE_SET_NONE = 0,	/* inactive */
	CAKE_SET_SPARSE,	/* active, has not used up a quantum backlogged */
	CAKE_SET_SPARSE_WAIT,	/* sparse, but empty in the old rotation */
	CAKE_SET_BULK,		/* active, counted in its hosts' bulk counts */
	CAKE_SET_DECAYING	/* empty, COBALT state not yet at rest */
};

/* A flow of packets (sub-queue). */
struct cake_flow {
	struct mq	mq;	/* list of packets */
	struct cake_flow_stats stats;	/* statistics */
	int32_t	deficit;
	uint32_t tag;		/* full flow hash, for set-assoc lookup */
	uint32_t srchost;	/* host table slots, within the tin */
	uint32_t dsthost;
	uint8_t	tin;		/* tin this flow belongs to */
	uint8_t	active;		/* 1: flow is in a list (any set but NONE) */
	uint8_t	set;		/* CAKE_SET_* */
	uint32_t heap_idx;	/* position in the overflow heap */
	struct cobalt_vars cvars;
	TAILQ_ENTRY(cake_flow) flowchain;
};

/* a host table slot; source and destination hosts are tracked separately */
struct cake_host {
	uint32_t	srchost_tag;
	uint32_t	dsthost_tag;
	uint32_t	srchost_bulk;	/* bulk flows from this source host */
	uint32_t	dsthost_bulk;	/* bulk flows to this destination host */
};

/* list of flows */
TAILQ_HEAD(cake_flow_list, cake_flow);

/* A tin: one diffserv class with its own flows and AQM parameters */
struct cake_tin {
	struct cake_flow_list newflows;	/* sparse flows */
	struct cake_flow_list oldflows;	/* bulk flows */
	struct cake_flow_list decayingflows; /* empty, COBALT decaying */
	struct cobalt_params cparams;
	uint64_t	time_next;	/* ns, virtual clock at the tin's rate */
	uint64_t	rate_ns;	/* ns per byte at the tin's rate share, */
	uint8_t		rate_shft;	/* shifted left by rate_shft */
	int32_t		tin_deficit;	/* WDRR, only used without a rate */
	uint32_t	tin_quantum;	/* WDRR weight between tins */
	uint32_t	flow_quantum;	/* DRR quantum of its flows, bytes */
	uint32_t	backlog;	/* packets queued in this tin */
	uint64_t	backlog_bytes;
	uint32_t	sparse_flows;	/* CAKE_SET_SPARSE and _SPARSE_WAIT */
	uint32_t	bulk_flows;	/* flows in CAKE_SET_BULK */
	uint32_t	decaying_flows;	/* flows in CAKE_SET_DECAYING */
	uint32_t	unresponsive_flows; /* flows with BLUE active */
	uint64_t	ecn_marks;
	uint64_t	drops;
	uint64_t	ack_drops;	/* removed by the ACK filter */
	uint64_t	tx_pkts;	/* dequeued and sent */
	uint64_t	tx_bytes;
	uint64_t	way_collisions;	/* flows that had to share a queue */
	/* queue delay of sent packets, ns, as sch_cake's EWMAs */
	uint64_t	peak_delay;
	uint64_t	avg_delay;
	uint64_t	base_delay;
};

/*
 * The CAKE state of an instance dummynet expired, kept with its scheduler
 * for the next instance to adopt (only without a mask): dummynet destroys
 * an instance as soon as nothing is queued, which would throw away and
 * reallocate the tables, COBALT and host state and the statistics.
 */
struct cake_stash {
	struct cake_flow *flows;	/* NULL: nothing kept */
	struct cake_host *hosts;
	uint32_t	*overflow_heap;
	uint32_t	overflow_timeout;
	struct cake_tin	tins[CAKE_MAX_TINS];
	struct dn_sch_cake_parms cfg;
	const uint8_t	*dscp_map;
	uint64_t	buffer_limit;
	uint32_t	tin_cnt;
	uint32_t	flows_cnt;
	uint32_t	cur_tin;
	uint32_t	perturbation;
	uint32_t	flow_mode;
	uint32_t	gen;
	uint32_t	bw;
	uint8_t		shaped;
	struct dn_schk	*sched;		/* its scheduler, for the statistics */
	struct vnet	*vnet;
	LIST_ENTRY(cake_stash) all;
};

/* extra cake scheduler configurations */
struct cake_schk {
	struct dn_sch_cake_parms cfg;
	uint32_t	gen;		/* bumped by every reconfiguration */
	uint8_t		held;		/* holds a module reference */
	struct cake_stash stash;
};

/* cake scheduler instance */
struct cake_si {
	struct dn_sch_inst _si;	/* standard scheduler instance */
	struct dn_queue main_q; /* main queue is after si directly */

	struct cake_flow *flows; /* tin_cnt * flows_cnt flows */
	struct cake_host *hosts; /* tin_cnt * flows_cnt host slots */
	/* the overflow drop's max-heap of flow backlogs, as sch_cake's: one
	 * entry per flow of each of CAKE_MAX_TINS tins, (flow << 3) | tin,
	 * kept up to date while it is warm (overflow_timeout dequeues after
	 * the last overflow) and rebuilt when it is cold */
	uint32_t *overflow_heap;
	uint32_t overflow_timeout;
	struct cake_tin tins[CAKE_MAX_TINS];
	const uint8_t *dscp_map; /* DSCP -> tin */
	uint32_t tin_cnt;	/* geometry of the current tables */
	uint32_t flows_cnt;	/* per tin */
	uint32_t cur_tin;	/* tin being served */
	uint32_t perturbation;	/* random value */
	uint32_t flow_mode;	/* mode the host counts were kept for */
	uint32_t gen;		/* cake_schk.gen the tables were built for */
	uint32_t bw;		/* pipe rate the tin parameters are for */
	uint64_t link_time;	/* when the last packet left a paced link */
	uint64_t link_batch;	/* the pipe's sched_time for this release */
	uint64_t link_cur;	/* real times of this release and the one */
	uint64_t link_prev;	/* before it, 0 before there was one */
	uint64_t link_rate_ns;	/* ns per byte at the pipe's rate, */
	uint8_t	link_rate_shft;	/* shifted left by link_rate_shft */
	uint64_t failsafe_time;	/* ingress: next send allowed despite drops */
	struct dn_sch_cake_parms cfg; /* configuration of this instance */
	uint64_t buffer_limit;	/* bytes queued at most, all tins */
	uint8_t	shaped;		/* pipe has a rate: use tin thresholds */
	uint8_t	listed;		/* on cake_instances, for the statistics */
	struct vnet *vnet;	/* whose dummynet (and lock) it belongs to */
	LIST_ENTRY(cake_si) all;
};

#endif /* _IP_DN_SCHED_CAKE_H */
