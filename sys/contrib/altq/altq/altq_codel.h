#ifndef _ALTQ_ALTQ_CODEL_H_
#define _ALTQ_ALTQ_CODEL_H_

struct codel_stats {
	u_int32_t	 maxpacket;
	struct pktcntr	 drop_cnt;
	u_int		 marked_packets;
};

struct codel_ifstats {
	u_int                   qlength;
        u_int                   qlimit;
        struct codel_stats       stats;
	struct pktcntr  cl_xmitcnt;	/* transmitted packet counter */
	struct pktcntr  cl_dropcnt;	/* dropped packet counter */
};

#ifdef _KERNEL
#include <altq/altq_classq.h>

/**
 * struct codel_params - contains codel parameters
 *  <at> target:        target queue size (in time units)
 *  <at> interval:      width of moving time window
 *  <at> ecn:   is Explicit Congestion Notification enabled
 */
struct codel_params {
        u_int64_t       target;
        u_int64_t       interval;
        int             ecn;
};

/**
 * struct codel_vars - contains codel variables
 *  <at> count:         how many drops we've done since the last time we
 *                      entered dropping state
 *  <at> lastcount:             count at entry to dropping state
 *  <at> dropping:              set to true if in dropping state
 *  <at> rec_inv_sqrt:  reciprocal value of sqrt(count) >> 1
 *  <at> first_above_time:      when we went (or will go) continuously above target
 *                      for interval
 *  <at> drop_next:             time to drop next packet, or when we dropped last
 *  <at> ldelay:                sojourn time of last dequeued packet
 */
struct codel_vars {
        u_int32_t       count;
        u_int32_t       lastcount;
        int             dropping;
        u_int16_t       rec_inv_sqrt;
        u_int64_t       first_above_time;
        u_int64_t       drop_next;
        u_int64_t       ldelay;
};
        
struct codel {
        struct codel_params      params;
        struct codel_vars        vars;
        struct codel_stats       stats;
        u_int32_t                drop_overlimit;
};

/*
 * codel interface state
 */
struct codel_if {
	struct codel_if		*cif_next;	/* interface state list */
	struct ifaltq		*cif_ifq;	/* backpointer to ifaltq */
	u_int			cif_bandwidth;	/* link bandwidth in bps */

	class_queue_t	*cl_q;		/* class queue structure */
	struct codel	codel;

	/* statistics */
	struct codel_ifstats cl_stats;
};

struct codel;

struct codel	*codel_alloc(int, int, int);
void		 codel_destroy(struct codel *);
int		 codel_addq(struct codel *, class_queue_t *, struct mbuf *);
struct mbuf	*codel_getq(struct codel *, class_queue_t *);
void		 codel_getstats(struct codel *, struct codel_stats *);

#endif

#endif /* _ALTQ_ALTQ_CODEL_H_ */
