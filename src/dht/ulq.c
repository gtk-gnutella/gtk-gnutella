/*
 * Copyright (c) 2008, Raphael Manfredi
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup dht
 * @file
 *
 * User lookup queue.
 *
 * A DHT node lookup typically runs for about 100 seconds and generates
 * 20 KiB of incoming traffic, with 3 KiB of outgoing traffic.  So we do
 * not want to have too many such lookups running in parallel or the UDP
 * traffic is going to explode.
 *
 * This queue is for user lookups only.  Internal lookups launched by the
 * DHT to update its routing table are running in parallel but are not
 * too frequent.
 *
 * By allowing at most 10 (say) user lookups in parallel, we statistically
 * limit the amount of UDP traffic to about 2 KiB/s in and 0.3 KiB/s out,
 * using the above sample traffic statistics for lookups.  The exact amount
 * of traffic generated will naturally vary.
 *
 * For each created lookup, statistics are gathered upon completion.  This
 * allows the queue to measure the actual bandwidth used by the lookups and
 * to adjust the amount of concurrency based on bandwidth hints provided
 * by the user: the larger the hints, the more concurrency will take place
 * and the faster the results will come back, at the expense on bandwidth.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

#include "ulq.h"
#include "kuid.h"
#include "lookup.h"

#include "if/gnet_property_priv.h"
#include "if/dht/kademlia.h"

#include "core/nodes.h"
#include "core/gnet_stats.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/fifo.h"
#include "lib/slist.h"
#include "lib/str.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define ULQ_MAX_RUNNING		3		/**< Initial amount of concurrent reqs */
#define ULQ_UDP_DELAY		5000	/**< Delay in ms if UDP flow-controlled */
#define ULQ_EMA_SHIFT		7		/**< Shifting during EMA computation */

#define vema(x)	((x) >> ULQ_EMA_SHIFT)

enum ulq_magic {
	ULQ_MAGIC = 0x7c777379U
};

/**
 * The user lookup queue.
 */
struct ulq {
	enum ulq_magic magic;
	const char *name;				/**< Queue name */
	fifo_t *q;						/**< Queue is a FIFO */
	slist_t *launched;				/**< Launched lookups */
	int running;					/**< Amount of launched lookups */
	int weight;						/**< Scheduling weight */
	int scheduled;					/**< Amount scheduled in the round */
	bool runnable;					/**< Is queue placed in the runq? */
};

enum ulqitem_magic {
	ULQ_ITEM_MAGIC = 0x0aadd4e5U
};

/**
 * The queued lookup item.
 */
struct ulq_item {
	enum ulqitem_magic magic;
	lookup_type_t type;				/**< Type of lookup (STORE or VALUE) */
	const kuid_t *kuid;				/**< KUID to look for (atom) */
	struct ulq *uq;					/**< The queue where item lies */
	union {
		struct {
			lookup_cb_ok_t ok;		/**< OK callback for node lookups */
		} fn;
		struct {
			lookup_cbv_ok_t ok;		/**< OK callback for value lookups */
			dht_value_type_t vtype;	/**< Type of value they want */
		} fv;
	} u;
	lookup_cb_start_t start;		/**< Optional starting callback */
	lookup_cb_err_t err;			/**< Error callback */
	void *arg;						/**< Common callback opaque argument */
};

/**
 * There are several lookup queues defined, to regroup together lookups
 * with a similar priority.  For instance, PROX lookups are more urgent
 * than ALOC ones.
 */
enum ulq_qtype {
	ULQ_PROX = 0,					/**< Push proxy lookups */
	ULQ_ALOC,						/**< Alt-loc lookups */
	ULQ_STORE,						/**< Node lookups (for publishing) */
	ULQ_PRIO,						/**< Prioritary lookups */
	ULQ_OTHER,						/**< Other types of lookups */

	ULQ_QUEUE_COUNT					/**< Amount of queues */
};

static struct ulq *ulq[ULQ_QUEUE_COUNT];	/**< The user lookup queues */
static cevent_t *service_ev;				/**< Servicing event */

/**
 * Scheduling informations.
 */
static struct ulq_sched {
	slist_t *runq;					/**< Runnable queues */
	int running;					/**< Total running lookups */
	int pending;					/**< Total pending lookups */
	int bw_in_ema;					/**< Slow EMA of incoming b/w per lookup */
	int bw_out_ema;					/**< Slow EMA of outgoing b/w per lookup */
	int sz_in_ema;					/**< Slow EMA of incoming message size */
	int sz_out_ema;					/**< Slow EMA of outgoing message size */
	int msg_dropped;				/**< Exponentially decaying # of drops */
	bool udp_flow_controlled;		/**< Whether UDP was flow-controlled */
} sched;

static void ulq_needs_servicing(void);
static void ulq_delay_servicing(void);

static inline void
ulq_check(const struct ulq *uq)
{
	g_assert(uq != NULL);
	g_assert(ULQ_MAGIC == uq->magic);
}

static inline void
ulq_item_check(const struct ulq_item *ui)
{
	g_assert(ui != NULL);
	g_assert(ULQ_ITEM_MAGIC == ui->magic);
}

/**
 * Allocate new ulq item.
 */
static struct ulq_item *
allocate_ulq_item(lookup_type_t type, const kuid_t *kuid,
	lookup_cb_start_t start, lookup_cb_err_t err, void *arg)
{
	struct ulq_item *ui;

	WALLOC(ui);
	ui->magic = ULQ_ITEM_MAGIC;
	ui->type = type;
	ui->kuid = kuid_get_atom(kuid);
	ui->start = start;
	ui->err = err;
	ui->arg = arg;

	return ui;
}

/**
 * Free queued item.
 */
static void
free_ulq_item(struct ulq_item *ui)
{
	ulq_item_check(ui);

	kuid_atom_free(ui->kuid);
	ui->kuid = NULL;
	ui->magic = 0;
	WFREE(ui);
}

/**
 * Add queue to the run queue.
 */
static void
ulq_sched_add(struct ulq *uq)
{
	ulq_check(uq);
	g_assert(!uq->runnable);

	slist_prepend(sched.runq, uq);
	uq->runnable = TRUE;
}

/**
 * Reset scheduler once all that could be distributed was.
 */
static void
ulq_sched_reset(void)
{
	size_t i;

	for (i = 0; i < N_ITEMS(ulq); i++) {
		struct ulq *uq = ulq[i];

		g_assert(!uq->runnable);

		uq->scheduled = 0;
		if (fifo_count(uq->q) > 0)
			ulq_sched_add(uq);
	}
}

/**
 * Lookup is completed.
 */
static void
ulq_completed(struct ulq_item *ui)
{
	struct ulq *uq;

	ulq_item_check(ui);
	g_assert(ui->uq->running > 0);
	g_assert(sched.running > 0);

	uq = ui->uq;
	ulq_check(uq);

	uq->running--;
	sched.running--;
	slist_remove(uq->launched, ui);
	free_ulq_item(ui);

	ulq_needs_servicing();		/* Check for more work to do */
}

/**
 * Intercepting "error" callback.
 */
static void
ulq_error_cb(const kuid_t *kuid, lookup_error_t error, void *arg)
{
	struct ulq_item *ui = arg;

	ulq_item_check(ui);
	g_assert(LOOKUP_VALUE == ui->type || LOOKUP_STORE == ui->type);
	g_assert(ui->kuid == kuid);		/* Atoms */

	(*ui->err)(ui->kuid, error, ui->arg);
	ulq_completed(ui);
}

/**
 * Intercepting "value found" callback.
 */
static void
ulq_value_found_cb(const kuid_t *kuid, const lookup_val_rs_t *rs, void *arg)
{
	struct ulq_item *ui = arg;

	ulq_item_check(ui);
	g_assert(LOOKUP_VALUE == ui->type);
	g_assert(ui->kuid == kuid);		/* Atoms */

	(*ui->u.fv.ok)(ui->kuid, rs, ui->arg);
	ulq_completed(ui);
}

/**
 * Intercepting "node found" callback.
 */
static void
ulq_node_found_cb(const kuid_t *kuid, const lookup_rs_t *rs, void *arg)
{
	struct ulq_item *ui = arg;

	ulq_item_check(ui);
	g_assert(LOOKUP_STORE == ui->type);
	g_assert(ui->kuid == kuid);		/* Atoms */

	(*ui->u.fn.ok)(ui->kuid, rs, ui->arg);
	ulq_completed(ui);
}

/**
 * Statistics callback invoked when loookup is finished, before user-defined
 * callbacks for error and results.
 */
static void
ulq_lookup_stats(const kuid_t *kuid,
	const struct lookup_stats *ls, void *arg)
{
	struct ulq_item *ui = arg;
	int avg;

	ulq_item_check(ui);
	g_assert(ui->kuid == kuid);		/* Atoms */

	/*
	 * Update the slow EMAs (n = 31 => sm = 2/(n+1) = 0.0625 = 1/2^4).
	 *
	 * To avoid loosing too much of the decimals when computing the EMA,
	 * we shift the values by ULQ_EMA_SHIFT, and of course we need to
	 * correct the read values later on by the same amount.
	 */

	if (ls->elapsed > 0.0) {
		avg = (ls->bw_incoming << ULQ_EMA_SHIFT) / ls->elapsed;
		sched.bw_in_ema += (avg >> 4) - (sched.bw_in_ema >> 4);

		avg = (ls->bw_outgoing << ULQ_EMA_SHIFT) / ls->elapsed;
		sched.bw_out_ema += (avg >> 4) - (sched.bw_out_ema >> 4);
	}

	if (ls->rpc_replies) {
		avg = (ls->bw_incoming << ULQ_EMA_SHIFT) / ls->rpc_replies;
		sched.sz_in_ema += (avg >> 4) - (sched.sz_in_ema >> 4);
	}

	if (ls->msg_sent) {
		avg = (ls->bw_outgoing << ULQ_EMA_SHIFT) / ls->msg_sent;
		sched.sz_out_ema += (avg >> 4) - (sched.sz_out_ema >> 4);
	}

	/*
	 * Exponential decay of number of messages dropped.
	 */

	if (1 == sched.msg_dropped)
		sched.msg_dropped = 0;
	sched.msg_dropped += ls->msg_dropped;
	sched.msg_dropped -= sched.msg_dropped >> 1;	/* Halve the count */

	if (GNET_PROPERTY(dht_ulq_debug) > 1)
		g_debug("DHT ULQ %s lookup completed in %g secs (in=%d, out=%d)",
			ui->uq->name, ls->elapsed, ls->bw_incoming, ls->bw_outgoing);

	if (GNET_PROPERTY(dht_ulq_debug) > 2)
		g_debug("DHT ULQ sched avg: "
			"bw_in=%d, bw_out=%d, sz_in=%d, sz_out=%d, dropped=%d",
			vema(sched.bw_in_ema), vema(sched.bw_out_ema),
			vema(sched.sz_in_ema), vema(sched.sz_out_ema),
			sched.msg_dropped);
}

/**
 * Produce a human readable status of running/pending entries for all queues.
 *
 * @return pointer to static string
 */
static const char *
ulq_queue_status(void)
{
	static char buf[120];
	size_t i, offset = 0;

	for (i = 0; i < N_ITEMS(ulq); i++) {
		struct ulq *uq = ulq[i];

		offset += str_bprintf(&buf[offset], sizeof(buf) - offset,
			"%s%s: %u/%u", offset > 0 ? ", " : "",
			uq->name, uq->running, fifo_count(uq->q));
	}

	return buf;
}

/**
 * Launch an enqueued lookup.
 *
 * @return whether a lookup was actually launched
 */
static bool
ulq_launch(struct ulq *uq)
{
	nlookup_t *nl;
	struct ulq_item *ui;

	ulq_check(uq);
	g_assert(fifo_count(uq->q));
	g_assert(sched.pending > 0);

	ui = fifo_remove(uq->q);
	sched.pending--;

	ulq_item_check(ui);

	/*
	 * If there is a "starting" callback, make sure it returns TRUE
	 * before launching the request.
	 */

	if (ui->start != NULL && !(*ui->start)(ui->kuid, ui->arg)) {
		(*ui->err)(ui->kuid, LOOKUP_E_CANCELLED, ui->arg);
		free_ulq_item(ui);
		return FALSE;
	}

	/*
	 * We trap the ok and error callbacks so as to be notified when the
	 * lookup has completed.
	 */

	switch (ui->type) {
	case LOOKUP_VALUE:
		nl = lookup_find_value(ui->kuid, ui->u.fv.vtype,
			ulq_value_found_cb, ulq_error_cb, ui);
		goto initialized;
	case LOOKUP_STORE:
		nl = lookup_store_nodes(ui->kuid, ulq_node_found_cb, ulq_error_cb, ui);
		goto initialized;
		break;
	case LOOKUP_REFRESH:
	case LOOKUP_NODE:
	case LOOKUP_TOKEN:
		break;
	}
	nl = NULL;
	g_assert_not_reached();

initialized:

	if (nl) {
		ulq_item_check(ui);
		slist_append(uq->launched, ui);
		uq->running++;
		uq->scheduled++;
		sched.running++;
		lookup_ctrl_stats(nl, ulq_lookup_stats);

		if (LOOKUP_VALUE == ui->type) {
			switch (ui->u.fv.vtype) {
			case DHT_VT_ANY:
				/*
				 * We use generic lookups to locate PROX or NOPE values.
				 * These are scheduled in the ULQ_PROX queue.
				 */
				if (uq == ulq[ULQ_PROX])
					gnet_stats_inc_general(GNR_DHT_PUSH_PROXY_LOOKUPS);
				break;
			case DHT_VT_PROX:
				gnet_stats_inc_general(GNR_DHT_PUSH_PROXY_LOOKUPS);
				break;
			case DHT_VT_ALOC:
				gnet_stats_inc_general(GNR_DHT_ALT_LOC_LOOKUPS);
				break;
			default:
				break;
			}
		}
	} else {
		/*
		 * We know the only cause for a lookup not starting is that the
		 * initial shortlist is empty.  Since here we are called asynchronously
		 * with respect to the initial lookup launch, it is safe to invoke
		 * the error callback.
		 */

		(*ui->err)(ui->kuid, LOOKUP_E_EMPTY_ROUTE, ui->arg);
		free_ulq_item(ui);
	}

	return nl != NULL;
}

/**
 * Service the lookup queue.
 *
 * This call is scheduled on the "periodic event" stack, asynchronously, to
 * avoid problems when error callbacks are triggered because a lookup cannot
 * be launched.
 */
static void
ulq_service(void)
{
	int max;

	if (GNET_PROPERTY(dht_ulq_debug) > 2) {
		g_debug("DHT ULQ service on entry: has %d running and %d pending: %s",
			sched.running, sched.pending, ulq_queue_status());
	}

	/*
	 * Compute suitable amount of lookups we can have in parallel to reach
	 * our bandwidth targets.
	 */

	{
		int in_ema = vema(sched.bw_in_ema);
		int out_ema = vema(sched.bw_out_ema);
		int sz_in_ema = vema(sched.sz_in_ema) * KDA_ALPHA;
		int sz_out_ema = vema(sched.sz_out_ema) * KDA_ALPHA;
		int in_limit = ULQ_MAX_RUNNING;
		int out_limit = ULQ_MAX_RUNNING;
		int sz_in_limit = ULQ_MAX_RUNNING;
		int sz_out_limit = ULQ_MAX_RUNNING;

		/*
		 * The average traffic per request provides a first limit.
		 */

		if (in_ema)
			in_limit = 1 + GNET_PROPERTY(bw_dht_lookup_in) / in_ema;
		if (out_ema)
			out_limit = 1 + GNET_PROPERTY(bw_dht_lookup_out) / out_ema;

		/*
		 * Also consider peak traffic.  We're going to send KDA_ALPHA requests
		 * simultaneously, however replies are not going to come back
		 * at the same time, which is why we multiply the max bandwidth by 2,
		 * considering that the KDA_ALPHA replies will come back within 2
		 * seconds and not just in the same second timeframe.
		 */

		if (sz_in_ema)
			sz_in_limit = 1 + GNET_PROPERTY(bw_dht_lookup_in) * 2 / sz_in_ema;
		if (sz_out_ema)
			sz_out_limit = 1 + GNET_PROPERTY(bw_dht_lookup_out) / sz_out_ema;

		if (GNET_PROPERTY(dht_ulq_debug) > 1)
			g_debug("DHT ULQ service: limits in = (bw: %d, sz: %d), "
				"out = (bw: %d, sz: %d)",
				in_limit, sz_in_limit, out_limit, sz_out_limit);

		in_limit = MIN(in_limit, sz_in_limit);
		out_limit = MIN(out_limit, sz_out_limit);

		max = MIN(out_limit, in_limit);
	}

	/*
	 * Schedule queues in a round-robin fashion until they have used all
	 * their scheduling slots, at which point we reset them all.
	 */

	while (sched.pending > 0 && sched.running < max) {
		struct ulq *uq;
		bool launched;

		/*
		 * If the UDP queue would flow-control with the first batch of
		 * queries, stop launching.
		 */

		if (node_dht_would_flow_control(KDA_ALPHA * vema(sched.sz_out_ema)))
			break;

		if (0 == slist_length(sched.runq))
			ulq_sched_reset();

		uq = slist_shift(sched.runq);

		g_assert(uq);			/* At least one of the queue has something */
		g_assert(uq->runnable);
		g_assert(uq->scheduled < uq->weight);

		launched = ulq_launch(uq);

		if (fifo_count(uq->q) > 0 && uq->scheduled < uq->weight)
			slist_append(sched.runq, uq);
		else
			uq->runnable = FALSE;

		/*
		 * When the UDP queue was flagged as flow-controlled, only launch one.
		 * Likewise if we see dropped messages.
		 */

		if (launched && (sched.udp_flow_controlled || sched.msg_dropped > 0))
			break;
	}

	sched.udp_flow_controlled = FALSE;

	if (GNET_PROPERTY(dht_ulq_debug) > 1)
		g_debug("DHT ULQ service at exit: "
			"max %d, has %d running and %d pending: %s",
			max, sched.running, sched.pending, ulq_queue_status());

	/*
	 * If nothing is running but we still have queries pending, it means we
	 * could not launch anything because it would trigger an UDP flow control.
	 * Attempt servicing again after some delay to let the UDP queue flush.
	 */

	if (0 == sched.running && sched.pending)
		ulq_delay_servicing();
}

/**
 * Callout queue callback to perform queue servicing.
 */
static void
ulq_do_service(cqueue_t *cq, void *unused_obj)
{
	(void) unused_obj;

	cq_zero(cq, &service_ev);

	/*
	 * If the DHT is not properly seeded, do not perform user lookups.
	 */

	if (!dht_seeded()) {
		if (GNET_PROPERTY(dht_ulq_debug))
			g_warning("DHT ULQ deferring servicing: DHT not seeded");
		ulq_delay_servicing();
		return;
	}

	/*
	 * If we're no longer connected to the Internet, no servicing.
	 */

	if (!GNET_PROPERTY(is_inet_connected)) {
		if (GNET_PROPERTY(dht_ulq_debug))
			g_warning("DHT ULQ deferring servicing: not connected to Internet");
		ulq_delay_servicing();
		return;
	}

	/*
	 * DHT lookups can stress the outgoing UDP queue.
	 *
	 * If the UDP queue is flow-controlled, do not add another DHT lookup
	 * yet: rather wait for 5 more seconds and check again. Also remember
	 * that we experienced a flow-control situation.
	 *
	 * Moreover, we increase the computed EMA by 25% each time, to not cause
	 * a sudden release of many lookups when we resume.
	 */

	if (node_dht_is_flow_controlled()) {
		if (GNET_PROPERTY(dht_ulq_debug))
			g_warning("DHT ULQ deferring servicing: UDP queue flow-controlled");

		sched.bw_in_ema += sched.bw_in_ema / 4;
		sched.bw_out_ema += sched.bw_out_ema / 4;
		sched.udp_flow_controlled = TRUE;
		ulq_delay_servicing();
		return;
	}

	ulq_service();
}

/**
 * Delay servicing.
 */
static void
ulq_delay_servicing(void)
{
	if (NULL == service_ev)
		service_ev = cq_main_insert(ULQ_UDP_DELAY, ulq_do_service, NULL);
}

/**
 * Schedule asynchronous queue servicing.
 */
static void
ulq_needs_servicing(void)
{
	if (NULL == service_ev)
		service_ev = cq_main_insert(1, ulq_do_service, NULL);
}

/**
 * @return proper lookup queue depending on the type of data and whether
 * the lookup is flagged as urgent.
 */
static struct ulq *
ulq_get(lookup_type_t ltype, dht_value_type_t vtype, bool prioritary)
{
	if (prioritary)
		return ulq[ULQ_PRIO];

	switch (ltype) {
	case LOOKUP_STORE:
		return ulq[ULQ_STORE];
		break;
	case LOOKUP_VALUE:
		break;
	case LOOKUP_REFRESH:
	case LOOKUP_NODE:
	case LOOKUP_TOKEN:
		g_assert_not_reached();
	}

	g_assert(LOOKUP_VALUE == ltype);

	switch (vtype) {
	case DHT_VT_ALOC:
		return ulq[ULQ_ALOC];
	case DHT_VT_NOPE:
	case DHT_VT_PROX:
		return ulq[ULQ_PROX];
	default:
		return ulq[ULQ_OTHER];
	}
}

/**
 * Enqueue lookup item.
 */
static void
ulq_putq(struct ulq *uq, struct ulq_item *ui)
{
	ulq_check(uq);
	ulq_item_check(ui);

	fifo_put(uq->q, ui);
	ui->uq = uq;
	sched.pending++;

	if (!uq->runnable && uq->scheduled < uq->weight)
		ulq_sched_add(uq);

	ulq_needs_servicing();
}

/**
 * Enqueue store roots lookup.
 *
 * This is meant to be used only via user store operations, and is not to be
 * directly invoked by user code.
 */
void
ulq_find_store_roots(const kuid_t *kuid, bool prioritary,
	lookup_cb_ok_t ok, lookup_cb_err_t error, void *arg)
{
	struct ulq_item *ui;
	struct ulq *uq;

	g_assert(ok);
	g_assert(error);

	uq = ulq_get(LOOKUP_STORE, DHT_VT_BINARY, prioritary);

	ui = allocate_ulq_item(LOOKUP_STORE,  kuid, NULL, error, arg);
	ui->u.fn.ok = ok;

	ulq_putq(uq, ui);
}

/**
 * Enqueue value lookup of specific type.
 */
void
ulq_find_value(const kuid_t *kuid, dht_value_type_t type,
	lookup_cbv_ok_t ok, lookup_cb_start_t start, lookup_cb_err_t error,
	void *arg)
{
	struct ulq_item *ui;
	struct ulq *uq;

	g_assert(ok);
	g_assert(error);

	uq = ulq_get(LOOKUP_VALUE, type, FALSE);

	ui = allocate_ulq_item(LOOKUP_VALUE,  kuid, start, error, arg);
	ui->u.fv.ok = ok;
	ui->u.fv.vtype = type;

	ulq_putq(uq, ui);
}

/**
 * Enqueue value lookup for any value type.
 *
 * The specified ``queue_type'' is simply used to select the proper
 * scheduling queue.
 */
void
ulq_find_any_value(const kuid_t *kuid, dht_value_type_t queue_type,
	lookup_cbv_ok_t ok, lookup_cb_err_t error, void *arg)
{
	struct ulq_item *ui;
	struct ulq *uq;

	g_assert(ok);
	g_assert(error);

	uq = ulq_get(LOOKUP_VALUE, queue_type, FALSE);

	ui = allocate_ulq_item(LOOKUP_VALUE,  kuid, NULL, error, arg);
	ui->u.fv.ok = ok;
	ui->u.fv.vtype = DHT_VT_ANY;	/* Generic type */

	ulq_putq(uq, ui);
}

/**
 * Initialize a user lookup queue.
 *
 * @param name		queue name for logging purposes
 * @param weight	scheduling weight
 *
 * @return the created queue
 */
static struct ulq * G_COLD
ulq_init_queue(const char *name, int weight)
{
	struct ulq *uq;

	g_assert(weight > 0);

	WALLOC0(uq);
	uq->magic = ULQ_MAGIC;
	uq->name = name;
	uq->q = fifo_make();
	uq->launched = slist_new();
	uq->running = 0;
	uq->weight = weight;

	return uq;
}

/**
 * Initialize the user lookup queues.
 */
void G_COLD
ulq_init(void)
{
	STATIC_ASSERT(ULQ_QUEUE_COUNT == N_ITEMS(ulq));

	g_assert(NULL == ulq[ULQ_PROX]);
	g_assert(NULL == ulq[ULQ_ALOC]);
	g_assert(NULL == ulq[ULQ_STORE]);
	g_assert(NULL == ulq[ULQ_OTHER]);
	g_assert(NULL == ulq[ULQ_PRIO]);
	g_assert(NULL == sched.runq);

	/*
	 * The weights are arbitrary values, not necessarily summing to 100.
	 *
	 * To avoid too frequent schduler resets, they are somehow scaled, i.e.
	 * we would not put 12,3,4,1 as weights, but 60,15,20,5 to ensure we will
	 * serve a fair amount of entries in each queue between each scheduler
	 * resets -- see ulq_sched_reset().
	 *
	 * Values must not be too large though, or a given queue would monopolize
	 * the scheduling as long as it has entries and others have expired all
	 * their slots.
	 *
	 * The ULQ_PRIO queue is meant for things that should be scheduled more
	 * urgently, and its weight must therefore be a number greater than the
	 * others but not too large or a bug (like too many enqueuing of prioritary
	 * lookups) would litterally starve the other queues.
	 */

	ulq[ULQ_PROX]	= ulq_init_queue("PROX", 60);
	ulq[ULQ_ALOC]	= ulq_init_queue("ALOC", 10);
	ulq[ULQ_STORE]	= ulq_init_queue("STORE", 25);
	ulq[ULQ_OTHER]	= ulq_init_queue("OTHER", 5);
	ulq[ULQ_PRIO]	= ulq_init_queue("PRIO", 100);

	ZERO(&sched);
	sched.runq = slist_new();
}

/**
 * FIFO free item freeing callback.
 */
static void
free_fifo_item(void *item, void *data)
{
	struct ulq_item *ui = item;
	bool *exiting = data;

	ulq_item_check(ui);

	/*
	 * If the process is not exiting, we're simply shutdowning the DHT
	 * layer and therefore callers need to be informed that their enqueued
	 * lookups were cancelled, so that they may cleanup after themselves.
	 */

	if (!*exiting)
		(*ui->err)(ui->kuid, LOOKUP_E_CANCELLED, ui->arg);

	free_ulq_item(ui);
}

/**
 * Shutdown the user lookup queue.
 *
 * @param exiting	whether the whole process is exiting
 */
void G_COLD
ulq_close(bool exiting)
{
	size_t i;
	bool one = TRUE;

	cq_cancel(&service_ev);
	slist_free(&sched.runq);

	for (i = 0; i < N_ITEMS(ulq); i++) {
		struct ulq *uq = ulq[i];

		if (uq) {
			/*
			 * Do not invoke callback for launched lookups, they will be
			 * duly cancelled by lookup_close(): tell free_fifo_item() that
			 * we are exiting.
			 *
			 * Enqueued lookups on the other hand (still in the FIFO) need
			 * to be properly cleaned-up by forcing the registered error
			 * callback, since there is no lookup object yet.
			 */

			slist_foreach(uq->launched, free_fifo_item, &one);
			slist_free(&uq->launched);
			fifo_free_all(uq->q, free_fifo_item, &exiting);
			WFREE(uq);

			ulq[i] = NULL;
		}
	}
}

/* vi: set ts=4 sw=4 cindent: */
