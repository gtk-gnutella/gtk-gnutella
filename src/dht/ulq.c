/*
 * $Id$
 *
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

RCSID("$Id$")

#include "ulq.h"
#include "kuid.h"
#include "lookup.h"

#include "if/gnet_property_priv.h"

#include "core/nodes.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/fifo.h"
#include "lib/slist.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define ULQ_MAX_RUNNING		3		/**< Initial amount of concurrent reqs */
#define ULQ_UDP_DELAY		5000	/**< Delay in ms if UDP flow-controlled */
#define ULQ_EMA_SHIFT		7		/**< Shifting during EMA computation */

enum ulq_magic {
	ULQ_MAGIC = 0xfc777379U
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
	gboolean runnable;				/**< Is queue placed in the runq? */
};

enum ulqitem_magic {
	ULQ_ITEM_MAGIC = 0x0aadd4e5U
};

/**
 * The queued lookup item.
 */
struct ulq_item {
	enum ulqitem_magic magic;
	lookup_type_t type;				/**< Type of lookup (NODE or VALUE) */
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
	lookup_cb_err_t err;			/**< Error callback */
	gpointer arg;					/**< Common callback opaque argument */
	/* Collected statistics */
	int bw_in;						/**< Incoming bandwidth used */
	int bw_out;						/**< Outgoing bandwidth used */
	guint elapsed;					/**< Elapsed time in ms */
};

/**
 * There are several lookup queues defined, to regroup together lookups
 * with a similar priority.  For instance, PROX lookups are more urgent
 * than ALOC ones.
 */
enum ulq_qtype {
	ULQ_PROX = 0,					/**< Push proxy lookups */
	ULQ_ALOC,						/**< Alt-loc lookups */
	ULQ_NODE,						/**< Node lookups (for publishing) */

	ULQ_QUEUE_COUNT					/**< Amount of queues */
};

static struct ulq *ulq[ULQ_QUEUE_COUNT];	/**< The user lookup queues */
static cevent_t *service_ev;				/**< Servicing event */

/**
 * Scheduling informations.
 */
static struct ulq_sched {
	slist_t *runq;					/**< Runnable queues */
	guint weight;					/**< Total weight among queues */
	int running;					/**< Total running lookups */
	int pending;					/**< Total pending lookups */
	int bw_in_ema;					/**< Slow EMA of incoming b/w per lookup */
	int bw_out_ema;					/**< Slow EMA of outgoing b/w per lookup */
	gboolean udp_flow_controlled;	/**< Whether UDP was flow-controlled */
} sched;

static void ulq_needs_servicing(void);

static inline void
ulq_check(const struct ulq *uq)
{
	g_assert(uq);
	g_assert(ULQ_MAGIC == uq->magic);
}

static inline void
ulq_item_check(const struct ulq_item *ui)
{
	g_assert(ui);
	g_assert(ULQ_ITEM_MAGIC == ui->magic);
}

/**
 * Allocate new ulq item.
 */
static struct ulq_item *
allocate_ulq_item(
	lookup_type_t type, const kuid_t *kuid, lookup_cb_err_t err, gpointer arg)
{
	struct ulq_item *ui;

	ui = walloc(sizeof *ui);
	ui->magic = ULQ_ITEM_MAGIC;
	ui->type = type;
	ui->kuid = kuid_get_atom(kuid);
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
	wfree(ui, sizeof *ui);
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

	for (i = 0; i < G_N_ELEMENTS(ulq); i++) {
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

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_message("DHT ULQ %s lookup completed in %.3f secs (in=%d, out=%d)",
			uq->name, ui->elapsed / 1000.0, ui->bw_in, ui->bw_out);

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
ulq_error_cb(const kuid_t *kuid, lookup_error_t error, gpointer arg)
{
	struct ulq_item *ui = arg;

	ulq_item_check(ui);
	g_assert(LOOKUP_VALUE == ui->type || LOOKUP_NODE == ui->type);
	g_assert(ui->kuid == kuid);		/* Atoms */

	(*ui->err)(ui->kuid, error, ui->arg);
	ulq_completed(ui);
}

/**
 * Intercepting "value found" callback.
 */
static void
ulq_value_found_cb(const kuid_t *kuid, const lookup_val_rs_t *rs, gpointer arg)
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
ulq_node_found_cb(const kuid_t *kuid, const lookup_rs_t *rs, gpointer arg)
{
	struct ulq_item *ui = arg;

	ulq_item_check(ui);
	g_assert(LOOKUP_NODE == ui->type);
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
	const struct lookup_stats *ls, gpointer arg)
{
	struct ulq_item *ui = arg;
	int avg;

	ulq_item_check(ui);
	g_assert(ui->kuid == kuid);		/* Atoms */

	ui->bw_in = ls->bw_incoming;
	ui->bw_out = ls->bw_outgoing;
	ui->elapsed = ls->elapsed * 1000.0;

	/*
	 * Update the Slow EMA (n = 31 => sm = 2/(n+1) = 0.0625 = 1/2^4).
	 *
	 * To avoid loosing too much of the decimals when computing the EMA,
	 * we shift the values by ULQ_EMA_SHIFT, and of course we need to
	 * correct the read values later on by the same amount.
	 */

	avg = (ui->bw_in << ULQ_EMA_SHIFT) / ls->elapsed;
	sched.bw_in_ema += (avg >> 4) - (sched.bw_in_ema >> 4);

	avg = (ui->bw_out << ULQ_EMA_SHIFT) / ls->elapsed;
	sched.bw_out_ema += (avg >> 4) - (sched.bw_out_ema >> 4);
}

/**
 * Produce a human readable status of running/pending entries for all queues.
 *
 * @return pointer to static string
 */
static const char *
ulq_queue_status(void)
{
	static char buf[80];
	size_t i, offset = 0;

	for (i = 0; i < G_N_ELEMENTS(ulq); i++) {
		struct ulq *uq = ulq[i];

		offset += gm_snprintf(&buf[offset], sizeof(buf) - offset,
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
static gboolean
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
	 * We trap the ok and error callbacks so as to be notified when the
	 * lookup has completed.
	 */

	switch (ui->type) {
	case LOOKUP_VALUE:
		nl = lookup_find_value(ui->kuid, ui->u.fv.vtype,
			ulq_value_found_cb, ulq_error_cb, ui);
		goto initialized;
	case LOOKUP_NODE:
		nl = lookup_find_node(ui->kuid, ulq_node_found_cb, ulq_error_cb, ui);
		goto initialized;
	case LOOKUP_REFRESH:
		break;
	}
	nl = NULL;
	g_assert_not_reached();

initialized:

	if (nl) {
		slist_append(uq->launched, ui);
		uq->running++;
		uq->scheduled++;
		sched.running++;
		lookup_ctrl_stats(nl, ulq_lookup_stats);
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

	if (GNET_PROPERTY(dht_lookup_debug) > 2) {
		g_message("DHT ULQ service on entry: has %d running and %d pending: %s",
			sched.running, sched.pending, ulq_queue_status());
	}

	/*
	 * Compute suitable amount of lookups we can have in parallel to reach
	 * our bandwidth targets.
	 */

	{
		int in_ema = sched.bw_in_ema >> BIO_EMA_SHIFT;
		int out_ema = sched.bw_out_ema >> BIO_EMA_SHIFT;
		int in_limit = ULQ_MAX_RUNNING;
		int out_limit = ULQ_MAX_RUNNING;

		if (in_ema)
			in_limit = 1 + GNET_PROPERTY(bw_dht_lookup_in) / in_ema;
		if (out_ema)
			out_limit = 1 + GNET_PROPERTY(bw_dht_lookup_out) / out_ema;
		max = MIN(out_limit, in_limit);

		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_message("DHT ULQ service: limits in = %d, out = %d",
				in_limit, out_limit);
	}

	/*
	 * Schedule queues in a round-robin fashion until they have used all
	 * their scheduling slots, at which point we reset them all.
	 */

	while (sched.pending > 0 && sched.running < max) {
		struct ulq *uq;
		gboolean launched;

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
		 */

		if (launched && sched.udp_flow_controlled)
			goto done;
	}

done:
	sched.udp_flow_controlled = FALSE;

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_message("DHT ULQ service at exit: "
			"max %d, has %d running and %d pending: %s",
			max, sched.running, sched.pending, ulq_queue_status());

	g_assert(sched.running || 0 == sched.pending);	/* Ensures not stuck */
}

/**
 * Callout queue callback to perform queue servicing.
 */
static void
ulq_do_service(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	service_ev = NULL;

	/*
	 * DHT lookups can stress the outgoing UDP queue.
	 *
	 * If the UDP queue is flow-controlled, do not add another DHT lookup
	 * yet: rather wait for 5 more seconds and check again. Also remember
	 * that we experienced a flow-control situation.
	 */

	if (node_udp_is_flow_controlled()) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT ULQ deferring servicing: UDP queue flow-controlled");

		sched.udp_flow_controlled = TRUE;
		service_ev = cq_insert(callout_queue,
			ULQ_UDP_DELAY, ulq_do_service, NULL);
		return;
	}

	ulq_service();
}

/**
 * Schedule asynchronous queue servicing.
 */
static void
ulq_needs_servicing(void)
{
	if (NULL == service_ev)
		service_ev = cq_insert(callout_queue, 1, ulq_do_service, NULL);
}

/**
 * @return proper lookup queue depending on the type of data.
 */
static struct ulq *
ulq_get(lookup_type_t ltype, dht_value_type_t vtype)
{
	switch (ltype) {
	case LOOKUP_NODE:
		return ulq[ULQ_NODE];
		break;
	case LOOKUP_VALUE:
		break;
	case LOOKUP_REFRESH:
		g_assert_not_reached();
	}

	g_assert(LOOKUP_VALUE == ltype);

	switch (vtype) {
	case DHT_VT_ALOC:
		return ulq[ULQ_ALOC];
	case DHT_VT_PROX:
		return ulq[ULQ_PROX];
	default:
		return ulq[ULQ_ALOC];		/* XXX or dedicated queue for others? */
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
 * Enqueue node lookup.
 *
 * This is meant to be used only via user store operations, and is not to be
 * directly invoked by user code.
 */
void
ulq_find_node(const kuid_t *kuid,
	lookup_cb_ok_t ok, lookup_cb_err_t error, gpointer arg)
{
	struct ulq_item *ui;
	struct ulq *uq;

	g_assert(ok);
	g_assert(error);

	uq = ulq_get(LOOKUP_NODE, DHT_VT_BINARY);

	ui = allocate_ulq_item(LOOKUP_NODE,  kuid, error, arg);
	ui->u.fn.ok = ok;

	ulq_putq(uq, ui);
}

/**
 * Enqueue value lookup.
 */
void
ulq_find_value(const kuid_t *kuid, dht_value_type_t type,
	lookup_cbv_ok_t ok, lookup_cb_err_t error, gpointer arg)
{
	struct ulq_item *ui;
	struct ulq *uq;

	g_assert(ok);
	g_assert(error);

	uq = ulq_get(LOOKUP_VALUE, type);

	ui = allocate_ulq_item(LOOKUP_VALUE,  kuid, error, arg);
	ui->u.fv.ok = ok;
	ui->u.fv.vtype = type;

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
static struct ulq *
ulq_init_queue(const char *name, int weight)
{
	struct ulq *uq;

	g_assert(weight > 0);

	uq = walloc0(sizeof *uq);
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
void
ulq_init(void)
{
	size_t i;

	STATIC_ASSERT(ULQ_QUEUE_COUNT == G_N_ELEMENTS(ulq));

	ulq[ULQ_PROX] = ulq_init_queue("PROX", 60);
	ulq[ULQ_ALOC] = ulq_init_queue("ALOC", 20);
	ulq[ULQ_NODE] = ulq_init_queue("NODE", 20);

	sched.runq = slist_new();

	for (i = 0; i < G_N_ELEMENTS(ulq); i++)
		sched.weight += ulq[i]->weight;
}

/**
 * FIFO free item freeing callback.
 */
static void
free_fifo_item(gpointer item, gpointer unused_data)
{
	(void) unused_data;

	free_ulq_item(item);
}

/**
 * Shutdown the user lookup queue.
 */
void
ulq_close(void)
{
	size_t i;

	cq_cancel(callout_queue, &service_ev);
	slist_free(&sched.runq);

	for (i = 0; i < G_N_ELEMENTS(ulq); i++) {
		struct ulq *uq = ulq[i];

		if (uq) {
			fifo_free_all(uq->q, free_fifo_item, NULL);
			slist_foreach(uq->launched, free_fifo_item, NULL);
			slist_free(&uq->launched);
			wfree(uq, sizeof *uq);

			ulq[i] = NULL;
		}
	}
}

/* vi: set ts=4 sw=4 cindent: */
