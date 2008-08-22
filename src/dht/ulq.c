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
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "ulq.h"
#include "kuid.h"
#include "lookup.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/fifo.h"
#include "lib/slist.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define ULQ_MAX_RUNNING		10		/**< Max amount of concurrent requests */

/**
 * The user lookup queue.
 */
struct ulq {
	fifo_t *q;						/**< Queue is a FIFO */
	slist_t *launched;				/**< Launched lookups */
	int running;					/**< Amount of launched lookups */
};

/**
 * The queued lookup item.
 */
struct ulq_item {
	lookup_type_t type;				/**< Type of lookup (NODE or VALUE) */
	const kuid_t *kuid;				/**< KUID to look for (atom) */
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
};

static struct ulq *ulq;				/**< The user lookup queue */

static void ulq_needs_servicing(void);

/**
 * Allocate new ulq item.
 */
static struct ulq_item *
allocate_ulq_item(
	lookup_type_t type, const kuid_t *kuid, lookup_cb_err_t err, gpointer arg)
{
	struct ulq_item *ui;

	ui = walloc(sizeof *ui);
	ui->type = type;
	ui->kuid = kuid_get_atom(kuid);
	ui->err = err;
	ui->arg = arg;

	return ui;
}

/**
 * Free ulq item.
 */
static void
free_ulq_item(struct ulq_item *ui)
{
	g_assert(ui);

	kuid_atom_free(ui->kuid);
	wfree(ui, sizeof *ui);
}

/**
 * Lookup is completed.
 */
static void
ulq_completed(struct ulq_item *ui)
{
	g_assert(ui);
	g_assert(ulq->running > 0);

	ulq->running--;
	slist_remove(ulq->launched, ui);
	free_ulq_item(ui);

	ulq_needs_servicing();	/* Check for more work to do */
}

/**
 * Intercepting "error" callback.
 */
static void
ulq_error_cb(const kuid_t *kuid, lookup_error_t error, gpointer arg)
{
	struct ulq_item *ui = arg;

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

	g_assert(LOOKUP_NODE == ui->type);
	g_assert(ui->kuid == kuid);		/* Atoms */

	(*ui->u.fn.ok)(ui->kuid, rs, ui->arg);
	ulq_completed(ui);
}

/**
 * Launch an enqueued lookup.
 */
static void
ulq_launch(void)
{
	nlookup_t *nl;
	struct ulq_item *ui;

	g_assert(fifo_count(ulq->q));

	ui = fifo_remove(ulq->q);

	g_assert(ui);

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
		slist_append(ulq->launched, ui);
		ulq->running++;
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
	if (NULL == ulq)
		return;

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_message("DHT ULQ service on entry: has %d running and %d pending",
			ulq->running, fifo_count(ulq->q));

	while (fifo_count(ulq->q) && ulq->running < ULQ_MAX_RUNNING)
		ulq_launch();

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_message("DHT ULQ service at exit: has %d running and %d pending",
			ulq->running, fifo_count(ulq->q));
}

/**
 * Callout queue callback to perform queue servicing.
 */
static void
ulq_do_service(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	ulq_service();
}

/**
 * Schedule asynchronous queue servicing.
 */
static void
ulq_needs_servicing(void)
{
	cq_insert(callout_queue, 1, ulq_do_service, NULL);
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

	g_assert(ok);
	g_assert(error);

	ui = allocate_ulq_item(LOOKUP_NODE,  kuid, error, arg);
	ui->u.fn.ok = ok;

	fifo_put(ulq->q, ui);
	ulq_needs_servicing();
}

/**
 * Enqueue value lookup.
 */
void
ulq_find_value(const kuid_t *kuid, dht_value_type_t type,
	lookup_cbv_ok_t ok, lookup_cb_err_t error, gpointer arg)
{
	struct ulq_item *ui;

	g_assert(ok);
	g_assert(error);

	ui = allocate_ulq_item(LOOKUP_VALUE,  kuid, error, arg);
	ui->u.fv.ok = ok;
	ui->u.fv.vtype = type;

	fifo_put(ulq->q, ui);
	ulq_needs_servicing();
}

/**
 * Initialize the user lookup queue.
 */
void
ulq_init(void)
{
	ulq = walloc(sizeof *ulq);
	ulq->q = fifo_make();
	ulq->launched = slist_new();
	ulq->running = 0;
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
	if (ulq) {
		fifo_free_all(ulq->q, free_fifo_item, NULL);
		slist_foreach(ulq->launched, free_fifo_item, NULL);
		slist_free(&ulq->launched);
		wfree(ulq, sizeof *ulq);
		ulq = NULL;
	}
}

#include "lib/override.h"		/* Must be the last header included */

/* vi: set ts=4 sw=4 cindent: */
