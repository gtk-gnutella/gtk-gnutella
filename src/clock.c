/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Maintain an accurate clock skew of our host's clock with respect
 * to the absolute time.
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

#include "gnutella.h"

#include <stdio.h>

#include "clock.h"

RCSID("$Id$");

#define MAX_DELTA	86400		/* 1 day */
#define MAX_ADJUST	9600		/* 3 hours */

#define REUSE_DELAY	86400		/* 1 day */

static GHashTable *used;		/* Records the IP address used */

struct used_val {
	guint *ip_atom;				/* The atom used for the key */
	gpointer cq_ev;				/* Scheduled cleanup event */
};

extern cqueue_t *callout_queue;

/*
 * val_free
 *
 * Dispose of the value from the `used' table.
 */
static void val_free(struct used_val *v)
{
	g_assert(v);
	g_assert(v->ip_atom);

	atom_int_free(v->ip_atom);

	if (v->cq_ev)
		cq_cancel(callout_queue, v->cq_ev);

	wfree(v, sizeof(*v));
}

/*
 * val_destroy
 *
 * Called from callout queue when it's time to destroy the record.
 */
static void val_destroy(cqueue_t *cq, gpointer obj)
{
	struct used_val *v = (struct used_val *) obj;

	g_assert(v);
	g_assert(v->ip_atom);

	g_hash_table_remove(used, v->ip_atom);
	v->cq_ev = NULL;
	val_free(v);
}

/*
 * val_create
 *
 * Create a value for the `used' table.
 */
struct used_val *val_create(guint32 ip)
{
	struct used_val *v = walloc(sizeof(*v));

	v->ip_atom = atom_int_get(&ip);
	v->cq_ev = cq_insert(callout_queue, REUSE_DELAY * 1000, val_destroy, v);

	return v;
}

/*
 * clock_init
 *
 * Called at startup time to initialize local structures.
 */
void clock_init(void)
{
	used = g_hash_table_new(g_int_hash, g_int_equal);
}

static void used_free_kv(gpointer key, gpointer val, gpointer x)
{
	struct used_val *v = (struct used_val *) val;

	val_free(v);
}

/*
 * clock_close
 *
 * Called at shutdown time to cleanup local structures.
 */
void clock_close(void)
{
	g_hash_table_foreach(used, used_free_kv, NULL);
	g_hash_table_destroy(used);
}

/*
 * clock_update
 *
 * Update clock information, with given precision in seconds.
 *
 * The `ip' is used to avoid using the same source more than once per
 * REUSE_DELAY seconds.
 */
void clock_update(time_t update, gint precision, guint32 ip)
{
	time_t now;
	gint epsilon;
	gint32 delta_skew;
	gint32 delta;
    guint32 new_skew;
    gint32 skew;
	struct used_val *v;

	g_assert(used);

	/*
	 * Discard update if from an IP we've seen less than REUSE_DELAY secs ago.
	 */

	if (g_hash_table_lookup(used, &ip))
		return;

	v = val_create(ip);
	g_hash_table_insert(used, v->ip_atom, v);

    gnet_prop_get_guint32_val(PROP_CLOCK_SKEW, &new_skew);
	skew = (gint32) new_skew;
	now = time(NULL);

	/*
	 * It's not reasonable to have a delta of more than a day.  If people
	 * accept to run with such a wrong clock (even if it's the local host),
	 * then too bad but GTKG can't fix it.  It's broken beyond repair.
	 */

	if (ABS(skew) > MAX_DELTA) {
		delta = skew > 0 ? +MAX_DELTA : -MAX_DELTA;
		g_warning("truncating clock skew from %d to %d [%s]",
			skew, delta, ip_to_gchar(ip));
		new_skew = (guint32) delta;
		gnet_prop_set_guint32_val(PROP_CLOCK_SKEW, new_skew);
	}

	/*
	 * Compute how far we land from the absolute time given our present skew.
	 * If that epsilon is smaller than the precision of the measure, don't
	 * further update the skew.
	 */

	epsilon = now + skew - update;

	if (ABS(epsilon) <= precision)
		return;

	/*
	 * Limit the amount by which we can correct to avoid sudden jumps.
	 */

	delta = update - now;

	if (ABS(delta) > MAX_DELTA) {
		if (dbg)
			printf("CLOCK rejecting update=%u, precision=%d [%s]"
				" (more than %d seconds off)\n",
				(guint32) update, precision, ip_to_gchar(ip), MAX_DELTA);
		return;
	}

	if (delta < -MAX_ADJUST)
		delta = -MAX_ADJUST;
	else if (delta > MAX_ADJUST)
		delta = MAX_ADJUST;

	/*
	 * Update the clock_skew as a slow EMA.
	 */

	delta_skew = delta / 32 - skew / 32;
	new_skew = (guint32) (skew + delta_skew);
    gnet_prop_set_guint32_val(PROP_CLOCK_SKEW, new_skew);

	if (dbg)
		printf("CLOCK skew=%d, precision=%d, epsilon=%d [%s]\n",
			(gint32) clock_skew, precision, epsilon, ip_to_gchar(ip));
}

/*
 * clock_loc2gmt
 *
 * Given a local timestamp, use our skew to correct it to GMT.
 */
time_t clock_loc2gmt(time_t stamp)
{
	if (host_runs_ntp)
		return stamp;

	return stamp + (gint32) clock_skew;
}

/*
 * clock_gmt2loc
 *
 * Given a GMT timestamp, convert it to a local stamp using our skew.
 */
time_t clock_gmt2loc(time_t stamp)
{
	if (host_runs_ntp)
		return stamp;

	return stamp - (gint32) clock_skew;
}

