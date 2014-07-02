/*
 * Copyright (c) 2003, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Maintain an accurate clock skew of our host's clock with respect
 * to the absolute time.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#include "common.h"

#include "clock.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/cq.h"
#include "lib/entropy.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hevset.h"
#include "lib/misc.h"
#include "lib/stats.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define REUSE_DELAY	10800		/**< 3 hours */
#define ENOUGH_DATA	30			/**< Update skew when we have enough data */
#define MIN_DATA	15			/**< Minimum amount of points for update */
#define MAX_SDEV	60.0		/**< Maximum dispersion we tolerate */
#define CLEAN_STEPS	3			/**< Amount of steps to remove off-track data */

struct used_val {
	host_addr_t addr;			/**< The IP address */
	cevent_t *cq_ev;			/**< Scheduled cleanup event */
	int precision;				/**< The precision used for the last update */
};

static hevset_t *used;			/**< Records the IP address used */

/**
 * This container holds the data points (clock offset between the real UTC
 * time and our local clock time) collected.  For each update, there are
 * two data points entered: u+d and u-d, where u is the update point and
 * d is the precision of the value.
 *
 * When we have "enough" data points, we compute the average and the
 * standard deviation, then we remove all the points lying outside the
 * range [average - sigma, average + sigma].  We then recompute the
 * average and use that to update our clock skew.
 *
 * Since we can't update the system clock, we define a skew and the relation
 * between the real, the local time and the skew is:
 *
 *		real_time = local_time + clock_skew
 *
 * The routine clock_loc2gmt() is used to compute the real time based on
 * the local time, given the currently determined skew.  The skewing of the
 * local time is only used when the host is not running NTP.  Otherwise,
 * we compute the skew just for the fun of it.
 */
static statx_t *datapoints;

/**
 * Dispose of the value from the `used' table.
 */
static void
val_free(struct used_val *v)
{
	g_assert(v);
	g_assert(is_host_addr(v->addr));

	cq_cancel(&v->cq_ev);
	WFREE(v);
}

/**
 * Called from callout queue when it's time to destroy the record.
 */
static void
val_destroy(cqueue_t *cq, void *obj)
{
	struct used_val *v = obj;

	g_assert(v);
	g_assert(is_host_addr(v->addr));

	hevset_remove(used, &v->addr);
	cq_zero(cq, &v->cq_ev);
	val_free(v);
}

/**
 * Create a value for the `used' table.
 */
static struct used_val *
val_create(const host_addr_t addr, int precision)
{
	struct used_val *v;

	g_assert(is_host_addr(addr));

	WALLOC(v);
	v->addr = addr;
	v->precision = precision;
	v->cq_ev = cq_main_insert(REUSE_DELAY * 1000, val_destroy, v);

	return v;
}

/**
 * Accepted an update due to a lower precision entry, reschedule the
 * expiration timeout.
 */
static void
val_reused(struct used_val *v, int precision)
{
	v->precision = precision;
	cq_resched(v->cq_ev, REUSE_DELAY * 1000);
}

/**
 * Called at startup time to initialize local structures.
 */
void
clock_init(void)
{
	used = hevset_create_any(offsetof(struct used_val, addr),
		host_addr_hash_func, host_addr_hash_func2, host_addr_eq_func);
	datapoints = statx_make();
}

static void
used_free_kv(void *val, void *unused_x)
{
	struct used_val *v = val;

	(void) unused_x;
	val_free(v);
}

/**
 * Called at shutdown time to cleanup local structures.
 */
void
clock_close(void)
{
	hevset_foreach(used, used_free_kv, NULL);
	hevset_free_null(&used);
	statx_free(datapoints);
}

/**
 * Adjust clock skew when we have enough datapoints.
 */
static void
clock_adjust(void)
{
	int n;
	double avg;
	double sdev;
	double min;
	double max;
	int i;
	uint32 new_skew;
	int k;

	/*
	 * Compute average and standard deviation using all the data points.
	 */

	n = statx_n(datapoints);

	g_assert(n > 1);		/* To be able to compute the standard deviation */

	avg = statx_avg(datapoints);
	sdev = statx_sdev(datapoints);

	entropy_harvest_many(VARLEN(n), VARLEN(avg), VARLEN(sdev), NULL);

	/*
	 * Incrementally remove aberration points.
	 */

	for (k = 0; k < CLEAN_STEPS; k++) {
		double *value = statx_data(datapoints);

		g_assert(value != NULL);	/* Since n > 1, there are data points */

		if (GNET_PROPERTY(clock_debug) > 1)
			g_debug("CLOCK before #%d: n=%d avg=%g sdev=%g",
				k, n, avg, sdev);

		statx_clear(datapoints);

		/*
		 * Remove aberration points: keep only the sigma range around the
		 * average.
		 */

		min = avg - sdev;
		max = avg + sdev;

		for (i = 0; i < n; i++) {
			double v = value[i];
			if (v < min || v > max)
				continue;
			statx_add(datapoints, v);
		}

		HFREE_NULL(value);

		/*
		 * Recompute the new average using the "sound" points we kept.
		 */

		n = statx_n(datapoints);

		if (n < 2)
			break;		/* Not enough data to compute standard deviation */

		avg = statx_avg(datapoints);
		sdev = statx_sdev(datapoints);

		if (GNET_PROPERTY(clock_debug) > 1)
			g_debug("CLOCK after #%d: kept n=%d avg=%g sdev=%g",
				k, n, avg, sdev);

		if (sdev <= MAX_SDEV || n < MIN_DATA)
			break;
	}

	/*
	 * If standard deviation is too large still, we cannot update our
	 * clock, collect more points.
	 *
	 * If we don't have a minimum amount of data, don't attempt the
	 * update yet, continue collecting.
	 */

	if (sdev > MAX_SDEV || n < MIN_DATA) {
		if (GNET_PROPERTY(clock_debug) > 1)
			g_debug("CLOCK will continue collecting data");
		return;
	}

	statx_clear(datapoints);

	new_skew = GNET_PROPERTY(clock_skew) + (int32) avg;

	if (GNET_PROPERTY(clock_debug))
		g_debug("CLOCK with n=%d avg=%g sdev=%g => SKEW old=%d new=%d",
			n, avg, sdev, (int32) GNET_PROPERTY(clock_skew),
			(int32) new_skew);

	gnet_prop_set_guint32_val(PROP_CLOCK_SKEW, new_skew);
}

/**
 * Update clock information, with given precision in seconds.
 *
 * The `ip' is used to avoid using the same source more than once per
 * REUSE_DELAY seconds.
 */
void
clock_update(time_t update, int precision, const host_addr_t addr)
{
	time_t now;
	int32 delta;
	struct used_val *v;

	g_assert(used);
	g_assert(is_host_addr(addr));

	/*
	 * Discard update if from an IP we've seen less than REUSE_DELAY secs ago
	 * and the precision used for the update was more fine grained than it
	 * is now.
	 *
	 * We always allow updates when the precision is 0, which means the remote
	 * end is running NTP.
	 */

	if ((v = hevset_lookup(used, &addr))) {
		if (precision && precision >= v->precision)
			return;
		val_reused(v, precision);
	} else {
		v = val_create(addr, precision);
		hevset_insert(used, v);
	}

	entropy_harvest_small(
		VARLEN(update), VARLEN(precision), VARLEN(addr), NULL);

	now = tm_time();
	delta = delta_time(update, (now + (int32) GNET_PROPERTY(clock_skew)));

	statx_add(datapoints, (double) (delta + precision));
	statx_add(datapoints, (double) (delta - precision));

	if (GNET_PROPERTY(clock_debug) > 1)
		g_debug("CLOCK skew=%d delta=%d +/-%d [%s] (n=%d avg=%g sdev=%g)",
			(int32) GNET_PROPERTY(clock_skew),
			delta, precision, host_addr_to_string(addr),
			statx_n(datapoints), statx_avg(datapoints), statx_sdev(datapoints));

	if (statx_n(datapoints) >= ENOUGH_DATA)
		clock_adjust();
}

/**
 * Given a local timestamp, use our skew to correct it to GMT.
 */
time_t
clock_loc2gmt(time_t stamp)
{
	if (GNET_PROPERTY(host_runs_ntp))
		return stamp;

	return stamp + (int32) GNET_PROPERTY(clock_skew);
}

/**
 * Given a GMT timestamp, convert it to a local stamp using our skew.
 */
time_t
clock_gmt2loc(time_t stamp)
{
	if (GNET_PROPERTY(host_runs_ntp))
		return stamp;

	return stamp - (int32) GNET_PROPERTY(clock_skew);
}

/* vi: set ts=4 sw=4 cindent: */
