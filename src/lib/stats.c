/*
 * Copyright (c) 2004, 2013 Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Statistics routines.
 *
 * @author Raphael Manfredi
 * @date 2004, 2013
 */

#include "common.h"

#ifdef I_MATH
#include <math.h>
#endif	/* I_MATH */

#include "stats.h"

#include "elist.h"
#include "halloc.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

enum statx_magic { STATX_MAGIC = 0x560044e5 };

/**
 * A one-dimension container (x).
 */
struct statistics {
	enum statx_magic magic;	/**< Magic number */
	elist_t data;			/**< Data points */
	long n;					/**< Amount of data points */
	double sx;				/**< Sx: sum of all points */
	double sx2;				/**< Sx2: sum of the square of all points */
	bool no_data;			/**< Do not keep data, it is managed externally */
};

static inline void
statx_check(const struct statistics * const sx)
{
	g_assert(sx != NULL);
	g_assert(STATX_MAGIC == sx->magic);
}

/**
 * Items stored in the data list.
 */
struct stat_datapoint {
	link_t data_link;		/**< Embedded link */
	double value;
};

typedef enum op {
	STATS_OP_REMOVE = -1,
	STATS_OP_ADD = +1
} stats_op_t;

/**
 * Create one-dimension container.
 */
statx_t *
statx_make(void)
{
	statx_t *sx;

	WALLOC0(sx);
	sx->magic = STATX_MAGIC;
	elist_init(&sx->data, offsetof(struct stat_datapoint, data_link));
	return sx;
}

/**
 * Create one-dimension set of statistics with no data management.
 */
statx_t *
statx_make_nodata(void)
{
	statx_t *sx;

	sx = statx_make();
	sx->no_data = TRUE;
	return sx;
}

/**
 * Destroy one-dimension container.
 */
void
statx_free(statx_t *sx)
{
	statx_check(sx);

	statx_clear(sx);
	sx->magic = 0;
	WFREE(sx);
}

/**
 * Free stats container and nullify its pointer.
 */
void
statx_free_null(statx_t **sx_ptr)
{
	statx_t *sx = *sx_ptr;

	if (sx != NULL) {
		statx_free(sx);
		*sx_ptr = NULL;
	}
}

/**
 * Clear container.
 */
void
statx_clear(statx_t *sx)
{
	statx_check(sx);

	elist_wfree(&sx->data, sizeof(struct stat_datapoint));

	sx->n = 0;
	sx->sx = 0.0;
	sx->sx2 = 0.0;
}

/**
 * Add/substract one data point.
 *
 * @param sx the container
 * @param val the value to add/remove
 * @param op the operation: STATS_OP_ADD or STATS_OP_REMOVE
 */
static void
statx_opx(statx_t *sx, double val, stats_op_t op)
{
	g_assert(op == STATS_OP_ADD || sx->n > 0);
	g_assert(op == STATS_OP_ADD || 0 != elist_count(&sx->data) || sx->no_data);

	if (!sx->no_data) {
		struct stat_datapoint *dp;

		if (op == STATS_OP_REMOVE) {
			/*
			 * If value is removed, it must belong to the data set.
			 */

			ELIST_FOREACH_DATA(&sx->data, dp) {
				double delta = dp->value - val;

				if (fabs(delta) < 1e-56) {
					elist_remove(&sx->data, dp);
					WFREE(dp);
					break;
				}
			}

			g_assert(dp != NULL);		/* Found it */
		} else {
			WALLOC0(dp);
			dp->value = val;
			elist_prepend(&sx->data, dp);
		}
	}

	sx->n += op;
	sx->sx += op * val;
	sx->sx2 += op * val * val;
}

/**
 * Add data point to container.
 */
void
statx_add(statx_t *sx, double val)
{
	statx_check(sx);

	statx_opx(sx, val, STATS_OP_ADD);
}

/**
 * Remove data point from container.
 */
void
statx_remove(statx_t *sx, double val)
{
	statx_check(sx);

	statx_opx(sx, val, STATS_OP_REMOVE);
}

/**
 * Remove oldest data point from container.
 */
void
statx_remove_oldest(statx_t *sx)
{
	struct stat_datapoint *dp;
	double val = 0;

	statx_check(sx);
	g_assert(!sx->no_data);
	g_assert(sx->n >= 0);
	g_assert((sx->n > 0) ^ (0 == elist_count(&sx->data)));

	if (sx->n < 1)
		return;

	/*
	 * Since we prepend new items to the list, the oldest item is the last.
	 */

	dp = elist_tail(&sx->data);
	g_assert(dp != NULL);			/* We have at least one item */
	val = dp->value;
	elist_remove(&sx->data, dp);
	WFREE(dp);

	sx->n--;
	sx->sx -= val;
	sx->sx2 -= val * val;

	g_assert((sx->n > 0) ^ (0 == elist_count(&sx->data)));
}

/**
 * @return amount of data points.
 */
int
statx_n(const statx_t *sx)
{
	statx_check(sx);

	return sx->n;
}

/**
 * @return average of data points.
 */
double
statx_avg(const statx_t *sx)
{
	statx_check(sx);
	g_assert(sx->n > 0);

	return sx->sx / sx->n;
}

/**
 * @return the standard deviation of the data points.
 */
double
statx_sdev(const statx_t *sx)
{
	return sqrt(statx_var(sx));
}

/**
 * @return the variance of the data points.
 */
double
statx_var(const statx_t *sx)
{
	statx_check(sx);
	g_assert(sx->n > 1);

	return (sx->sx2 - (sx->sx * sx->sx) / sx->n) / (sx->n - 1);
}

/**
 * @return the standard error of the mean.
 */
double
statx_stderr(const statx_t *sx)
{
	return sqrt(statx_var(sx) / sx->n);
}

/**
 * @return an array of datapoints which can be freed via hfree() when done.
 */
double *
statx_data(const statx_t *sx)
{
	double *array;
	int i;
	struct stat_datapoint *dp;

	statx_check(sx);
	g_assert(!sx->no_data);
	g_assert(sx->n > 0);

	HALLOC_ARRAY(array, sx->n);

	i = 0;
	ELIST_FOREACH_DATA(&sx->data, dp) {
		array[i++] = dp->value;
	}

	return array;
}

struct statx_foreach_trampoline_ctx {
	double_data_fn_t cb;
	void *udata;
};

static void
statx_foreach_trampoline(void *data, void *udata)
{
	struct stat_datapoint *dp = data;
	struct statx_foreach_trampoline_ctx *ctx = udata;

	(*ctx->cb)(dp->value, ctx->udata);
}

/**
 * Iterate over the datapoints.
 *
 * @param sx	the stats data container
 * @param cb	function to invoke on all items
 * @param data	opaque user-data to pass to callback
 */
void
statx_foreach(const statx_t *sx, double_data_fn_t cb, void *udata)
{
	struct statx_foreach_trampoline_ctx ctx;

	statx_check(sx);
	g_assert(!sx->no_data);

	ctx.cb = cb;
	ctx.udata = udata;

	elist_foreach(&sx->data, statx_foreach_trampoline, &ctx);
}

struct statx_foreach_remove_trampoline_ctx {
	double_data_rm_fn_t cb;
	void *udata;
};

static bool
statx_foreach_remove_trampoline(void *data, void *udata)
{
	struct stat_datapoint *dp = data;
	struct statx_foreach_remove_trampoline_ctx *ctx = udata;

	return (*ctx->cb)(dp->value, ctx->udata);
}

/**
 * Iterate over the datapoints, involing the callback for each of them and
 * removing them when the callback returns TRUE.
 *
 * @param sx	the stats data container
 * @param cb	function to invoke on all items
 * @param data	opaque user-data to pass to callback
 *
 * @return amount of removed items from the stats container.
 */
size_t
statx_foreach_remove(statx_t *sx, double_data_rm_fn_t cb, void *udata)
{
	struct statx_foreach_remove_trampoline_ctx ctx;

	statx_check(sx);
	g_assert(!sx->no_data);

	ctx.cb = cb;
	ctx.udata = udata;

	return elist_foreach_remove(&sx->data,
		statx_foreach_remove_trampoline, &ctx);
}

struct statx_remove_outliers_ctx {
	double mean;			/* Initial average of the data set */
	double limit;			/* Limit distance from the mean */
	statx_t *sx;			/* The stats container we're iterating over */
};

/**
 * Iterator callbacl to remove outlier data points.
 *
 * @return TRUE if datapoint is further from the mean than the set limit.
 */
static bool
stats_remove_outlier_data(void *data, void *udata)
{
	const struct stat_datapoint *dp = data;
	struct statx_remove_outliers_ctx *ctx = udata;
	statx_t *sx;
	double d;

	d = fabs(dp->value - ctx->mean);
	if (d <= ctx->limit)
		return FALSE;		/* Within range */

	/* Remove the datapoint, update internal data structures */

	sx = ctx->sx;
	statx_check(sx);

	sx->n--;
	sx->sx -= dp->value;
	sx->sx2 -= dp->value * dp->value;

	return TRUE;	/* Outlier, remove from set */
}

/**
 * Remove outliers: datapoints further from the mean than the specified amount
 * of standard deviations.
 *
 * @param sx	the stats data container
 * @param range	how many standard deviations is considered within range
 *
 * @return amount of removed items from the stats container.
 */
size_t
statx_remove_outliers(statx_t *sx, double range)
{
	struct statx_remove_outliers_ctx ctx;

	statx_check(sx);
	g_assert(!sx->no_data);
	g_assert(sx->n > 1);
	g_assert(range >= 0);

	ctx.mean = statx_avg(sx);
	ctx.limit = statx_sdev(sx) * range;
	ctx.sx = sx;

	return elist_foreach_remove(&sx->data, stats_remove_outlier_data, &ctx);
}

/* vi: set ts=4 sw=4 cindent: */
