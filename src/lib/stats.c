/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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
 * @date 2004
 */

#include "common.h"

RCSID("$Id$")

#ifdef I_MATH
#include <math.h>
#endif	/* I_MATH */

#include "stats.h"
#include "glib-missing.h"	/* For g_slist_delete_link() */
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

/**
 * A one-dimension container (x).
 */
struct statx {
	GSList *data;			/**< Data points (value = gdouble *) */
	gint n;					/**< Amount of points */
	gdouble sx;				/**< Sx: sum of all points */
	gdouble sx2;			/**< Sx2: sum of the square of all points */
};

typedef enum op {
	STATS_OP_REMOVE = -1,
	STATS_OP_ADD = +1
} stats_op_t;

/**
 * Create one-dimension container.
 */
gpointer
statx_make(void)
{
	struct statx *sx;

	sx = walloc0(sizeof(*sx));
	return sx;
}

/**
 * Destroy one-dimension container.
 */
void
statx_free(gpointer ox)
{
	struct statx *sx = (struct statx *) ox;

	statx_clear(ox);
	wfree(sx, sizeof(*sx));
}

/**
 * Clear container.
 */
void
statx_clear(gpointer ox)
{
	struct statx *sx = (struct statx *) ox;
	GSList *l;

	for (l = sx->data; l; l = g_slist_next(l)) {
		gdouble *vp = (gdouble *) l->data;
		wfree(vp, sizeof(*vp));
	}
	g_slist_free(sx->data);

	sx->data = NULL;
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
statx_opx(struct statx *sx, gdouble val, stats_op_t op)
{
	g_assert(op == STATS_OP_ADD || sx->n > 0);
	g_assert(op == STATS_OP_ADD || sx->data != NULL);

	if (op == STATS_OP_REMOVE) {
		GSList *l;

		/*
		 * If value is removed, it must belong to the data set.
		 */

		for (l = sx->data; l; l = g_slist_next(l)) {
			gdouble *vp = (gdouble *) l->data;

			if (*vp == val) {
				sx->data = g_slist_remove(sx->data, vp);
				wfree(vp, sizeof(*vp));
				break;
			}
		}

		g_assert(l != NULL);		/* Found it */
	} else {
		gdouble *vp;

		vp = walloc(sizeof(*vp));
		*vp = val;
		sx->data = g_slist_prepend(sx->data, vp);
	}

	sx->n += op;
	sx->sx += op * val;
	sx->sx2 += op * val * val;
}

/**
 * Add data point to container.
 */
void
statx_add(gpointer ox, gdouble val)
{
	statx_opx(ox, val, STATS_OP_ADD);
}

/**
 * Remove data point from container.
 */
void
statx_remove(gpointer ox, gdouble val)
{
	statx_opx(ox, val, STATS_OP_REMOVE);
}

/**
 * Remove oldest data point from container.
 */
void
statx_remove_oldest(gpointer ox)
{
	struct statx *sx = ox;
	GSList *l;
	gdouble val;

	g_assert(sx->n > 0);
	g_assert(sx->data != NULL);

	/*
	 * Since we prepend new items to the list (for speed), we need to find
	 * the next to last item to delete the final item.
	 */

	for (l = sx->data; l; l = g_slist_next(l)) {
		GSList *next = g_slist_next(l);
		if (next == NULL) {
			/* Only one item in list, `l' points to it */
			gdouble *vp = (gdouble *) l->data;
			val = *vp;
			wfree(vp, sizeof(*vp));
			g_slist_free(sx->data);
			sx->data = NULL;
			break;
		} else if (NULL == g_slist_next(next)) {
			/* The item after `l' is the last item of the list */
			gdouble *vp = (gdouble *) next ->data;
			val = *vp;
			wfree(vp, sizeof(*vp));
			(void) g_slist_delete_link(l, next);
			break;
		}
	}

	sx->n--;
	sx->sx -= val;
	sx->sx2 -= val * val;

	g_assert(sx->n > 0 || sx->data == NULL);
}

/**
 * @return amount of data points.
 */
gint
statx_n(gpointer ox)
{
	struct statx *sx = ox;
	return sx->n;
}

/**
 * @return average of data points.
 */
gdouble
statx_avg(gpointer ox)
{
	struct statx *sx = ox;

	g_assert(sx->n > 0);

	return sx->sx / sx->n;
}

/**
 * @return the standard deviation of the data points.
 */
gdouble
statx_sdev(gpointer ox)
{
	return sqrt(statx_var(ox));
}

/**
 * @return the variance of the data points.
 */
gdouble
statx_var(gpointer ox)
{
	struct statx *sx = ox;

	g_assert(sx->n > 1);

	return (sx->sx2 - (sx->sx * sx->sx) / sx->n) / (sx->n - 1);
}

/**
 * @return an array of datapoints which can be freed when done.
 */
gdouble *
statx_data(gpointer ox)
{
	struct statx *sx = ox;
	gdouble *array;
	gint i;
	GSList *l;

	g_assert(sx->n > 0);

	array = g_malloc(sizeof(gdouble) * sx->n);

	for (i = 0, l = sx->data; i < sx->n && l; l = g_slist_next(l), i++) {
		gdouble *vp = (gdouble *) l->data;
		array[i] = *vp;
	}

	return array;
}

/* vi: set ts=4: */
