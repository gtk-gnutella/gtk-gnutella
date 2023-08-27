/*
 * Copyright (c) 2012 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Embedded "circular" lists.
 *
 * This provides the illusion that a list (one-way or two-way) is actually a
 * circular list that can be traversed from a given starting point, not
 * necessarily the head of the list.
 *
 * Once the iteration starts, it will loop around and will stop after it has
 * iterated over all the items present in the underlying list, as determined
 * by the list count at the time the iteration starts.
 *
 * One can iterate forward on one-way or two-way lists, and backwards only
 * on two-way lists.
 *
 * Here is a sample pattern that can be used to iterate on a one-way list
 * starting from a given item in the list as if it were the head of the
 * circular list:
 *
 *      eslist_t list;
 *      eclist_t clist;
 *      slink_t *sl;
 *      void *item;
 *
 *      eclist_init(&clist, &list, item);
 *      ...
 *      for (sl = eclist_first(&clist); sl; sl = eclist_next(&clist, sl)) {
 *          void *data = eclist_data(&clist, sl);
 *          ....
 *      }
 *
 * The iteration stops when the amount of traversed items reaches the item
 * count in the list, which means direction cannot be changed once chosen.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _eclist_h_
#define _eclist_h_

#include "elist.h"
#include "eslist.h"

enum eclist_magic { ECLIST_MAGIC = 0x0f6c4428 };

enum eclist_direction {
	ECLIST_UNKNOWN = 0,
	ECLIST_FORWARD,
	ECLIST_BACKWARD
};

typedef struct eclist {
	enum eclist_magic magic;
	enum eclist_direction dir;
	int list_magic;				/* Union discriminent */
	union {
		elist_t *l;
		eslist_t *sl;
	} u;
	size_t count;				/* Amount of items to iterate over */
	size_t iterated;			/* Amount of items we traversed already */
	size_t offset;				/* Offset of embedded link in the item */
	const void *start;			/* Initial item to start with */
} eclist_t;

static inline void
eclist_check(const struct eclist * const cl)
{
	g_assert(cl != NULL);
	g_assert(ECLIST_MAGIC == cl->magic);
}

/**
 * Initialize "circular" iteration over a list from a given item.
 *
 * @param cl		the circular list we're initializing
 * @param list		the physical list where items are chained
 * @param item		the starting point in the circular list we create
 */
static inline void
eclist_init(eclist_t *cl, void *list, const void *item)
{
	struct { int magic; } *head = list;		/* Relies on magic at the start */

	g_assert(cl != NULL);
	g_assert(item != NULL);
	g_assert(list != NULL);

	ZERO(cl);
	cl->magic = ECLIST_MAGIC;
	cl->list_magic = head->magic;
	cl->start = item;

	switch (head->magic) {
	case ELIST_MAGIC:
		{
			elist_t *l = list;
			cl->u.l = l;
			cl->offset = l->offset;
		}
		break;
	case ESLIST_MAGIC:
		{
			eslist_t *sl = list;
			cl->u.sl = sl;
			cl->offset = sl->offset;
		}
		break;
	default:
		g_error("%s(): unknown list type %d in list %p",
			G_STRFUNC, head->magic, list);
	}
}

/**
 * @return the data associated with the curernt link, NULL if none.
 */
static inline void *
eclist_data(const eclist_t *cl, const void * const lk)
{
	eclist_check(cl);

	return NULL == lk ? NULL :
		deconstify_pointer(const_ptr_add_offset(lk, -cl->offset));
}

/**
 * Starts iteration on the pseudo-circular list.
 *
 * @return the first link in the "circular" list, NULL if list is empty.
 */
static inline void *
eclist_first(eclist_t *cl)
{
	eclist_check(cl);

	cl->iterated = 0;
	cl->dir = ECLIST_UNKNOWN;

	switch (cl->list_magic) {
	case ELIST_MAGIC:
		cl->count = cl->u.l->count;
		break;
	case ESLIST_MAGIC:
		cl->count = cl->u.sl->count;
		break;
	default:
		g_error("%s(): unknown list type %d", G_STRFUNC, cl->list_magic);
	}

	return NULL == cl->start ? NULL :
		deconstify_pointer(const_ptr_add_offset(cl->start, cl->offset));
}

/**
 * @return next link in the "circular" list, NULL if none.
 */
static inline void *
eclist_next(eclist_t *cl, const void * const lk)
{
	void *next;

	eclist_check(cl);

	if G_UNLIKELY(cl->count == cl->iterated)
		return NULL;

	if G_UNLIKELY(ECLIST_UNKNOWN == cl->dir)
		cl->dir = ECLIST_FORWARD;

	g_assert(ECLIST_FORWARD == cl->dir);	/* No change in direction */

	cl->iterated++;

	switch (cl->list_magic) {
	case ELIST_MAGIC:
		{
			elist_t *l = cl->u.l;
			next = elist_next(lk);
			if (NULL == next)
				next = elist_first(l);
		}
		break;
	case ESLIST_MAGIC:
		{
			eslist_t *sl = cl->u.sl;
			next = eslist_next(lk);
			if (NULL == next)
				next = eslist_first(sl);
		}
		break;
	default:
		g_assert_not_reached();
	}

	return next;
}

/**
 * @return previous link in the "circular" list, NULL if none.
 */
static inline void *
eclist_prev(eclist_t *cl, const void * const lk)
{
	void *prev;

	eclist_check(cl);

	if G_UNLIKELY(cl->count == cl->iterated)
		return NULL;

	if G_UNLIKELY(ECLIST_UNKNOWN == cl->dir)
		cl->dir = ECLIST_BACKWARD;

	g_assert(ECLIST_BACKWARD == cl->dir);	/* No change in direction */

	cl->iterated++;

	switch (cl->list_magic) {
	case ELIST_MAGIC:
		{
			elist_t *l = cl->u.l;
			prev = elist_prev(lk);
			if (NULL == prev)
				prev = elist_last(l);
		}
		break;
	case ESLIST_MAGIC:
		g_error("%s(): backward iteration not possible with one-way list",
			G_STRFUNC);
	default:
		g_assert_not_reached();
	}

	return prev;
}

/**
 * This is in line with other E*LIST_FOREACH() iterators.
 *
 * An earlier eclist_init() needs to define the starting point in the
 * pseudo-circular list.
 */
#define ECLIST_FOREACH(list, l) \
	for ((l) = eclist_first(list); (l) != NULL; (l) = eclist_next((list), (l)))

#endif /* _eclist_h_ */

/* vi: set ts=4 sw=4 cindent: */
