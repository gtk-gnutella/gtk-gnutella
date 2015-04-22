/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Expanded one-way list (within another data structure).
 *
 *   +-----+     +-----+     +-----+  ^
 *   |/////|     |/////|     |/////|  |
 *   |/////|     |/////|     |/////|  |  offset
 *   |/////|     |/////|     |/////|  |
 *   +=====+  +->+=====+  +->+=====+  x
 *   |     | /   |     | /   |     |  |  link offset
 *   | ***-+/    | ***-+/    |(nil)|  v
 *   +=====+     +=====+     +=====+
 *
 * These are a form of embedded lists when the link offset is not zero, i.e.
 * the chaining pointer does not immediately refer to the chaining pointer of
 * the next item in the list.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "xslist.h"

#include "unsigned.h"

#if 0
#define XSLIST_SAFETY_ASSERT	/**< Turn on costly integrity assertions */
#endif

#ifdef XSLIST_SAFETY_ASSERT
#define safety_assert(x)	g_assert(x)
#else
#define safety_assert(x)
#endif

/*
 * Configure owlist-gen.c for an "xslist".
 */

#define CHECK(l)			xslist_check(l)
#define INVARIANT(l)		xslist_invariant(l)
#define PREFIX				xslist_
#define OWLIST_T			xslist_t
#define OWLINK_T			xslink_t
#define NEXT(l,lk)			xslist_next((l), (lk))
#define SET_NEXT(l,lk,v)	xslist_set_next((l), (lk), (v))
#define LENGTH(l,h)			xslist_length((l), (h))
#define LINK_OFFSET(l)		((l)->link_offset)
#define LIST_ARG(l)			(l),

/**
 * Initialize expanded list.
 *
 * Assuming items in the list are defined as:
 *
 *     struct item {
 *         <data fields>
 *         struct chaining {
 *             <some chaining links>
 *             struct chaining *next;	// our "next" pointer, linking field
 *         } chain;
 *     };
 *
 * then the offset argument can be given as:
 *
 *     offsetof(struct item, chain)
 *
 * and the link_offset argument can be given as:
 *
 *     offsetof(struct chaining, next)
 *
 * to indicate the place of the field chaining items together.
 *
 * @param list			the list structure to initialize
 * @param offset		the offset of the expanded link field within items
 * @param link_offset	the offset of the linking field in the chaining struct
 */
void
xslist_init(xslist_t *list, size_t offset, size_t link_offset)
{
	g_assert(list != NULL);
	g_assert(size_is_non_negative(offset));
	g_assert(size_is_non_negative(link_offset));

	list->magic = XSLIST_MAGIC;
	list->head = NULL;
	list->tail = NULL;
	list->count = 0;
	list->offset = offset;
	list->link_offset = link_offset;
}

/**
 * Initialize and load linked items into a list.
 *
 * This routine is meant to allow the creation of an expanded list from
 * homogeneous items that happen to be linked into another data structure
 * through a single pointer.
 *
 * It is useful to allow reuse of code that can process such lists, such
 * as xslist_sort(), xslist_shuffle(), etc...  It is naturally up to the
 * caller to then refetch the proper head pointer.
 *
 * @param list			the list into which we are loading items
 * @param head			first data item part of the linked list (NULL possible)
 * @param offset		the offset of the expanded link field within items
 * @param link_offset	the offset of the linking field in the chaining struct
 *
 * @return the amount of loaded items, as a convenience.
 */
size_t
xslist_load(xslist_t *list, void *head, size_t offset, size_t link_offset)
{
	xslink_t *lk, *next;
	size_t n;

	g_assert(list != NULL);
	g_assert(size_is_non_negative(offset));

	xslist_init(list, offset, link_offset);

	if G_UNLIKELY(NULL == head)
		return 0;

	lk = ptr_add_offset(head, offset);
	list->head = lk;

	for (n = 1; NULL != (next = xslist_next(list, lk)); n++, lk = next)
		/* empty */;

	list->tail = lk;
	list->count = n;

	safety_assert(xslist_length(list, list->head) == list->count);

	return n;
}

#include "owlist-gen.c"

/*
 * These defines are there only for tags
 * Routines are defined in owlist-gen.c, as included above
 */

#define xslist_discard						OWLIST_discard
#define xslist_clear						OWLIST_clear
#define xslist_link_append_internal			OWLIST_link_append_internal
#define xslist_link_append					OWLIST_link_append
#define xslist_append						OWLIST_append
#define xslist_link_prepend_internal		OWLIST_link_prepend_internal
#define xslist_link_prepend					OWLIST_link_prepend
#define xslist_prepend						OWLIST_prepend
#define xslist_prepend_list					OWLIST_prepend_list
#define xslist_append_list					OWLIST_append_list
#define xslist_link_remove_after_internal	OWLIST_link_remove_after_internal
#define xslist_shift						OWLIST_shift
#define xslist_rotate_left					OWLIST_rotate_left
#define xslist_link_insert_after_internal	OWLIST_link_insert_after_internal
#define xslist_link_insert_after			OWLIST_link_insert_after
#define xslist_insert_after					OWLIST_insert_after
#define xslist_remove						OWLIST_remove
#define xslist_remove_after					OWLIST_remove_after
#define xslist_reverse						OWLIST_reverse
#define xslist_find							OWLIST_find
#define xslist_foreach						OWLIST_foreach
#define xslist_foreach_remove				OWLIST_foreach_remove
#define xslist_merge_sort					OWLIST_merge_sort
#define xslist_sort_internal				OWLIST_sort_internal
#define xslist_sort_with_data				OWLIST_sort_with_data
#define xslist_sort							OWLIST_sort
#define xslist_insert_sorted_internal		OWLIST_insert_sorted_internal
#define xslist_insert_sorted_with_data		OWLIST_insert_sorted_with_data
#define xslist_insert_sorted				OWLIST_insert_sorted
#define xslist_nth							OWLIST_nth
#define xslist_nth_next_data				OWLIST_nth_next_data
#define xslist_random						OWLIST_random
#define xslist_shuffle_with					OWLIST_shuffle_with
#define xslist_shuffle						OWLIST_shuffle

/* vi: set ts=4 sw=4 cindent: */
