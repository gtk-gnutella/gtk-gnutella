/*
 * Copyright (c) 2012-2015 Raphael Manfredi
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
 * Embedded one-way list (within another data structure).
 *
 *   +-----+     +-----+     +-----+  ^
 *   |/////|     |/////|     |/////|  |
 *   |/////|     |/////|     |/////|  |  offset
 *   |/////|     |/////|     |/////|  |
 *   +=====+     +=====+     +=====+  v
 *   | ***-+---->| ***-+---->|(nil)|     link offset = 0
 *   +=====+     +=====+     +=====+
 *
 * Embedded lists are created when the linking pointers are directly
 * held within the data structure, as opposed to glib's lists which are
 * containers pointing at objects.
 *
 * Embedded lists are intrusive in the sense that the objects have an explicit
 * slink_t field, but this saves one pointer per item being linked compared
 * to glib's lists.  On the other hand, if an object may belong to several lists
 * based on certain criteria, but not all of the lists (and without any mutual
 * exclusion), then the embedded list approach is not necessarily saving space
 * since some items will have slink_t fields that do not get used.
 *
 * Due to the nature of the data structure, the definition of the internal
 * structures is visible in the header file but users must refrain from
 * peeking and poking into the structures.  Using embedded data structures
 * requires more discipline than opaque data structures.
 *
 * The API of embedded lists mirrors that of glib's lists to make a smooth
 * transition possible and maintain some consistency in the code.  That said,
 * the glib list API is quite good so mirroring it is not a problem.
 *
 * @author Raphael Manfredi
 * @date 2012-2015
 */

#include "common.h"

#include "eslist.h"

#include "unsigned.h"
#include "walloc.h"

#if 0
#define ESLIST_SAFETY_ASSERT	/**< Turn on costly integrity assertions */
#endif

#ifdef ESLIST_SAFETY_ASSERT
#define safety_assert(x)	g_assert(x)
#else
#define safety_assert(x)
#endif

/*
 * Configure owlist-gen.c for an "eslist".
 */

#define CHECK(l)			eslist_check(l)
#define INVARIANT(l)		eslist_invariant(l)
#define CONTAINS(l,v)		eslist_contains(l,v)
#define PREFIX				eslist_
#define OWLIST_T			eslist_t
#define OWLINK_T			slink_t
#define NEXT(l,lk)			((lk)->next)
#define SET_NEXT(l,lk,v)	((lk)->next = (v))
#define LENGTH(l,h)			eslist_length(h)
#define LINK_OFFSET(l)		0
#define LIST_ARG(l)

/**
 * Initialize embedded list.
 *
 * Assuming items in the list are defined as:
 *
 *     struct item {
 *         <data fields>
 *         slink_t lk;
 *     };
 *
 * then the last argument can be given as:
 *
 *     offsetof(struct item, lk)
 *
 * to indicate the place of the node field within the item.
 *
 * @param list		the list structure to initialize
 * @param offset	the offset of the embedded link field within items
 */
void
eslist_init(eslist_t *list, size_t offset)
{
	g_assert(list != NULL);
	g_assert(size_is_non_negative(offset));

	list->magic = ESLIST_MAGIC;
	list->head = NULL;
	list->tail = NULL;
	list->count = 0;
	list->offset = offset;
}

/**
 * Free all items in the list, using wfree() on each of them, clearing the list.
 *
 * Each item must be of the same size and have been allocated via walloc().
 * Each item must have been cleared first, so that any internal memory allocated
 * and referenced by the item has been properly released.
 *
 * This is more efficient that looping over all the items, clearing them and
 * then calling wfree() on them because we amortize the wfree() cost over a
 * large amount of objects and need to lock/unlock once only, if any lock is
 * to be taken.
 *
 * @param list		the list to free
 * @param size		the size of each item, passed to wfree()
 */
void
eslist_wfree(eslist_t *list, size_t size)
{
	eslist_check(list);

	if G_UNLIKELY(0 == list->count)
		return;

	wfree_eslist(list, size);
	eslist_clear(list);
}

#include "owlist-gen.c"

/*
 * These defines are there only for tags
 * Routines are defined in owlist-gen.c, as included above
 */

#define eslist_discard						OWLIST_discard
#define eslist_clear						OWLIST_clear
#define eslist_mark_removed					OWLIST_mark_removed
#define eslist_link_mark_removed			OWLIST_link_mark_removed
#define eslist_link_append_internal			OWLIST_link_append_internal
#define eslist_link_append					OWLIST_link_append
#define eslist_append						OWLIST_append
#define eslist_link_prepend_internal		OWLIST_link_prepend_internal
#define eslist_link_prepend					OWLIST_link_prepend
#define eslist_prepend						OWLIST_prepend
#define eslist_prepend_list					OWLIST_prepend_list
#define eslist_append_list					OWLIST_append_list
#define eslist_link_remove_after_internal	OWLIST_link_remove_after_internal
#define eslist_shift						OWLIST_shift
#define eslist_rotate_left					OWLIST_rotate_left
#define eslist_link_insert_after_internal	OWLIST_link_insert_after_internal
#define eslist_link_insert_after			OWLIST_link_insert_after
#define eslist_insert_after					OWLIST_insert_after
#define eslist_remove						OWLIST_remove
#define eslist_remove_after					OWLIST_remove_after
#define eslist_reverse						OWLIST_reverse
#define eslist_find							OWLIST_find
#define eslist_foreach						OWLIST_foreach
#define eslist_foreach_remove				OWLIST_foreach_remove
#define eslist_merge_sort					OWLIST_merge_sort
#define eslist_sort_internal				OWLIST_sort_internal
#define eslist_sort_with_data				OWLIST_sort_with_data
#define eslist_sort							OWLIST_sort
#define eslist_insert_sorted_internal		OWLIST_insert_sorted_internal
#define eslist_insert_sorted_with_data		OWLIST_insert_sorted_with_data
#define eslist_insert_sorted				OWLIST_insert_sorted
#define eslist_nth							OWLIST_nth
#define eslist_nth_next_data				OWLIST_nth_next_data
#define eslist_random						OWLIST_random
#define eslist_shuffle_with					OWLIST_shuffle_with
#define eslist_shuffle						OWLIST_shuffle

/* vi: set ts=4 sw=4 cindent: */
