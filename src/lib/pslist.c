/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Plain one-way list.
 *
 * This is a very low-level list, with no bookkeeping of meta information:
 * the list is known by a pointer to the head cell, and all operations that
 * can change the head of the list return a new head.
 *
 * An empty list is represented by a NULL pointer.
 *
 * List cells are allocated through walloc() by default, but all the *_ext()
 * routines take an extra pointer to a pcell_alloc_t structure that can provide
 * specific cell allocation/deallocation routines.
 *
 * The whole API is not available for externally allocated cells, and the
 * caller is responsible for consistently supplying the same cell allocator!
 * Only the most common insertion / removal routines have an *_ext() version
 * for now (2016-08-28).

 * However, routines that do not need to allocate / deallocate cells do not
 * have an *_ext() version.  For instance, pslist_shuffle() or pslist_reverse()
 * can be freely used even if the cells are not allocated using the defaults.
 *
 *
 * The API of plain lists mirrors that of glib's lists to make a smooth
 * transition possible and maintain some consistency in the code.  That
 * said, the glib list API is quite good so mirroring it is not a problem.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "pslist.h"

#include "eslist.h"
#include "log.h"
#include "pcell.h"
#include "random.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

/*
 * Parts of the code below have been "copied" from Glib's implementation.
 * Sometimes copying merely involved translation and adaptation to the local
 * coding style, sometimes it involved more, with additional assertions.
 *
 * That original code was released under the LGPL, and was:
 *
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 * Modified by the GLib Team and others 1997-2000.
 *
 * Additional routines and initial adaptation are:
 *
 * Copyright (c) 2013, 2016 Raphael Manfredi
 */

/*
 * Default cell allocators.
 */

static void *
pslist_cell_alloc(void)
{
	pslist_t *pl;

	WALLOC0(pl);
	return pl;
}

static void
pslist_cell_free(void *cell)
{
	pslist_t *l = cell;

	WFREE(l);
}

static pcell_alloc_t pslist_default_alloc = {
	pslist_cell_alloc,		/* pcell_alloc */
	pslist_cell_free,		/* pcell_free */
};

/**
 * Allocate a list cell for storing one element.
 *
 * @return pointer to newly allocated element, pointing to NULL data.
 */
pslist_t *
pslist_alloc(void)
{
	return pslist_cell_alloc();
}

/**
 * Free the cell element only, which must not be part of any list.
 *
 * @attention
 * The held item is not freed.
 *
 * @param l		the cell to be freed (can be NULL)
 */
void
pslist_free_1(pslist_t *l)
{
	g_assert(NULL == l || NULL == l->next);		/* Not part of any list */

	if (l != NULL)
		WFREE(l);
}

/**
 * Free the cell element and nullify its pointer.
 */
void
pslist_free_1_null(pslist_t **l_ptr)
{
	pslist_t *l = *l_ptr;

	if (l != NULL) {
		pslist_free_1(l);
		*l_ptr = NULL;
	}
}

/**
 * Free all the cell elements in the list, but do not touch the held data.
 *
 * To be able to free the items in the list, use pslist_free_full().
 *
 * @param pl		the head of the list
 *
 * @return NULL as a convenience.
 */
pslist_t *
pslist_free(pslist_t *pl)
{
	if G_UNLIKELY(NULL == pl)
		return NULL;

	/*
	 * To be extremely fast, use a specialized freeing routine that will
	 * limit the amount of overhead to process all the entries in the list.
	 */

	wfree_pslist(PTRLEN(pl));
	return NULL;
}

/**
 * Free pslist and nullify pointer holding it.
 */
void
pslist_free_null(pslist_t **pl_ptr)
{
	pslist_t *pl = *pl_ptr;

	if (pl != NULL) {
		pslist_free(pl);
		*pl_ptr = NULL;
	}
}

/**
 * Free all the cell elements in the list, applying the free callback on
 * each item.
 *
 * @param pl		the head of the list
 * @param fn		routine to call on each item of the list
 *
 * @return NULL as a convenience.
 */
pslist_t *
pslist_free_full(pslist_t *pl, free_fn_t fn)
{
	pslist_t *l;

	for (l = pl; l != NULL; l = l->next) {
		(*fn)(l->data);
	}

	pslist_free(pl);
	return NULL;
}

/**
 * Free pslist, applying free callback each item, and then nullify pointer
 * holding it.
 */
void
pslist_free_full_null(pslist_t **pl_ptr, free_fn_t fn)
{
	pslist_t *pl = *pl_ptr;

	if (pl != NULL) {
		pslist_free_full(pl, fn);
		*pl_ptr = NULL;
	}
}

/**
 * @return the last cell of the list.
 */
pslist_t *
pslist_last(const pslist_t *pl)
{
	if G_LIKELY(pl != NULL) {
		pslist_t *l = deconstify_pointer(pl);

		while (l->next != NULL)
			l = l->next;

		return l;
	} else {
		return NULL;
	}
}

/**
 * Go to last cell and computes length as we go.
 *
 * @param pl	the head of the list
 * @param count	where count is written back
 *
 * @return the last cell of the list, with length set in ``count''.
 */
pslist_t *
pslist_last_count(const pslist_t *pl, size_t *count)
{
	size_t n = 0;
	pslist_t *l = deconstify_pointer(pl);

	g_assert(count != NULL);	/* Use pslist_last() if you don't care! */

	if G_LIKELY(l != NULL) {
		n++;
		while (l->next != NULL) {
			l = l->next;
			n++;
		}
	}

	*count = n;
	return l;
}

/**
 * Append new item at the end of the list.
 *
 * @attention
 * This is inefficient and requires a full traversal of the list.
 *
 * @param pl		the head of the list
 * @param data		the data item to append
 * @param ca		cell allocator
 *
 * @return the new head of the list.
 */
pslist_t *
pslist_append_ext(pslist_t *pl, void *data, const pcell_alloc_t *ca)
{
	pslist_t *nl = ca->pcell_alloc();

	nl->next = NULL;
	nl->data = data;

	if (pl != NULL) {
		pslist_t *last = pslist_last(pl);
		last->next = nl;
		return pl;
	} else {
		return nl;
	}
}

/**
 * Append new item at the end of the list.
 *
 * @attention
 * This is inefficient and requires a full traversal of the list.
 *
 * @param pl		the head of the list
 * @param data		the data item to append
 *
 * @return the new head of the list.
 */
pslist_t *
pslist_append(pslist_t *pl, void *data)
{
	return pslist_append_ext(pl, data, &pslist_default_alloc);
}

/**
 * Prepend new item at the head of the list.
 *
 * @param pl		the head of the list
 * @param data		the data item to prepend
 * @param ca		cell allocator
 *
 * @return the new head of the list.
 */
pslist_t *
pslist_prepend_ext(pslist_t *pl, void *data, const pcell_alloc_t *ca)
{
	pslist_t *nl = ca->pcell_alloc();

	nl->next = pl;
	nl->data = data;

	return nl;
}

/**
 * Prepend new item at the head of the list.
 *
 * @param pl		the head of the list
 * @param data		the data item to prepend
 *
 * @return the new head of the list.
 */
pslist_t *
pslist_prepend(pslist_t *pl, void *data)
{
	return pslist_prepend_ext(pl, data, &pslist_default_alloc);
}

/**
 * Insert a new cell with data before specified cell (which must belong
 * to the list, or be NULL to indicate that data should be inserted at the
 * end of the list).
 *
 * @attention
 * This is inefficient and requires a traversal of the list.
 *
 * @param pl		the head of the list
 * @param sibling	the cell before which we need to insert a new cell
 * @param data		the data item to prepend
 *
 * @return the new head of the list.
 */
pslist_t *
pslist_insert_before(pslist_t *pl, pslist_t *sibling, void *data)
{
	g_assert(NULL != pl || NULL == sibling);

	if G_UNLIKELY(NULL == sibling) {
		return pslist_append(pl, data);
	} else {
		pslist_t *l, *last = NULL;

		for (l = pl; l != NULL; last = l, l = last->next) {
			if (l == sibling)
				goto found;
		}

		g_assert_not_reached();		/* Sibling not found in list */

	found:
		if (NULL == last) {
			/* Sibling was head, hence we prepend */
			return pslist_prepend(pl, data);
		} else {
			/* Insert new link after ``last'', which precedes ``sibling'' */
			WALLOC(l);
			l->data = data;
			l->next = last->next;
			last->next = l;

			return pl;
		}
	}
}

/**
 * Insert a new cell with data after specified cell (which must belong
 * to the list, but this is not checked to keep the routine efficient,
 * or be NULL in which case insertion happens at the head of the list).
 *
 * @param pl		the head of the list
 * @param sibling	the cell after which we need to insert a new cell
 * @param data		the data item to append
 *
 * @return the new head of the list.
 */
pslist_t *
pslist_insert_after(pslist_t *pl, pslist_t *sibling, void *data)
{
	pslist_t *nl;

	g_assert(NULL != pl || NULL == sibling);

	if G_UNLIKELY(NULL == sibling)
		return pslist_prepend(pl, data);

	WALLOC(nl);
	nl->data = data;
	nl->next = sibling->next;
	sibling->next = nl;

	return pl;
}

/**
 * Adds the second list at the end of the first.
 *
 * The second list becomes part of the first list, physically, i.e. the cells
 * are not copied.
 *
 * @param l1		the first list, the one we append to
 * @param l2		the second list to concatenate at the tail of the first
 *
 * @return the new head of the list.
 */
pslist_t *
pslist_concat(pslist_t *l1, pslist_t *l2)
{
	if (l2 != NULL) {
		if (l1 != NULL)
			pslist_last(l1)->next = l2;
		else
			l1 = l2;
	}

	return l1;
}

/**
 * Remove the first cell we find that contains the specified data, if any.
 *
 * @param pl		the head of the list
 * @param data		the data item we wish to remove
 * @param ca		cell allocator
 *
 * @return the new head of the list.
 */
pslist_t *
pslist_remove_ext(pslist_t *pl, const void *data, const pcell_alloc_t *ca)
{
	pslist_t *l, *prev = NULL;

	l = pl;
	while (l != NULL) {
		if G_UNLIKELY(l->data == data) {
			if (prev != NULL)
				prev->next = l->next;
			else
				pl = l->next;
			ca->pcell_free(l);
			break;
		}
		prev = l;
		l = prev->next;
	}

	return pl;
}

/**
 * Remove the first cell we find that contains the specified data, if any.
 *
 * @param pl		the head of the list
 * @param data		the data item we wish to remove
 *
 * @return the new head of the list.
 */
pslist_t *
pslist_remove(pslist_t *pl, const void *data)
{
	return pslist_remove_ext(pl, data, &pslist_default_alloc);
}

/**
 * Remove specified cell from the list, without freeing it.
 *
 * @attention
 * This is inefficient and requires a traversal of the list.
 *
 * @param pl		the head of the list
 * @param cell		the cell we wish to remove
 *
 * @return the new head of the list.
 */
static pslist_t *
pslist_remove_link_internal(pslist_t *pl, pslist_t *cell)
{
	pslist_t *l = pl, *prev = NULL;

	while (l != NULL) {
		if (l == cell) {
			if (prev != NULL)
				prev->next = l->next;
			if (pl == l)
				pl = pl->next;
			l->next = NULL;
			break;
		}
		prev = l;
		l = l->next;
	}

	return pl;
}

/**
 * Remove specified cell from the list without freeing it.
 *
 * @attention
 * This is inefficient and requires a traversal of the list.
 *
 * @param pl		the head of the list
 * @param cell		the cell we wish to remove
 *
 * @return the new head of the list.
 */
pslist_t *
pslist_remove_link(pslist_t *pl, pslist_t *cell)
{
	return pslist_remove_link_internal(pl, cell);
}

/**
 * Remove specified cell from the list, then free it.
 *
 * @note
 * The data held in the cell is not freed.
 *
 * @attention
 * This is inefficient and requires a traversal of the list.
 *
 * @param pl		the head of the list
 * @param cell		the cell we wish to remove
 * @param ca		cell allocator
 *
 * @return new head of the list
 */
pslist_t *
pslist_delete_link_ext(pslist_t *pl, pslist_t *cell, const pcell_alloc_t *ca)
{
	pslist_t *np;

	np = pslist_remove_link_internal(pl, cell);
	ca->pcell_free(cell);

	return np;
}

/**
 * Remove specified cell from the list, then free it.
 *
 * @note
 * The data held in the cell is not freed.
 *
 * @attention
 * This is inefficient and requires a traversal of the list.
 *
 * @param pl		the head of the list
 * @param cell		the cell we wish to remove
 *
 * @return new head of the list
 */
pslist_t *
pslist_delete_link(pslist_t *pl, pslist_t *cell)
{
	return pslist_delete_link_ext(pl, cell, &pslist_default_alloc);
}

/**
 * Perform a deep copy of the list (cells + data).
 *
 * Each item is copied using the supplied copying callback, which can be
 * passed an extra contextual argument.  If the callback is NULL, no data
 * copying happens, hence we fall back to shallow copying.
 *
 * @param pl		the head of the list
 * @param fn		the data copying callback (can be NULL)
 * @param udata		opaque user-data passed to the copying callback
 *
 * @return the head of the new list.
 */
pslist_t *
pslist_copy_deep(pslist_t *pl, copy_data_fn_t fn, void *udata)
{
	pslist_t *nl = NULL;

	if (pl != NULL) {
		pslist_t *l, *last;

		WALLOC(nl);
		if (fn != NULL) {
			nl->data = (*fn)(pl->data, udata);
		} else {
			nl->data = pl->data;
		}
		last = nl;
		l = pl->next;
		while (l != NULL) {
			WALLOC(last->next);
			last = last->next;
			if (fn != NULL) {
				last->data = (*fn)(l->data, udata);
			} else {
				last->data = l->data;
			}
			l = l->next;
		}
		last->next = NULL;
	}

	return nl;
}

/**
 * Perform a shallow copy of the list (only the cells).
 *
 * @param pl		the head of the list
 *
 * @return the head of the new list.
 */
pslist_t *
pslist_copy(pslist_t *pl)
{
	return pslist_copy_deep(pl, NULL, NULL);
}

/**
 * Reverse list.
 *
 * @param pl		the head of the list
 *
 * @return the head of the new list.
 */
pslist_t *
pslist_reverse(pslist_t *pl)
{
	pslist_t *l = pl, *prev = NULL;

	while (l != NULL) {
		pslist_t *next = l->next;

		l->next = prev;
		prev = l;
		l = next;
	}

	return prev;
}

/**
 * Get the n-th cell in the list.
 *
 * @param pl		the head of the list
 * @param n			the n-th item to retrieve (0-based)
 *
 * @return the n-th cell, NULL if the position is off the end of the list.
 */
pslist_t *
pslist_nth(pslist_t *pl, size_t n)
{
	while (n-- != 0 && pl != NULL)
		pl = pl->next;

	return pl;
}

/**
 * Get the n-th item in the list.
 *
 * @param pl		the head of the list
 * @param n			the n-th item to retrieve (0-based)
 *
 * @return the n-th item, NULL if the position is off the end of the list.
 */
void *
pslist_nth_data(pslist_t *pl, size_t n)
{
	while (n-- != 0 && pl != NULL)
		pl = pl->next;

	return NULL == pl ? NULL : pl->data;
}

/**
 * Find the cell in the list containing the specified item.
 *
 * @param pl		the head of the list
 *
 * @return the first matching cell in the list, NULL if not found.
 */
pslist_t *
pslist_find(pslist_t *pl, const void *data)
{
	pslist_t *l;

	for (l = pl; l != NULL; l = l->next) {
		if (l->data == data)
			break;
	}

	return l;
}

/**
 * Find cell in the list using a specified comparison function to identify
 * the matching element.
 *
 * @param pl		the head of the list
 * @param object	the object to which we need to compare list data
 * @param cmp		comparison routine with object, returns 0 when equals.
 *
 * @return the first matching cell in the list, NULL if not found.
 */
pslist_t *
pslist_find_custom(pslist_t *pl, const void *object, cmp_fn_t cmp)
{
	pslist_t *l;

	if G_UNLIKELY(NULL == pl)
		return NULL;

	for (l = pl; l != NULL; l = l->next) {
		if (0 == (*cmp)(l->data, object))
			return l;
	}

	return NULL;
}

/**
 * Gets the position of the given cell in the list (0-based indexing).
 *
 * @param pl		the head of the list
 * @param cell		the cell we're looking for
 *
 * @return the position of the cell in the list, -1 if not found.
 */
long
pslist_position(const pslist_t *pl, const pslist_t *cell)
{
	pslist_t *l;
	long i;

	for (i = 0, l = deconstify_pointer(pl); l != NULL; i++, l = l->next) {
		if (l == cell)
			return i;
	}

	return -1L;
}

/**
 * Gets the position of the first cell containing the given data (0-based).
 *
 * @param pl		the head of the list
 * @param data		the data we're looking for
 *
 * @return the position of the first cell containing the data in the list,
 * -1 if not found.
 */
long
pslist_index(const pslist_t *pl, const void *data)
{
	pslist_t *l;
	long i;

	for (i = 0, l = deconstify_pointer(pl); l != NULL; i++, l = l->next) {
		if (l->data == data)
			return i;
	}

	return -1L;
}

/**
 * Compute the length of the list.
 *
 * @attention
 * This requires a complete traversal of the list.
 *
 * @param pl		the head of the list
 *
 * @return the amount of items in the list.
 */
size_t
pslist_length(const pslist_t *pl)
{
	pslist_t *l = deconstify_pointer(pl);
	size_t n = 0;

	while (l != NULL) {
		n++;
		l = l->next;
	}

	return n;
}

/**
 * Iterate over the list, invoking the callback for every item.
 *
 * @param pl		the head of the list
 * @param cb		routine to invoke on all items
 * @param data		opaque user-data to pass to callback
 */
void
pslist_foreach(const pslist_t *pl, data_fn_t cb, void *data)
{
	pslist_t *l;

	for (l = deconstify_pointer(pl); l != NULL; l = l->next) {
		(*cb)(l->data, data);
	}
}

/**
 * Iterate over the list, invoking the callback for every item and removing
 * the entry if the callback returns TRUE.
 *
 * @param pl		the head of the list
 * @param cbr		routine to invoke on item to see whether we remove it
 * @param data		opaque user-data to pass to callback
 * @param ca		cell allocator
 *
 * @return the new list head.
 */
pslist_t *
pslist_foreach_remove_ext(pslist_t *pl, data_rm_fn_t cbr, void *data,
	const pcell_alloc_t *ca)
{
	pslist_t *l, *next, *prev;

	for (l = pl, prev = NULL; l != NULL; l = next) {
		next = l->next;
		if ((*cbr)(l->data, data)) {
			if G_UNLIKELY(l == pl)
				pl = next;
			else if (prev != NULL)
				prev->next = next;
			ca->pcell_free(l);
		} else {
			prev = l;
		}
	}

	return pl;
}

/**
 * Iterate over the list, invoking the callback for every item and removing
 * the entry if the callback returns TRUE.
 *
 * @param pl		the head of the list
 * @param cbr		routine to invoke on item to see whether we remove it
 * @param data		opaque user-data to pass to callback
 *
 * @return the new list head.
 */
pslist_t *
pslist_foreach_remove(pslist_t *pl, data_rm_fn_t cbr, void *data)
{
	return pslist_foreach_remove_ext(pl, cbr, data, &pslist_default_alloc);
}

/**
 * Inserts element into the list, using the given comparison function to
 * determine the proper position.
 *
 * @param pl		the head of the list
 * @param data		data to insert
 * @param cmp		data comparison routine, with extra udata argument
 * @param udata		trailing comparison argument (user-supplied context)
 *
 * @return the new list head.
 */
static pslist_t *
pslist_insert_sorted_internal(pslist_t *pl, void *data,
	cmp_data_fn_t cmp, void *udata)
{
	pslist_t *tl = pl, *prev = NULL, *nl;
	int c;

	g_assert(cmp != NULL);

	if G_UNLIKELY(NULL == pl) {
		WALLOC(nl);
		nl->data = data;
		nl->next = NULL;
		return nl;
	}

	c = (*cmp)(data, tl->data, udata);

	while (tl->next != NULL && c > 0) {
		prev = tl;
		tl = tl->next;
		c = (*cmp)(data, tl->data, udata);
	}

	WALLOC(nl);
	nl->data = data;

	if (tl->next != NULL && c > 0) {
		tl->next = nl;
		nl->next = NULL;
		return pl;
	}

	if (prev != NULL) {
		prev->next = nl;
		nl->next = tl;
		return pl;
	} else {
		nl->next = pl;
		return nl;
	}
}

/**
 * Inserts element into the list, using the given comparison function to
 * determine the proper position.
 *
 * @param pl		the head of the list
 * @param data		data to insert
 * @param cmp		data comparison routine
 *
 * @return the new list head.
 */
pslist_t *
pslist_insert_sorted(pslist_t *pl, void *data, cmp_fn_t cmp)
{
	return pslist_insert_sorted_internal(pl, data, (cmp_data_fn_t) cmp, NULL);
}

/**
 * Inserts element into the list, using the given comparison function to
 * determine the proper position.
 *
 * @param pl		the head of the list
 * @param data		data to insert
 * @param cmp		data comparison routine, with extra udata argument
 * @param udata		trailing comparison argument (user-supplied context)
 *
 * @return the new list head.
 */
pslist_t *
pslist_insert_sorted_with_dta(pslist_t *pl, void *data,
	cmp_data_fn_t cmp, void *udata)
{
	return pslist_insert_sorted_internal(pl, data, cmp, udata);
}

/**
 * Merge two sorted lists.
 *
 * @param l1		first sorted list
 * @param l2		second sorted list
 * @param cmp		data comparison function
 * @param udata		extra parameter passed to comparison function
 *
 * @return the head of the merged list.
 */
static pslist_t *
pslist_sort_merge(pslist_t *l1, pslist_t *l2, cmp_data_fn_t cmp, void *udata)
{
	pslist_t list, *l = &list;

	while (l1 != NULL && l2 != NULL) {
		int c = (*cmp)(l1->data, l2->data, udata);

		if (c <= 0) {
			l = l->next = l1;
			l1 = l1->next;
		} else {
			l = l->next = l2;
			l2 = l2->next;
		}
	}

	l->next = (NULL == l1) ? l2 : l1;

	return list.next;
}

/**
 * Sort list using supplied comparison function.
 *
 * @param pl		the head of the list
 * @param cmp		data comparison function
 * @param udata		extra parameter passed to comparison function
 *
 * @return the head of the sorted list.
 */
static pslist_t *
pslist_sort_internal(pslist_t *pl, cmp_data_fn_t cmp, void *udata)
{
	pslist_t *l1, *l2;

	if G_UNLIKELY(NULL == pl)
		return NULL;					/* Empty list */

	if G_UNLIKELY(NULL == pl->next)
		return pl;						/* Single-item list */

	/*
	 * Split list in half, roughly, by advancing the pointer in l2 twice as
	 * fast as the one in l1.
	 */

	l1 = pl;
	l2 = pl->next;

	while (NULL != (l2 = l2->next)) {
		if (NULL == (l2 = l2->next))
			break;
		l1 = l1->next;
	}

	l2 = l1->next;
	l1->next = NULL;

	return pslist_sort_merge(
		pslist_sort_internal(pl, cmp, udata),
		pslist_sort_internal(l2, cmp, udata),
		cmp, udata
	);
}

/**
 * Sort list according to the comparison function, which takes two items
 * plus an additional opaque argument, meant to be used as context to sort
 * the two items.
 *
 * @param pl		the head of the list
 * @param cmp		item comparison function
 * @param udata		extra parameter passed to comparison function
 *
 * @return the head of the sorted list.
 */
pslist_t *
pslist_sort_with_data(pslist_t *pl, cmp_data_fn_t cmp, void *data)
{
	return pslist_sort_internal(pl, cmp, data);
}

/**
 * Sort list according to the comparison function, which compares items.
 *
 * @param pl		the head of the list
 * @param cmp		item comparison function
 *
 * @return the head of the sorted list.
 */
pslist_t *
pslist_sort(pslist_t *pl, cmp_fn_t cmp)
{
	return pslist_sort_internal(pl, (cmp_data_fn_t) cmp, NULL);
}

/**
 * Randomly shuffle the items in the list using supplied random function.
 *
 * @param rf		the random function to use (NULL means: use defaults)
 * @param pl		the head of the list
 *
 * @return the head of the shuffled list.
 */
pslist_t *
pslist_shuffle_with(random_fn_t rf, pslist_t *pl)
{
	eslist_t list;

	/*
	 * These assertions ensure that we can treat the chain of a pslist
	 * as if the cells were part of an eslist, so that eslist_shuffle()
	 * can perform invisibly.
	 */

	STATIC_ASSERT(offsetof(slink_t, next) == offsetof(pslist_t, next));

	if G_UNLIKELY(NULL == pl)
		return NULL;					/* Empty list */

	if G_UNLIKELY(NULL == pl->next)
		return pl;						/* Single-item list */

	/*
	 * This code relies on the fact that the plain list can be viewed as
	 * a valid embedded list of cells, whose link is at the beginning of
	 * the structure.
	 *
	 * There is no need to set the list.tail field as this is not used by
	 * eslist_shuffle_with().
	 */

	eslist_init(&list, offsetof(pslist_t, next));
	list.head = (slink_t *) pl;
	list.count = pslist_length(pl);		/* Have to count, unfortunately */
	eslist_shuffle_with(rf, &list);		/* Shuffles the cells */

	return (pslist_t *) list.head;
}

/**
 * Randomly shuffle the items in the list.
 *
 * @param pl		the head of the list
 *
 * @return the head of the shuffled list.
 */
pslist_t *
pslist_shuffle(pslist_t *pl)
{
	return pslist_shuffle_with(NULL, pl);
}

/**
 * Pick a random cell from the list.
 *
 * @param pl	the head of the list
 *
 * @return the randomly picked cell, NULL if the list is empty.
 */
pslist_t *
pslist_random(const pslist_t *pl)
{
	const pslist_t *l, *picked = NULL;
	ulong n;

	/*
	 * This algorithm uniformly selects elements among the list (whose count
	 * is not known initially) by letting item #i be selected and supersede
	 * any previously chosen item with probability 1/i.  If there are N items
	 * in the list, then each has a probabily 1/N of ending up being picked.
	 *
	 * Proof:
	 *
	 * Let our hypothesis Hn be: all n items have a uniform 1/n probability
	 * of being selected.
	 *
	 * H1 is trivially true (n = 1).
	 *
	 * Now suppose Hn is true and let's prove that Hn+1 is also true:
	 *
	 * The item #n+1 has clearly a probability of 1/(n+1) of being selected,
	 * since this is the way the algorithm picks new items as it progresses
	 * among the list.
	 *
	 * For the other n items, they all had a 1/n probability of being picked so
	 * far (our hypothesis).  So let's pick one item E in this set of n items,
	 * and let's denote p(E) the probability that this item be picked in our
	 * set of n+1 items.
	 *
	 * The probability that the n+1 item be not picked is 1 - 1/(n+1).  So the
	 * probability that E remains picked is p(E) = 1/n * (1 - 1/(n+1)).
	 *
	 * p(E) = 1/n * (n+1 - 1)/(n+1) = 1/n * (n / (n+1) = 1/(n+1)
	 *
	 * Therefore, among the  set of n+1 items, each item has a probability of
	 * being picked of 1/(n+1).  QED.
	 *
	 * Note than in our code below, the first item is n = 0, hence item n
	 * has 1/(n+1) chances of being selected at each step, not 1/n.
	 */

	for (l = pl, n = 0; l != NULL; l = l->next, n++) {
		if (0 == random_ulong_value(n))
			picked = l;		/* Item n has 1/(n+1) chances of being selected */
	}

	return deconstify_pointer(picked);
}

/**
 * Remove head of list.
 *
 * @param pl_ptr	pointer to the head of the list
 * @param ca		cell allocator
 *
 * @return the data item at the head of the list, NULL if the list was empty.
 */
void *
pslist_shift_ext(pslist_t **pl_ptr, const pcell_alloc_t *ca)
{
	pslist_t *pl = *pl_ptr, *nl;
	void *data;

	if G_UNLIKELY(NULL == pl)
		return NULL;

	data = pl->data;

	nl = pl->next;
	ca->pcell_free(pl);

	/*
	 * If the list contains NULL items, this is going to confuse the caller
	 * because NULL is also an indication that the list was empty.
	 */

	if G_UNLIKELY(NULL == data)
		s_carp_once("%s(): used on a list that contains NULL items", G_STRFUNC);

	*pl_ptr = nl;
	return data;
}

/**
 * Remove head of list.
 *
 * @param pl_ptr	pointer to the head of the list
 *
 * @return the data item at the head of the list, NULL if the list was empty.
 */
void *
pslist_shift(pslist_t **pl_ptr)
{
	return pslist_shift_ext(pl_ptr, &pslist_default_alloc);
}

/* vi: set ts=4 sw=4 cindent: */
