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
 * Plain two-way list.
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
 * have an *_ext() version.  For instance, plist_shuffle() or plist_reverse()
 * can be freely used even if the cells are not allocated using the defaults.
 *
 * The API of plain lists mirrors that of glib's lists to make a smooth
 * transition possible and maintain some consistency in the code.  That
 * said, the glib list API is quite good so mirroring it is not a problem.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "plist.h"

#include "elist.h"
#include "log.h"
#include "pcell.h"
#include "pslist.h"
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
 * Copyright (c) 2013 Raphael Manfredi
 */

/*
 * Default cell allocators.
 */

static void *
plist_cell_alloc(void)
{
	plist_t *pl;

	WALLOC0(pl);
	return pl;
}

static void
plist_cell_free(void *cell)
{
	plist_t *l = cell;

	WFREE(l);
}

static void
plist_free_all(void *l)
{
	wfree_pslist(l, sizeof(plist_t));
}

static pcell_alloc_t plist_default_alloc = {
	plist_cell_alloc,		/* pcell_alloc */
	plist_cell_free,		/* pcell_free */
	plist_free_all,			/* pcell_listfree */
};

/**
 * Allocate a list cell for storing one element.
 *
 * @return pointer to newly allocated element, pointing to NULL data.
 */
plist_t *
plist_alloc(void)
{
	return plist_cell_alloc();
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
plist_free_1(plist_t *l)
{
	g_assert(NULL == l || (NULL == l->next && NULL == l->prev));

	if (l != NULL)
		WFREE(l);
}

/**
 * Free the cell element and nullify its pointer.
 */
void
plist_free_1_null(plist_t **l_ptr)
{
	plist_t *l = *l_ptr;

	if (l != NULL) {
		plist_free_1(l);
		*l_ptr = NULL;
	}
}

/**
 * Free all the cell elements in the list, but do not touch the held data.
 *
 * @param pl		the head of the list
 * @param ca		the cell allocator
 *
 * @return NULL as a convenience.
 */
plist_t *
plist_free_ext(plist_t *pl, const pcell_alloc_t *ca)
{
	if G_UNLIKELY(NULL == pl)
		return NULL;

	g_assert(ca != NULL);

	if G_UNLIKELY(NULL == ca->pcell_listfree) {
		plist_t *l = pl;

		g_assert(ca->pcell_free != NULL);

		/*
		 * When they have not configured a dedicated callback for that,
		 * do it manually, one item at a time.
		 */

		while (l != NULL) {
			plist_t *next = l->next;
			ca->pcell_free(l);
			l = next;
		}
	} else {
		/*
		 * To be extremely fast, use a specialized freeing routine that will
		 * limit the amount of overhead to process all the entries in the list.
		 *
		 * Note that we pass a pslist_t because the data field will not be
		 * used and only the next field will be followed, which is at the same
		 * place in a pslist_t.
		 */

		STATIC_ASSERT(offsetof(pslist_t, next) == offsetof(plist_t, next));

		ca->pcell_listfree(pl);
	}

	return NULL;
}

/**
 * Free all the cell elements in the list, but do not touch the held data.
 *
 * To be able to free the items in the list, use plist_free_full().
 *
 * @param pl		the head of the list
 *
 * @return NULL as a convenience.
 */
plist_t *
plist_free(plist_t *pl)
{
	return plist_free_ext(pl, &plist_default_alloc);
}

/**
 * Free plist and nullify pointer holding it.
 */
void
plist_free_null(plist_t **pl_ptr)
{
	plist_t *pl = *pl_ptr;

	if (pl != NULL) {
		plist_free(pl);
		*pl_ptr = NULL;
	}
}

/**
 * Free plist and nullify pointer holding it.
 */
void
plist_free_null_ext(plist_t **pl_ptr, const pcell_alloc_t *ca)
{
	plist_t *pl = *pl_ptr;

	if (pl != NULL) {
		plist_free_ext(pl, ca);
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
plist_t *
plist_free_full(plist_t *pl, free_fn_t fn)
{
	plist_t *l;

	for (l = pl; l != NULL; l = l->next) {
		(*fn)(l->data);
	}

	plist_free(pl);
	return NULL;
}

/**
 * Free plist, applying free callback each item, and then nullify pointer
 * holding it.
 */
void
plist_free_full_null(plist_t **pl_ptr, free_fn_t fn)
{
	plist_t *pl = *pl_ptr;

	if (pl != NULL) {
		plist_free_full(pl, fn);
		*pl_ptr = NULL;
	}
}

/**
 * @return the last cell of the list.
 */
plist_t *
plist_last(const plist_t *pl)
{
	if G_LIKELY(pl != NULL) {
		plist_t *l = deconstify_pointer(pl);

		while (l->next != NULL)
			l = l->next;

		return l;
	} else {
		return NULL;
	}
}

/**
 * @return the first cell of the list.
 */
plist_t *
plist_first(const plist_t *pl)
{
	if G_LIKELY(pl != NULL) {
		plist_t *l = deconstify_pointer(pl);

		while (l->prev != NULL)
			l = l->prev;

		return l;
	} else {
		return NULL;
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
plist_t *
plist_append_ext(plist_t *pl, void *data, const pcell_alloc_t *ca)
{
	plist_t *nl;

	g_assert(ca != NULL);
	g_assert(ca->pcell_alloc != NULL);

	nl = ca->pcell_alloc();
	nl->next = NULL;
	nl->data = data;

	if (pl != NULL) {
		plist_t *last = plist_last(pl);
		last->next = nl;
		nl->prev = last;
		return pl;
	} else {
		nl->prev = NULL;
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
plist_t *
plist_append(plist_t *pl, void *data)
{
	return plist_append_ext(pl, data, &plist_default_alloc);
}

/**
 * Prepend new item at the head of the list.
 *
 * @param pl		the head of the list
 * @param data		the data item to prepend
 *
 * @return the new head of the list.
 */
plist_t *
plist_prepend_ext(plist_t *pl, void *data, const pcell_alloc_t *ca)
{
	plist_t *nl;

	g_assert(ca != NULL);
	g_assert(ca->pcell_alloc != NULL);

	nl = ca->pcell_alloc();
	nl->next = pl;
	nl->data = data;

	if (pl != NULL) {
		/*
		 * @note
		 * This is translated code from GLib's original sources, which
		 * allows ``pl'' to not be the real head of the list but any item
		 * in the list, hence we're really doing a plist_insert_before() here!
		 * Keeping code as it is, to allow easy transition from GList in the
		 * existing code, just in case.
		 *		--RAM, 2013-12-14
		 */
		nl->prev = pl->prev;
		if G_UNLIKELY(pl->prev != NULL)
			pl->prev->next = nl;
		pl->prev = nl;
	} else {
		nl->prev = NULL;
	}

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
plist_t *
plist_prepend(plist_t *pl, void *data)
{
	return plist_prepend_ext(pl, data, &plist_default_alloc);
}

/**
 * Insert a new cell with data before specified cell (which must belong
 * to the list, or be NULL to indicate that data should be inserted at the
 * end of the list).
 *
 * @param pl		the head of the list
 * @param sibling	the cell before which we need to insert a new cell
 * @param data		the data item to prepend
 *
 * @return the new head of the list.
 */
plist_t *
plist_insert_before(plist_t *pl, plist_t *sibling, void *data)
{
	g_assert(NULL != pl || NULL == sibling);

	if G_UNLIKELY(NULL == pl) {
		return plist_prepend(NULL, data);
	} else if G_UNLIKELY(NULL == sibling) {
		return plist_append(pl, data);
	} else {
		/*
		 * Since ``sibling'' must be part of the list, we do not have to
		 * traverse the structure, contrary to GLib's code which does the
		 * traversal to validate that the sibling is indeed part of the list.
		 */

		if (NULL == sibling->prev) {
			/* Sibling was head, hence we prepend */
			return plist_prepend(pl, data);
		} else {
			plist_t *l;

			/* Insert new cell before ``sibling'', which was not the head */
			WALLOC(l);
			l->data = data;
			l->next = sibling;
			l->prev = sibling->prev;
			sibling->prev->next = l;
			sibling->prev = l;

			return pl;
		}
	}
}

/**
 * Insert a new cell with data after specified cell (which must belong
 * to the list, or be NULL to indicate that data should be inserted at the
 * head of the list).
 *
 * @param pl		the head of the list
 * @param sibling	the cell after which we need to insert a new cell
 * @param data		the data item to append
 *
 * @return the new head of the list.
 */
plist_t *
plist_insert_after(plist_t *pl, plist_t *sibling, void *data)
{
	plist_t *nl;

	g_assert(NULL != pl || NULL == sibling);

	if G_UNLIKELY(NULL == sibling)
		return plist_prepend(pl, data);

	WALLOC(nl);
	nl->data = data;
	nl->next = sibling->next;
	nl->prev = sibling;
	if (sibling->next != NULL)
		sibling->next->prev = nl;
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
plist_t *
plist_concat(plist_t *l1, plist_t *l2)
{
	if (l2 != NULL) {
		plist_t *last = plist_last(l1);
		if (last != NULL)
			last->next = l2;
		else
			l1 = l2;
		l2->prev = last;
	}

	return l1;
}

/**
 * Remove specified cell from the list, without freeing it.
 *
 * @param pl		the head of the list
 * @param cell		the cell we wish to remove
 *
 * @return the new head of the list.
 */
static plist_t *
plist_remove_link_internal(plist_t *pl, plist_t *cell)
{
	if G_UNLIKELY(NULL == cell)
		return pl;

	if (cell->prev != NULL) {
		g_assert(cell->prev->next == cell);
		cell->prev->next = cell->next;
	}
	if (cell->next != NULL) {
		g_assert(cell->next->prev == cell);
		cell->next->prev = cell->prev;
	}

	if (cell == pl)
		pl = pl->next;

	cell->next = cell->prev = NULL;

	return pl;
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
plist_t *
plist_remove_ext(plist_t *pl, const void *data, const pcell_alloc_t *ca)
{
	plist_t *l;

	g_assert(ca != NULL);
	g_assert(ca->pcell_free != NULL);

	for (l = pl; l != NULL; l = l->next) {
		if G_UNLIKELY(l->data == data) {
			pl = plist_remove_link_internal(pl, l);
			ca->pcell_free(l);
			break;
		}
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
plist_t *
plist_remove(plist_t *pl, const void *data)
{
	return plist_remove_ext(pl, data, &plist_default_alloc);
}

/**
 * Remove all the cells that contain the specified data, if any.
 *
 * @param pl		the head of the list
 * @param data		the data item we wish to remove
 * @param ca		cell allocator
 *
 * @return the new head of the list.
 */
plist_t *
plist_remove_all_ext(plist_t *pl, const void *data, const pcell_alloc_t *ca)
{
	plist_t *l, *next;

	g_assert(ca != NULL);
	g_assert(ca->pcell_free != NULL);

	for (l = pl; l != NULL; l = next) {
		next = l->next;
		if G_UNLIKELY(l->data == data) {
			pl = plist_remove_link_internal(pl, l);
			ca->pcell_free(l);
		}
	}

	return pl;
}

/**
 * Remove all the cells that contain the specified data, if any.
 *
 * @param pl		the head of the list
 * @param data		the data item we wish to remove
 *
 * @return the new head of the list.
 */
plist_t *
plist_remove_all(plist_t *pl, const void *data)
{
	return plist_remove_all_ext(pl, data, &plist_default_alloc);
}

/**
 * Remove specified cell from the list without freeing it.
 *
 * @param pl		the head of the list
 * @param cell		the cell we wish to remove
 *
 * @return the new head of the list.
 */
plist_t *
plist_remove_link(plist_t *pl, plist_t *cell)
{
	return plist_remove_link_internal(pl, cell);
}

/**
 * Remove specified cell from the list, then free it.
 *
 * @note
 * The data held in the cell is not freed.
 *
 * @param pl		the head of the list
 * @param cell		the cell we wish to remove
 * @param ca		cell allocator
 *
 * @return new head of the list
 */
plist_t *
plist_delete_link_ext(plist_t *pl, plist_t *cell, const pcell_alloc_t *ca)
{
	plist_t *np;

	g_assert(ca != NULL);
	g_assert(ca->pcell_free != NULL);

	np = plist_remove_link_internal(pl, cell);
	ca->pcell_free(cell);

	return np;
}

/**
 * Remove specified cell from the list, then free it.
 *
 * @note
 * The data held in the cell is not freed.
 *
 * @param pl		the head of the list
 * @param cell		the cell we wish to remove
 *
 * @return new head of the list
 */
plist_t *
plist_delete_link(plist_t *pl, plist_t *cell)
{
	return plist_delete_link_ext(pl, cell, &plist_default_alloc);
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
plist_t *
plist_copy_deep(plist_t *pl, copy_data_fn_t fn, void *udata)
{
	plist_t *nl = NULL;

	if (pl != NULL) {
		plist_t *l, *last;

		WALLOC(nl);
		if (fn != NULL) {
			nl->data = (*fn)(pl->data, udata);
		} else {
			nl->data = pl->data;
		}
		nl->prev = NULL;
		last = nl;
		l = pl->next;
		while (l != NULL) {
			WALLOC(last->next);
			last->next->prev = last;
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
plist_t *
plist_copy(plist_t *pl)
{
	return plist_copy_deep(pl, NULL, NULL);
}

/**
 * Reverse list.
 *
 * @param pl		the head of the list
 *
 * @return the head of the new list.
 */
plist_t *
plist_reverse(plist_t *pl)
{
	plist_t *l = pl, *last = NULL;

	while (l != NULL) {
		last = l;
		l = last->next;
		last->next = last->prev;
		last->prev = l;
	}

	return last;
}

/**
 * Get the n-th cell in the list.
 *
 * @param pl		the head of the list
 * @param n			the n-th item to retrieve (0-based)
 *
 * @return the n-th cell, NULL if the position is off the end of the list.
 */
plist_t *
plist_nth(plist_t *pl, size_t n)
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
plist_nth_data(plist_t *pl, size_t n)
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
plist_t *
plist_find(plist_t *pl, const void *data)
{
	plist_t *l;

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
plist_t *
plist_find_custom(plist_t *pl, const void *object, cmp_fn_t cmp)
{
	plist_t *l;

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
plist_position(const plist_t *pl, const plist_t *cell)
{
	plist_t *l;
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
plist_index(const plist_t *pl, const void *data)
{
	plist_t *l;
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
plist_length(const plist_t *pl)
{
	plist_t *l = deconstify_pointer(pl);
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
plist_foreach(const plist_t *pl, data_fn_t cb, void *data)
{
	plist_t *l;

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
plist_t *
plist_foreach_remove_ext(plist_t *pl, data_rm_fn_t cbr, void *data,
	const pcell_alloc_t *ca)
{
	plist_t *l, *next, *prev;

	g_assert(ca != NULL);
	g_assert(ca->pcell_free != NULL);

	for (l = pl, prev = NULL; l != NULL; l = next) {
		next = l->next;
		if ((*cbr)(l->data, data)) {
			if G_UNLIKELY(l == pl) {
				pl = next;
				if (next != NULL)
					next->prev = NULL;
			} else if (prev != NULL) {
				prev->next = next;
				if (next != NULL)
					next->prev = prev;
			}
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
plist_t *
plist_foreach_remove(plist_t *pl, data_rm_fn_t cbr, void *data)
{
	return plist_foreach_remove_ext(pl, cbr, data, &plist_default_alloc);
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
static plist_t *
plist_insert_sorted_internal(plist_t *pl, void *data,
	cmp_data_fn_t cmp, void *udata)
{
	plist_t *tl = pl, *nl;
	int c;

	g_assert(cmp != NULL);

	if G_UNLIKELY(NULL == pl) {
		WALLOC0(nl);
		nl->data = data;
		return nl;
	}

	c = (*cmp)(data, tl->data, udata);

	while (tl->next != NULL && c > 0) {
		tl = tl->next;
		c = (*cmp)(data, tl->data, udata);
	}

	WALLOC0(nl);
	nl->data = data;

	if (tl->next != NULL && c > 0) {
		tl->next = nl;
		nl->prev = tl;
		return pl;
	}

	if (tl->prev != NULL) {
		tl->prev->next = nl;
		nl->prev = tl->prev;
	}
	nl->next = tl;
	tl->prev = nl;

	return tl == pl ? nl : pl;
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
plist_t *
plist_insert_sorted(plist_t *pl, void *data, cmp_fn_t cmp)
{
	return plist_insert_sorted_internal(pl, data, (cmp_data_fn_t) cmp, NULL);
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
plist_t *
plist_insert_sorted_with_dta(plist_t *pl, void *data,
	cmp_data_fn_t cmp, void *udata)
{
	return plist_insert_sorted_internal(pl, data, cmp, udata);
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
static plist_t *
plist_sort_merge(plist_t *l1, plist_t *l2, cmp_data_fn_t cmp, void *udata)
{
	plist_t list, *l = &list, *lprev = NULL;

	while (l1 != NULL && l2 != NULL) {
		int c = (*cmp)(l1->data, l2->data, udata);

		if (c <= 0) {
			l = l->next = l1;
			l1 = l1->next;
		} else {
			l = l->next = l2;
			l2 = l2->next;
		}
		l->prev = lprev;
		lprev = l;
	}

	l->next = (NULL == l1) ? l2 : l1;
	l->next->prev = l;

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
static plist_t *
plist_sort_internal(plist_t *pl, cmp_data_fn_t cmp, void *udata)
{
	plist_t *l1, *l2;

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

	return plist_sort_merge(
		plist_sort_internal(pl, cmp, udata),
		plist_sort_internal(l2, cmp, udata),
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
plist_t *
plist_sort_with_data(plist_t *pl, cmp_data_fn_t cmp, void *data)
{
	return plist_sort_internal(pl, cmp, data);
}

/**
 * Sort list according to the comparison function, which compares items.
 *
 * @param pl		the head of the list
 * @param cmp		item comparison function
 *
 * @return the head of the sorted list.
 */
plist_t *
plist_sort(plist_t *pl, cmp_fn_t cmp)
{
	return plist_sort_internal(pl, (cmp_data_fn_t) cmp, NULL);
}

/**
 * Randomly shuffle the items in the list using supplied random function.
 *
 * @param rf		the random function to use (NULL means: use defaults)
 * @param pl		the head of the list
 *
 * @return the head of the shuffled list.
 */
plist_t *
plist_shuffle_with(random_fn_t rf, plist_t *pl)
{
	elist_t list;

	/*
	 * These assertions ensure that we can treat the chain of a plist
	 * as if the cells were part of an elist, so that elist_shuffle()
	 * can perform invisibly.
	 */

	STATIC_ASSERT(offsetof(link_t, next) == offsetof(plist_t, next));
	STATIC_ASSERT(offsetof(link_t, prev) == offsetof(plist_t, prev));

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
	 * elist_shuffle().
	 */

	elist_init(&list, offsetof(plist_t, next));
	list.head = (link_t *) pl;
	list.count = plist_length(pl);		/* Have to count, unfortunately */
	elist_shuffle_with(rf, &list);		/* Shuffle the cells */

	return (plist_t *) list.head;
}

/**
 * Randomly shuffle the items in the list.
 *
 * @param pl		the head of the list
 *
 * @return the head of the shuffled list.
 */
plist_t *
plist_shuffle(plist_t *pl)
{
	return plist_shuffle_with(NULL, pl);
}

/**
 * Pick a random cell from the list.
 *
 * @param pl	the head of the list
 *
 * @return the randomly picked cell, NULL if the list is empty.
 */
plist_t *
plist_random(const plist_t *pl)
{
	const plist_t *l, *picked = NULL;
	ulong n;

	/*
	 * Correctness of this algorithm is documented in pslist_random().
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
 * @param pl_ptr		pointer to the head of the list
 * @param ca			cell allocator
 *
 * @return the data item at the head of the list, NULL if the list was empty.
 */
void *
plist_shift_ext(plist_t **pl_ptr, const pcell_alloc_t *ca)
{
	plist_t *pl = *pl_ptr, *nl;
	void *data;

	g_assert(ca != NULL);
	g_assert(ca->pcell_free != NULL);

	if G_UNLIKELY(NULL == pl)
		return NULL;

	data = pl->data;

	nl = pl->next;
	if (nl != NULL)
		nl->prev = NULL;
	g_assert(NULL == pl->prev);		/* Was at the head of the list */
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
 * This is the routine to be used when the list can contain NULL data, to avoid
 * warnings and simplify user code.
 *
 * @param pl_ptr	pointer to the head of the list
 * @param d_ptr		pointer where data is written
 * @param ca		cell allocator
 *
 * @return TRUE if we fetched data, FALSE if the list was empty.
 */
bool
plist_shift_data_ext(plist_t **pl_ptr, void **d_ptr, const pcell_alloc_t *ca)
{
	plist_t *pl = *pl_ptr, *nl;

	g_assert(ca != NULL);
	g_assert(ca->pcell_free != NULL);

	if G_UNLIKELY(NULL == pl)
		return FALSE;

	*d_ptr = pl->data;
	nl = pl->next;
	if (nl != NULL)
		nl->prev = NULL;
	g_assert(NULL == pl->prev);		/* Was at the head of the list */
	ca->pcell_free(pl);

	*pl_ptr = nl;
	return TRUE;

}

/**
 * Remove head of list.
 *
 * @param pl_ptr		pointer to the head of the list
 *
 * @return the data item at the head of the list, NULL if the list was empty.
 */
void *
plist_shift(plist_t **pl_ptr)
{
	return plist_shift_ext(pl_ptr, &plist_default_alloc);
}

/**
 * Remove head of list.
 *
 * This is the routine to be used when the list can contain NULL data, to avoid
 * warnings and simplify user code.
 *
 * @param pl_ptr	pointer to the head of the list
 * @param d_ptr		pointer where data is written
 *
 * @return TRUE if we fetched data, FALSE if the list was empty.
 */
bool
plist_shift_data(plist_t **pl_ptr, void **d_ptr)
{
	return plist_shift_data_ext(pl_ptr, d_ptr, &plist_default_alloc);
}

/* vi: set ts=4 sw=4 cindent: */
