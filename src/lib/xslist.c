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
 * This collection of routines help factorize code handling one-way lists,
 * albeit for very specific operations and without otherwise being the
 * owner of the list.
 *
 * A little bit of ASCII art will help clarify what is managed exactly
 * and in which situations one would want to use these routines:
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
 * The 'next' pointer in the bottom area of the data structure (above part
 * being user-data, opaque for us) is not pointing to another link but to the
 * start of another structure containing the link to the next item.
 *
 * For instance, in a tree we could have the bottom part defined as:
 *
 *     struct node {
 *         struct node *parent, *child, *sibling;
 *     }
 *
 * and the `next' pointer would be node->sibling, which is not pointing to
 * another memory location containing a sibling pointer, but at the start of
 * the node structure in another item.
 *
 * If the 'next' pointer were to point to another chaining pointer in the
 * same direction, we would have the following picture:
 *
 *   +-----+     +-----+     +-----+  ^
 *   |/////|     |/////|     |/////|  |
 *   |/////|     |/////|     |/////|  |  offset
 *   |/////|     |/////|     |/////|  |
 *   +=====+     +=====+     +=====+  v
 *   | ***-+---->| ***-+---->|(nil)|     link offset = 0
 *   +=====+     +=====+     +=====+
 *
 * That would be the case in the following situation:
 *
 *     struct link {
 *         struct link *next;
 *     }
 *
 * where the 'next' pointer points to a memory location containing the pointer
 * to the next item in the list.  That is an embedded single list ("eslist").
 *
 * When the "link offset" (offset within the chaining structure of the pointer
 * of the 'next' item, which points to the root of the next chaining structure)
 * is not 0, then we have an expanded single list ("xslist").
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "xslist.h"

#include "random.h"
#include "shuffle.h"
#include "unsigned.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

#if 0
#define XSLIST_SAFETY_ASSERT	/**< Turn on costly integrity assertions */
#endif

#ifdef XSLIST_SAFETY_ASSERT
#define safety_assert(x)	g_assert(x)
#else
#define safety_assert(x)
#endif

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
 * Discard list, making the list object invalid.
 *
 * This does not free any of the items, it just discards the list descriptor.
 * The underlying items remain chained though, so retaining a pointer to one
 * of the xslink_t of one item still allows limited link-level traversal.
 */
void
xslist_discard(xslist_t *list)
{
	xslist_check(list);

	list->magic = 0;
}

/**
 * Clear list, forgetting about all the items
 *
 * This does not free or unlink any of the items, it just empties the list
 * descriptor.
 */
void
xslist_clear(xslist_t *list)
{
	xslist_check(list);

	list->head = list->tail = NULL;
	list->count = 0;
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

static inline void
xslist_link_append_internal(xslist_t *list, xslink_t *lk)
{
	if G_UNLIKELY(NULL == list->tail) {
		g_assert(NULL == list->head);
		g_assert(0 == list->count);
		list->head = list->tail = lk;
		xslist_set_next(list, lk, NULL);
	} else {
		g_assert(NULL == xslist_next(list, list->tail));
		g_assert(NULL != list->head);	/* Since list not empty */
		g_assert(size_is_positive(list->count));
		xslist_set_next(list, list->tail, lk);
		xslist_set_next(list, lk, NULL);
		list->tail = lk;
	}

	list->count++;

	safety_assert(xslist_length(list, list->head) == list->count);
}

/**
 * Append new link to the list.
 *
 * This is efficient and does not require a full traversal of the list.
 */
void
xslist_link_append(xslist_t *list, xslink_t *lk)
{
	xslist_check(list);
	g_assert(lk != NULL);

	xslist_link_append_internal(list, lk);
}

/**
 * Append new item with expanded link to the list.
 *
 * This is efficient and does not require a full traversal of the list.
 */
void
xslist_append(xslist_t *list, void *data)
{
	xslink_t *lk;

	xslist_check(list);
	g_assert(data != NULL);

	lk = ptr_add_offset(data, list->offset);
	xslist_link_append_internal(list, lk);
}

static inline void
xslist_link_prepend_internal(xslist_t *list, xslink_t *lk)
{
	if G_UNLIKELY(NULL == list->head) {
		g_assert(NULL == list->tail);
		g_assert(0 == list->count);
		list->head = list->tail = lk;
		xslist_set_next(list, lk, NULL);
	} else {
		g_assert(NULL != list->tail);	/* Since list not empty */
		g_assert(size_is_positive(list->count));
		xslist_set_next(list, lk, list->head);
		list->head = lk;
	}

	list->count++;

	safety_assert(xslist_length(list, list->head) == list->count);
}

/**
 * Prepend link to the list.
 */
void
xslist_link_prepend(xslist_t *list, xslink_t *lk)
{
	xslist_check(list);
	g_assert(lk != NULL);

	xslist_link_prepend_internal(list, lk);
}

/**
 * Prepend new item with expanded link to the list.
 */
void
xslist_prepend(xslist_t *list, void *data)
{
	xslink_t *lk;

	xslist_check(list);
	g_assert(data != NULL);

	lk = ptr_add_offset(data, list->offset);
	xslist_link_prepend_internal(list, lk);
}

/**
 * Prepend other list to the list.
 *
 * The other list descriptor is cleared, since its items are transferred
 * to the first list.
 *
 * The two lists must be compatible, that is the offset to the link pointer
 * must be identical.
 *
 * @param list		the destination list
 * @param other		the other list to prepend (descriptor will be cleared)
 */
void
xslist_prepend_list(xslist_t *list, xslist_t *other)
{
	xslist_check(list);
	xslist_check(other);
	g_assert(list->offset == other->offset);

	if G_UNLIKELY(0 == other->count)
		return;

	if G_UNLIKELY(NULL == list->head) {
		g_assert(NULL == list->tail);
		g_assert(0 == list->count);
		list->tail = other->tail;
		list->count = other->count;
	} else {
		g_assert(NULL != other->tail);	/* Since list not empty */
		g_assert(NULL == xslist_next(other, other->tail));
		g_assert(size_is_positive(list->count));
		xslist_set_next(other, other->tail, list->head);
		list->count += other->count;
	}

	list->head = other->head;
	xslist_clear(other);

	safety_assert(xslist_length(list, list->head) == list->count);
}

/**
 * Append other list to the list.
 *
 * The other list descriptor is cleared, since its items are transferred
 * to the first list.
 *
 * The two lists must be compatible, that is the offset to the link pointer
 * must be identical.
 *
 * @param list		the destination list
 * @param other		the other list to append (descriptor will be cleared)
 */
void
xslist_append_list(xslist_t *list, xslist_t *other)
{
	xslist_check(list);
	xslist_check(other);
	g_assert(list->offset == other->offset);

	if G_UNLIKELY(0 == other->count)
		return;

	if G_UNLIKELY(NULL == list->tail) {
		g_assert(NULL == list->head);
		g_assert(0 == list->count);
		list->head = other->head;
		list->count = other->count;
	} else {
		g_assert(NULL == xslist_next(list, list->tail));
		g_assert(size_is_positive(list->count));
		xslist_set_next(list, list->tail, other->head);
		list->count += other->count;
	}

	list->tail = other->tail;
	xslist_clear(other);

	safety_assert(xslist_length(list, list->head) == list->count);
}

static inline void
xslist_link_remove_after_internal(xslist_t *list, xslink_t *prevlk, xslink_t *lk)
{
	g_assert(size_is_positive(list->count));
	xslist_invariant(list);

	if G_UNLIKELY(list->tail == lk)
		list->tail = prevlk;

	if (NULL == prevlk) {
		/* Removing the head */
		g_assert(list->head == lk);
		list->head = xslist_next(list, lk);
	} else {
		xslist_set_next(list, prevlk, xslist_next(list, lk));
	}

	xslist_set_next(list, lk, NULL);
	list->count--;

	safety_assert(xslist_invariant(list));
	safety_assert(xslist_length(list, list->head) == list->count);
}

/**
 * Remove head of list, return pointer to item, NULL if list was empty.
 */
void *
xslist_shift(xslist_t *list)
{
	void *item;

	xslist_check(list);

	if (NULL == list->head) {
		item = NULL;
	} else {
		item = ptr_add_offset(list->head, -list->offset);
		xslist_link_remove_after_internal(list, NULL, list->head);
	}

	return item;
}

/**
 * Rotate list by one item to the left.
 *
 * The head is inserted back at the tail.
 */
void
xslist_rotate_left(xslist_t *list)
{
	xslink_t *lk;

	xslist_check(list);

	if G_UNLIKELY(list->count <= 1U)
		return;

	lk = list->head;
	xslist_link_remove_after_internal(list, NULL, lk);
	xslist_link_append_internal(list, lk);

	safety_assert(xslist_invariant(list));
}

static void
xslist_link_insert_after_internal(xslist_t *list, xslink_t *siblk, xslink_t *lk)
{
	g_assert(size_is_positive(list->count));
	xslist_invariant(list);

	if G_UNLIKELY(list->tail == siblk)
		list->tail = lk;

	xslist_set_next(list, lk, xslist_next(list, siblk));
	xslist_set_next(list, siblk, lk);
	list->count++;

	safety_assert(xslist_invariant(list));
	safety_assert(xslist_length(list, list->head) == list->count);
}

/**
 * Insert link after another one in list.
 *
 * The sibling must already be part of the list, the new link must not.
 * If the sibling is NULL, insertion happens at the head of the list.
 */
void
xslist_link_insert_after(xslist_t *list, xslink_t *sibling_lk, xslink_t *lk)
{
	xslist_check(list);
	g_assert(lk != NULL);

	if (NULL == sibling_lk)
		xslist_link_prepend_internal(list, lk);
	else
		xslist_link_insert_after_internal(list, sibling_lk, lk);
}

/**
 * Insert item after another one in list.
 *
 * The sibling item must already be part of the list, the data item must not.
 */
void
xslist_insert_after(xslist_t *list, void *sibling, void *data)
{
	xslink_t *lk;

	xslist_check(list);
	g_assert(data != NULL);

	lk = ptr_add_offset(data, list->offset);
	if (NULL == sibling) {
		xslist_link_prepend_internal(list, lk);
	} else {
		xslink_t *siblk = ptr_add_offset(sibling, list->offset);
		xslist_link_insert_after_internal(list, siblk, lk);
	}
}

/**
 * Remove data item from list.
 *
 * This is usually very inefficient as the list needs to be traversed
 * to find the previous item.
 */
void
xslist_remove(xslist_t *list, void *data)
{
	xslink_t *lk, *prevlk, *datalk;

	xslist_check(list);
	g_assert(data != NULL);

	datalk = ptr_add_offset(data, list->offset);
	prevlk = NULL;

	for (lk = list->head; lk != NULL; prevlk = lk, lk = xslist_next(list, lk)) {
		if (datalk == lk) {
			xslist_link_remove_after_internal(list, prevlk, lk);
			return;
		}
	}

	g_assert_not_reached();		/* Item not found in list! */
}

/**
 * Remove data item following sibling, if any.
 *
 * @return the item removed, NULL if there was nother after sibling.
 */
void *
xslist_remove_after(xslist_t *list, void *sibling)
{
	xslink_t *lk, *next;
	void *data;

	xslist_check(list);
	g_assert(sibling != NULL);

	lk = ptr_add_offset(sibling, list->offset);
	next = xslist_next(list, lk);

	if G_UNLIKELY(NULL == next)
		return NULL;		/* Nothing after, not an error */

	data = ptr_add_offset(next, -list->offset);
	xslist_link_remove_after_internal(list, lk, next);

	return data;
}

/**
 * Reverse list.
 */
void
xslist_reverse(xslist_t *list)
{
	xslink_t *lk, *prev;

	xslist_check(list);
	xslist_invariant(list);

	for (lk = list->head, prev = NULL; lk != NULL; /* empty */) {
		xslink_t *next = xslist_next(list, lk);

		xslist_set_next(list, lk, prev);
		prev = lk;
		lk = next;
	}

	/* Swap head and tail */
	lk = list->head;
	list->head = list->tail;
	list->tail = lk;

	safety_assert(xslist_invariant(list));
	safety_assert(xslist_length(list, list->head) == list->count);
}

/**
 * Find item in list, using supplied comparison callback to compare list
 * items with the key we're looking for.
 *
 * The key is usually a "dummy" structure with enough fields set to allow
 * comparisons to be made.
 *
 * @param list		the list
 * @param key		key item to locate
 * @param cmp		comparison function to use
 *
 * @return the found item, or NULL if not found.
 */
void *
xslist_find(const xslist_t *list, const void *key, cmp_fn_t cmp)
{
	xslink_t *lk;

	xslist_check(list);
	g_assert(key != NULL);
	g_assert(cmp != NULL);

	for (lk = list->head; lk != NULL; lk = xslist_next(list, lk)) {
		void *data = ptr_add_offset(lk, -list->offset);
		if (0 == (*cmp)(data, key))
			return data;
	}

	return NULL;
}

/**
 * Iterate over the list, invoking the callback for every data item.
 *
 * It is safe for the callback to destroy the item, however this corrupts
 * the list which must therefore be discarded upon return.
 *
 * @param list		the list
 * @param cb		function to invoke on all items
 * @param data		opaque user-data to pass to callback
 */
void
xslist_foreach(const xslist_t *list, data_fn_t cb, void *data)
{
	xslink_t *lk, *next;

	xslist_check(list);
	xslist_invariant(list);
	g_return_unless(cb != NULL);
	safety_assert(xslist_length(lisst, list->head) == list->count);

	for (lk = list->head; lk != NULL; lk = next) {
		void *item = ptr_add_offset(lk, -list->offset);
		next = xslist_next(list, lk);	/* Allow callback to destroy item */
		(*cb)(item, data);
	}

	safety_assert(xslist_invariant(list));
	safety_assert(xslist_length(list, list->head) == list->count);
}

/**
 * Iterate over the list, invoking the callback for every data item
 * and removing the current item if it returns TRUE.
 *
 * @param list		the list
 * @param cbr		function to invoke to determine whether to remove item
 * @param data		opaque user-data to pass to callback
 *
 * @return amount of removed items from the list.
 */
size_t
xslist_foreach_remove(xslist_t *list, data_rm_fn_t cbr, void *data)
{
	xslink_t *lk, *next, *prev;
	size_t removed = 0;

	xslist_check(list);
	xslist_invariant(list);
	g_return_val_unless(cbr != NULL, 0);
	safety_assert(xslist_length(list->head) == list->count);

	for (lk = list->head, prev = NULL; lk != NULL; lk = next) {
		void *item = ptr_add_offset(lk, -list->offset);

		/*
		 * The callback can free the item, so we must copy the next
		 * pointer first.
		 */

		next = xslist_next(list, lk);

		if ((*cbr)(item, data)) {
			if G_UNLIKELY(list->head == lk)
				list->head = next;
			if G_UNLIKELY(list->tail == lk) {
				g_assert(NULL == next);
				list->tail = prev;
			}
			if (prev != NULL)
				xslist_set_next(list, prev, next);
			list->count--;
			removed++;
		} else {
			prev = lk;		/* Item not removed, becomes new previous */
		}
	}

	safety_assert(xslist_invariant(list));
	safety_assert(xslist_length(list, list->head) == list->count);

	return removed;
}

/**
 * Run the merge sort algorithm of the sublist, merging back into list.
 *
 * @return the head of the list
 */
static xslink_t * G_GNUC_HOT
xslist_merge_sort(xslist_t *list, xslink_t *sublist, size_t count,
	cmp_data_fn_t cmp, void *data)
{
	xslink_t *l1, *l2, *l;
	size_t n1, i;
	xslink_t *head;
	void *ptr;

	if (count <= 1) {
		g_assert(0 != count || NULL == sublist);
		g_assert(0 == count || NULL == xslist_next(list, sublist));

		return sublist;		/* Trivially sorted */
	}

	/*
	 * Divide and conquer: split the list into two, sort each part then
	 * merge the two sorted sublists.
	 */

	n1 = count / 2;

	for (i = 1, l1 = sublist; i < n1; l1 = xslist_next(list, l1), i++)
		/* empty */;

	l2 = xslist_next(list, l1);			/* Start of 2nd list */
	xslist_set_next(list, l1, NULL);	/* End of 1st list with ``n1'' items */

	l1 = xslist_merge_sort(list, sublist, n1, cmp, data);
	l2 = xslist_merge_sort(list, l2, count - n1, cmp, data);

	/*
	 * We're only going to change the pointer at "head + list->link_offset",
	 * which happens to be the ``ptr'' variable!
	 */

	head = ptr_add_offset(&ptr, -list->link_offset);
	l = head;

	/*
	 * We now have two sorted (one-way) lists: ``l1'' and ``l2''.
	 * Merge them into `list', taking care of updating its tail, since
	 * we return the head.
	 */

	while (l1 != NULL && l2 != NULL) {
		void *d1 = ptr_add_offset(l1, -list->offset);
		void *d2 = ptr_add_offset(l2, -list->offset);
		int c = (*cmp)(d1, d2, data);

		if (c <= 0) {
			l = xslist_set_next(list, l, l1);
			l1 = xslist_next(list, l1);
		} else {
			l = xslist_set_next(list, l, l2);
			l2 = xslist_next(list, l2);
		}
	}

	xslist_set_next(list, l, (NULL == l1) ? l2 : l1);

	{
		xslink_t *next;

		while (NULL != (next = xslist_next(list, l)))
			l = next;
	}

	list->tail = l;
	return xslist_next(list, head);
}

/**
 * Sort list in place using a merge sort.
 */
static void
xslist_sort_internal(xslist_t *list, cmp_data_fn_t cmp, void *data)
{
	xslist_check(list);
	xslist_invariant(list);
	g_return_unless(cmp != NULL);

	/*
	 * During merging, we use the list as a one-way list chained through
	 * its next pointers and identified by its head and by its amount of
	 * items (to make sub-splitting faster).
	 *
	 * When we come back from the recursion we merge the two sorted lists.
	 */

	list->head = xslist_merge_sort(list, list->head, list->count, cmp, data);

	safety_assert(xslist_invariant(list));
	safety_assert(xslist_length(list, list->head) == list->count);
}

/**
 * Sort list according to the comparison function, which takes two items
 * plus an additional opaque argument, meant to be used as context to sort
 * the two items.
 *
 * @param list	the list to sort
 * @param cmp	comparison routine to use (for two items)
 * @param data	additional argument to supply to comparison routine
 */
void
xslist_sort_with_data(xslist_t *list, cmp_data_fn_t cmp, void *data)
{
	xslist_sort_internal(list, cmp, data);
}

/**
 * Sort list according to the comparison function, which compares items.
 *
 * @param list	the list to sort
 * @param cmp	comparison routine to use (for two items)
 */
void
xslist_sort(xslist_t *list, cmp_fn_t cmp)
{
	xslist_sort_internal(list, (cmp_data_fn_t) cmp, NULL);
}

/**
 * Insert item in sorted list at the proper position.
 *
 * @param list	the list into which we insert
 * @param item	the item to insert
 * @param cmp	comparison routine to use (for two items) with extra data
 * @param data	user-supplied data for the comparison routine
 */
static void
xslist_insert_sorted_internal(xslist_t *list, void *item,
	cmp_data_fn_t cmp, void *data)
{
	xslink_t *lk, *ln, *prev;

	xslist_check(list);
	xslist_invariant(list);
	g_assert(item != NULL);
	g_assert(cmp != NULL);

	ln = ptr_add_offset(item, list->offset);

	for (
		lk = list->head, prev = NULL;
		lk != NULL;
		prev = lk, lk = xslist_next(list, lk)
	) {
		void *p = ptr_add_offset(lk, -list->offset);
		if ((*cmp)(item, p, data) <= 0)
			break;
	}

	if (NULL == lk) {
		xslist_link_append_internal(list, ln);
	} else {
		/* Insert ``ln'' before ``lk'' */
		if (prev != NULL) {
			xslist_set_next(list, prev, ln);
		} else {
			list->head = ln;
		}
		xslist_set_next(list, ln, lk);
	}

	safety_assert(xslist_length(list, list->head) == list->count);
}

/**
 * Insert item in sorted list at the proper position, as determined by
 * the item comparison routine, in order to keep the whole list sorted
 * after insertion, using the same comparison criteria.
 *
 * The comparison routine takes an extra user-defined context, to assist
 * in the item comparison.
 *
 * @param list	the list into which we insert
 * @param item	the item to insert
 * @param cmp	comparison routine to use (for two items) with extra data
 * @param data	user-supplied data for the comparison routine
 */
void
xslist_insert_sorted_with_data(xslist_t *list, void *item,
	cmp_data_fn_t cmp, void *data)
{
	xslist_insert_sorted_internal(list, item, cmp, data);
}

/**
 * Insert item in sorted list at the proper position, as determined by
 * the item comparison routine, in order to keep the whole list sorted
 * after insertion, using the same comparison criteria.
 *
 * @param list	the list into which we insert
 * @param item	the item to insert
 * @param cmp	comparison routine to use (for two items)
 */
void
xslist_insert_sorted(xslist_t *list, void *item, cmp_fn_t cmp)
{
	xslist_insert_sorted_internal(list, item, (cmp_data_fn_t) cmp, NULL);
}

/**
 * Get the n-th item in the list (0-based index).
 *
 * A negative index gets items from the tail of the list, i.e. -1 gets the
 * last item, -2 the penultimate one, -3 the antepenultimate one, etc...
 *
 * @param list	the list
 * @param n		the n-th item index to retrieve (0 = first item)
 *
 * @return the n-th item, NULL if the position is off the end of the list.
 */
void *
xslist_nth(const xslist_t *list, long n)
{
	size_t i = n;
	xslink_t *lk;

	xslist_check(list);

	if (n < 0)
		i = list->count + n;

	if (i >= list->count)
		return NULL;

	for (lk = list->head; lk != NULL; lk = xslist_next(list, lk)) {
		if (0 == i--)
			return ptr_add_offset(lk, -list->offset);
	}

	g_assert_not_reached();		/* Item must have been selected above */
}

/**
 * Given a link, return the item associated with the nth link that follows it,
 * or NULL if there is nothing.  The 0th item is the data associated with
 * the given link.
 *
 * @param list	the list
 * @param lk	the starting link, which must be part of the list
 * @param n		how mnay items to move forward starting from the link
 *
 * @return item at the nth position following the link, NULL if none.
 */
void *
xslist_nth_next_data(const xslist_t *list, const xslink_t *lk, size_t n)
{
	xslink_t *l;

	xslist_check(list);
	g_assert(lk != NULL);
	g_assert(size_is_non_negative(n));

	l = xslist_nth_next(list, lk, n);
	return NULL == l ? NULL : ptr_add_offset(l, -list->offset);
}

/**
 * Pick random item in list.
 *
 * @return pointer to the selected item, NULL if list is empty.
 */
void *
xslist_random(const xslist_t *list)
{
	xslist_check(list);
	g_assert(list->count <= MAX_INT_VAL(long));

	if G_UNLIKELY(0 == list->count)
		return NULL;

	return xslist_nth(list, random_ulong_value(list->count - 1));
}

/**
 * Randomly shuffle the items in the list using supplied random function.
 *
 * @param rf	the random function to use (NULL means: use defaults)
 * @param list	the list to shuffle
 */
void
xslist_shuffle_with(random_fn_t rf, xslist_t *list)
{
	xslink_t *lk;
	xslink_t **array;
	size_t i;

	xslist_check(list);
	xslist_invariant(list);

	if G_UNLIKELY(list->count <= 1U)
		return;

	/*
	 * To ensure O(n) shuffling, build an array containing all the items,
	 * shuffle that array then recreate the list according to the shuffled
	 * array.
	 */

	XMALLOC_ARRAY(array, list->count);

	for (i = 0, lk = list->head; lk != NULL; i++, lk = xslist_next(list, lk)) {
		array[i] = lk;
	}

	shuffle_with(rf, array, list->count, sizeof array[0]);

	/*
	 * Rebuild the list.
	 */

	list->head = array[0];
	list->tail = array[list->count - 1];

	lk = list->head;

	for (i = 1; i < list->count; i++) {
		xslink_t *ln = array[i];

		xslist_set_next(list, lk, ln);
		lk = ln;
	}

	xslist_set_next(list, lk, NULL);
	xfree(array);

	safety_assert(xslist_invariant(list));
	safety_assert(xslist_length(list, list->head) == list->count);
}

/**
 * Randomly shuffle the items in the list.
 */
void
xslist_shuffle(xslist_t *list)
{
	xslist_shuffle_with(NULL, list);
}

/* vi: set ts=4 sw=4 cindent: */
