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
 * Common code for managing a one-way list (chaining within data structure).
 *
 * The general form of one-way list with the chaining data structure being
 * embedded within the list items can be depicted as:
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

#include "random.h"
#include "shuffle.h"
#include "unsigned.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

/***
 *** This file is not meant to be compiled as a standalone version, but rather
 *** included with the following macro definitions:
 ***
 *** safety_assert(x)	either empty or g_assert(x)
 *** CHECK(l)			either eslist_check(l) or xslist_check(l)
 *** INVARIANT(l)		either eslist_invariant(l) or xslist_invariant(l)
 *** PREFIX				routine prefix, usually eslist_ or xslist_
 *** OWLIST_T			type of the list object (e.g. eslist_t)
 *** OWLINK_T			type of the chaining structure (e.g. slink_t)
 *** NEXT(l,lk)			get next item in list ``l'' after link ``lk''
 *** SET_NEXT(l,lk,v)	set next item in list ``l'' after link ``lk'' to ``v''
 *** LENGTH(l,h)		get list length for ``l'' whose head link is ``h''
 *** LINK_OFFSET(l)		get the link offset of ``l'' (0 for eslist)
 *** LIST_ARG(l)		either "l," when the list is needed, or empty
 ***/

#ifndef OWLIST_T
#error "this file is not meant to be compiled directly"
#endif

/**
 * Discard list, making the list object invalid.
 *
 * This does not free any of the items, it just discards the list descriptor.
 * The underlying items remain chained though, so retaining a pointer to one
 * of the OWLINK_T of one item still allows limited link-level traversal.
 */
#define OWLIST_discard	CAT2(PREFIX,discard)
void
OWLIST_discard(OWLIST_T *list)
{
	CHECK(list);

	list->magic = 0;
}

/**
 * Clear list, forgetting about all the items
 *
 * This does not free or unlink any of the items, it just empties the list
 * descriptor.
 */
#define OWLIST_clear	CAT2(PREFIX,clear)
void
OWLIST_clear(OWLIST_T *list)
{
	CHECK(list);

	list->head = list->tail = NULL;
	list->count = 0;
}

#define OWLIST_link_append_internal	CAT2(PREFIX,link_append_internal)
static inline void
OWLIST_link_append_internal(OWLIST_T *list, OWLINK_T *lk)
{
	if G_UNLIKELY(NULL == list->tail) {
		g_assert(NULL == list->head);
		g_assert(0 == list->count);
		list->head = list->tail = lk;
	} else {
		g_assert(NULL == NEXT(list, list->tail));
		g_assert(NULL != list->head);	/* Since list not empty */
		g_assert(size_is_positive(list->count));
		SET_NEXT(list, list->tail, lk);
		list->tail = lk;
	}

	SET_NEXT(list, lk, NULL);

	list->count++;

	safety_assert(LENGTH(list, list->head) == list->count);
}

/**
 * Append new link to the list.
 *
 * This is efficient and does not require a full traversal of the list.
 */
#define OWLIST_link_append	CAT2(PREFIX,link_append)
void
OWLIST_link_append(OWLIST_T *list, OWLINK_T *lk)
{
	CHECK(list);
	g_assert(lk != NULL);

	OWLIST_link_append_internal(list, lk);
}

/**
 * Append new item with expanded link to the list.
 *
 * This is efficient and does not require a full traversal of the list.
 */
#define OWLIST_append	CAT2(PREFIX,append)
void
OWLIST_append(OWLIST_T *list, void *data)
{
	OWLINK_T *lk;

	CHECK(list);
	g_assert(data != NULL);

	lk = ptr_add_offset(data, list->offset);
	OWLIST_link_append_internal(list, lk);
}

#define OWLIST_link_prepend_internal CAT2(PREFIX,link_prepend_internal)
static inline void
OWLIST_link_prepend_internal(OWLIST_T *list, OWLINK_T *lk)
{
	if G_UNLIKELY(NULL == list->head) {
		g_assert(NULL == list->tail);
		g_assert(0 == list->count);
		list->head = list->tail = lk;
		SET_NEXT(list, lk, NULL);
	} else {
		g_assert(NULL != list->tail);	/* Since list not empty */
		g_assert(size_is_positive(list->count));
		SET_NEXT(list, lk, list->head);
		list->head = lk;
	}

	list->count++;

	safety_assert(LENGTH(list, list->head) == list->count);
}

/**
 * Prepend link to the list.
 */
#define OWLIST_link_prepend	CAT2(PREFIX,link_prepend)
void
OWLIST_link_prepend(OWLIST_T *list, OWLINK_T *lk)
{
	CHECK(list);
	g_assert(lk != NULL);

	OWLIST_link_prepend_internal(list, lk);
}

/**
 * Prepend new item with expanded link to the list.
 */
#define OWLIST_prepend	CAT2(PREFIX,prepend)
void
OWLIST_prepend(OWLIST_T *list, void *data)
{
	OWLINK_T *lk;

	CHECK(list);
	g_assert(data != NULL);

	lk = ptr_add_offset(data, list->offset);
	OWLIST_link_prepend_internal(list, lk);
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
#define OWLIST_prepend_list	CAT2(PREFIX,prepend_list)
void
OWLIST_prepend_list(OWLIST_T *list, OWLIST_T *other)
{
	CHECK(list);
	CHECK(other);
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
		g_assert(NULL == NEXT(other, other->tail));
		g_assert(size_is_positive(list->count));
		SET_NEXT(other, other->tail, list->head);
		list->count += other->count;
	}

	list->head = other->head;
	OWLIST_clear(other);

	safety_assert(LENGTH(list, list->head) == list->count);
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
#define OWLIST_append_list	CAT2(PREFIX,append_list)
void
OWLIST_append_list(OWLIST_T *list, OWLIST_T *other)
{
	CHECK(list);
	CHECK(other);
	g_assert(list->offset == other->offset);

	if G_UNLIKELY(0 == other->count)
		return;

	if G_UNLIKELY(NULL == list->tail) {
		g_assert(NULL == list->head);
		g_assert(0 == list->count);
		list->head = other->head;
		list->count = other->count;
	} else {
		g_assert(NULL == NEXT(list, list->tail));
		g_assert(size_is_positive(list->count));
		SET_NEXT(list, list->tail, other->head);
		list->count += other->count;
	}

	list->tail = other->tail;
	OWLIST_clear(other);

	safety_assert(LENGTH(list, list->head) == list->count);
}

#define OWLIST_link_remove_after_internal CAT2(PREFIX,link_remove_after_internal)
static inline void
OWLIST_link_remove_after_internal(OWLIST_T *list, OWLINK_T *prevlk, OWLINK_T *lk)
{
	g_assert(size_is_positive(list->count));
	INVARIANT(list);

	if G_UNLIKELY(list->tail == lk)
		list->tail = prevlk;

	if (NULL == prevlk) {
		/* Removing the head */
		g_assert(list->head == lk);
		list->head = NEXT(list, lk);
	} else {
		SET_NEXT(list, prevlk, NEXT(list, lk));
	}

	SET_NEXT(list, lk, NULL);
	list->count--;

	safety_assert(INVARIANT(list));
	safety_assert(LENGTH(list, list->head) == list->count);
}

/**
 * Remove head of list, return pointer to item, NULL if list was empty.
 */
#define OWLIST_shift	CAT2(PREFIX,shift)
void *
OWLIST_shift(OWLIST_T *list)
{
	void *item;

	CHECK(list);

	if (NULL == list->head) {
		item = NULL;
	} else {
		item = ptr_add_offset(list->head, -list->offset);
		OWLIST_link_remove_after_internal(list, NULL, list->head);
	}

	return item;
}

/**
 * Rotate list by one item to the left.
 *
 * The head is inserted back at the tail.
 */
#define OWLIST_rotate_left	CAT2(PREFIX,rotate_left)
void
OWLIST_rotate_left(OWLIST_T *list)
{
	OWLINK_T *lk;

	CHECK(list);

	if G_UNLIKELY(list->count <= 1U)
		return;

	lk = list->head;
	OWLIST_link_remove_after_internal(list, NULL, lk);
	OWLIST_link_append_internal(list, lk);

	safety_assert(INVARIANT(list));
}

#define OWLIST_link_insert_after_internal CAT2(PREFIX,link_insert_after_internal)
static void
OWLIST_link_insert_after_internal(OWLIST_T *list, OWLINK_T *siblk, OWLINK_T *lk)
{
	g_assert(size_is_positive(list->count));
	INVARIANT(list);

	if G_UNLIKELY(list->tail == siblk)
		list->tail = lk;

	SET_NEXT(list, lk, NEXT(list, siblk));
	SET_NEXT(list, siblk, lk);
	list->count++;

	safety_assert(INVARIANT(list));
	safety_assert(LENGTH(list, list->head) == list->count);
}

/**
 * Insert link after another one in list.
 *
 * The sibling must already be part of the list, the new link must not.
 * If the sibling is NULL, insertion happens at the head of the list.
 */
#define OWLIST_link_insert_after	CAT2(PREFIX,link_insert_after)
void
OWLIST_link_insert_after(OWLIST_T *list, OWLINK_T *sibling_lk, OWLINK_T *lk)
{
	CHECK(list);
	g_assert(lk != NULL);

	if (NULL == sibling_lk)
		OWLIST_link_prepend_internal(list, lk);
	else
		OWLIST_link_insert_after_internal(list, sibling_lk, lk);
}

/**
 * Insert item after another one in list.
 *
 * The sibling item must already be part of the list, the data item must not.
 */
#define OWLIST_insert_after	CAT2(PREFIX,insert_after)
void
OWLIST_insert_after(OWLIST_T *list, void *sibling, void *data)
{
	OWLINK_T *lk;

	CHECK(list);
	g_assert(data != NULL);

	lk = ptr_add_offset(data, list->offset);
	if (NULL == sibling) {
		OWLIST_link_prepend_internal(list, lk);
	} else {
		OWLINK_T *siblk = ptr_add_offset(sibling, list->offset);
		OWLIST_link_insert_after_internal(list, siblk, lk);
	}
}

#undef remove		/* On Windows, this is remapped */

/**
 * Remove data item from list.
 *
 * This is usually very inefficient as the list needs to be traversed
 * to find the previous item.
 */
#define OWLIST_remove	CAT2(PREFIX,remove)
void
OWLIST_remove(OWLIST_T *list, void *data)
{
	OWLINK_T *lk, *prevlk, *datalk;

	CHECK(list);
	g_assert(data != NULL);
	safety_assert(CONTAINS(list, data));

	datalk = ptr_add_offset(data, list->offset);
	prevlk = NULL;

	for (lk = list->head; lk != NULL; prevlk = lk, lk = NEXT(list, lk)) {
		if (datalk == lk) {
			OWLIST_link_remove_after_internal(list, prevlk, lk);
			return;
		}
	}

	g_assert_not_reached();		/* Item not found in list! */
}

/**
 * Remove data item following sibling, if any.
 *
 * As a special case, if `sibling' is NULL then this behaves like a shift,
 * that is we remove the head item.
 *
 * @return the item removed, NULL if there was nothing after sibling.
 */
#define OWLIST_remove_after	CAT2(PREFIX,remove_after)
void *
OWLIST_remove_after(OWLIST_T *list, void *sibling)
{
	OWLINK_T *lk, *next;
	void *data;

	CHECK(list);

	if G_UNLIKELY(NULL == sibling) {
		lk = NULL;
		next = list->head;
	} else {
		lk = ptr_add_offset(sibling, list->offset);
		next = NEXT(list, lk);
	}

	if G_UNLIKELY(NULL == next)
		return NULL;		/* Nothing after, not an error */

	data = ptr_add_offset(next, -list->offset);
	OWLIST_link_remove_after_internal(list, lk, next);

	return data;
}

/**
 * Reverse list.
 */
#define OWLIST_reverse	CAT2(PREFIX,reverse)
void
OWLIST_reverse(OWLIST_T *list)
{
	OWLINK_T *lk, *prev;

	CHECK(list);
	INVARIANT(list);

	for (lk = list->head, prev = NULL; lk != NULL; /* empty */) {
		OWLINK_T *next = NEXT(list, lk);

		SET_NEXT(list, lk, prev);
		prev = lk;
		lk = next;
	}

	/* Swap head and tail */
	lk = list->head;
	list->head = list->tail;
	list->tail = lk;

	safety_assert(INVARIANT(list));
	safety_assert(LENGTH(list, list->head) == list->count);
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
#define OWLIST_find	CAT2(PREFIX,find)
void *
OWLIST_find(const OWLIST_T *list, const void *key, cmp_fn_t cmp)
{
	OWLINK_T *lk;

	CHECK(list);
	g_assert(key != NULL);
	g_assert(cmp != NULL);

	for (lk = list->head; lk != NULL; lk = NEXT(list, lk)) {
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
#define OWLIST_foreach	CAT2(PREFIX,foreach)
void
OWLIST_foreach(const OWLIST_T *list, data_fn_t cb, void *data)
{
	OWLINK_T *lk, *next;

	CHECK(list);
	INVARIANT(list);
	g_return_unless(cb != NULL);
	safety_assert(LENGTH(list, list->head) == list->count);

	for (lk = list->head; lk != NULL; lk = next) {
		void *item = ptr_add_offset(lk, -list->offset);
		next = NEXT(list, lk);	/* Allow callback to destroy item */
		(*cb)(item, data);
	}

	safety_assert(INVARIANT(list));
	safety_assert(LENGTH(list, list->head) == list->count);
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
#define OWLIST_foreach_remove	CAT2(PREFIX,foreach_remove)
size_t
OWLIST_foreach_remove(OWLIST_T *list, data_rm_fn_t cbr, void *data)
{
	OWLINK_T *lk, *next, *prev;
	size_t removed = 0;

	CHECK(list);
	INVARIANT(list);
	g_return_val_unless(cbr != NULL, 0);
	safety_assert(LENGTH(list, list->head) == list->count);

	for (lk = list->head, prev = NULL; lk != NULL; lk = next) {
		void *item = ptr_add_offset(lk, -list->offset);

		/*
		 * The callback can free the item, so we must copy the next
		 * pointer first.
		 */

		next = NEXT(list, lk);

		if ((*cbr)(item, data)) {
			if G_UNLIKELY(list->head == lk)
				list->head = next;
			if G_UNLIKELY(list->tail == lk) {
				g_assert(NULL == next);
				list->tail = prev;
			}
			if (prev != NULL)
				SET_NEXT(list, prev, next);
			list->count--;
			removed++;
		} else {
			prev = lk;		/* Item not removed, becomes new previous */
		}
	}

	safety_assert(INVARIANT(list));
	safety_assert(LENGTH(list, list->head) == list->count);

	return removed;
}

/**
 * Run the merge sort algorithm of the sublist, merging back into list.
 *
 * @return the head of the list
 */
#define OWLIST_merge_sort	CAT2(PREFIX,merge_sort)
static OWLINK_T * G_HOT
OWLIST_merge_sort(OWLIST_T *list, OWLINK_T *sublist, size_t count,
	cmp_data_fn_t cmp, void *data)
{
	OWLINK_T *l1, *l2, *l;
	size_t n1, i;
	OWLINK_T *head;
	void *ptr;

	if (count <= 1) {
		g_assert(0 != count || NULL == sublist);
		g_assert(0 == count || NULL == NEXT(list, sublist));

		return sublist;		/* Trivially sorted */
	}

	/*
	 * Divide and conquer: split the list into two, sort each part then
	 * merge the two sorted sublists.
	 */

	n1 = count / 2;

	for (i = 1, l1 = sublist; i < n1; l1 = NEXT(list, l1), i++)
		/* empty */;

	l2 = NEXT(list, l1);		/* Start of 2nd list */
	SET_NEXT(list, l1, NULL);	/* End of 1st list with ``n1'' items */

	l1 = OWLIST_merge_sort(list, sublist, n1, cmp, data);
	l2 = OWLIST_merge_sort(list, l2, count - n1, cmp, data);

	/*
	 * We're only going to change the pointer at "head + LINK_OFFSET(list)",
	 * which happens to be the ``ptr'' variable!
	 */

	head = ptr_add_offset(&ptr, -LINK_OFFSET(list));
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
			l = SET_NEXT(list, l, l1);
			l1 = NEXT(list, l1);
		} else {
			l = SET_NEXT(list, l, l2);
			l2 = NEXT(list, l2);
		}
	}

	SET_NEXT(list, l, (NULL == l1) ? l2 : l1);

	{
		OWLINK_T *next;

		while (NULL != (next = NEXT(list, l)))
			l = next;
	}

	list->tail = l;
	return NEXT(list, head);
}

/**
 * Sort list in place using a merge sort.
 */
#define OWLIST_sort_internal	CAT2(PREFIX,sort_internal)
static void
OWLIST_sort_internal(OWLIST_T *list, cmp_data_fn_t cmp, void *data)
{
	CHECK(list);
	INVARIANT(list);
	g_return_unless(cmp != NULL);

	/*
	 * During merging, we use the list as a one-way list chained through
	 * its next pointers and identified by its head and by its amount of
	 * items (to make sub-splitting faster).
	 *
	 * When we come back from the recursion we merge the two sorted lists.
	 */

	list->head = OWLIST_merge_sort(list, list->head, list->count, cmp, data);

	safety_assert(INVARIANT(list));
	safety_assert(LENGTH(list, list->head) == list->count);
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
#define OWLIST_sort_with_data	CAT2(PREFIX,sort_with_data)
void
OWLIST_sort_with_data(OWLIST_T *list, cmp_data_fn_t cmp, void *data)
{
	OWLIST_sort_internal(list, cmp, data);
}

/**
 * Sort list according to the comparison function, which compares items.
 *
 * @param list	the list to sort
 * @param cmp	comparison routine to use (for two items)
 */
#define OWLIST_sort	CAT2(PREFIX,sort)
void
OWLIST_sort(OWLIST_T *list, cmp_fn_t cmp)
{
	OWLIST_sort_internal(list, (cmp_data_fn_t) cmp, NULL);
}

/**
 * Insert item in sorted list at the proper position.
 *
 * @param list	the list into which we insert
 * @param item	the item to insert
 * @param cmp	comparison routine to use (for two items) with extra data
 * @param data	user-supplied data for the comparison routine
 */
#define OWLIST_insert_sorted_internal	CAT2(PREFIX,insert_sorted_internal)
static void
OWLIST_insert_sorted_internal(OWLIST_T *list, void *item,
	cmp_data_fn_t cmp, void *data)
{
	OWLINK_T *lk, *ln, *prev;

	CHECK(list);
	INVARIANT(list);
	g_assert(item != NULL);
	g_assert(cmp != NULL);

	ln = ptr_add_offset(item, list->offset);

	for (
		lk = list->head, prev = NULL;
		lk != NULL;
		prev = lk, lk = NEXT(list, lk)
	) {
		void *p = ptr_add_offset(lk, -list->offset);
		if ((*cmp)(item, p, data) <= 0)
			break;
	}

	if (NULL == lk) {
		OWLIST_link_append_internal(list, ln);
	} else {
		/* Insert ``ln'' before ``lk'' */
		if (prev != NULL) {
			SET_NEXT(list, prev, ln);
		} else {
			list->head = ln;
		}
		SET_NEXT(list, ln, lk);
	}

	safety_assert(LENGTH(list, list->head) == list->count);
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
#define OWLIST_insert_sorted_with_data	CAT2(PREFIX,insert_sorted_with_data)
void
OWLIST_insert_sorted_with_data(OWLIST_T *list, void *item,
	cmp_data_fn_t cmp, void *data)
{
	OWLIST_insert_sorted_internal(list, item, cmp, data);
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
#define OWLIST_insert_sorted	CAT2(PREFIX,insert_sorted)
void
OWLIST_insert_sorted(OWLIST_T *list, void *item, cmp_fn_t cmp)
{
	OWLIST_insert_sorted_internal(list, item, (cmp_data_fn_t) cmp, NULL);
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
#define OWLIST_nth	CAT2(PREFIX,nth)
void *
OWLIST_nth(const OWLIST_T *list, long n)
{
	size_t i = n;
	OWLINK_T *lk;

	CHECK(list);

	if (n < 0)
		i = list->count + n;

	if (i >= list->count)
		return NULL;

	for (lk = list->head; lk != NULL; lk = NEXT(list, lk)) {
		if (0 == i--)
			return ptr_add_offset(lk, -list->offset);
	}

	g_assert_not_reached();		/* Item must have been selected above */
}

#define OWLIST_nth_next	CAT2(PREFIX,nth_next)

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
#define OWLIST_nth_next_data	CAT2(PREFIX,nth_next_data)
void *
OWLIST_nth_next_data(const OWLIST_T *list, const OWLINK_T *lk, size_t n)
{
	OWLINK_T *l;

	CHECK(list);
	g_assert(lk != NULL);
	g_assert(size_is_non_negative(n));

	l = OWLIST_nth_next(LIST_ARG(list) lk, n);
	return NULL == l ? NULL : ptr_add_offset(l, -list->offset);
}

/**
 * Pick random item in list.
 *
 * @return pointer to the selected item, NULL if list is empty.
 */
#define OWLIST_random	CAT2(PREFIX,random)
void *
OWLIST_random(const OWLIST_T *list)
{
	CHECK(list);
	g_assert(list->count <= MAX_INT_VAL(long));

	if G_UNLIKELY(0 == list->count)
		return NULL;

	return OWLIST_nth(list, random_ulong_value(list->count - 1));
}

/**
 * Randomly shuffle the items in the list using supplied random function.
 *
 * @param rf	the random function to use (NULL means: use defaults)
 * @param list	the list to shuffle
 */
#define OWLIST_shuffle_with	CAT2(PREFIX,shuffle_with)
void
OWLIST_shuffle_with(random_fn_t rf, OWLIST_T *list)
{
	OWLINK_T *lk;
	OWLINK_T **array;
	size_t i;

	CHECK(list);
	INVARIANT(list);

	if G_UNLIKELY(list->count <= 1U)
		return;

	/*
	 * To ensure O(n) shuffling, build an array containing all the items,
	 * shuffle that array then recreate the list according to the shuffled
	 * array.
	 */

	XMALLOC_ARRAY(array, list->count);

	for (i = 0, lk = list->head; lk != NULL; i++, lk = NEXT(list, lk)) {
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
		OWLINK_T *ln = array[i];

		SET_NEXT(list, lk, ln);
		lk = ln;
	}

	SET_NEXT(list, lk, NULL);
	xfree(array);

	safety_assert(INVARIANT(list));
	safety_assert(LENGTH(list, list->head) == list->count);
}

/**
 * Randomly shuffle the items in the list.
 */
#define OWLIST_shuffle	CAT2(PREFIX,shuffle)
void
OWLIST_shuffle(OWLIST_T *list)
{
	OWLIST_shuffle_with(NULL, list);
}

/* vi: set ts=4 sw=4 cindent: */
