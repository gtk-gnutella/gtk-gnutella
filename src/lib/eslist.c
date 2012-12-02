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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Embedded one-way list (within another data structure).
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
 * @date 2012
 */

#include "common.h"

#include "eslist.h"
#include "random.h"
#include "shuffle.h"
#include "unsigned.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

#if 0
#define ESLIST_SAFETY_ASSERT	/**< Turn on costly integrity assertions */
#endif

#ifdef ESLIST_SAFETY_ASSERT
#define safety_assert(x)	g_assert(x)
#else
#define safety_assert(x)
#endif

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
 * Discard list, making the list object invalid.
 *
 * This does not free any of the items, it just discards the list descriptor.
 * The underlying items remain chained though, so retaining a pointer to one
 * of the slink_t of one item still allows limited link-level traversal.
 */
void
eslist_discard(eslist_t *list)
{
	eslist_check(list);

	list->magic = 0;
}

/**
 * Clear list, forgetting about all the items
 *
 * This does not free or unlink any of the items, it just empties the list
 * descriptor.
 */
void
eslist_clear(eslist_t *list)
{
	eslist_check(list);

	list->head = list->tail = NULL;
	list->count = 0;
}

static inline void
eslist_link_append_internal(eslist_t *list, slink_t *lk)
{
	if G_UNLIKELY(NULL == list->tail) {
		g_assert(NULL == list->head);
		g_assert(0 == list->count);
		list->head = list->tail = lk;
		lk->next = NULL;
	} else {
		g_assert(NULL == list->tail->next);
		g_assert(NULL != list->head);	/* Since list not empty */
		g_assert(size_is_positive(list->count));
		list->tail->next = lk;
		lk->next = NULL;
		list->tail = lk;
	}

	list->count++;

	safety_assert(eslist_length(list->head) == list->count);
}

/**
 * Append new link to the list.
 *
 * This is efficient and does not require a full traversal of the list.
 */
void
eslist_link_append(eslist_t *list, slink_t *lk)
{
	eslist_check(list);
	g_assert(lk != NULL);

	eslist_link_append_internal(list, lk);
}

/**
 * Append new item with embedded link to the list.
 *
 * This is efficient and does not require a full traversal of the list.
 */
void
eslist_append(eslist_t *list, void *data)
{
	slink_t *lk;

	eslist_check(list);
	g_assert(data != NULL);

	lk = ptr_add_offset(data, list->offset);
	eslist_link_append_internal(list, lk);
}

static inline void
eslist_link_prepend_internal(eslist_t *list, slink_t *lk)
{
	if G_UNLIKELY(NULL == list->head) {
		g_assert(NULL == list->tail);
		g_assert(0 == list->count);
		list->head = list->tail = lk;
		lk->next = NULL;
	} else {
		g_assert(NULL != list->tail);	/* Since list not empty */
		g_assert(size_is_positive(list->count));
		lk->next = list->head;
		list->head = lk;
	}

	list->count++;

	safety_assert(eslist_length(list->head) == list->count);
}

/**
 * Prepend link to the list.
 */
void
eslist_link_prepend(eslist_t *list, slink_t *lk)
{
	eslist_check(list);
	g_assert(lk != NULL);

	eslist_link_prepend_internal(list, lk);
}

/**
 * Prepend new item with embedded link to the list.
 */
void
eslist_prepend(eslist_t *list, void *data)
{
	slink_t *lk;

	eslist_check(list);
	g_assert(data != NULL);

	lk = ptr_add_offset(data, list->offset);
	eslist_link_prepend_internal(list, lk);
}

static inline void
eslist_link_remove_after_internal(eslist_t *list, slink_t *prevlk, slink_t *lk)
{
	g_assert(size_is_positive(list->count));
	eslist_invariant(list);

	if G_UNLIKELY(list->tail == lk)
		list->tail = prevlk;

	if (NULL == prevlk) {
		/* Removing the head */
		g_assert(list->head == lk);
		list->head = lk->next;
	} else {
		prevlk->next = lk->next;
	}

	lk->next = NULL;
	list->count--

	safety_assert(eslist_invariant(list));
	safety_assert(eslist_length(list->head) == list->count);
}

/**
 * Remove head of list, return pointer to item, NULL if list was empty.
 */
void *
eslist_shift(eslist_t *list)
{
	void *item;

	eslist_check(list);

	if (NULL == list->head) {
		item = NULL;
	} else {
		item = ptr_add_offset(list->head, -list->offset);
		eslist_link_remove_after_internal(list, NULL, list->head);
	}

	return item;
}

static void
eslist_link_insert_after_internal(eslist_t *list, slink_t *siblk, slink_t *lk)
{
	g_assert(size_is_positive(list->count));
	eslist_invariant(list);

	if G_UNLIKELY(list->tail == siblk)
		list->tail = lk;

	lk->next = siblk->next;
	siblk->next = lk;

	list->count++;
	safety_assert(eslist_invariant(list));
	safety_assert(eslist_length(list->head) == list->count);
}

/**
 * Insert link after another one in list.
 *
 * The sibling must already be part of the list, the new link must not.
 * If the sibling is NULL, insertion happens at the head of the list.
 */
void
eslist_link_insert_after(eslist_t *list, slink_t *sibling_lk, slink_t *lk)
{
	eslist_check(list);
	g_assert(lk != NULL);

	if (NULL == sibling_lk)
		eslist_link_prepend_internal(list, lk);
	else
		eslist_link_insert_after_internal(list, sibling_lk, lk);
}

/**
 * Insert item after another one in list.
 *
 * The sibling item must already be part of the list, the data item must not.
 */
void
eslist_insert_after(eslist_t *list, void *sibling, void *data)
{
	slink_t *lk;

	eslist_check(list);
	g_assert(data != NULL);

	lk = ptr_add_offset(data, list->offset);
	if (NULL == sibling) {
		eslist_link_prepend_internal(list, lk);
	} else {
		slink_t *siblk = ptr_add_offset(sibling, list->offset);
		eslist_link_insert_after_internal(list, siblk, lk);
	}
}

/**
 * Remove data item from list.
 *
 * This is usually very inefficient as the list needs to be traversed
 * to find the previous item.
 */
void
eslist_remove(eslist_t *list, void *data)
{
	slink_t *lk, *prevlk, *datalk;

	eslist_check(list);
	g_assert(data != NULL);

	datalk = ptr_add_offset(data, list->offset);
	prevlk = NULL;

	for (lk = list->head; lk != NULL; prevlk = lk, lk = lk->next) {
		if (datalk == lk) {
			eslist_link_remove_after_internal(list, prevlk, lk);
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
eslist_remove_after(eslist_t *list, void *sibling)
{
	slink_t *lk;
	void *data;

	eslist_check(list);
	g_assert(sibling != NULL);

	lk = ptr_add_offset(sibling, list->offset);

	if G_UNLIKELY(NULL == lk->next)
		return NULL;		/* Nothing after, not an error */

	data = ptr_add_offset(lk->next, -list->offset);
	eslist_link_remove_after_internal(list, lk, lk->next);

	return data;
}

/**
 * Reverse list.
 */
void
eslist_reverse(eslist_t *list)
{
	slink_t *lk, *prev;

	eslist_check(list);
	eslist_invariant(list);

	for (lk = list->head, prev = NULL; lk != NULL; /* empty */) {
		slink_t *next = lk->next;

		lk->next = prev;
		prev = lk;
		lk = next;
	}

	/* Swap head and tail */
	lk = list->head;
	list->head = list->tail;
	list->tail = lk;

	safety_assert(eslist_invariant(list));
	safety_assert(eslist_length(list->head) == list->count);
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
eslist_find(const eslist_t *list, const void *key, cmp_fn_t cmp)
{
	slink_t *lk;

	eslist_check(list);
	g_assert(key != NULL);
	g_assert(cmp != NULL);

	for (lk = list->head; lk != NULL; lk = lk->next) {
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
eslist_foreach(const eslist_t *list, data_fn_t cb, void *data)
{
	slink_t *lk, *next;

	eslist_check(list);
	eslist_invariant(list);
	g_return_unless(cb != NULL);
	safety_assert(eslist_length(list->head) == list->count);

	for (lk = list->head; lk != NULL; lk = next) {
		void *item = ptr_add_offset(lk, -list->offset);
		next = lk->next;		/* Allow callback to destroy item */
		(*cb)(item, data);
	}

	safety_assert(eslist_invariant(list));
	safety_assert(eslist_length(list->head) == list->count);
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
eslist_foreach_remove(eslist_t *list, data_rm_fn_t cbr, void *data)
{
	slink_t *lk, *next, *prev;
	size_t removed = 0;

	eslist_check(list);
	eslist_invariant(list);
	g_return_val_unless(cbr != NULL, 0);
	safety_assert(eslist_length(list->head) == list->count);

	for (lk = list->head, prev = NULL; lk != NULL; lk = next) {
		void *item = ptr_add_offset(lk, -list->offset);

		/*
		 * The callback can free the item, so we must copy the next
		 * pointer first.
		 */

		next = lk->next;

		if ((*cbr)(item, data)) {
			if G_UNLIKELY(list->head == lk)
				list->head = next;
			if G_UNLIKELY(list->tail == lk) {
				g_assert(NULL == next);
				list->tail = prev;
			}
			if (prev != NULL)
				prev->next = next;
			list->count--;
			removed++;
		} else {
			prev = lk;		/* Item not removed, becomes new previous */
		}
	}

	safety_assert(eslist_invariant(list));
	safety_assert(eslist_length(list->head) == list->count);

	return removed;
}

/**
 * Run the merge sort algorithm of the sublist, merging back into list.
 *
 * @return the head of the list
 */
static slink_t *
eslist_merge_sort(eslist_t *list, slink_t *sublist, size_t count,
	cmp_data_fn_t cmp, void *data)
{
	slink_t *l1, *l2, *l;
	size_t n1, i;
	slink_t head;

	if (count <= 1) {
		g_assert(0 != count || NULL == sublist);
		g_assert(0 == count || NULL == sublist->next);

		return sublist;		/* Trivially sorted */
	}

	/*
	 * Divide and conquer: split the list into two, sort each part then
	 * merge the two sorted sublists.
	 */

	n1 = count / 2;

	for (i = 1, l1 = sublist; i < n1; l1 = l1->next, i++)
		/* empty */;

	l2 = l1->next;			/* Start of second list */
	l1->next = NULL;		/* End of first list with ``n1'' items */

	l1 = eslist_merge_sort(list, sublist, n1, cmp, data);
	l2 = eslist_merge_sort(list, l2, count - n1, cmp, data);

	/*
	 * We now have two sorted (one-way) lists: ``l1'' and ``l2''.
	 * Merge them into `list', taking care of updating its tail, since
	 * we return the head.
	 */

	l = &head;

	while (l1 != NULL && l2 != NULL) {
		void *d1 = ptr_add_offset(l1, -list->offset);
		void *d2 = ptr_add_offset(l2, -list->offset);
		int c = (*cmp)(d1, d2, data);

		if (c <= 0) {
			l->next = l1;
			l1 = l1->next;
		} else {
			l->next = l2;
			l2 = l2->next;
		}
		l = l->next;
	}

	l->next = (NULL == l1) ? l2 : l1;

	while (l->next != NULL)
		l = l->next;

	list->tail = l;
	return head.next;
}

/**
 * Sort list in place using a merge sort.
 */
static void
eslist_sort_internal(eslist_t *list, cmp_data_fn_t cmp, void *data)
{
	eslist_check(list);
	eslist_invariant(list);
	g_return_unless(cmp != NULL);

	/*
	 * During merging, we use the list as a one-way list chained through
	 * its next pointers and identified by its head and by its amount of
	 * items (to make sub-splitting faster).
	 *
	 * When we come back from the recursion we merge the two sorted lists.
	 */

	list->head = eslist_merge_sort(list, list->head, list->count, cmp, data);

	safety_assert(eslist_invariant(list));
	safety_assert(eslist_length(list->head) == list->count);
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
eslist_sort_with_data(eslist_t *list, cmp_data_fn_t cmp, void *data)
{
	eslist_sort_internal(list, cmp, data);
}

/**
 * Sort list according to the comparison function, which compares items.
 *
 * @param list	the list to sort
 * @param cmp	comparison routine to use (for two items)
 */
void
eslist_sort(eslist_t *list, cmp_fn_t cmp)
{
	eslist_sort_internal(list, (cmp_data_fn_t) cmp, NULL);
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
eslist_insert_sorted_internal(eslist_t *list, void *item,
	cmp_data_fn_t cmp, void *data)
{
	slink_t *lk, *ln, *prev;

	eslist_check(list);
	eslist_invariant(list);
	g_assert(item != NULL);
	g_assert(cmp != NULL);

	ln = ptr_add_offset(item, list->offset);

	for (lk = list->head, prev = NULL; lk != NULL; prev = lk, lk = lk->next) {
		void *p = ptr_add_offset(lk, -list->offset);
		if ((*cmp)(item, p, data) <= 0)
			break;
	}

	if (NULL == lk) {
		eslist_link_append_internal(list, ln);
	} else {
		/* Insert ``ln'' before ``lk'' */
		if (prev != NULL) {
			prev->next = ln;
		} else {
			list->head = ln;
		}
		ln->next = lk;
	}

	safety_assert(eslist_length(list->head) == list->count);
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
eslist_insert_sorted_with_data(eslist_t *list, void *item,
	cmp_data_fn_t cmp, void *data)
{
	eslist_insert_sorted_internal(list, item, cmp, data);
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
eslist_insert_sorted(eslist_t *list, void *item, cmp_fn_t cmp)
{
	eslist_insert_sorted_internal(list, item, (cmp_data_fn_t) cmp, NULL);
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
eslist_nth_next_data(const eslist_t *list, const slink_t *lk, size_t n)
{
	slink_t *l;

	eslist_check(list);
	g_assert(lk != NULL);
	g_assert(size_is_non_negative(n));

	l = eslist_nth_next(lk, n);
	return NULL == l ? NULL : ptr_add_offset(l, -list->offset);
}

/**
 * Randomly shuffle the items in the list.
 */
void
eslist_shuffle(eslist_t *list)
{
	slink_t *lk;
	slink_t **array;
	size_t i;

	eslist_check(list);
	eslist_invariant(list);

	if G_UNLIKELY(list->count <= 1U)
		return;

	/*
	 * To ensure O(n) shuffling, build an array containing all the items,
	 * shuffle that array then recreate the list according to the shuffled
	 * array.
	 */

	array = xmalloc(list->count * sizeof array[0]);

	for (i = 0, lk = list->head; lk != NULL; i++, lk = lk->next) {
		array[i] = lk;
	}

	shuffle(array, list->count, sizeof array[0]);

	/*
	 * Rebuild the list.
	 */

	list->head = array[0];
	list->tail = array[list->count - 1];

	lk = list->head;

	for (i = 1; i < list->count; i++) {
		slink_t *ln = array[i];

		lk->next = ln;
		lk = ln;
	}

	lk->next = NULL;
	xfree(array);

	safety_assert(eslist_invariant(list));
	safety_assert(eslist_length(list->head) == list->count);
}

/* vi: set ts=4 sw=4 cindent: */
