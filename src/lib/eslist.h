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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Embedded one-way list (within another data structure).
 *
 * @author Raphael Manfredi
 * @date 2012-2015
 */

#ifndef _eslist_h_
#define _eslist_h_

/**
 * Get the enclosing data item from an embedded link.
 */
#ifdef __GNUC__
#define eslist_item(lnk, type, field) G_EXTENSION({		\
	const struct slink *__mptr = (lnk);						\
	(type *)((char *) __mptr - offsetof(type, field));})
#else
#define eslist_item(lnk, type, field)						\
	((type *)((char *) (node) - offsetof(type, field)))
#endif

/**
 * A list one-way (single) link.
 */
typedef struct slink {
	struct slink *next;
} slink_t;

#define SLINK_NULL	{ NULL }	/* For static initializations */

enum eslist_magic { ESLIST_MAGIC = 0x1662f297 };

/**
 * An embedded one-way list is represented by this structure.
 */
typedef struct eslist {
	enum eslist_magic magic;
	slink_t *head, *tail;
	size_t offset;		/* Offset of embedded slink in the item structure */
	size_t count;		/* Amount of items held */
} eslist_t;

static inline void
eslist_check(const eslist_t * const es)
{
	g_assert(es != NULL);
	g_assert(ESLIST_MAGIC == es->magic);
}

#define ESLIST_INIT(offset)		{ ESLIST_MAGIC, NULL, NULL, offset, 0 }

static inline bool
eslist_invariant(const eslist_t * const list)
{
	g_assert(list->count != 0 || (NULL == list->head && NULL == list->tail));
	g_assert((list->head != list->tail) == (list->count > 1U));
	g_assert(NULL == list->tail || NULL == list->tail->next);
	return TRUE;		/* So that we can safety_assert() this routine */
}

/**
 * Public interface.
 */

/**
 * @return whether the embedded list descriptor is non-zero.
 */
static inline bool
eslist_is_initialized(const eslist_t * const es)
{
	return 0 != es->magic;		/* Initialized, not necessarily valid! */
}

/**
 * @return length of embedded list.
 */
static inline size_t
eslist_count(const eslist_t * const es)
{
	eslist_check(es);
	return es->count;
}

/**
 * @return length of embedded list by traversing the list from the
 * specified link, following forward pointers.
 */
static inline size_t
eslist_length(const slink_t *lk)
{
	size_t n = 0;

	while (lk != NULL) {
		n++;
		lk = lk->next;
	}

	return n;
}

/**
 * @return pointer to first item of list, NULL if empty.
 */
static inline void *
eslist_head(const eslist_t * const es)
{
	eslist_check(es);
	return NULL == es->head ? NULL : ptr_add_offset(es->head, -es->offset);
}

/**
 * @return pointer to last item of list, NULL if empty.
 */
static inline void *
eslist_tail(const eslist_t * const es)
{
	eslist_check(es);
	return NULL == es->tail ? NULL : ptr_add_offset(es->tail, -es->offset);
}

/**
 * @return pointer to first link of list, NULL if empty.
 */
static inline slink_t *
eslist_first(const eslist_t * const es)
{
	eslist_check(es);
	return es->head;
}

/**
 * @return pointer to last link of list, NULL if empty.
 */
static inline slink_t *
eslist_last(const eslist_t * const es)
{
	eslist_check(es);
	return es->tail;
}

/**
 * @return last link in forward chain.
 */
static inline slink_t *
eslist_last_link(const slink_t *lk)
{
	if (NULL == lk)
		return NULL;

	while (lk->next != NULL)
		lk = lk->next;

	return deconstify_pointer(lk);
}

/**
 * @return next link, NULL if none.
 */
static inline slink_t *
eslist_next(const slink_t * const lk)
{
	return NULL == lk ? NULL : lk->next;
}

/**
 * @return nth next link, NULL if none.
 */
static inline slink_t *
eslist_nth_next(const slink_t * const lk, size_t n)
{
	const slink_t *l = lk;

	while (n-- > 0 && l != NULL)
		l = l->next;

	return deconstify_pointer(l);
}

/**
 * @return the data associated with the curernt link, NULL if none.
 */
static inline void *
eslist_data(const eslist_t *list, const slink_t * const lk)
{
	eslist_check(list);

	return NULL == lk ? NULL :
		deconstify_pointer(const_ptr_add_offset(lk, -list->offset));
}

/**
 * @note
 * As a special case, behaves as eslist_head() if `p' is NULL.
 *
 * This allows using the following code pattern to iterate over a one-way
 * list and removing items during the traversal:
 *
 *   for (
 *       i = eslist_head(list), b = NULL;	// `i' is item, `b' is previous
 *       i != NULL;
 *       b = i, i = eslist_next_data(list, i)
 *   ) {
 *       if (keep_item)
 *           continue;
 *       (void) eslist_remove_after(list, b);
 *       i = b;		// removed item, leave cursor at before (could be NULL)
 *   }
 *
 * @return the data associated with the next item, NULL if none.
 */
static inline void *
eslist_next_data(const eslist_t *list, const void *p)
{
	const slink_t *lk;

	eslist_check(list);

	if G_UNLIKELY(NULL == p)
		return eslist_head(list);

	lk = const_ptr_add_offset(p, list->offset);
	return NULL == lk->next ? NULL :
		deconstify_pointer(const_ptr_add_offset(lk->next, -list->offset));
}

/**
 * For assertions, check whether item is a member of the list.
 *
 * @attention
 * This is very inefficient, as it needs to traverse the whole list, possibly.
 * It only needs to be called when debugging.
 */
static inline bool
eslist_contains(const eslist_t *list, const void *p)
{
	const slink_t *l, *lk;

	eslist_check(list);
	g_assert(p != NULL);

	lk = const_ptr_add_offset(p, list->offset);
	l = list->head;

	while (l != NULL) {
		if G_UNLIKELY(l == lk)
			return TRUE;
		l = l->next;
	}

	return FALSE;
}

void eslist_init(eslist_t *list, size_t offset);
void eslist_discard(eslist_t *list);
void eslist_clear(eslist_t *list);
void eslist_mark_removed(const eslist_t *list, void *data);
void eslist_link_mark_removed(const eslist_t *list, slink_t *lk);
void eslist_wfree(eslist_t *list, size_t size);
size_t eslist_load(eslist_t *list, void *head, size_t offset);

void eslist_foreach(const eslist_t *list, data_fn_t cb, void *data);
size_t eslist_foreach_remove(eslist_t *list, data_rm_fn_t cbr, void *data);

void eslist_link_append(eslist_t *list, slink_t *lk);
void eslist_append(eslist_t *list, void *data);
void eslist_link_prepend(eslist_t *list, slink_t *lk);
void eslist_prepend(eslist_t *list, void *data);
void *eslist_shift(eslist_t *list);
void eslist_rotate_left(eslist_t *list);
void eslist_link_insert_after(eslist_t *list, slink_t *sibling_lk, slink_t *lk);
void eslist_insert_after(eslist_t *list, void *sibling, void *data);
void eslist_reverse(eslist_t *list);
void eslist_remove(eslist_t *list, void *data);
void *eslist_remove_after(eslist_t *list, void *sibling);
void *eslist_find(const eslist_t *list, const void *key, cmp_fn_t cmp);
void eslist_sort_with_data(eslist_t *list, cmp_data_fn_t cmp, void *data);
void eslist_sort(eslist_t *list, cmp_fn_t cmp);
void eslist_insert_sorted_with_data(eslist_t *list, void *item,
	cmp_data_fn_t cmp, void *data);
void eslist_insert_sorted(eslist_t *list, void *item, cmp_fn_t cmp);
void *eslist_nth(const eslist_t *list, long n);
void *eslist_nth_next_data(const eslist_t *list, const slink_t *lk, size_t n);
void *eslist_random(const eslist_t *list);
void eslist_shuffle(eslist_t *list);
void eslist_shuffle_with(random_fn_t rf, eslist_t *list);

void eslist_append_list(eslist_t *list, eslist_t *other);
void eslist_prepend_list(eslist_t *list, eslist_t *other);

#define ESLIST_FOREACH(slist, l) \
	for ((l) = eslist_first(slist); NULL != (l); (l) = eslist_next(l))

#define ESLIST_FOREACH_DATA(ls, d) \
	for ((d) = eslist_head(ls); NULL != (d); (d) = eslist_next_data((ls), (d)))

#endif /* _eslist_h_ */

/* vi: set ts=4 sw=4 cindent: */
