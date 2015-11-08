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
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _xslist_h_
#define _xslist_h_

/**
 * Get the enclosing data item from an expanded link.
 */
#ifdef __GNUC__
#define xslist_item(lnk, type, field) G_GNUC_EXTENSION({		\
	const struct slink *__mptr = (lnk);						\
	(type *)((char *) __mptr - offsetof(type, field));})
#else
#define xslist_item(lnk, type, field)						\
	((type *)((char *) (node) - offsetof(type, field)))
#endif

enum xslist_magic { XSLIST_MAGIC = 0x20c76ebb };

typedef void xslink_t;	/* Expanded link start, at ``offset'' bytes in item */

/**
 * An expanded one-way list is represented by this structure.
 */
typedef struct xslist {
	enum xslist_magic magic;
	xslink_t *head, *tail;	/* These refer to the expanded link, not items */
	size_t offset;		/* Offset of expanded link in the item structure */
	size_t link_offset;	/* Offset of "next" in the expanded link */
	size_t count;		/* Amount of items held */
} xslist_t;

static inline void
xslist_check(const xslist_t * const xs)
{
	g_assert(xs != NULL);
	g_assert(XSLIST_MAGIC == xs->magic);
}

#define XSLIST_INIT(off, lkoff)	{ XSLIST_MAGIC, NULL, NULL, off, lkoff, 0 }

/**
 * @return next link, NULL if none.
 */
static inline xslink_t *
xslist_next(const xslist_t * const xs, const xslink_t * const lk)
{
	xslist_check(xs);

	if G_UNLIKELY(NULL == lk)
		return NULL;

	return *(void **) const_ptr_add_offset(lk, xs->link_offset);
}

/**
 * set next link to specified value
 *
 * @return the set value, as a convenience.
 */
static inline xslink_t *
xslist_set_next(const xslist_t * const xs, xslink_t * const lk, xslink_t *value)
{
	xslist_check(xs);
	g_assert(lk != NULL);

	return *(void **) const_ptr_add_offset(lk, xs->link_offset) = value;
}

static inline bool
xslist_invariant(const xslist_t * const list)
{
	g_assert(list->count != 0 || (NULL == list->head && NULL == list->tail));
	g_assert((list->head != list->tail) == (list->count > 1U));
	g_assert(NULL == list->tail || NULL == xslist_next(list, list->tail));
	return TRUE;		/* So that we can safety_assert() this routine */
}

/**
 * Public interface.
 */

/**
 * @return whether the expanded list descriptor is non-zero.
 */
static inline bool
xslist_is_initialized(const xslist_t * const xs)
{
	return 0 != xs->magic;		/* Initialized, not necessarily valid! */
}

/**
 * @return length of expanded list.
 */
static inline size_t
xslist_count(const xslist_t * const xs)
{
	xslist_check(xs);
	return xs->count;
}

/**
 * @return length of expanded list by traversing the list from the
 * specified link, following forward pointers.
 */
static inline size_t
xslist_length(const xslist_t * const xs, const xslink_t *lk)
{
	size_t n = 0;

	while (lk != NULL) {
		n++;
		lk = xslist_next(xs, lk);
	}

	return n;
}

/**
 * @return pointer to first item of list, NULL if empty.
 */
static inline void *
xslist_head(const xslist_t * const xs)
{
	xslist_check(xs);
	return NULL == xs->head ? NULL : ptr_add_offset(xs->head, -xs->offset);
}

/**
 * @return pointer to last item of list, NULL if empty.
 */
static inline void *
xslist_tail(const xslist_t * const xs)
{
	xslist_check(xs);
	return NULL == xs->tail ? NULL : ptr_add_offset(xs->tail, -xs->offset);
}

/**
 * @return pointer to first link of list, NULL if empty.
 */
static inline xslink_t *
xslist_first(const xslist_t * const xs)
{
	xslist_check(xs);
	return xs->head;
}

/**
 * @return pointer to last link of list, NULL if empty.
 */
static inline xslink_t *
xslist_last(const xslist_t * const xs)
{
	xslist_check(xs);
	return xs->tail;
}

/**
 * @return last link in forward chain.
 */
static inline xslink_t *
xslist_last_link(const xslist_t * const xs, const xslink_t *lk)
{
	xslink_t *next;

	xslist_check(xs);

	if (NULL == lk)
		return NULL;

	while (NULL != (next = xslist_next(xs, lk)))
		lk = next;

	return deconstify_pointer(lk);
}

/**
 * @return nth next link, NULL if none.
 */
static inline xslink_t *
xslist_nth_next(const xslist_t * const xs, const xslink_t * const lk, size_t n)
{
	const xslink_t *l = lk;

	while (n-- > 0 && l != NULL)
		l = xslist_next(xs, l);

	return deconstify_pointer(l);
}

/**
 * @return the data associated with the curernt link, NULL if none.
 */
static inline void *
xslist_data(const xslist_t *list, const xslink_t * const lk)
{
	xslist_check(list);

	return NULL == lk ? NULL :
		deconstify_pointer(const_ptr_add_offset(lk, -list->offset));
}

/**
 * @return the data associated with the next item, NULL if none.
 */
static inline void *
xslist_next_data(const xslist_t *list, const void *p)
{
	const xslink_t *lk;

	xslist_check(list);
	g_assert(p != NULL);

	lk = const_ptr_add_offset(p, list->offset);
	lk = xslist_next(list, lk);
	return NULL == lk ? NULL :
		deconstify_pointer(const_ptr_add_offset(lk, -list->offset));
}

/**
 * For assertions, check whether item is a member of the list.
 *
 * @attention
 * This is very inefficient, as it needs to traverse the whole list, possibly.
 * It only needs to be called when debugging.
 */
static inline bool
xslist_contains(const xslist_t *list, const void *p)
{
	const xslink_t *l, *lk;

	xslist_check(list);
	g_assert(p != NULL);

	lk = const_ptr_add_offset(p, list->offset);
	l = list->head;

	while (l != NULL) {
		if G_UNLIKELY(l == lk)
			return TRUE;
		l = xslist_next(list, l);
	}

	return FALSE;
}

void xslist_init(xslist_t *list, size_t offset, size_t link_offset);
void xslist_discard(xslist_t *list);
void xslist_clear(xslist_t *list);
size_t xslist_load(xslist_t *list,
	void *head, size_t offset, size_t link_offset);

void xslist_foreach(const xslist_t *list, data_fn_t cb, void *data);
size_t xslist_foreach_remove(xslist_t *list, data_rm_fn_t cbr, void *data);

void xslist_link_append(xslist_t *list, xslink_t *lk);
void xslist_append(xslist_t *list, void *data);
void xslist_link_prepend(xslist_t *list, xslink_t *lk);
void xslist_prepend(xslist_t *list, void *data);
void *xslist_shift(xslist_t *list);
void xslist_rotate_left(xslist_t *list);
void xslist_link_insert_after(xslist_t *list, xslink_t *sibling_lk, xslink_t *lk);
void xslist_insert_after(xslist_t *list, void *sibling, void *data);
void xslist_reverse(xslist_t *list);
void xslist_remove(xslist_t *list, void *data);
void *xslist_remove_after(xslist_t *list, void *sibling);
void *xslist_find(const xslist_t *list, const void *key, cmp_fn_t cmp);
void xslist_sort_with_data(xslist_t *list, cmp_data_fn_t cmp, void *data);
void xslist_sort(xslist_t *list, cmp_fn_t cmp);
void xslist_insert_sorted_with_data(xslist_t *list, void *item,
	cmp_data_fn_t cmp, void *data);
void xslist_insert_sorted(xslist_t *list, void *item, cmp_fn_t cmp);
void *xslist_nth(const xslist_t *list, long n);
void *xslist_nth_next_data(const xslist_t *list, const xslink_t *lk, size_t n);
void *xslist_random(const xslist_t *list);
void xslist_shuffle(xslist_t *list);
void xslist_shuffle_with(random_fn_t rf, xslist_t *list);

void xslist_append_list(xslist_t *list, xslist_t *other);
void xslist_prepend_list(xslist_t *list, xslist_t *other);

#define XSLIST_FOREACH(ls, l) \
	for ((l) = xslist_first(ls); NULL != (l); (l) = xslist_next((ls), (l)))

#define XSLIST_FOREACH_DATA(ls, d) \
	for ((d) = xslist_head(ls); NULL != (d); (d) = xslist_next_data((ls), (d)))

#endif /* _xslist_h_ */

/* vi: set ts=4 sw=4 cindent: */
