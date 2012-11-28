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
 * Embedded two-way list (within another data structure).
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _elist_h_
#define _elist_h_

/**
 * Get the enclosing data item from an embedded link.
 */
#ifdef __GNUC__
#define elist_item(lnk, type, field) G_GNUC_EXTENSION({		\
	const struct link *__mptr = (lnk);						\
	(type *)((char *) __mptr - offsetof(type, field));})
#else
#define elist_item(lnk, type, field)						\
	((type *)((char *) (node) - offsetof(type, field)))
#endif

/**
 * A list link.
 */
typedef struct link {
	struct link *next, *prev;
} link_t;

enum elist_magic { ELIST_MAGIC = 0x12a51414 };

/**
 * An embedded list is represented by this structure.
 */
typedef struct elist {
	enum elist_magic magic;
	link_t *head, *tail;
	size_t offset;		/* Offset of embedded link in the item structure */
	size_t count;		/* Amount of items held */
} elist_t;

static inline void
elist_check(const elist_t * const el)
{
	g_assert(el != NULL);
	g_assert(ELIST_MAGIC == el->magic);
}

static inline bool
elist_invariant(const elist_t * const list)
{
	g_assert(list->count != 0 || (NULL == list->head && NULL == list->tail));
	g_assert((list->head != list->tail) == (list->count > 1U));
	g_assert(NULL == list->head || NULL == list->head->prev);
	g_assert(NULL == list->tail || NULL == list->tail->next);
	return TRUE;		/* So that we can safety_assert() this routine */
}

/**
 * Public interface.
 */

/**
 * @return length of embedded list.
 */
static inline size_t
elist_count(const elist_t * const el)
{
	elist_check(el);
	return el->count;
}

/**
 * @return length of embedded list by traversing the list from the
 * specified link, following forward pointers.
 */
static inline size_t
elist_length(const link_t *lk)
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
elist_head(const elist_t * const el)
{
	elist_check(el);
	return NULL == el->head ? NULL : ptr_add_offset(el->head, -el->offset);
}

/**
 * @return pointer to last item of list, NULL if empty.
 */
static inline void *
elist_tail(const elist_t * const el)
{
	elist_check(el);
	return NULL == el->tail ? NULL : ptr_add_offset(el->tail, -el->offset);
}

/**
 * @return pointer to first link of list, NULL if empty.
 */
static inline link_t *
elist_first(const elist_t * const el)
{
	elist_check(el);
	return el->head;
}

/**
 * @return pointer to last link of list, NULL if empty.
 */
static inline link_t *
elist_last(const elist_t * const el)
{
	elist_check(el);
	return el->tail;
}

/**
 * @return first link in backward chain.
 */
static inline link_t *
elist_first_link(const link_t *lk)
{
	if (NULL == lk)
		return NULL;

	while (lk->prev != NULL)
		lk = lk->prev;

	return deconstify_pointer(lk);
}

/**
 * @return last link in forward chain.
 */
static inline link_t *
elist_last_link(const link_t *lk)
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
static inline link_t *
elist_next(const link_t * const lk)
{
	return NULL == lk ? NULL : lk->next;
}

/**
 * @return previous link, NULL if none.
 */
static inline link_t *
elist_prev(const link_t * const lk)
{
	return NULL == lk ? NULL : lk->prev;
}

/**
 * @return nth next link, NULL if none.
 */
static inline link_t *
elist_nth_next(const link_t * const lk, size_t n)
{
	const link_t *l = lk;

	while (n-- > 0 && l != NULL)
		l = l->next;

	return deconstify_pointer(l);
}

/**
 * @return nth previous link, NULL if none.
 */
static inline link_t *
elist_nth_prev(const link_t * const lk, size_t n)
{
	const link_t *l = lk;

	while (n-- > 0 && l != NULL)
		l = l->prev;

	return deconstify_pointer(l);
}

/**
 * @return the data associated with the curernt link, NULL if none.
 */
static inline void *
elist_data(const elist_t *list, const link_t * const lk)
{
	elist_check(list);

	return NULL == lk ? NULL :
		deconstify_pointer(const_ptr_add_offset(lk, -list->offset));
}

void elist_init(elist_t *list, size_t offset);
void elist_discard(elist_t *list);
void elist_clear(elist_t *list);

void elist_foreach(const elist_t *list, data_fn_t cb, void *data);
size_t elist_foreach_remove(elist_t *list, data_rm_fn_t cbr, void *data);

void elist_link_append(elist_t *list, link_t *lk);
void elist_append(elist_t *list, void *data);
void elist_link_prepend(elist_t *list, link_t *lk);
void elist_prepend(elist_t *list, void *data);
void elist_link_remove(elist_t *list, link_t *lk);
void elist_remove(elist_t *list, void *data);
void elist_link_insert_before(elist_t *list, link_t *sibling_lk, link_t *lk);
void elist_insert_before(elist_t *list, void *sibling, void *data);
void elist_link_insert_after(elist_t *list, link_t *sibling_lk, link_t *lk);
void elist_insert_after(elist_t *list, void *sibling, void *data);
void elist_link_replace(elist_t *list, link_t *old, link_t *new);
void elist_replace(elist_t *list, void *old, void *new);
void elist_reverse(elist_t *list);
void *elist_find(const elist_t *list, const void *key, cmp_fn_t cmp);
void elist_sort_with_data(elist_t *list, cmp_data_fn_t cmp, void *data);
void elist_sort(elist_t *list, cmp_fn_t cmp);
void elist_insert_sorted_with_data(elist_t *list, void *item,
	cmp_data_fn_t cmp, void *data);
void elist_insert_sorted(elist_t *list, void *item, cmp_fn_t cmp);
void *elist_nth_next_data(const elist_t *list, const link_t *lk, size_t n);
void *elist_nth_prev_data(const elist_t *list, const link_t *lk, size_t n);
void elist_shuffle(elist_t *list);
void elist_rotate_left(elist_t *list);
void elist_rotate_right(elist_t *list);
void *elist_shift(elist_t *list);

#define ELIST_FOREACH(list, l) \
	for ((l) = elist_first(list); NULL != (l); (l) = elist_next(l))

#endif /* _elist_h_ */

/* vi: set ts=4 sw=4 cindent: */
