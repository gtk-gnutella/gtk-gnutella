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
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _plist_h_
#define _plist_h_

/**
 * A tw-way cell, pointing to a data item and to the next element.
 *
 * @attention
 * It is imperative that the ``next'' pointer be kept as the first item
 * of the structure, so that we can handle plain lists as embedded lists
 * to be able to share some code with eslist.
 */
typedef struct plist {
	struct plist *next;			/**< Next item (must be first element) */
	struct plist *prev;			/**< Previous item */
	void *data;					/**< Cell data (item at this position) */
} plist_t;

/**
 * @return next cell in list, NULL if none.
 */
static inline plist_t *
plist_next(const plist_t *pl)
{
	if G_UNLIKELY(NULL == pl)
		return NULL;

	return deconstify_pointer(pl->next);
}

/**
 * @return previous cell in list, NULL if none.
 */
static inline plist_t *
plist_prev(const plist_t *pl)
{
	if G_UNLIKELY(NULL == pl)
		return NULL;

	return deconstify_pointer(pl->prev);
}

/**
 * @return data held in given list cell.
 */
static inline void *
plist_data(const plist_t *pl)
{
	if G_UNLIKELY(NULL == pl)
		return NULL;

	return deconstify_pointer(pl->data);
}

/*
 * Public interface.
 */

plist_t *plist_alloc(void) G_MALLOC;
void plist_free_1(plist_t *l);
void plist_free_1_null(plist_t **l_ptr);
plist_t *plist_free(plist_t *pl);
void plist_free_null(plist_t **pl_ptr);
plist_t *plist_free_full(plist_t *pl, free_fn_t fn);
void plist_free_full_null(plist_t **pl_ptr, free_fn_t fn);
plist_t *plist_last(const plist_t *pl) WARN_UNUSED_RESULT;
plist_t *plist_first(const plist_t *pl) WARN_UNUSED_RESULT;
plist_t *plist_append(plist_t *pl, void *data);
plist_t *plist_prepend(plist_t *pl, void *data) WARN_UNUSED_RESULT;
plist_t *plist_insert_before(plist_t *pl,
	plist_t *sibling, void *data) WARN_UNUSED_RESULT;
plist_t *plist_insert_after(plist_t *pl,
	plist_t *sibling, void *data) WARN_UNUSED_RESULT;
plist_t *plist_concat(plist_t *l1, plist_t *l2) WARN_UNUSED_RESULT;
plist_t *plist_remove(plist_t *pl, const void *data) WARN_UNUSED_RESULT;
plist_t *plist_remove_all(plist_t *pl, const void *data) WARN_UNUSED_RESULT;
plist_t *plist_remove_link(plist_t *pl, plist_t *cell);
plist_t *plist_delete_link(plist_t *pl, plist_t *cell);
plist_t *plist_copy(plist_t *pl) WARN_UNUSED_RESULT;
plist_t *plist_copy_deep(plist_t *pl,
	copy_data_fn_t fn, void *udata) WARN_UNUSED_RESULT;
plist_t *plist_reverse(plist_t *pl) WARN_UNUSED_RESULT;
plist_t *plist_nth(plist_t *pl, size_t n);
void *plist_nth_data(plist_t *pl, size_t n);
plist_t *plist_find(plist_t *pl, const void *data);
plist_t *plist_find_custom(plist_t *pl, const void *object, cmp_fn_t cmp);
long plist_position(const plist_t *pl, const plist_t *cell);
long plist_index(const plist_t *pl, const void *data);
size_t plist_length(const plist_t *pl);
void plist_foreach(const plist_t *pl, data_fn_t cb, void *data);
plist_t *plist_foreach_remove(plist_t *pl,
	data_rm_fn_t cbr, void *data) WARN_UNUSED_RESULT;
plist_t *plist_insert_sorted(plist_t *pl,
	void *data, cmp_fn_t cmp) WARN_UNUSED_RESULT;
plist_t *plist_insert_sorted_with_dta(plist_t *pl, void *data,
	cmp_data_fn_t cmp, void *udata) WARN_UNUSED_RESULT;
plist_t *plist_sort(plist_t *pl, cmp_fn_t cmp) WARN_UNUSED_RESULT;
plist_t *plist_sort_with_data(plist_t *pl,
	cmp_data_fn_t cmp, void *data) WARN_UNUSED_RESULT;
plist_t *plist_shuffle(plist_t *pl) WARN_UNUSED_RESULT;
plist_t *plist_shuffle_with(random_fn_t rf, plist_t *pl) WARN_UNUSED_RESULT;
plist_t *plist_random(const plist_t *pl);
void *plist_shift(plist_t **pl) NON_NULL_PARAM((1));

static inline plist_t * WARN_UNUSED_RESULT
plist_prepend_const(plist_t *pl, const void *data)
{
	return plist_prepend(pl, deconstify_pointer(data));
}

static inline plist_t * WARN_UNUSED_RESULT
plist_append_const(plist_t *pl, const void *data)
{
	return plist_append(pl, deconstify_pointer(data));
}

static inline void *
plist_random_data(const plist_t *pl)
{
	plist_t *r = plist_random(pl);
	return NULL == r ? NULL : r->data;
}

#define PLIST_FOREACH(list, l) \
	for (l = (list); NULL != (l); l = (l)->next)

#define PLIST_FOREACH_CALL(list, func)	\
G_STMT_START {							\
	plist_t *l_ = (list);				\
	while (NULL != l_) {				\
		func(l_->data);					\
		l_ = l_->next;					\
	}									\
} G_STMT_END

#define PLIST_FOREACH_CALL_DATA(list, func, user_data)	\
G_STMT_START {											\
	plist_t *l_ = (list);								\
	void *user_data_ = (user_data);						\
	while (NULL != l_) {								\
		func(l_->data, user_data_);						\
		l_ = l_->next;									\
	}													\
} G_STMT_END

#endif	/* _plist_h_ */

/* vi: set ts=4 sw=4 cindent: */
