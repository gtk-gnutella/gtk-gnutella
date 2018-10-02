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
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _pslist_h_
#define _pslist_h_

/**
 * A one-way cell, pointing to a data item and to the next element.
 *
 * @attention
 * It is imperative that the ``next'' pointer be kept as the first item
 * of the structure, so that we can handle plain lists as embedded lists
 * to be able to share some code with eslist.
 */
typedef struct pslist {
	struct pslist *next;		/**< Next item (must be first element) */
	void *data;					/**< Cell data (item at this position) */
} pslist_t;

/**
 * @return next cell in list, NULL if none.
 */
static inline pslist_t *
pslist_next(const pslist_t *pl)
{
	if G_UNLIKELY(NULL == pl)
		return NULL;

	return deconstify_pointer(pl->next);
}

/**
 * @return data held in given list cell.
 */
static inline void *
pslist_data(const pslist_t *pl)
{
	if G_UNLIKELY(NULL == pl)
		return NULL;

	return deconstify_pointer(pl->data);
}

/*
 * Public interface.
 */

pslist_t *pslist_alloc(void) G_MALLOC;
void pslist_free_1(pslist_t *l);
void pslist_free_1_null(pslist_t **l_ptr);
pslist_t *pslist_free(pslist_t *pl);
void pslist_free_null(pslist_t **pl_ptr);
pslist_t *pslist_free_full(pslist_t *pl, free_fn_t fn);
void pslist_free_full_null(pslist_t **pl_ptr, free_fn_t fn);
pslist_t *pslist_last(const pslist_t *pl) WARN_UNUSED_RESULT;
pslist_t *pslist_last_count(const pslist_t *, size_t *) WARN_UNUSED_RESULT;
pslist_t *pslist_append(pslist_t *pl, void *data);
pslist_t *pslist_prepend(pslist_t *pl, void *data) WARN_UNUSED_RESULT;
pslist_t *pslist_insert_before(pslist_t *pl,
	pslist_t *sibling, void *data) WARN_UNUSED_RESULT;
pslist_t *pslist_insert_after(pslist_t *pl,
	pslist_t *sibling, void *data) WARN_UNUSED_RESULT;
pslist_t *pslist_concat(pslist_t *l1, pslist_t *l2) WARN_UNUSED_RESULT;
pslist_t *pslist_remove(pslist_t *pl, const void *data) WARN_UNUSED_RESULT;
pslist_t *pslist_remove_link(pslist_t *pl, pslist_t *cell);
pslist_t *pslist_delete_link(pslist_t *pl, pslist_t *cell);
pslist_t *pslist_copy(pslist_t *pl) WARN_UNUSED_RESULT;
pslist_t *pslist_copy_deep(pslist_t *pl,
	copy_data_fn_t fn, void *udata) WARN_UNUSED_RESULT;
pslist_t *pslist_reverse(pslist_t *pl) WARN_UNUSED_RESULT;
pslist_t *pslist_nth(pslist_t *pl, size_t n);
void *pslist_nth_data(pslist_t *pl, size_t n);
pslist_t *pslist_find(pslist_t *pl, const void *data);
pslist_t *pslist_find_custom(pslist_t *pl, const void *object, cmp_fn_t cmp);
long pslist_position(const pslist_t *pl, const pslist_t *cell);
long pslist_index(const pslist_t *pl, const void *data);
size_t pslist_length(const pslist_t *pl);
void pslist_foreach(const pslist_t *pl, data_fn_t cb, void *data);
pslist_t *pslist_foreach_remove(pslist_t *pl,
	data_rm_fn_t cbr, void *data) WARN_UNUSED_RESULT;
pslist_t *pslist_insert_sorted(pslist_t *pl,
	void *data, cmp_fn_t cmp) WARN_UNUSED_RESULT;
pslist_t *pslist_insert_sorted_with_dta(pslist_t *pl, void *data,
	cmp_data_fn_t cmp, void *udata) WARN_UNUSED_RESULT;
pslist_t *pslist_sort(pslist_t *pl, cmp_fn_t cmp) WARN_UNUSED_RESULT;
pslist_t *pslist_sort_with_data(pslist_t *pl,
	cmp_data_fn_t cmp, void *data) WARN_UNUSED_RESULT;
pslist_t *pslist_shuffle(pslist_t *pl) WARN_UNUSED_RESULT;
pslist_t *pslist_shuffle_with(random_fn_t rf, pslist_t *pl) WARN_UNUSED_RESULT;
pslist_t *pslist_random(const pslist_t *pl);
void *pslist_shift(pslist_t **pl_ptr) NON_NULL_PARAM((1));
bool pslist_shift_data(pslist_t **pl_ptr, void **d_ptr) NON_NULL_PARAM((1));

struct pcell_allocator;

pslist_t *pslist_append_ext(pslist_t *pl,
	void *data, const struct pcell_allocator *ca);
pslist_t *pslist_prepend_ext(pslist_t *pl,
	void *data, const struct pcell_allocator *ca);
pslist_t *pslist_remove_ext(pslist_t *pl,
	const void *data, const struct pcell_allocator *ca);
pslist_t *pslist_delete_link_ext(pslist_t *pl,
	pslist_t *cell, const struct pcell_allocator *ca);
pslist_t *pslist_foreach_remove_ext(pslist_t *pl,
	data_rm_fn_t cbr, void *data, const struct pcell_allocator *ca);
void *pslist_shift_ext(pslist_t **pl_ptr, const struct pcell_allocator *ca);
bool pslist_shift_data_ext(pslist_t **pl_ptr, void **d_ptr,
		const struct pcell_allocator *ca);
pslist_t *pslist_free_ext(pslist_t *pl, const struct pcell_allocator *ca);
void pslist_free_null_ext(pslist_t **pl_ptr, const struct pcell_allocator *ca);

static inline pslist_t * WARN_UNUSED_RESULT
pslist_prepend_const(pslist_t *pl, const void *data)
{
	return pslist_prepend(pl, deconstify_pointer(data));
}

static inline pslist_t * WARN_UNUSED_RESULT
pslist_append_const(pslist_t *pl, const void *data)
{
	return pslist_append(pl, deconstify_pointer(data));
}

static inline void *
pslist_random_data(const pslist_t *pl)
{
	pslist_t *r = pslist_random(pl);
	return NULL == r ? NULL : r->data;
}

#define PSLIST_FOREACH(slist, l) \
	for (l = (slist); NULL != (l); l = (l)->next)

#define PSLIST_FOREACH_CALL(slist, func)	\
G_STMT_START {								\
	pslist_t *sl_ = (slist);				\
	while (NULL != sl_) {					\
		func(sl_->data);					\
		sl_ = sl_->next;					\
	}										\
} G_STMT_END

#define PSLIST_FOREACH_CALL_DATA(slist, func, user_data)	\
G_STMT_START {												\
	pslist_t *sl_ = (slist);								\
	void *user_data_ = (user_data);							\
	while (NULL != sl_) {									\
		func(sl_->data, user_data_);						\
		sl_ = sl_->next;									\
	}														\
} G_STMT_END

#endif	/* _pslist_h_ */

/* vi: set ts=4 sw=4 cindent: */
