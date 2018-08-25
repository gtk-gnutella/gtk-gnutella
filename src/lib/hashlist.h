/*
 * Copyright (c) 2003, Christian Biere
 * Copyright (c) 2009-2013, Raphael Manfredi
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

#ifndef _hashlist_h_
#define _hashlist_h_

#include "common.h"

typedef struct hash_list_iter hash_list_iter_t;
typedef struct hash_list hash_list_t;

hash_list_t *hash_list_new(hash_fn_t, eq_fn_t);
void hash_list_thread_safe(hash_list_t *);
void hash_list_lock(hash_list_t *);
void hash_list_unlock(hash_list_t *);
void hash_list_free(hash_list_t **);
void hash_list_free_all(hash_list_t **hl_ptr, free_fn_t freecb);
void *hash_list_remove(hash_list_t *, const void *key);
void *hash_list_remove_head(hash_list_t *);
void *hash_list_remove_tail(hash_list_t *);
void *hash_list_shift(hash_list_t *);
void *hash_list_random(const hash_list_t *);
void hash_list_append(hash_list_t *, const void *key);
void hash_list_prepend(hash_list_t *, const void *key);
void hash_list_insert_sorted(hash_list_t *, const void *key, cmp_fn_t);
void hash_list_moveto_head(hash_list_t *, const void *key);
void hash_list_moveto_tail(hash_list_t *, const void *key);
void *hash_list_head(const hash_list_t *);
void *hash_list_tail(const hash_list_t *);
void *hash_list_next(hash_list_t *, const void *key);
void *hash_list_previous(hash_list_t *, const void *key);
void hash_list_clear(hash_list_t *hl);
unsigned hash_list_length(const hash_list_t *);
size_t hash_list_count(const hash_list_t *);
struct plist *hash_list_list(hash_list_t *) WARN_UNUSED_RESULT;
void hash_list_sort(hash_list_t *, cmp_fn_t);
void hash_list_sort_with_data(hash_list_t *, cmp_data_fn_t, void *);
void hash_list_shuffle(hash_list_t *hl);
void hash_list_shuffle_with(random_fn_t rf, hash_list_t *hl);
void hash_list_rotate_left(hash_list_t *hl);
void hash_list_rotate_right(hash_list_t *hl);

hash_list_iter_t *hash_list_iterator(hash_list_t *);
hash_list_iter_t *hash_list_iterator_tail(hash_list_t *);
hash_list_iter_t *hash_list_iterator_at(hash_list_t *, const void *key);
void hash_list_iter_release(hash_list_iter_t **);
bool hash_list_iter_has_next(const hash_list_iter_t *) G_PURE;
bool hash_list_iter_has_previous(const hash_list_iter_t *) G_PURE;
bool hash_list_iter_has_more(const hash_list_iter_t *iter) G_PURE;
void *hash_list_iter_next(hash_list_iter_t *);
void *hash_list_iter_previous(hash_list_iter_t *);
void *hash_list_iter_move(hash_list_iter_t *iter);
void *hash_list_iter_remove(hash_list_iter_t *iter);

bool hash_list_find(hash_list_t *, const void *key, const void **orig_key);
bool hash_list_contains(hash_list_t *, const void *key);
void *hash_list_lookup(hash_list_t *hl, const void *key);
void hash_list_foreach(const hash_list_t *, data_fn_t, void *);
size_t hash_list_foreach_remove(hash_list_t *, data_rm_fn_t, void *);

void *hash_list_remove_position(hash_list_t *hl, const void *key);
void hash_list_insert_position(hash_list_t *hl, const void *key, void *pos);
void hash_list_forget_position(void *position);

static inline free_fn_t
cast_to_hashlist_destroy(func_ptr_t fn)
{
	return (free_fn_t) fn;
}

#endif	/* _hashlist_h_ */

/* vi: set ts=4 sw=4 cindent: */
