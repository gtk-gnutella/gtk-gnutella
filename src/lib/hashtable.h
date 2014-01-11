/*
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006, Christian Biere
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
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006
 */

#ifndef _hash_table_h_
#define _hash_table_h_

#include "common.h"

/**
 * Callback for special allocation of the hash table object.
 *
 * @param allocator		the object handling allocation (opaque)
 * @param len			length of the block to allocate
 */
typedef void *(*hash_table_alloc_t)(void *allocator, size_t len);

typedef struct hash_table hash_table_t;

hash_table_t *hash_table_new(void);
hash_table_t *hash_table_new_full(hash_fn_t hash, eq_fn_t eq);
void hash_table_clear(hash_table_t *ht);
void hash_table_destroy(hash_table_t *ht);
void hash_table_destroy_null(hash_table_t **ht_ptr);

void hash_table_readonly(hash_table_t *ht);
void hash_table_writable(hash_table_t *ht);

hash_table_t *hash_table_new_special(const hash_table_alloc_t alloc, void *obj);
hash_table_t *hash_table_new_special_full(
	const hash_table_alloc_t alloc, void *obj,
	hash_fn_t hash, eq_fn_t eq);

hash_table_t *hash_table_new_not_leaking(void);
hash_table_t *hash_table_new_full_not_leaking(hash_fn_t hash, eq_fn_t eq);

hash_table_t *hash_table_new_fixed(void *arena, size_t len);
hash_table_t *hash_table_new_full_fixed(hash_fn_t hash, eq_fn_t eq,
	void *arena, size_t len);

#if defined(MALLOC_SOURCE) || defined(VMM_SOURCE) || defined(THREAD_SOURCE)
/* These routines are reserved for the tracking malloc code and for threads */
hash_table_t *hash_table_new_real(void);
hash_table_t *hash_table_once_new_real(void);
hash_table_t *hash_table_new_full_real(hash_fn_t hash, eq_fn_t eq);
hash_table_t *hash_table_once_new_full_real(hash_fn_t hash, eq_fn_t eq);
void hash_table_destroy_real(hash_table_t *ht);
#endif /* MALLOC_SOURCE || VMM_SOURCE || THREAD_SOURCE */

size_t hash_table_size(const hash_table_t *ht);
size_t hash_table_capacity(const hash_table_t *ht);
size_t hash_table_buckets(const hash_table_t *ht);
size_t hash_table_memory(const hash_table_t *ht);
size_t hash_table_arena_memory(const hash_table_t *ht);
bool hash_table_insert(hash_table_t *ht,
	const void *key, const void *value);
void hash_table_replace(hash_table_t *ht, const void *key, const void *value);
void *hash_table_lookup(const hash_table_t *ht, const void *key);
bool hash_table_lookup_extended(const hash_table_t *ht,
	const void *key, const void **kp, void **vp);
bool hash_table_contains(const hash_table_t *ht, const void *key);
bool hash_table_remove(hash_table_t *ht, const void *key);
bool hash_table_remove_no_resize(hash_table_t *ht, const void *key);
void hash_table_foreach(const hash_table_t *ht, ckeyval_fn_t func, void *data);
size_t hash_table_foreach_remove(hash_table_t *ht,
	ckeyval_rm_fn_t func, void *data);

const void **hash_table_keys(const hash_table_t *ht, size_t *count);
void **hash_table_values(const hash_table_t *ht, size_t *count);

void hash_table_thread_safe(hash_table_t *ht);
void hash_table_lock(hash_table_t *ht);
void hash_table_unlock(hash_table_t *ht);

double hash_table_clustering(const hash_table_t *ht) G_GNUC_PURE;

#endif /* _hash_table_h_ */

/* vi: set ts=4 sw=4 cindent: */
