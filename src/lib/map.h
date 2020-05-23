/*
 * Copyright (c) 2008, Raphael Manfredi
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
 * Interface definition for a map (association between a key and a value).
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _map_h_
#define _map_h_

#include "common.h"

#include "htable.h"
#include "patricia.h"
#include "ohash_table.h"

struct map;
typedef struct map map_t;

/**
 * Creation interface.
 */

map_t *map_create_hash(hash_fn_t hash_func, eq_fn_t key_eq_func);
map_t *map_create_ordered_hash(hash_fn_t hash_func, eq_fn_t key_eq_func);
map_t *map_create_patricia(size_t keybits);
map_t *map_create_from_hash(htable_t *ht);
map_t *map_create_from_patricia(patricia_t *pt);
map_t *map_create_from_ordered_hash(ohash_table_t *ot);
void *map_switch_to_hash(map_t *m, htable_t *ht);
void *map_switch_to_patricia(map_t *m, patricia_t *pt);
void *map_switch_to_ordered_hash(map_t *m, ohash_table_t *ot);

/**
 * Public map interface.
 */

void map_insert(const map_t *m, const void *key, const void *value);
void map_replace(const map_t *m, const void *key, const void *value);
bool map_remove(const map_t *m, const void *key);
void *map_lookup(const map_t *m, const void *key);
bool map_lookup_extended(const map_t *m, const void *key,
	void **okey, void **oval);
bool map_contains(const map_t *m, const void *key);
size_t map_count(const map_t *m);
void *map_implementation(const map_t *m);
void *map_release(map_t *m);
void map_thread_safe(const map_t *m);
void map_destroy(map_t *m);
void map_destroy_null(map_t **m_ptr);

void map_foreach(const map_t *m, keyval_fn_t cb, void *u);
size_t map_foreach_remove(const map_t *m, keyval_rm_fn_t cb, void *u);

void map_test(void);

#endif	/* _map_h_ */

/* vi: set ts=4 sw=4 cindent: */
