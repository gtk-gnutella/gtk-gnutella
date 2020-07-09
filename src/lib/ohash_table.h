/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * Ordered hash table preserving the order of its keys.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _ohash_table_h_
#define _ohash_table_h_

#include "common.h"

#include "glib-missing.h"

struct ohash_table;
typedef struct ohash_table ohash_table_t;

/*
 * Public interface.
 */

ohash_table_t *ohash_table_new(hash_fn_t hash_func, eq_fn_t key_eq_func);
void ohash_table_destroy(ohash_table_t *oh);
void ohash_table_destroy_null(ohash_table_t **oh_ptr);
void ohash_table_insert(ohash_table_t *oh, const void *key, const void *value);
bool ohash_table_replace(ohash_table_t *oh, const void *k, const void *v);
bool ohash_table_remove(ohash_table_t *oh, const void *key);
bool ohash_table_contains(const ohash_table_t *oh, const void *key);
void *ohash_table_lookup(const ohash_table_t *oh, const void *key);
bool ohash_table_lookup_extended(const ohash_table_t *oh, const void *key,
	void *okey, void *oval);
size_t ohash_table_count(const ohash_table_t *oh);
void ohash_table_foreach(const ohash_table_t *oh, keyval_fn_t func, void *data);
size_t ohash_table_foreach_remove(const ohash_table_t *oh,
	keyval_rm_fn_t f, void *u);

#endif	/* _ohash_table_h_ */

/* vi: set ts=4 sw=4 cindent: */
