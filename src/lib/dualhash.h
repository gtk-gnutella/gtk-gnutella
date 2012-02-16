/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Dual hash table, mapping keys and values together and being able to
 * see the table from the keys or from the values (as keys) perspective.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _dualhash_h_
#define _dualhash_h_

#include "common.h"

#include "hash.h"		/* For hash_func_t and hash_eq_t */

struct dualhash;
typedef struct dualhash dualhash_t;

/*
 * Public interface.
 */

dualhash_t *dualhash_new(hash_func_t key_hash_func, hash_eq_t key_eq_func,
	hash_func_t val_hash_func, hash_eq_t val_eq_func);
void dualhash_destroy(dualhash_t *dh);
void dualhash_destroy_null(dualhash_t **dh_ptr);
void dualhash_insert_key(dualhash_t *dh, const void *key, const void *value);
void dualhash_insert_value(dualhash_t *dh, const void *value, const void *key);
bool dualhash_remove_key(dualhash_t *dh, const void *key);
bool dualhash_remove_value(dualhash_t *dh, const void *value);
bool dualhash_contains_key(const dualhash_t *dh, const void *key);
bool dualhash_contains_value(const dualhash_t *dh, const void *val);
void *dualhash_lookup_key(const dualhash_t *dh, const void *key);
void *dualhash_lookup_value(const dualhash_t *dh, const void *value);
bool dualhash_lookup_key_extended(const dualhash_t *dh, const void *key,
	void **okey, void **oval);
bool dualhash_lookup_value_extended(const dualhash_t *dh, const void *value,
	void **okey, void **oval);
size_t dualhash_count(const dualhash_t *dh);

#endif	/* _dualhash_h_ */

/* vi: set ts=4 sw=4 cindent: */
