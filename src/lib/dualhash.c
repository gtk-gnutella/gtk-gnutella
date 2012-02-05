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
 * The dual hash represents a bijective relationship between keys and values.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "dualhash.h"
#include "hashing.h"
#include "htable.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum dualhash_magic { DUALHASH_MAGIC = 0x46d7b44d };

/**
 * A dual hash table.
 */
struct dualhash {
	enum dualhash_magic magic;
	htable_t *kht;			/**< Hash table from the keys' viewpoint */
	htable_t *vht;			/**< Hash table from the values' viewpoint */
	hash_eq_t key_eq_func;
	hash_eq_t val_eq_func;
};

static inline void
dualhash_check(const struct dualhash * const dh)
{
	g_assert(dh != NULL);
	g_assert(DUALHASH_MAGIC == dh->magic);
	g_assert(dh->kht != NULL);
	g_assert(dh->vht != NULL);
}

/**
 * Create a new dual hash table.
 *
 * @param key_hash_func		the hash function for keys
 * @param keys_eq_func		the key comparison function
 * @param val_hash_func		the hash function for values
 * @param val_eq_func		the value comparison function
 *
 * @return the new dual hash table.
 */
dualhash_t *
dualhash_new(hash_func_t key_hash_func, hash_eq_t key_eq_func,
	hash_func_t val_hash_func, hash_eq_t val_eq_func)
{
	dualhash_t *dh;

	if (NULL == key_hash_func)
		key_hash_func = pointer_hash;

	if (NULL == val_hash_func)
		val_hash_func = pointer_hash;

	WALLOC(dh);
	dh->magic = DUALHASH_MAGIC;
	dh->kht = htable_create_any(key_hash_func, NULL, key_eq_func);
	dh->vht = htable_create_any(val_hash_func, NULL, val_eq_func);
	dh->key_eq_func = key_eq_func;
	dh->val_eq_func = val_eq_func;

	return dh;
}

/**
 * Free a dual hash table.
 */
void
dualhash_destroy(dualhash_t *dh)
{
	dualhash_check(dh);

	htable_free_null(&dh->kht);
	htable_free_null(&dh->vht);
	dh->magic = 0;
	WFREE(dh);
}

/**
 * Free dual hash table and nullify its pointer.
 */
void
dualhash_destroy_null(dualhash_t **dh_ptr)
{
	dualhash_t *dh = *dh_ptr;

	if (dh != NULL) {
		dualhash_destroy(dh);
		*dh_ptr = NULL;
	}
}

/**
 * Insert a key/value pair in the table.
 */
void
dualhash_insert_key(dualhash_t *dh, const void *key, const void *value)
{
	void *held_key;
	void *held_value;

	dualhash_check(dh);
	g_assert(htable_count(dh->kht) == htable_count(dh->vht));

	if (htable_lookup_extended(dh->kht, key, NULL, &held_value)) {
		if ((*dh->val_eq_func)(held_value, value)) {
			return;		/* Key/value tuple already present in the table */
		} else {
			htable_remove(dh->vht, held_value);
		}
	}
	if (htable_lookup_extended(dh->vht, value, NULL, &held_key)) {
		/* Keys cannot be equal, or we'd have the key/value tuple already */
		g_assert(!(*dh->key_eq_func)(held_key, key));
		htable_remove(dh->kht, held_key);
	}

	htable_insert_const(dh->kht, key, value);
	htable_insert_const(dh->vht, value, key);

	g_assert(htable_count(dh->kht) == htable_count(dh->vht));
}

/**
 * Insert a value/key pair in the table.
 */
void
dualhash_insert_value(dualhash_t *dh, const void *value, const void *key)
{
	dualhash_check(dh);

	dualhash_insert_key(dh, key, value);
}

/**
 * Remove a key from the table.
 *
 * @return TRUE if the key was found and removed.
 */
bool
dualhash_remove_key(dualhash_t *dh, const void *key)
{
	void *held_value;
	bool existed = FALSE;

	dualhash_check(dh);
	g_assert(htable_count(dh->kht) == htable_count(dh->vht));

	if (htable_lookup_extended(dh->kht, key, NULL, &held_value)) {
		htable_remove(dh->kht, key);
		htable_remove(dh->vht, held_value);
		existed = TRUE;
	}

	g_assert(htable_count(dh->kht) == htable_count(dh->vht));

	return existed;
}

/**
 * Remove a value from the table.
 *
 * @return TRUE if the value was found and removed.
 */
bool
dualhash_remove_value(dualhash_t *dh, const void *value)
{
	void *held_key;
	bool existed = FALSE;

	dualhash_check(dh);
	g_assert(htable_count(dh->kht) == htable_count(dh->vht));

	if (htable_lookup_extended(dh->vht, value, NULL, &held_key)) {
		htable_remove(dh->vht, value);
		htable_remove(dh->kht, held_key);
		existed = TRUE;
	}

	g_assert(htable_count(dh->kht) == htable_count(dh->vht));

	return existed;
}

/**
 * Check whether a key is contained in the table.
 */
bool
dualhash_contains_key(const dualhash_t *dh, const void *key)
{
	dualhash_check(dh);

	return htable_contains(dh->kht, key);
}

/**
 * Check whether a value is contained in the table.
 */
bool
dualhash_contains_value(const dualhash_t *dh, const void *value)
{
	dualhash_check(dh);

	return htable_contains(dh->vht, value);
}

/**
 * Lookup a key in the table.
 */
void *
dualhash_lookup_key(const dualhash_t *dh, const void *key)
{
	dualhash_check(dh);

	return htable_lookup(dh->kht, key);
}

/**
 * Lookup a value in the table.
 */
void *
dualhash_lookup_value(const dualhash_t *dh, const void *value)
{
	dualhash_check(dh);

	return htable_lookup(dh->vht, value);
}

/**
 * Extended lookup of a key in the table, returning both key/value pointers.
 */
bool
dualhash_lookup_key_extended(const dualhash_t *dh, const void *key,
	void **okey, void **oval)
{
	dualhash_check(dh);

	return htable_lookup_extended(dh->kht, key, (const void **) okey, oval);
}

/**
 * Extended lookup of a value in the table, returning both key/value pointers.
 */
bool
dualhash_lookup_value_extended(const dualhash_t *dh, const void *value,
	void **okey, void **oval)
{
	dualhash_check(dh);

	return htable_lookup_extended(dh->vht, value, (const void **) oval, okey);
}

/**
 * @return amount of items held in table.
 */
size_t
dualhash_count(const dualhash_t *dh)
{
	size_t count;

	dualhash_check(dh);

	count = htable_count(dh->kht);

	g_assert(htable_count(dh->vht) == count);

	return count;
}

/* vi: set ts=4 sw=4 cindent: */
