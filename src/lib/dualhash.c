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
#include "mutex.h"
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
	eq_fn_t key_eq_func;
	eq_fn_t val_eq_func;
	mutex_t *lock;			/**< Thread-safe lock (optional) */
};

static inline void
dualhash_check(const struct dualhash * const dh)
{
	g_assert(dh != NULL);
	g_assert(DUALHASH_MAGIC == dh->magic);
	g_assert(dh->kht != NULL);
	g_assert(dh->vht != NULL);
}

#define dualhash_synchronize(d) G_STMT_START {		\
	if G_UNLIKELY((d)->lock != NULL)				\
		mutex_lock((d)->lock);						\
} G_STMT_END

#define dualhash_unsynchronize(d) G_STMT_START {	\
	if G_UNLIKELY((d)->lock != NULL)				\
		mutex_unlock((d)->lock);					\
} G_STMT_END

/**
 * Create a new dual hash table.
 *
 * If a NULL hash function is provided, pointer_hash() will be used.
 * If a NULL equality is provided, '==' will be used to compare items.
 *
 * @param khash		the hash function for keys
 * @param keq		the key comparison function
 * @param vhash		the hash function for values
 * @param veq		the value comparison function
 *
 * @return the new dual hash table.
 */
dualhash_t *
dualhash_new(hash_fn_t khash, eq_fn_t keq, hash_fn_t vhash, eq_fn_t veq)
{
	dualhash_t *dh;

	WALLOC0(dh);
	dh->magic = DUALHASH_MAGIC;

	if (NULL == khash || pointer_hash == khash)
		dh->kht = htable_create_any(pointer_hash, pointer_hash2, keq);
	else
		dh->kht = htable_create_any(khash, NULL, keq);

	if (NULL == vhash || pointer_hash == vhash)
		dh->vht = htable_create_any(pointer_hash, pointer_hash2, veq);
	else
		dh->vht = htable_create_any(vhash, NULL, veq);

	dh->key_eq_func = keq;
	dh->val_eq_func = veq;

	return dh;
}

/**
 * Free a dual hash table.
 */
void
dualhash_destroy(dualhash_t *dh)
{
	dualhash_check(dh);

	dualhash_synchronize(dh);

	htable_free_null(&dh->kht);
	htable_free_null(&dh->vht);

	if (dh->lock != NULL) {
		mutex_destroy(dh->lock);		/* Releases lock */
		WFREE(dh->lock);
	}

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
 * Mark dualhash thread-safe.
 */
void
dualhash_thread_safe(dualhash_t *dh)
{
	dualhash_check(dh);
	g_assert(NULL == dh->lock);

	WALLOC0(dh->lock);
	mutex_init(dh->lock);
}

/**
 * Lock dualhash.
 *
 * The hash must have been marked thread-safe already.
 */
void
dualhash_lock(dualhash_t *dh)
{
	dualhash_check(dh);
	g_assert_log(dh->lock != NULL,
		"%s(): dualhash %p not marked thread-safe", G_STRFUNC, dh);

	mutex_lock(dh->lock);
}

/**
 * Unlock dualhash.
 *
 * The hash must have been marked thread-safe already and locked by the
 * calling thread.
 */
void
dualhash_unlock(dualhash_t *dh)
{
	dualhash_check(dh);
	g_assert_log(dh->lock != NULL,
		"%s(): dualhash %p not marked thread-safe", G_STRFUNC, dh);

	mutex_unlock(dh->lock);
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

	dualhash_synchronize(dh);

	g_assert(htable_count(dh->kht) == htable_count(dh->vht));

	if (htable_lookup_extended(dh->kht, key, NULL, &held_value)) {
		if ((*dh->val_eq_func)(held_value, value)) {
			goto done;		/* Key/value tuple already present in the table */
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

done:
	dualhash_unsynchronize(dh);
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

	dualhash_synchronize(dh);

	g_assert(htable_count(dh->kht) == htable_count(dh->vht));

	if (htable_lookup_extended(dh->kht, key, NULL, &held_value)) {
		htable_remove(dh->kht, key);
		htable_remove(dh->vht, held_value);
		existed = TRUE;
	}

	g_assert(htable_count(dh->kht) == htable_count(dh->vht));

	dualhash_unsynchronize(dh);

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

	dualhash_synchronize(dh);

	g_assert(htable_count(dh->kht) == htable_count(dh->vht));

	if (htable_lookup_extended(dh->vht, value, NULL, &held_key)) {
		htable_remove(dh->vht, value);
		htable_remove(dh->kht, held_key);
		existed = TRUE;
	}

	g_assert(htable_count(dh->kht) == htable_count(dh->vht));

	dualhash_unsynchronize(dh);

	return existed;
}

/**
 * Check whether a key is contained in the table.
 */
bool
dualhash_contains_key(const dualhash_t *dh, const void *key)
{
	bool res;

	dualhash_check(dh);

	dualhash_synchronize(dh);
	res = htable_contains(dh->kht, key);
	dualhash_unsynchronize(dh);

	return res;
}

/**
 * Check whether a value is contained in the table.
 */
bool
dualhash_contains_value(const dualhash_t *dh, const void *value)
{
	bool res;

	dualhash_check(dh);

	dualhash_synchronize(dh);
	res = htable_contains(dh->vht, value);
	dualhash_unsynchronize(dh);

	return res;
}

/**
 * Lookup a key in the table.
 */
void *
dualhash_lookup_key(const dualhash_t *dh, const void *key)
{
	void *res;

	dualhash_check(dh);

	dualhash_synchronize(dh);
	res = htable_lookup(dh->kht, key);
	dualhash_unsynchronize(dh);

	return res;
}

/**
 * Lookup a value in the table.
 */
void *
dualhash_lookup_value(const dualhash_t *dh, const void *value)
{
	void *res;

	dualhash_check(dh);

	dualhash_synchronize(dh);
	res = htable_lookup(dh->vht, value);
	dualhash_unsynchronize(dh);

	return res;
}

/**
 * Extended lookup of a key in the table, returning both key/value pointers.
 */
bool
dualhash_lookup_key_extended(const dualhash_t *dh, const void *key,
	void **okey, void **oval)
{
	bool res;

	dualhash_check(dh);

	dualhash_synchronize(dh);
	res = htable_lookup_extended(dh->kht, key, (const void **) okey, oval);
	dualhash_unsynchronize(dh);

	return res;
}

/**
 * Extended lookup of a value in the table, returning both key/value pointers.
 */
bool
dualhash_lookup_value_extended(const dualhash_t *dh, const void *value,
	void **okey, void **oval)
{
	bool res;

	dualhash_check(dh);

	dualhash_synchronize(dh);
	res = htable_lookup_extended(dh->vht, value, (const void **) oval, okey);
	dualhash_unsynchronize(dh);

	return res;
}

/**
 * @return amount of items held in table.
 */
size_t
dualhash_count(const dualhash_t *dh)
{
	size_t count;

	dualhash_check(dh);

	dualhash_synchronize(dh);

	count = htable_count(dh->kht);
	g_assert(htable_count(dh->vht) == count);

	dualhash_unsynchronize(dh);

	return count;
}

/* vi: set ts=4 sw=4 cindent: */
