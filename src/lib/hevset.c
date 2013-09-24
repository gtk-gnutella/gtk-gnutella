/*
 * Copyright (c) 2012-2013 Raphael Manfredi
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
 * Hashed set with embedded keys within values.
 *
 * A set with embedded keys can actually behave as a hash table from an
 * external point of view.  The keys that are put in the set are structured
 * thusly:
 *
 *    struct item {
 *        <value fields>
 *        struct key key;		// The key
 *        <other value fields>
 *    };
 *
 * The set points to the embedded key in the item.  The value structure ties
 * the key with associated attibutes.
 *
 * From an implementation perspective, we use a set but store the offset of
 * the key within the item, so we can always derive the address of the item
 * from that of the key.
 *
 * This allows us to create a hash table, i.e store (key, value) tuples,
 * without requiring an extra pointer for the value.
 *
 * The API is closer to hash sets than to hash tables.
 *
 * Each hash set object can be made thread-safe, optionally, so that
 * concurrent access to it be possible.
 *
 * @author Raphael Manfredi
 * @date 2012-2013
 */

#include "common.h"

#define HASH_SOURCE

#include "hevset.h"
#include "unsigned.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

/* Reverse assignment attempt */
#define HASH_EVSET(x) \
	(((x) != NULL && \
		HEVSET_MAGIC == (x)->magic) ? (hevset_t *) (x) : NULL)

/**
 * The hash set structure.
 */
struct hevset {
	HASH_COMMON_ATTRIBUTES
	size_t offset;			/* Offset of key within the value structure */
};

enum hevset_iter_magic { HEVSET_ITER_MAGIC = 0x33cbb728 };

static inline void
hevset_check(const hevset_t * const hx)
{
	g_assert(hx != NULL);
	g_assert(HEVSET_MAGIC == hx->magic);
}

/**
 * A hash set iterator.
 */
struct hevset_iter {
	enum hevset_iter_magic magic;
	const hevset_t *hx;
	size_t pos;					/* Current position (next item returned) */
	size_t stamp;				/* Modification stamp */
	unsigned deleted:1;			/* Whether we deleted items */
};

static inline void
hevset_iter_check(const hevset_iter_t * const hxi)
{
	g_assert(hxi != NULL);
	g_assert(HEVSET_ITER_MAGIC == hxi->magic);
	hevset_check(hxi->hx);
}

static const struct hash_ops hevset_ops;

static void
hevset_values_set(struct hash *h, const void **values)
{
	(void) h;
	(void) values;

	g_assert_not_reached();		/* Cannot be called */
}

static const void **
hevset_values_get(const struct hash *h)
{
	(void) h;

	return NULL;				/* No values (embedded with keys) */
}

static void
hevset_hash_free(struct hash *h)
{
	hevset_t *hx = HASH_EVSET(h);

	hevset_free_null(&hx);
}

/**
 * Allocate a new hash set capable of holding 2^bits items.
 */
static hevset_t *
hevset_allocate(size_t bits, bool raw, size_t offset)
{
	hevset_t *hx;

	if (raw)
		XPMALLOC0(hx);
	else
		WALLOC0(hx);

	hx->magic = HEVSET_MAGIC;
	hx->ops = &hevset_ops;
	hx->kset.raw_memory = booleanize(raw);
	hx->offset = offset;
	hash_arena_allocate(HASH(hx), bits);

	return hx;
}

/**
 * Create a new hash set using default sizing approach, for specific
 * key types (i.e. not HASH_KEY_ANY).
 *
 * @param offset	the offset of the key in the value structure
 * @param ktype		key type
 * @param keysize	expected for HASH_KEY_FIXED to give key size, otherwise 0
 *
 * @return new hash set.
 */
hevset_t *
hevset_create(size_t offset, enum hash_key_type ktype, size_t keysize)
{
	hevset_t *hx;

	g_assert(ktype != HASH_KEY_ANY);	/* Use hevset_create_any() */

	hx = hevset_allocate(HASH_MIN_BITS, FALSE, offset);
	hash_keyhash_setup(&hx->kset, ktype, keysize);

	return hx;
}

/**
 * Create a new hash set using default sizing approach, for specific
 * key types (i.e. not HASH_KEY_ANY).
 *
 * The object is allocated via xpmalloc() and avoids walloc() for the arena.
 *
 * @param offset	the offset of the key in the value structure
 * @param ktype		key type
 * @param keysize	expected for HASH_KEY_FIXED to give key size, otherwise 0
 *
 * @return new hash set.
 */
hevset_t *
hevset_create_real(size_t offset, enum hash_key_type ktype, size_t keysize)
{
	hevset_t *hx;

	g_assert(ktype != HASH_KEY_ANY);	/* Use hevset_create_any() */

	hx = hevset_allocate(HASH_MIN_BITS, TRUE, offset);
	hash_keyhash_setup(&hx->kset, ktype, keysize);

	return hx;
}

/**
 * Create a new hash set using default sizing approach, for any key.
 *
 * @param offset	the offset of the key in the value structure
 * @param primary	primary hash function (cannot be NULL)
 * @param secondary	secondary hash function (may be NULL)
 * @param eq		key equality function (NULL means '==' checks)
 *
 * @return new hash set.
 */
hevset_t *
hevset_create_any(size_t offset,
	hash_fn_t primary, hash_fn_t secondary, eq_fn_t eq)
{
	hevset_t *hx;

	g_assert(primary != NULL);

	hx = hevset_allocate(HASH_MIN_BITS, FALSE, offset);
	hash_keyhash_any_setup(&hx->kset, primary, secondary, eq);

	return hx;
}

/**
 * Create a new hash set using default sizing approach, for any key.
 *
 * The object is allocated via xpmalloc() and avoids walloc() for the arena.
 *
 * @param offset	the offset of the key in the value structure
 * @param primary	primary hash function (cannot be NULL)
 * @param secondary	secondary hash function (may be NULL)
 * @param eq		key equality function (NULL means '==' checks)
 *
 * @return new hash set.
 */
hevset_t *
hevset_create_any_real(size_t offset,
	hash_fn_t primary, hash_fn_t secondary, eq_fn_t eq)
{
	hevset_t *hx;

	g_assert(primary != NULL);

	hx = hevset_allocate(HASH_MIN_BITS, TRUE, offset);
	hash_keyhash_any_setup(&hx->kset, primary, secondary, eq);

	return hx;
}

/**
 * Destroy hash set.
 */
static void
hevset_free(hevset_t *hx)
{
	hevset_check(hx);
	g_assert(0 == hx->refcnt);	/* No pending iterators */

	hash_arena_free(HASH(hx));
	hx->magic = 0;
	if (hx->kset.raw_memory)
		xfree(hx);
	else
		WFREE(hx);
}

/**
 * Destroy hash set and nullify its pointer.
 */
void
hevset_free_null(hevset_t **hx_ptr)
{
	hevset_t *hx = *hx_ptr;

	if (hx != NULL) {
		hevset_free(hx);
		*hx_ptr = NULL;
	}
}

/**
 * Mark hash set as thread-safe.
 */
void
hevset_thread_safe(hevset_t *ht)
{
	hevset_check(ht);

	hash_thread_safe(HASH(ht));
}

/**
 * Lock the hash set to allow a sequence of operations to be atomically
 * conducted.
 *
 * It is possible to lock the set several times as long as each locking
 * is paired with a corresponding unlocking in the execution flow.
 *
 * The set must have been marked thread-safe already.
 */
void
hevset_lock(hevset_t *hx)
{
	hevset_check(hx);
	g_assert_log(hx->lock != NULL,
		"%s(): hash set %p not marked thread-safe", G_STRFUNC, hx);

	mutex_lock(hx->lock);
}

/*
 * Release lock on hash set.
 *
 * The set must have been marked thread-safe already and locked by the
 * calling thread.
 */
void
hevset_unlock(hevset_t *hx)
{
	hevset_check(hx);
	g_assert_log(hx->lock != NULL,
		"%s(): hash set %p not marked thread-safe", G_STRFUNC, hx);

	mutex_unlock(hx->lock);
}

/**
 * Insert item in hash set.
 *
 * Any previously existing value for the key is replaced by the new one.
 *
 * @param ht		the hash table
 * @param key		pointer to the key within the value structure
 *
 * @attention
 * This routine takes a reference to the embedded key within the value to
 * insert.  It should be preferred to hevset_insert() when the values can have
 * multiple indexing keys, to emphasize which key is going to be used for
 * the insertion in that table.
 */
void
hevset_insert_key(hevset_t *ht, const void *key)
{
	hevset_check(ht);
	g_assert(key != NULL);

	hash_synchronize(HASH(ht));

	hash_insert_key(HASH(ht), key);
	ht->stamp++;

	hash_return_void(HASH(ht));
}

/**
 * Insert item in hash set.
 *
 * Any previously existing value for the key is replaced by the new one.
 *
 * @param ht		the hash table
 * @param value		the value (which embeds the key)
 *
 * @attention
 * This routine takes a value with its embedded expanded key, not the key.
 */
void
hevset_insert(hevset_t *ht, const void *value)
{
	const void *key;

	hevset_check(ht);
	g_assert(value != NULL);

	key = const_ptr_add_offset(value, ht->offset);
	hash_synchronize(HASH(ht));

	hash_insert_key(HASH(ht), key);
	ht->stamp++;

	hash_return_void(HASH(ht));
}

/**
 * Check whether key is held in hash set.
 *
 * @param hx		the hash table
 * @param key		the key
 *
 * @return whether table contains the key.
 */
bool
hevset_contains(const hevset_t *hx, const void *key)
{
	bool found;

	hevset_check(hx);
	g_assert(key != NULL);

	hash_synchronize(HASH(hx));
	found = (size_t) -1 != hash_lookup_key(HASH(hx), key);
	hash_return(HASH(hx), found);
}

/**
 * Fetch value from the hash set.
 *
 * @param ht		the hash table
 * @param key		the key being looked up
 *
 * @return found value, or NULL if not found.
 */
void *
hevset_lookup(const hevset_t *ht, const void *key)
{
	size_t idx;
	void *value;

	hevset_check(ht);
	g_assert(key != NULL);

	hash_synchronize(HASH(ht));
	idx = hash_lookup_key(HASH(ht), key);

	if ((size_t) -1 == idx)
		hash_return(HASH(ht), NULL);

	value = ptr_add_offset(deconstify_pointer(ht->kset.keys[idx]), -ht->offset);
	hash_return(HASH(ht), value);
}

/**
 * Fetch key/value from the hash table, returning whether the key exists.
 * If it does, the original value pointer is written valptr.
 *
 * @param ht		the hash table
 * @param key		the key being looked up
 * @param valptr	if non-NULL, where the original value pointer is written
 *
 * @return whether key exists in the table.
 */
bool
hevset_lookup_extended(const hevset_t *ht, const void *key, void **valptr)
{
	size_t idx;

	hevset_check(ht);

	hash_synchronize(HASH(ht));
	idx = hash_lookup_key(HASH(ht), key);

	if ((size_t) -1 == idx)
		hash_return(HASH(ht), FALSE);

	if (valptr != NULL) {
		void *kptr = deconstify_pointer(ht->kset.keys[idx]);
		*valptr = ptr_add_offset(kptr, -ht->offset);
	}

	hash_return(HASH(ht), TRUE);
}

/**
 * Remove key from the hash table.
 *
 * @return TRUE if the key was present in the table.
 */
bool
hevset_remove(hevset_t *hx, const void *key)
{
	bool present;

	hevset_check(hx);

	hash_synchronize(HASH(hx));

	hx->stamp++;
	present = hash_delete_key(HASH(hx), key);

	hash_return(HASH(hx), present);
}

/**
 * @return amount of items in the table.
 */
size_t
hevset_count(const hevset_t *hx)
{
	size_t count;

	hevset_check(hx);

	hash_synchronize(HASH(hx));
	count = hx->kset.items;
	hash_return(HASH(hx), count);
}

/**
 * Remove all items from hash table.
 */
void hevset_clear(hevset_t *hx)
{
	hevset_check(hx);

	hash_clear(HASH(hx));
}

/**
 * Traverse table, invoking callback for each entry.
 *
 * @param hx	the hash table
 * @param fn	callback to invoke
 * @param data	additional callback parameter
 */
void
hevset_foreach(const hevset_t *hx, data_fn_t fn, void *data)
{
	unsigned *hp, *end;
	size_t i, n;

	hevset_check(hx);

	hash_synchronize(HASH(hx));

	end = &hx->kset.hashes[hx->kset.size];
	hash_refcnt_inc(HASH(hx));		/* Prevent any key relocation */

	for (i = n = 0, hp = hx->kset.hashes; hp != end; i++, hp++) {
		if (HASH_IS_REAL(*hp)) {
			void *kptr = deconstify_pointer(hx->kset.keys[i]);
			(*fn)(ptr_add_offset(kptr, -hx->offset), data);
			n++;
		}
	}

	g_assert(n == hx->kset.items);

	hash_refcnt_dec(HASH(hx));
	hash_return_void(HASH(hx));
}

/**
 * Traverse table, invoking callback for each key.
 *
 * @param hx	the hash table
 * @param fn	callback to invoke on the key
 * @param data	additional callback parameter
 */
void
hevset_foreach_key(const hevset_t *ht, data_fn_t fn, void *data)
{
	hash_foreach(HASH(ht), fn, data);
}

/**
 * Traverse table, invoking callback for each entry and removing it when
 * the callback function returns TRUE.
 *
 * @param hx	the hash table
 * @param fn	callback to invoke
 * @param data	additional callback parameter
 *
 * @return the number of entries removed from the hash table.
 */
size_t
hevset_foreach_remove(hevset_t *hx, data_rm_fn_t fn, void *data)
{
	unsigned *hp, *end;
	size_t i, n, nr;

	hevset_check(hx);

	hash_synchronize(HASH(hx));

	end = &hx->kset.hashes[hx->kset.size];
	hash_refcnt_inc(HASH(hx));		/* Prevent any key relocation */

	for (i = n = nr = 0, hp = hx->kset.hashes; hp != end; i++, hp++) {
		if (HASH_IS_REAL(*hp)) {
			void *kptr = deconstify_pointer(hx->kset.keys[i]);
			bool r = (*fn)(ptr_add_offset(kptr, -hx->offset), data);
			n++;
			if (r) {
				nr++;
				hash_erect_tombstone(HASH(hx), i);
				hx->stamp++;
			}
		}
	}

	g_assert(n == hx->kset.items);
	g_assert(nr <= hx->kset.items);

	hash_refcnt_dec(HASH(hx));

	hx->kset.items -= nr;

	if (nr != 0)
		hash_resize_as_needed(HASH(hx));

	hash_return(HASH(hx), nr);
}

/**
 * Create a new hash set iterator.
 */
hevset_iter_t *
hevset_iter_new(const hevset_t *hx)
{
	hevset_iter_t *hxi;

	hevset_check(hx);

	WALLOC0(hxi);
	hxi->magic = HEVSET_ITER_MAGIC;
	hxi->hx = hx;

	hash_synchronize(HASH(hx));

	hxi->stamp = hx->stamp;
	hash_refcnt_inc(HASH(hx));

	hash_unsynchronize(HASH(hx));

	return hxi;
}

/**
 * Release hash set iterator.
 */
void
hevset_iter_release(hevset_iter_t **hxi_ptr)
{
	hevset_iter_t *hxi = *hxi_ptr;

	if (hxi != NULL) {
		hevset_iter_check(hxi);

		hash_synchronize(HASH(hxi->hx));

		hash_refcnt_dec(HASH(hxi->hx));
		if (hxi->deleted && 0 == hxi->hx->refcnt)
			hash_resize_as_needed(HASH(hxi->hx));

		hash_unsynchronize(HASH(hxi->hx));

		hxi->magic = 0;
		WFREE(hxi);
		*hxi_ptr = NULL;
	}
}

/**
 * Fetch next entry from iterator.
 *
 * @param hxi	the hash table iterator
 * @param vp	where value is written, if non-NULL
 *
 * @return TRUE if a new entry exists, FALSE otherwise.
 */
bool
hevset_iter_next(hevset_iter_t *hxi, void **vp)
{
	const hevset_t *hx;

	hevset_iter_check(hxi);

	hx = hxi->hx;
	hash_synchronize(HASH(hx));

	while (hxi->pos < hx->kset.size && !HASH_IS_REAL(hx->kset.hashes[hxi->pos]))
		hxi->pos++;

	if (hxi->pos >= hx->kset.size)
		hash_return(HASH(hx), FALSE);

	if (vp != NULL) {
		void *kptr = deconstify_pointer(hx->kset.keys[hxi->pos]);
		*vp = ptr_add_offset(kptr, -hx->offset);
	}

	hash_unsynchronize(HASH(hx));

	hxi->pos++;
	return TRUE;
}

/**
 * Remove current iterator item, returned by hevset_iter_next().
 */
void
hevset_iter_remove(hevset_iter_t *hxi)
{
	hevset_t *hx;
	size_t idx;

	hevset_iter_check(hxi);
	g_assert(size_is_positive(hxi->pos));		/* Called _next() once */
	g_assert(hxi->pos <= hxi->hx->kset.size);

	hx = deconstify_pointer(hxi->hx);
	hash_synchronize(HASH(hx));

	idx = hxi->pos - 1;		/* Current item */
	if (hash_erect_tombstone(HASH(hx), idx))
		hx->kset.items--;

	hash_unsynchronize(HASH(hx));
	hxi->deleted = TRUE;
}

/**
 * Polymorphic operations.
 */
static const struct hash_ops hevset_ops = {
	hevset_values_set,		/* set_values */
	hevset_values_get,		/* get_values */
	hevset_hash_free,		/* hash_free */
};

/* vi: set ts=4 sw=4 cindent: */
