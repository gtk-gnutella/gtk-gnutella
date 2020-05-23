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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Hashed set with keys internally referenced within values.
 *
 * A set with internal keys can actually behave as a hash table from an
 * external point of view.  The keys that are put in the set are structured
 * thusly:
 *
 *    struct item {
 *        <value fields>
 *        struct key *key;		// The key reference
 *        <other value fields>
 *    };
 *
 * From an implementation perspective, we use a set to store the items but
 * we keep the offset of the key within the item, so we can always derive a
 * proper hashing of the item.
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

#include "hikset.h"
#include "hashing.h"			/* For binary_hash() and friends */
#include "unsigned.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

/* Reverse assignment attempt */
#define HASH_IKSET(x) \
	(((x) != NULL && \
		HIKSET_MAGIC == (x)->magic) ? (hikset_t *) (x) : NULL)

/**
 * The hash set structure.
 *
 * We'll be storing the address of the key, trapping the hash function to come
 * back to this wrapping layer that will dereference the key pointer in the item
 * and call the original hashing routine or equality routine.
 *
 * Therefore we need to keep these original hash/equality routines in addition
 * to the offset of the key field in the value.
 */
struct hikset {
	HASH_COMMON_ATTRIBUTES
	enum hash_key_type ktype;	/* Real key type */
	size_t offset;				/* Offset of key within the value structure */
	hash_fn_t ihash;			/* Initial hash function for key */
	union {
		eq_fn_t eq;				/* Key equality test */
		size_t keysize;			/* For fixed-length keys */
	} uik;
};

enum hikset_iter_magic { HIKSET_ITER_MAGIC = 0x3d3f97a7 };

static inline void
hikset_check(const hikset_t * const hx)
{
	g_assert(hx != NULL);
	g_assert(HIKSET_MAGIC == hx->magic);
}

/**
 * A hash set iterator.
 */
struct hikset_iter {
	enum hikset_iter_magic magic;
	const hikset_t *hx;
	size_t pos;					/* Current position (next item returned) */
	size_t stamp;				/* Modification stamp */
	unsigned deleted:1;			/* Whether we deleted items */
};

static inline void
hikset_iter_check(const hikset_iter_t * const hxi)
{
	g_assert(hxi != NULL);
	g_assert(HIKSET_ITER_MAGIC == hxi->magic);
	hikset_check(hxi->hx);
}

static const struct hash_ops hikset_ops;

static void
hikset_values_set(struct hash *h, const void **values)
{
	(void) h;
	(void) values;

	g_assert_not_reached();		/* Cannot be called */
}

static const void **
hikset_values_get(const struct hash *h)
{
	(void) h;

	return NULL;				/* No values (stored as keys) */
}

static void
hikset_hash_free(struct hash *h)
{
	hikset_t *hx = HASH_IKSET(h);

	hikset_free_null(&hx);
}

/**
 * Hash key.
 *
 * This is the trapping function we're installing for our hash set, which will
 * dereference the pointer field of the user's key within the value and hash it.
 */
static uint
hikset_key_hash(const void *value, void *data)
{
	hikset_t *hik = data;
	const void * const *key = value;

	hikset_check(hik);

	return NULL == hik->ihash ?
		binary_hash(*key, hik->uik.keysize) :
		(*hik->ihash)(*key);
}

/**
 * Key equality check.
 *
 * This is the trapping function we're installing for our hash set.
 */
static bool
hikset_key_equals(const void *a, const void *b, void *data)
{
	hikset_t *hik = data;
	const void * const *ka = a;
	const void * const *kb = b;

	hikset_check(hik);

	switch (hik->ktype) {
	case HASH_KEY_SELF:
		return *ka == *kb;
	case HASH_KEY_STRING:
	case HASH_KEY_ANY:
		return (*hik->uik.eq)(*ka, *kb);
	case HASH_KEY_FIXED:
		return binary_eq(*ka, *kb, hik->uik.keysize);
	case HASH_KEY_ANY_DATA:
	case HASH_KEY_MAXTYPE:
		break;
	}

	g_assert_not_reached();
}

/**
 * Allocate a new hash set capable of holding 2^bits items.
 */
static hikset_t *
hikset_allocate(size_t bits, bool raw, size_t offset)
{
	hikset_t *hx;

	if (raw)
		XMALLOC0(hx);
	else
		WALLOC0(hx);

	hx->magic = HIKSET_MAGIC;
	hx->ops = &hikset_ops;
	hx->kset.raw_memory = booleanize(raw);
	hx->offset = offset;
	hash_arena_allocate(HASH(hx), bits);

	return hx;
}

/**
 * Setut hashing / comparison routines for keys.
 */
static void
hikset_key_setup(hikset_t *hik, enum hash_key_type ktype, size_t keysize)
{
	hik->ktype = ktype;
	switch (ktype) {
	case HASH_KEY_SELF:
		hik->ihash = pointer_hash;
		hik->uik.eq = NULL;			/* Will use == comparison */
		break;
	case HASH_KEY_STRING:
		hik->ihash = string_mix_hash;
		hik->uik.eq = string_eq;
		break;
	case HASH_KEY_FIXED:
		hik->ihash = NULL;			/* Will use binary_hash() */
		hik->uik.keysize = keysize;	/* Will use binary_eq() */
		break;
	case HASH_KEY_ANY:
	case HASH_KEY_ANY_DATA:
	case HASH_KEY_MAXTYPE:
		g_assert_not_reached();
	}
}

/**
 * Create a new hash set using default sizing approach, for specific
 * key types (i.e. not HASH_KEY_ANY).
 *
 * @param ktype		key type
 * @param offset	the offset of the key in the value structure
 * @param keysize	expected for HASH_KEY_FIXED to give key size, otherwise 0
 * @param real		whether to use VMM and avoid walloc()
 *
 * @return new hash set.
 */
static hikset_t *
hikset_new(enum hash_key_type ktype, size_t offset, size_t keysize, bool real)
{
	hikset_t *hx;

	g_assert(ktype != HASH_KEY_ANY);	/* Use hikset_create_any() */

	hx = hikset_allocate(HASH_MIN_BITS, real, offset);
	hx->offset = offset;
	hikset_key_setup(hx, ktype, keysize);
	hash_keyhash_data_setup(&hx->kset, hikset_key_hash, hx, hikset_key_equals);

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
hikset_t *
hikset_create(size_t offset, enum hash_key_type ktype, size_t keysize)
{
	return hikset_new(ktype, offset, keysize, FALSE);
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
hikset_t *
hikset_create_real(size_t offset, enum hash_key_type ktype, size_t keysize)
{
	return hikset_new(ktype, offset, keysize, TRUE);
}

/**
 * Create a new hash set using default sizing approach, for any key.
 *
 * Note that there is no secondary hash defined here: values with embedded
 * keys use a default secondary hash routine.
 *
 * @param offset	the offset of the key in the value structure
 * @param hash		hash function (cannot be NULL)
 * @param eq		key equality function (NULL means '==' checks)
 * @param real		whether to use VMM and avoid walloc()
 *
 * @return new hash set.
 */
static hikset_t *
hikset_new_any(size_t offset, hash_fn_t hash, eq_fn_t eq, bool real)
{
	hikset_t *hx;

	g_assert(hash != NULL);

	hx = hikset_allocate(HASH_MIN_BITS, real, offset);
	hx->ktype = HASH_KEY_ANY;
	hx->offset = offset;
	hx->ihash = hash;
	hx->uik.eq = NULL == eq ? pointer_eq : eq;
	hash_keyhash_data_setup(&hx->kset, hikset_key_hash, hx, hikset_key_equals);

	return hx;
}

/**
 * Create a new hash set using default sizing approach, for any key.
 *
 * Note that there is no secondary hash defined here: values with embedded
 * keys use a default secondary hash routine.
 *
 * @param offset	the offset of the key in the value structure
 * @param hash		hash function (cannot be NULL)
 * @param eq		key equality function (NULL means '==' checks)
 *
 * @return new hash set.
 */
hikset_t *
hikset_create_any(size_t offset, hash_fn_t hash, eq_fn_t eq)
{
	return hikset_new_any(offset, hash, eq, FALSE);
}

/**
 * Create a new hash set using default sizing approach, for any key.
 *
 * Note that there is no secondary hash defined here: values with embedded
 * keys use a default secondary hash routine.
 *
 * The object is allocated via xpmalloc() and avoids walloc() for the arena.
 *
 * @param offset	the offset of the key in the value structure
 * @param hash		hash function (cannot be NULL)
 * @param eq		key equality function (NULL means '==' checks)
 *
 * @return new hash set.
 */
hikset_t *
hikset_create_any_real(size_t offset, hash_fn_t hash, eq_fn_t eq)
{
	return hikset_new_any(offset, hash, eq, TRUE);
}

/**
 * Destroy hash set.
 */
static void
hikset_free(hikset_t *hx)
{
	hikset_check(hx);
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
hikset_free_null(hikset_t **hx_ptr)
{
	hikset_t *hx = *hx_ptr;

	if (hx != NULL) {
		hikset_free(hx);
		*hx_ptr = NULL;
	}
}

/**
 * Mark hash set as thread-safe.
 */
void
hikset_thread_safe(hikset_t *hx)
{
	hikset_check(hx);

	hash_thread_safe(HASH(hx));
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
hikset_lock(hikset_t *hx)
{
	hikset_check(hx);
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
hikset_unlock(hikset_t *hx)
{
	hikset_check(hx);
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
 * @param keyptr	pointer to the key field in the value
 *
 * @attention
 * This routine takes a reference to the embedded key pointer within the value
 * to insert.  It should be preferred to hikset_insert() when the values can
 * have multiple indexing keys, to emphasize which key is going to be used
 * for the insertion in the table.
 */
void
hikset_insert_key(hikset_t *hik, const void *keyptr)
{
	hikset_check(hik);
	g_assert(keyptr != NULL);

	/*
	 * We're really inserting the address within the value where the key
	 * is stored.  It will be hashed through hikset_key_hash() which
	 * will perform the necessary indirection.
	 */

	hash_synchronize(HASH(hik));

	hash_insert_key(HASH(hik), keyptr);
	hik->stamp++;

	hash_return_void(HASH(hik));
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
 * This routine takes a value with its embedded key reference, not the key.
 */
void
hikset_insert(hikset_t *hik, const void *value)
{
	void * const *key;		/* Pointer to the key field in the value */

	hikset_check(hik);
	g_assert(value != NULL);

	/*
	 * We're really inserting the address within the value where the key
	 * is stored.  It will be hashed through hikset_key_hash() which
	 * will perform the necessary indirection.
	 */

	key = const_ptr_add_offset(value, hik->offset);
	hash_synchronize(HASH(hik));

	hash_insert_key(HASH(hik), key);
	hik->stamp++;

	hash_return_void(HASH(hik));
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
hikset_contains(const hikset_t *hx, const void *key)
{
	bool found;

	hikset_check(hx);

	/*
	 * We store a pointer to the key, we look for a pointer to the key
	 * because the hashing routine hikset_key_hash() will do the additional
	 * indirection to get at the key pointer.
	 */

	hash_synchronize(HASH(hx));

	found = (size_t) -1 != hash_lookup_key(HASH(hx), &key);

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
hikset_lookup(const hikset_t *ht, const void *key)
{
	size_t idx;
	void *value;

	hikset_check(ht);

	hash_synchronize(HASH(ht));
	idx = hash_lookup_key(HASH(ht), &key);

	if ((size_t) -1 == idx)
		hash_return(HASH(ht), NULL);

	/*
	 * We stored a pointer to the key in the value structure.
	 * To get the start of the value, we simply offset that pointer.
	 */

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
hikset_lookup_extended(const hikset_t *ht, const void *key, void **valptr)
{
	size_t idx;

	hikset_check(ht);

	hash_synchronize(HASH(ht));
	idx = hash_lookup_key(HASH(ht), &key);

	if ((size_t) -1 == idx)
		hash_return(HASH(ht), FALSE);

	if (valptr != NULL) {
		void *kptr = deconstify_pointer(ht->kset.keys[idx]);
		*valptr = ptr_add_offset(kptr, -ht->offset);
	}

	hash_return(HASH(ht), TRUE);
}

/**
 * Fetch a random value from the set.
 *
 * @return the chosen random value, NULL if the set was empty.
 */
void *
hikset_random(const hikset_t *ht)
{
	size_t idx;
	const void *key;

	hikset_check(ht);

	idx = hash_random(HASH(ht), &key);

	if ((size_t) -1 == idx)
		return NULL;

	return ptr_add_offset(deconstify_pointer(key), -ht->offset);
}

/**
 * Remove key from the hash table.
 *
 * @return TRUE if the key was present in the table.
 */
bool
hikset_remove(hikset_t *hx, const void *key)
{
	bool present;

	hikset_check(hx);

	hash_synchronize(HASH(hx));

	hx->stamp++;
	present = hash_delete_key(HASH(hx), &key);

	hash_return(HASH(hx), present);
}

/**
 * @return amount of items in the table.
 */
size_t
hikset_count(const hikset_t *hx)
{
	size_t count;

	hikset_check(hx);

	hash_synchronize(HASH(hx));
	count = hx->kset.items;
	hash_return(HASH(hx), count);
}

/**
 * Remove all items from hash table.
 */
void hikset_clear(hikset_t *hx)
{
	hikset_check(hx);

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
hikset_foreach(const hikset_t *hx, data_fn_t fn, void *data)
{
	unsigned *hp, *end;
	size_t i, n;

	hikset_check(hx);

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
hikset_foreach_key(const hikset_t *ht, data_fn_t fn, void *data)
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
hikset_foreach_remove(hikset_t *hx, data_rm_fn_t fn, void *data)
{
	unsigned *hp, *end;
	size_t i, n, nr;

	hikset_check(hx);

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
hikset_iter_t *
hikset_iter_new(const hikset_t *hx)
{
	hikset_iter_t *hxi;

	hikset_check(hx);

	WALLOC0(hxi);
	hxi->magic = HIKSET_ITER_MAGIC;

	hash_synchronize(HASH(hx));

	hxi->hx = hx;
	hxi->stamp = hx->stamp;
	hash_refcnt_inc(HASH(hx));

	hash_unsynchronize(HASH(hx));

	return hxi;
}

/**
 * Release hash set iterator.
 */
void
hikset_iter_release(hikset_iter_t **hxi_ptr)
{
	hikset_iter_t *hxi = *hxi_ptr;

	if (hxi != NULL) {
		hikset_iter_check(hxi);

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
hikset_iter_next(hikset_iter_t *hxi, void **vp)
{
	const hikset_t *hx;

	hikset_iter_check(hxi);

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
 * Remove current iterator item, returned by hikset_iter_next().
 */
void
hikset_iter_remove(hikset_iter_t *hxi)
{
	hikset_t *hx;
	size_t idx;

	hikset_iter_check(hxi);
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
static const struct hash_ops hikset_ops = {
	hikset_values_set,		/* set_values */
	hikset_values_get,		/* get_values */
	hikset_hash_free,		/* hash_free */
};

/* vi: set ts=4 sw=4 cindent: */
