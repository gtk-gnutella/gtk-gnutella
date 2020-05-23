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

#include "common.h"

#include "map.h"
#include "atoms.h"				/* For tests */
#include "debug.h"
#include "htable.h"
#include "ohash_table.h"
#include "patricia.h"
#include "random.h"
#include "stringify.h"			/* For plural() */
#include "tm.h"					/* For tests */
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

/**
 * Allowed map types.
 */
enum map_type {
	MAP_HASH = 0x1,			/* Hash table from glib */
	MAP_PATRICIA,			/* PATRICIA tree */
	MAP_ORDERED_HASH,		/* Ordered hash table */

	MAP_MAXTYPE
};

enum map_magic { MAP_MAGIC = 0x7a16297fU };

/**
 * The map structure holding the necessary information to delegate all
 * the operations to different implementations.
 */
struct map {
	enum map_magic magic;
	enum map_type type;
	union {
		htable_t *ht;
		patricia_t *pt;
		ohash_table_t *ot;
	} u;
};

static inline void
map_check(const map_t *m)
{
	g_assert(m != NULL);
	g_assert(MAP_MAGIC == m->magic);
}

/**
 * Create a map implemented as a hash table.
 *
 * @param hash_func		the hash function for keys
 * @param key_eq_func	the key comparison function
 *
 * @return the new map
 */
map_t *
map_create_hash(hash_fn_t hash_func, eq_fn_t key_eq_func)
{
	map_t *m;

	WALLOC(m);
	m->magic = MAP_MAGIC;
	m->type = MAP_HASH;
	m->u.ht = htable_create_any(hash_func, NULL, key_eq_func);

	return m;
}

/**
 * Create a map implemented as an ordered hash table.
 *
 * @param hash_func		the hash function for keys
 * @param key_eq_func	the key comparison function
 *
 * @return the new map
 */
map_t *
map_create_ordered_hash(hash_fn_t hash_func, eq_fn_t key_eq_func)
{
	map_t *m;

	WALLOC(m);
	m->magic = MAP_MAGIC;
	m->type = MAP_ORDERED_HASH;
	m->u.ot = ohash_table_new(hash_func, key_eq_func);

	return m;
}

/**
 * Create a map implemented as a PATRICIA tree with constant-width keys.
 *
 * @param keybits		the size of all the keys, in bits.
 */
map_t *
map_create_patricia(size_t keybits)
{
	map_t *m;

	WALLOC(m);
	m->magic = MAP_MAGIC;
	m->type = MAP_PATRICIA;
	m->u.pt = patricia_create(keybits);

	return m;
}

/**
 * Create a map out of an existing hash table.
 * Use map_release() to discard the map encapsulation.
 */
map_t *
map_create_from_hash(htable_t *ht)
{
	map_t *m;

	g_assert(ht);

	WALLOC(m);
	m->magic = MAP_MAGIC;
	m->type = MAP_HASH;
	m->u.ht = ht;

	return m;
}

/**
 * Create a map out of an existing ordered hash table.
 * Use map_release() to discard the map encapsulation.
 */
map_t *
map_create_from_ordered_hash(ohash_table_t *ot)
{
	map_t *m;

	g_assert(ot);

	WALLOC(m);
	m->magic = MAP_MAGIC;
	m->type = MAP_ORDERED_HASH;
	m->u.ot = ot;

	return m;
}

/**
 * Create a map out of an existing PATRICIA tree.
 * Use map_release() to discard the map encapsulation.
 */
map_t *
map_create_from_patricia(patricia_t *pt)
{
	map_t *m;

	g_assert(pt);

	WALLOC(m);
	m->magic = MAP_MAGIC;
	m->type = MAP_PATRICIA;
	m->u.pt = pt;

	return m;
}

/**
 * Switch the implementation of an existing map to a hash table.
 * Returns the previous implementation.
 */
void *
map_switch_to_hash(map_t *m, htable_t *ht)
{
	void *implementation;

	map_check(m);
	g_assert(ht);

	implementation = map_implementation(m);
	m->type = MAP_HASH;
	m->u.ht = ht;

	return implementation;
}

/**
 * Switch the implementation of an existing map to an ordered hash table.
 * Returns the previous implementation.
 */
void *
map_switch_to_ordered_hash(map_t *m, ohash_table_t *ot)
{
	void *implementation;

	map_check(m);
	g_assert(ot);

	implementation = map_implementation(m);
	m->type = MAP_ORDERED_HASH;
	m->u.ot = ot;

	return implementation;
}

/**
 * Switch the implementation of an existing map to a PATRICIA tree.
 * Returns the previous implementation.
 */
void *
map_switch_to_patricia(map_t *m, patricia_t *pt)
{
	void *implementation;

	map_check(m);
	g_assert(pt);

	implementation = map_implementation(m);
	m->type = MAP_PATRICIA;
	m->u.pt = pt;

	return implementation;
}

/**
 * Insert a key/value pair in the map.
 */
void
map_insert(const map_t *m, const void *key, const void *value)
{
	map_check(m);

	switch (m->type) {
	case MAP_HASH:
		htable_insert_const(m->u.ht, key, value);
		break;
	case MAP_ORDERED_HASH:
		ohash_table_insert(m->u.ot, key, value);
		break;
	case MAP_PATRICIA:
		patricia_insert(m->u.pt, key, value);
		break;
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}
}

/**
 * Replace a key/value pair in the map.
 */
void
map_replace(const map_t *m, const void *key, const void *value)
{
	map_check(m);

	switch (m->type) {
	case MAP_HASH:
		htable_insert_const(m->u.ht, key, value);
		break;
	case MAP_ORDERED_HASH:
		ohash_table_replace(m->u.ot, key, value);
		break;
	case MAP_PATRICIA:
		patricia_insert(m->u.pt, key, value);		/* Does replace */
		break;
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}
}

/**
 * Remove a key from the map.
 *
 * @return TRUE if the key was found and removed from the map.
 */
bool
map_remove(const map_t *m, const void *key)
{
	map_check(m);

	switch (m->type) {
	case MAP_HASH:
		return htable_remove(m->u.ht, key);
		break;
	case MAP_ORDERED_HASH:
		return ohash_table_remove(m->u.ot, key);
		break;
	case MAP_PATRICIA:
		return patricia_remove(m->u.pt, key);
		break;
	case MAP_MAXTYPE:
		break;
	}

	g_assert_not_reached();
	return FALSE;
}

/**
 * Check whether map contains the key.
 */
bool
map_contains(const map_t *m, const void *key)
{
	map_check(m);

	switch (m->type) {
	case MAP_HASH:
		return htable_contains(m->u.ht, key);
	case MAP_ORDERED_HASH:
		return ohash_table_contains(m->u.ot, key);
	case MAP_PATRICIA:
		return patricia_contains(m->u.pt, key);
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}
	return FALSE;
}

/**
 * Lookup a key in the map.
 */
void *
map_lookup(const map_t *m, const void *key)
{
	map_check(m);

	switch (m->type) {
	case MAP_HASH:
		return htable_lookup(m->u.ht, key);
	case MAP_ORDERED_HASH:
		return ohash_table_lookup(m->u.ot, key);
	case MAP_PATRICIA:
		return patricia_lookup(m->u.pt, key);
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}
	return NULL;
}

/**
 * @return amount of items held in map.
 */
size_t
map_count(const map_t *m)
{
	map_check(m);

	switch (m->type) {
	case MAP_HASH:
		return htable_count(m->u.ht);
	case MAP_ORDERED_HASH:
		return ohash_table_count(m->u.ot);
	case MAP_PATRICIA:
		return patricia_count(m->u.pt);
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}
	return 0;
}

/**
 * Extended lookup of a key in the map, returning both key/value pointers.
 */
bool
map_lookup_extended(const map_t *m, const void *key, void **okey, void **oval)
{
	map_check(m);

	switch (m->type) {
	case MAP_HASH:
		return htable_lookup_extended(m->u.ht, key, (const void **) okey, oval);
	case MAP_ORDERED_HASH:
		return ohash_table_lookup_extended(m->u.ot, key, okey, oval);
	case MAP_PATRICIA:
		return patricia_lookup_extended(m->u.pt, key, okey, oval);
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}
	return FALSE;
}

/**
 * Mark map as thread-safe.
 *
 * If the underlying implementation does not implement thread-safety, this
 * causes a fatal error.
 */
void
map_thread_safe(const map_t *m)
{
	const char *type = NULL;

	map_check(m);

	switch (m->type) {
	case MAP_HASH:
		htable_thread_safe(m->u.ht);
		return;
	case MAP_ORDERED_HASH:
		type = "ordered hash";
		break;
	case MAP_PATRICIA:
		type = "PATRICIA";
		break;
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}

	s_error("%s(): %s implementation is not thread-safe yet", G_STRFUNC, type);
}

/**
 * Structure used to handle foreach() trampoline for PATRICIA.
 */
struct pat_foreach {
	keyval_fn_t cb;		/* Registered user callback */
	void *u;			/* User callback additional arg */
};

/**
 * foreach() trampoline for PATRICIA.
 */
static void
pat_foreach_wrapper(void *key, size_t u_keybits, void *value, void *u)
{
	struct pat_foreach *ctx = u;

	(void) u_keybits;

	ctx->cb(key, value, ctx->u);
}

/**
 * Iterate on each item of the map, applying callback.
 */
void
map_foreach(const map_t *m, keyval_fn_t cb, void *u)
{
	map_check(m);
	g_assert(cb);

	switch (m->type) {
	case MAP_HASH:
		htable_foreach(m->u.ht, (ckeyval_fn_t) cb, u);
		break;
	case MAP_ORDERED_HASH:
		ohash_table_foreach(m->u.ot, cb, u);
		break;
	case MAP_PATRICIA:
		{
			struct pat_foreach ctx;

			ctx.cb = cb;
			ctx.u = u;

			patricia_foreach(m->u.pt, pat_foreach_wrapper, &ctx);
		}
		break;
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}
}

/**
 * Structure used to handle foreach_remove() trampoline for PATRICIA.
 */
struct pat_foreach_remove {
	keyval_rm_fn_t cb;	/* Registered user callback */
	void *u;			/* User callback additional arg */
};

/**
 * foreach() trampoline for PATRICIA.
 */
static bool
pat_foreach_remove_wrapper(void *key, size_t u_keybits, void *value, void *u)
{
	struct pat_foreach_remove *ctx = u;

	(void) u_keybits;

	return ctx->cb(key, value, ctx->u);
}
/**
 * Iterate over the map, applying callback on each item and removing it if
 * the callback returns TRUE.
 *
 * @return the amount of items deleted.
 */
size_t
map_foreach_remove(const map_t *m, keyval_rm_fn_t cb, void *u)
{
	map_check(m);
	g_assert(cb);

	switch (m->type) {
	case MAP_HASH:
		return htable_foreach_remove(m->u.ht, (ckeyval_rm_fn_t) cb, u);
	case MAP_ORDERED_HASH:
		return ohash_table_foreach_remove(m->u.ot, cb, u);
	case MAP_PATRICIA:
		{
			struct pat_foreach_remove ctx;

			ctx.cb = cb;
			ctx.u = u;

			return patricia_foreach_remove(
				m->u.pt, pat_foreach_remove_wrapper, &ctx);
		}
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}
	return 0;
}

/**
 * Returns the underlying map implementation.
 */
void *
map_implementation(const map_t *m)
{
	map_check(m);

	switch (m->type) {
	case MAP_HASH:
		return m->u.ht;
	case MAP_ORDERED_HASH:
		return m->u.ot;
	case MAP_PATRICIA:
		return m->u.pt;
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}

	return NULL;
}

/**
 * Release the map encapsulation, returning the underlying implementation
 * object (will need to be cast back to the proper type for perusal).
 */
void *
map_release(map_t *m)
{
	void *implementation;

	map_check(m);

	implementation = map_implementation(m);

	m->type = MAP_MAXTYPE;
	m->magic = 0;
	WFREE(m);

	return implementation;
}

/**
 * Destroy a map.
 */
void
map_destroy(map_t *m)
{
	map_check(m);

	switch (m->type) {
	case MAP_HASH:
		htable_free_null(&m->u.ht);
		break;
	case MAP_ORDERED_HASH:
		ohash_table_destroy_null(&m->u.ot);
		break;
	case MAP_PATRICIA:
		patricia_destroy(m->u.pt);
		break;
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}

	m->type = MAP_MAXTYPE;
	m->magic = 0;
	WFREE(m);
}

/**
 * Destroy a map, nullifying its pointer.
 */
void
map_destroy_null(map_t **m_ptr)
{
	map_t *m = *m_ptr;

	if (m != NULL) {
		map_destroy(m);
		*m_ptr = NULL;
	}
}

/***
 *** Timing tests.
 ***/

#define ITEM_COUNT		10000
#define LOOPS			100
#define KEYBITS			(SHA1_RAW_SIZE * 8)

static void
test_map_insert(void *o, sha1_t *keys, size_t count)
{
	size_t i;
	map_t *m = o;

	for (i = 0; i < count; i++)
		map_insert(m, &keys[i], GINT_TO_POINTER(i+1));
}

static void
test_map_contains(void *o, sha1_t *keys, size_t count)
{
	size_t i;
	size_t items;
	map_t *m = o;

	for (items = 0, i = 0; i < count; i++)
		items += map_contains(m, &keys[i]) ? 1 : 0;

	g_assert(items == count);
}

static void
test_map_remove(void *o, sha1_t *keys, size_t count)
{
	size_t i;
	map_t *m = o;

	for (i = 0; i < count; i++)
		map_remove(m, &keys[i]);
}

static double G_COLD
timeit(
	void (*f)(void *, sha1_t *, size_t),
	void *o, sha1_t *keys, size_t count, size_t iter, const char *what,
	bool verbose)
{
	size_t i;
	tm_t start, end;
	double elapsed;

	tm_now_exact(&start);
	for (i = 0; i < iter; i++)
		(*f)(o, keys, count);
	tm_now_exact(&end);
	elapsed = tm_elapsed_f(&end, &start);

	if (verbose)
		g_debug("%s (%zu items, %zu loop%s): %F s (average: %F s)", what,
			count, iter, plural(iter), elapsed, elapsed / iter);

	return elapsed;
}

void G_COLD
map_test(void)
{
	sha1_t *keys;
	map_t *mh, *mp;
	int i;
	size_t count;
	int tests;
	struct {
		unsigned insertion, contains, removal;
	} faster = { 0, 0, 0};
	bool verbose = common_stats > 1;

	if (common_stats <= 0)
		return;

	XMALLOC_ARRAY(keys, ITEM_COUNT);

	for (i = 0; i < ITEM_COUNT; i++)
		random_bytes(keys[i].data, SHA1_RAW_SIZE);

	mh = map_create_hash(sha1_hash, sha1_eq);
	mp = map_create_patricia(KEYBITS);

	timeit(test_map_insert, mh, keys, ITEM_COUNT,
		LOOPS, "map hash insertion", verbose);

	timeit(test_map_insert, mp, keys, ITEM_COUNT,
		LOOPS, "map PATRICIA insertion", verbose);

	map_destroy(mh);
	map_destroy(mp);

	for (tests = 0, count = ITEM_COUNT; count > 1; count /= 10) {
		double htime;
		double ptime;

		tests++;

		mh = map_create_hash(sha1_hash, sha1_eq);
		mp = map_create_patricia(KEYBITS);

		htime = timeit(test_map_insert, mh, keys, count,
			1, "map hash reloading", verbose);

		ptime = timeit(test_map_insert, mp, keys, count,
			1, "map PATRICIA reloading", verbose);

		if (verbose)
			g_info("PATRICIA insertion %s than hash with %zu items",
				ptime < htime ? "faster" : "slower", count);

		if (ptime < htime)
			faster.insertion++;

		htime = timeit(test_map_contains, mh, keys, count,
			LOOPS, "map hash contains", verbose);

		ptime = timeit(test_map_contains, mp, keys, count,
			LOOPS, "map PATRICIA contains", verbose);

		if (verbose)
			g_info("PATRICIA contains %s than hash with %zu items",
				ptime < htime ? "faster" : "slower", count);

		if (ptime < htime)
			faster.contains++;

		htime = timeit(test_map_remove, mh, keys, count,
			1, "map hash remove", verbose);

		ptime = timeit(test_map_remove, mp, keys, count,
			1, "map PATRICIA remove", verbose);

		if (verbose)
			g_info("PATRICIA remove %s than hash with %zu items",
				ptime < htime ? "faster" : "slower", count);

		if (ptime < htime)
			faster.removal++;

		map_destroy(mh);
		map_destroy(mp);
	}

	if (faster.insertion)
		g_info("PATRICIA insert was faster than hash in %d out of %d tests",
			faster.insertion, tests);
	if (faster.contains)
		g_info(
			"PATRICIA contains was faster than hash in %d out of %d tests",
			faster.contains, tests);
	if (faster.removal)
		g_info("PATRICIA remove was faster than hash in %d out of %d tests",
			faster.removal, tests);

	XFREE_NULL(keys);
}

/* vi: set ts=4 sw=4 cindent: */
