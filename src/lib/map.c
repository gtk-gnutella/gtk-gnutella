/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

RCSID("$Id$")

#include "map.h"
#include "debug.h"
#include "misc.h"
#include "patricia.h"
#include "walloc.h"
#include "tm.h"					/* For tests */
#include "atoms.h"				/* For tests */
#include "override.h"			/* Must be the last header included */

/**
 * Allowed map types.
 */
enum map_type {
	MAP_HASH = 0x1,			/* Hash table from glib */
	MAP_PATRICIA,			/* PATRICIA tree */

	MAP_MAXTYPE
};

/**
 * The map structure holding the necessary information to delegate all
 * the operations to different implementations.
 */
struct map {
	union {
		GHashTable *ht;
		patricia_t *pt;
	} u;
	enum map_type type;
};

/**
 * Create a map implemented as a hash table.
 *
 * @param hash_func		the hash function for keys
 * @param key_eq_func	the key comparison function
 *
 * @return the new map
 */
map_t *
map_create_hash(GHashFunc hash_func, GEqualFunc key_eq_func)
{
	map_t *m;

	m = walloc(sizeof *m);
	m->type = MAP_HASH;
	m->u.ht = g_hash_table_new(hash_func, key_eq_func);

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

	m = walloc(sizeof *m);
	m->type = MAP_PATRICIA;
	m->u.pt = patricia_create(keybits);

	return m;
}

/**
 * Create a map out of an existing hash table.
 * Use map_release() to discard the map encapsulation.
 */
map_t *
map_create_from_hash(GHashTable *ht)
{
	map_t *m;

	g_assert(ht);

	m = walloc(sizeof *m);
	m->type = MAP_HASH;
	m->u.ht = ht;

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

	m = walloc(sizeof *m);
	m->type = MAP_PATRICIA;
	m->u.pt = pt;

	return m;
}

/**
 * Switch the implementation of an existing map to a hash table.
 * Returns the previous implementation.
 */
gpointer
map_switch_to_hash(map_t *m, GHashTable *ht)
{
	gpointer implementation;

	g_assert(m);
	g_assert(ht);

	implementation = map_implementation(m);
	m->type = MAP_HASH;
	m->u.ht = ht;

	return implementation;
}

/**
 * Switch the implementation of an existing map to a PATRICIA tree.
 * Returns the previous implementation.
 */
gpointer
map_switch_to_patricia(map_t *m, patricia_t *pt)
{
	gpointer implementation;

	g_assert(m);
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
map_insert(const map_t *m, gconstpointer key, gconstpointer value)
{
	g_assert(m);

	switch (m->type) {
	case MAP_HASH:
		gm_hash_table_insert_const(m->u.ht, key, value);
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
map_replace(const map_t *m, gconstpointer key, gconstpointer value)
{
	g_assert(m);

	switch (m->type) {
	case MAP_HASH:
		gm_hash_table_replace_const(m->u.ht, key, value);
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
 */
void
map_remove(const map_t *m, gconstpointer key)
{
	g_assert(m);

	switch (m->type) {
	case MAP_HASH:
		g_hash_table_remove(m->u.ht, key);
		break;
	case MAP_PATRICIA:
		(void) patricia_remove(m->u.pt, key);
		break;
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}
}

/**
 * Check whether map contains the key.
 */
gboolean
map_contains(const map_t *m, gconstpointer key)
{
	g_assert(m);

	switch (m->type) {
	case MAP_HASH:
		return g_hash_table_lookup_extended(m->u.ht, key, NULL, NULL);
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
gpointer
map_lookup(const map_t *m, gconstpointer key)
{
	g_assert(m);

	switch (m->type) {
	case MAP_HASH:
		return g_hash_table_lookup(m->u.ht, key);
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
	g_assert(m);

	switch (m->type) {
	case MAP_HASH:
		return g_hash_table_size(m->u.ht);
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
gboolean
map_lookup_extended(const map_t *m, gconstpointer key,
	gpointer *okey, gpointer *oval)
{
	g_assert(m);

	switch (m->type) {
	case MAP_HASH:
		return g_hash_table_lookup_extended(m->u.ht, key, okey, oval);
	case MAP_PATRICIA:
		return patricia_lookup_extended(m->u.pt, key, okey, oval);
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}
	return FALSE;
}

/**
 * Structure used to handle foreach() trampoline for PATRICIA.
 */
struct pat_foreach {
	map_cb_t cb;		/* Registered user callback */
	gpointer u;			/* User callback additional arg */
};

/**
 * foreach() trampoline for PATRICIA.
 */
static void
pat_foreach_wrapper(gpointer key, size_t u_keybits, gpointer value, gpointer u)
{
	struct pat_foreach *ctx = u;

	(void) u_keybits;

	ctx->cb(key, value, ctx->u);
}

/**
 * Iterate on each item of the map, applying callback.
 */
void
map_foreach(const map_t *m, map_cb_t cb, gpointer u)
{
	g_assert(m);
	g_assert(cb);

	switch (m->type) {
	case MAP_HASH:
		g_hash_table_foreach(m->u.ht, cb, u);
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
	map_cbr_t cb;		/* Registered user callback */
	gpointer u;			/* User callback additional arg */
};

/**
 * foreach() trampoline for PATRICIA.
 */
static gboolean
pat_foreach_remove_wrapper(
	gpointer key, size_t u_keybits, gpointer value, gpointer u)
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
size_t map_foreach_remove(const map_t *m, map_cbr_t cb, gpointer u)
{
	g_assert(m);
	g_assert(cb);

	switch (m->type) {
	case MAP_HASH:
		return g_hash_table_foreach_remove(m->u.ht, cb, u);
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
gpointer
map_implementation(const map_t *m)
{
	g_assert(m);

	switch (m->type) {
	case MAP_HASH:
		return m->u.ht;
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
gpointer
map_release(map_t *m)
{
	gpointer implementation;

	g_assert(m);

	implementation = map_implementation(m);

	m->type = MAP_MAXTYPE;
	wfree(m, sizeof *m);

	return implementation;
}

/**
 * Destroy a map.
 */
void
map_destroy(map_t *m)
{
	g_assert(m);

	switch (m->type) {
	case MAP_HASH:
		g_hash_table_destroy(m->u.ht);
		break;
	case MAP_PATRICIA:
		patricia_destroy(m->u.pt);
		break;
	case MAP_MAXTYPE:
		g_assert_not_reached();
	}

	m->type = MAP_MAXTYPE;
	wfree(m, sizeof *m);
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

static double
timeit(
	void (*f)(void *, sha1_t *, size_t),
	void *o, sha1_t *keys, size_t count, size_t iter, const char *what,
	gboolean verbose)
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
		g_message("%s (%lu items, %lu loop%s): %f s (average: %f s)", what,
			(unsigned long) count, (gulong) iter, iter == 1 ? "" : "s",
			elapsed, elapsed / iter);

	return elapsed;
}

void
map_test(void)
{
	sha1_t *keys;
	map_t *mh, *mp;
	int i;
	size_t count;
	int tests;
	int faster[3] = { 0, 0, 0};
	gboolean verbose = common_dbg > 0;

#define INSERT_IDX		0
#define CONTAINS_IDX	1
#define REMOVE_IDX		2

	keys = g_malloc(ITEM_COUNT * sizeof *keys);

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
			g_message("PATRICIA insertion %s than hash with %lu items",
				ptime < htime ? "faster" : "slower", (unsigned long) count);

		if (ptime < htime)
			faster[INSERT_IDX]++;

		htime = timeit(test_map_contains, mh, keys, count,
			LOOPS, "map hash contains", verbose);

		ptime = timeit(test_map_contains, mp, keys, count,
			LOOPS, "map PATRICIA contains", verbose);

		if (verbose)
			g_message("PATRICIA contains %s than hash with %lu items",
				ptime < htime ? "faster" : "slower", (unsigned long) count);

		if (ptime < htime)
			faster[CONTAINS_IDX]++;

		htime = timeit(test_map_remove, mh, keys, count,
			1, "map hash remove", verbose);

		ptime = timeit(test_map_remove, mp, keys, count,
			1, "map PATRICIA remove", verbose);

		if (verbose)
			g_message("PATRICIA remove %s than hash with %lu items",
				ptime < htime ? "faster" : "slower", (unsigned long) count);

		if (ptime < htime)
			faster[REMOVE_IDX]++;

		map_destroy(mh);
		map_destroy(mp);
	}

	if (faster[INSERT_IDX])
		g_message("PATRICIA insert was faster than hash in %d out of %d tests",
			faster[INSERT_IDX], tests);
	if (faster[CONTAINS_IDX])
		g_message(
			"PATRICIA contains was faster than hash in %d out of %d tests",
			faster[CONTAINS_IDX], tests);
	if (faster[REMOVE_IDX])
		g_message("PATRICIA remove was faster than hash in %d out of %d tests",
			faster[REMOVE_IDX], tests);

	G_FREE_NULL(keys);
}

/* vi: set ts=4 sw=4 cindent: */
