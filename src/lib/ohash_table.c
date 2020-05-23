/*
 * Copyright (c) 2010-2011, Raphael Manfredi
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
 * @date 2010-2011
 */

#include "common.h"

#include "ohash_table.h"
#include "glib-missing.h"
#include "hashlist.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum ohash_table_magic { OHASH_TABLE_MAGIC = 0x4a3e2b74U };

/**
 * An ordered hash table.
 */
struct ohash_table {
	enum ohash_table_magic magic;
	hash_list_t *hl;		/**< Remembers order of keys, contains values */
	hash_fn_t hash_func;
	eq_fn_t key_eq_func;
};

/**
 * A pair (key, value) stored in the ordered table.
 *
 * Each pair must reference the table that contains it so that we can access
 * the proper key hashing and comparing functions.
 */
struct ohash_pair {
	const struct ohash_table *oh;		/**< Table in which pair is held */
	const void *key;					/**< The key */
	const void *value;					/**< The value */
};

static inline void
ohash_table_check(const struct ohash_table * const oh)
{
	g_assert(oh != NULL);
	g_assert(OHASH_TABLE_MAGIC == oh->magic);
	g_assert(oh->hl != NULL);
}

/**
 * Hash function for the key from the key/value pair.
 */
static unsigned
ohash_key_hash(const void *key)
{
	const struct ohash_pair *op = key;

	g_assert(key != NULL);
	ohash_table_check(op->oh);

	return (*op->oh->hash_func)(op->key);
}

/**
 * Compare function for key/value pairs.
 */
static int
ohash_key_eq(const void *k1, const void *k2)
{
	const struct ohash_pair *op1 = k1, *op2 = k2;

	g_assert(k1 != NULL);
	g_assert(k2 != NULL);
	g_assert(op1->oh == op2->oh);		/* Keys from same table */
	ohash_table_check(op1->oh);

	return (*op1->oh->key_eq_func)(op1->key, op2->key);
}

/**
 * Create a new ordered hash table.
 *
 * @param hash_func			the hash function for keys
 * @param keys_eq_func		the key comparison function
 *
 * @return the new ordered hash table.
 */
ohash_table_t *
ohash_table_new(hash_fn_t hash_func, eq_fn_t key_eq_func)
{
	ohash_table_t *oh;

	WALLOC(oh);
	oh->magic = OHASH_TABLE_MAGIC;
	oh->hl = hash_list_new(ohash_key_hash, ohash_key_eq);
	oh->hash_func = hash_func;
	oh->key_eq_func = key_eq_func;

	return oh;
}

/**
 * Free key/value pair.
 */
static void
ohash_free_kv(void *kv)
{
	struct ohash_pair *op = kv;
	WFREE(op);
}

/**
 * Free an ordered hash table.
 */
void
ohash_table_destroy(ohash_table_t *oh)
{
	ohash_table_check(oh);

	hash_list_free_all(&oh->hl, ohash_free_kv);
	oh->magic = 0;
	WFREE(oh);
}

/**
 * Free ordered hash table and nullify its pointer.
 */
void
ohash_table_destroy_null(ohash_table_t **oh_ptr)
{
	ohash_table_t *oh = *oh_ptr;

	if (oh != NULL) {
		ohash_table_destroy(oh);
		*oh_ptr = NULL;
	}
}

/**
 * Insert a key/value pair in the table.
 *
 * If the key already exists, the value is replaced (but the old key is kept).
 *
 * For ordering purposes, the key is appended to the list of keys, unless it
 * already existed in which case its position is unchanged.
 */
void
ohash_table_insert(ohash_table_t *oh, const void *key, const void *value)
{
	struct ohash_pair pk;

	ohash_table_check(oh);

	pk.oh = oh;
	pk.key = key;

	if (!hash_list_contains(oh->hl, &pk)) {
		struct ohash_pair *op;

		WALLOC(op);
		op->key = key;
		op->value = value;
		op->oh = oh;
		hash_list_append(oh->hl, op);
	}
}

/**
 * Replace a key/value pair in the table.
 *
 * If the key already existed, the old key/values are replaced by the new ones,
 * at the same position.  Otherwise, the key is appended.
 *
 * @return TRUE when replacement occurred (the key existed).
 */
bool
ohash_table_replace(ohash_table_t *oh, const void *key, const void *value)
{
	struct ohash_pair pk;
	struct ohash_pair *op;
	const void *hkey;
	void *pos = NULL;

	ohash_table_check(oh);

	pk.oh = oh;
	pk.key = key;

	if (hash_list_find(oh->hl, &pk, &hkey)) {
		op = deconstify_pointer(hkey);
		g_assert(op->oh == oh);
		pos = hash_list_remove_position(oh->hl, &pk);
	} else {
		WALLOC(op);
		op->oh = oh;
		op->key = key;
	}

	op->value = value;
	if (pos != NULL) {
		hash_list_insert_position(oh->hl, op, pos);
	} else {
		hash_list_append(oh->hl, op);
	}

	return pos != NULL;
}

/**
 * Remove a key from the table.
 *
 * @return TRUE if the key was found and removed.
 */
bool
ohash_table_remove(ohash_table_t *oh, const void *key)
{
	struct ohash_pair pk;
	struct ohash_pair *op;

	ohash_table_check(oh);

	pk.oh = oh;
	pk.key = key;

	if (!hash_list_contains(oh->hl, &pk))
		return FALSE;

	op = hash_list_remove(oh->hl, &pk);
	g_assert(op->oh == oh);
	ohash_free_kv(op);

	return TRUE;
}

/**
 * Check whether a key is contained in the table.
 */
bool
ohash_table_contains(const ohash_table_t *oh, const void *key)
{
	struct ohash_pair pk;

	ohash_table_check(oh);

	pk.oh = oh;
	pk.key = key;

	return hash_list_contains(oh->hl, &pk);
}

/**
 * Lookup a key in the table.
 */
void *
ohash_table_lookup(const ohash_table_t *oh, const void *key)
{
	struct ohash_pair pk;
	const void *hkey;

	ohash_table_check(oh);

	pk.oh = oh;
	pk.key = key;

	if (hash_list_find(oh->hl, &pk, &hkey)) {
		const struct ohash_pair *op = hkey;
		g_assert(op->oh == oh);
		return deconstify_pointer(op->value);
	} else {
		return NULL;
	}
}

/**
 * Extended lookup of a key in the table, returning both key/value pointers.
 */
bool
ohash_table_lookup_extended(const ohash_table_t *oh, const void *key,
	void *okey, void *oval)
{
	struct ohash_pair pk;
	const void *hkey;

	ohash_table_check(oh);

	pk.oh = oh;
	pk.key = key;

	if (hash_list_find(oh->hl, &pk, &hkey)) {
		const struct ohash_pair *op = hkey;
		g_assert(op->oh == oh);
		if (okey != NULL)
			*(void **) okey = deconstify_pointer(op->key);
		if (oval != NULL)
			*(void **) oval = deconstify_pointer(op->value);
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * @return amount of items held in table.
 */
size_t
ohash_table_count(const ohash_table_t *oh)
{
	ohash_table_check(oh);

	return hash_list_length(oh->hl);
}

struct ohash_foreach_ctx {
	keyval_fn_t func;
	void *data;
};

static void
ohash_table_foreach_helper(void *key, void *data)
{
	struct ohash_pair *op = key;
	struct ohash_foreach_ctx *ctx = data;

	(*ctx->func)(deconstify_pointer(op->key), deconstify_pointer(op->value),
		ctx->data);
}

/**
 * Iterator over the table: apply function on each entry.
 *
 * The table is traversed in the order of keys.
 */
void
ohash_table_foreach(const ohash_table_t *oh, keyval_fn_t func, void *data)
{
	struct ohash_foreach_ctx ctx;

	ctx.func = func;
	ctx.data = data;

	hash_list_foreach(oh->hl, ohash_table_foreach_helper, &ctx);
}

struct ohash_foreach_remove_ctx {
	keyval_rm_fn_t func;
	void *data;
};

static bool
ohash_table_foreach_remove_helper(void *key, void *data)
{
	struct ohash_pair *op = key;
	struct ohash_foreach_remove_ctx *ctx = data;

	return (*ctx->func)(deconstify_pointer(op->key),
		deconstify_pointer(op->value), ctx->data);
}

/**
 * Iterator over the table: apply function on each entry, removing it when
 * the function returns TRUE.
 *
 * The table is traversed in the order of keys.
 *
 * @return the amount of items removed from the table.
 */
size_t
ohash_table_foreach_remove(const ohash_table_t *oh,
	keyval_rm_fn_t func, void *data)
{
	struct ohash_foreach_remove_ctx ctx;

	ctx.func = func;
	ctx.data = data;

	return hash_list_foreach_remove(oh->hl,
		ohash_table_foreach_remove_helper, &ctx);
}

/* vi: set ts=4 sw=4 cindent: */
