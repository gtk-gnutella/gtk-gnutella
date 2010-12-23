/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Ordered hash table preserving the order of its keys.
 *
 * Because this is implemented as a compound structure, the "foreach_remove"
 * operations are rather expensive when removal is not systematic, and should
 * be avoided if possible.
 *
 * With removal callbacks which always return TRUE, it is better to iterate
 * with ohash_table_random_foreach_remove(), which will be more efficient
 * than ohash_table_foreach_remove().
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

RCSID("$Id$")

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
	GHashTable *ht;			/**< Maps keys -> values */
	hash_list_t *hl;		/**< Remembers order of keys */
};

static inline void
ohash_table_check(const struct ohash_table * const oh)
{
	g_assert(oh != NULL);
	g_assert(OHASH_TABLE_MAGIC == oh->magic);
	g_assert(oh->ht != NULL);
	g_assert(oh->hl != NULL);
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
ohash_table_new(GHashFunc hash_func, GEqualFunc key_eq_func)
{
	ohash_table_t *oh;

	oh = walloc(sizeof *oh);
	oh->magic = OHASH_TABLE_MAGIC;
	oh->ht = g_hash_table_new(hash_func, key_eq_func);
	oh->hl = hash_list_new(hash_func, key_eq_func);

	return oh;
}

/**
 * Free an ordered hash table.
 */
void
ohash_table_destroy(ohash_table_t *oh)
{
	ohash_table_check(oh);

	gm_hash_table_destroy_null(&oh->ht);
	hash_list_free(&oh->hl);
	oh->magic = 0;
	wfree(oh, sizeof *oh);
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
	ohash_table_check(oh);

	if (!hash_list_contains(oh->hl, key))
		hash_list_append(oh->hl, key);

	gm_hash_table_insert_const(oh->ht, key, value);
}

/**
 * Replace a key/value pair in the table.
 *
 * If the key already existed, the old key/values are replaced by the new ones.
 *
 * For ordering purposes, the key is appended to the list of keys.
 */
void
ohash_table_replace(ohash_table_t *oh, const void *key, const void *value)
{
	ohash_table_check(oh);

	if (hash_list_contains(oh->hl, key))
		hash_list_remove(oh->hl, key);

	gm_hash_table_replace_const(oh->ht, key, value);
	hash_list_append(oh->hl, key);
}

/**
 * Remove a key from the table.
 *
 * @return TRUE if the key was found and removed.
 */
gboolean
ohash_table_remove(ohash_table_t *oh, const void *key)
{
	ohash_table_check(oh);

	if (!hash_list_contains(oh->hl, key))
		return FALSE;

	g_hash_table_remove(oh->ht, key);
	hash_list_remove(oh->hl, key);

	return TRUE;
}

/**
 * Check whether a key is contained in the table.
 */
gboolean
ohash_table_contains(const ohash_table_t *oh, const void *key)
{
	ohash_table_check(oh);

	return hash_list_contains(oh->hl, key);
}

/**
 * Lookup a key in the table.
 */
void *
ohash_table_lookup(const ohash_table_t *oh, const void *key)
{
	ohash_table_check(oh);

	return g_hash_table_lookup(oh->ht, key);
}

/**
 * Extended lookup of a key in the table, returning both key/value pointers.
 */
gboolean
ohash_table_lookup_extended(const ohash_table_t *oh, const void *key,
	void *okey, void *oval)
{
	return g_hash_table_lookup_extended(oh->ht, key, okey, oval);
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

/**
 * Iterator over the table: apply function on each entry.
 *
 * Order of traversal is random.
 */
void
ohash_table_random_foreach(const ohash_table_t *oh, GHFunc func, void *data)
{
	g_hash_table_foreach(oh->ht, func, data);
}

struct ohash_random_foreach_remove_ctx {
	hash_list_t *hl;
	GHRFunc func;
	void *data;
};

static gboolean
ohash_table_random_foreach_remove_helper(void *key, void *value, void *data)
{
	struct ohash_random_foreach_remove_ctx *ctx = data;
	gboolean remove_entry;
	void *pos;

	/*
	 * Updates ae not atomic: since we have two structures sharing the same
	 * physical objects (the key here), and given the user callback can free
	 * up the key, we cannot access the key if the callback returns TRUE.
	 *
	 * However, if the key is removed from the hash table, we must remove it
	 * from the hash list.  But if it is not removed, it must remain in the
	 * hash list.
	 *
	 * The solution to this dilemna is to remove the key from the hash list
	 * whilst remembering its position, so that we can possibly re-insert it
	 * if the key ends up being kept (since then it is safe to access it).
	 */

	pos = hash_list_remove_position(ctx->hl, key);
	g_assert(pos != NULL);

	remove_entry = (*ctx->func)(key, value, ctx->data);

	if (remove_entry) {
		hash_list_forget_position(pos);
	} else {
		hash_list_insert_position(ctx->hl, key, pos);
	}

	return remove_entry;
}

/**
 * Iterator over the table: apply function on each entry and remove from the
 * table if the function returns TRUE.
 *
 * Order of traversal is random.
 *
 * @return amount of items removed.
 */
size_t
ohash_table_random_foreach_remove(const ohash_table_t *oh,
	GHRFunc func, void *data)
{
	struct ohash_random_foreach_remove_ctx ctx;

	ctx.hl = oh->hl;
	ctx.func = func;
	ctx.data = data;

	return g_hash_table_foreach_remove(oh->ht,
		ohash_table_random_foreach_remove_helper, &ctx);
}

struct ohash_foreach_ctx {
	GHashTable *ht;
	GHFunc func;
	void *data;
};

static void
ohash_table_foreach_helper(void *key, void *data)
{
	struct ohash_foreach_ctx *ctx = data;
	void *value;

	value = g_hash_table_lookup(ctx->ht, key);
	(*ctx->func)(key, value, ctx->data);
}

/**
 * Iterator over the table: apply function on each entry.
 *
 * The table is traversed in the order of keys.
 */
void
ohash_table_foreach(const ohash_table_t *oh, GHFunc func, void *data)
{
	struct ohash_foreach_ctx ctx;

	ctx.ht = oh->ht;
	ctx.func = func;
	ctx.data = data;

	hash_list_foreach(oh->hl, ohash_table_foreach_helper, &ctx);
}

struct ohash_foreach_remove_ctx {
	GHashTable *ht;
	GHRFunc func;
	void *data;
};

static gboolean
ohash_table_foreach_remove_helper(void *key, void *data)
{
	struct ohash_foreach_remove_ctx *ctx = data;
	void *value;
	gboolean remove_entry;

	/*
	 * Since the callback can free-up the key/value type, we have to assume
	 * it will and remove the entry from the hash table before invoking it.
	 * If it ends up leaving the entry in place, we put it back.
	 */

	value = g_hash_table_lookup(ctx->ht, key);
	g_hash_table_remove(ctx->ht, key);
	remove_entry = (*ctx->func)(key, value, ctx->data);
	if (!remove_entry)
		g_hash_table_insert(ctx->ht, key, value);

	return remove_entry;
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
ohash_table_foreach_remove(const ohash_table_t *oh, GHRFunc func, void *data)
{
	struct ohash_foreach_remove_ctx ctx;

	ctx.ht = oh->ht;
	ctx.func = func;
	ctx.data = data;

	return hash_list_foreach_remove(oh->hl,
		ohash_table_foreach_remove_helper, &ctx);
}

/* vi: set ts=4 sw=4 cindent: */
