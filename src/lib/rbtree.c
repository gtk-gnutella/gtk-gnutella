/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * Red-Black Tree container.
 *
 * A red-black tree is a particular implementation of a sorted set which
 * uses O(n) memory and O(log n) for insertion, lookups and removals.
 *
 * Contrary to a sorted array which has O(n) complexity for insertions and
 * removals and only O(log n) for lookups, the red-black tree offers the
 * same complexity for insertions and removals, at the price of more space
 * used than with a sorted array.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "rbtree.h"
#include "erbtree.h"
#include "unsigned.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum rbtree_magic { RBTREE_MAGIC = 0x4eb7308c };

/**
 * A red-black tree descritor.
 */
struct rbtree {
	enum rbtree_magic magic;	/* Magic number */
	size_t refcnt;				/* Iterator reference count */
	size_t stamp;				/* Modification stamp */
	cmp_fn_t cmp;				/* Item comparison routine */
	erbtree_ext_t tree;			/* The (extended) tree */
};

static inline void
rbtree_check(const struct rbtree * const rbt)
{
	g_assert(rbt != NULL);
	g_assert(RBTREE_MAGIC == rbt->magic);
}

/*
 * A node in our red-black tree.
 */
struct rbdata {
	rbnode_t node;				/* Embedded tree structure */
	void *data;					/* Data held */
};

enum rbtree_iter_magic { RBTREE_ITER_MAGIC = 0x2be28d13 };

/**
 * A red-black tree iterator.
 */
struct rbtree_iter {
	enum rbtree_iter_magic magic;
	const rbtree_t *tree;
	struct rbdata *item;		/* Current item being iterated over */
	rbnode_t *next;				/* Next node to return */
	size_t stamp;				/* Modification stamp (at iteration start) */
	size_t visited;				/* Amount of visited nodes (for assertions) */
	size_t removed;				/* Amount of removed nodes during traversal */
};

static inline void
rbtree_iter_check(const struct rbtree_iter * const ri)
{
	g_assert(ri != NULL);
	g_assert(RBTREE_ITER_MAGIC == ri->magic);
	rbtree_check(ri->tree);
}

#define ERBTREE(x)	((erbtree_t *) &(x)->tree)

/**
 * Internal data comparison routine trampoline.
 */
static int
rbtree_cmp(const void *a, const void *b, void *data)
{
	rbtree_t *tree = data;
	const struct rbdata *da = a, *db = b;

	rbtree_check(tree);

	return (*tree->cmp)(da->data, db->data);
}

/**
 * Creates a new red-black tree.
 *
 * @param cmp		the item comparison routine
 *
 * @return a new red-back tree container.
 */
rbtree_t *
rbtree_create(cmp_fn_t cmp)
{
	rbtree_t *rbt;

	WALLOC0(rbt);
	rbt->magic = RBTREE_MAGIC;
	rbt->cmp = cmp;
	erbtree_init_data(&rbt->tree, rbtree_cmp, rbt,
		offsetof(struct rbdata, node));

	return rbt;
}

/**
 * @return amount of items held in tree.
 */ 
size_t
rbtree_count(const rbtree_t *rbt)
{
	rbtree_check(rbt);

	return erbtree_count(ERBTREE(rbt));
}

/**
 * Check whether tree contains the specified key.
 *
 * @param rbt		the red-black tree
 * @param key		the item key to look up
 *
 * @return whether key exists in the tree.
 */
bool
rbtree_contains(const rbtree_t *rbt, const void *key)
{
	struct rbdata item;

	rbtree_check(rbt);
	g_assert(key != NULL);

	item.data = deconstify_pointer(key);
	return erbtree_contains(ERBTREE(rbt), &item);
}

/**
 * Lookup key in the tree.
 *
 * The item returned is the data stored in the tree, which contains a
 * key that is identical to the supplied lookup key.  This means the
 * returned value cannot be NULL if the key is present.
 *
 * @param rbt		the red-black tree
 * @param key		the item key to look up
 *
 * @return the data associated with the key (with key embedded in data),
 * or NULL if the key is not present.
 */
void *
rbtree_lookup(const rbtree_t *rbt, const void *key)
{
	struct rbdata *rd;
	struct rbdata item;

	rbtree_check(rbt);
	g_assert(key != NULL);

	item.data = deconstify_pointer(key);
	rd = erbtree_lookup(ERBTREE(rbt), &item);

	return NULL == rd ? NULL : rd->data;
}

/**
 * Extended lookup in the tree to fetch value and the node cursor.
 *
 * The node cursor can then be used to efficiently traverse the tree.
 *
 * @param rbt		the red-black tree
 * @param key		the item key to look up
 * @param node		where the node cursor is written
 *
 * @return the data associate with the key, or NULL if the key is not present.
 * When the key is found, `node' is update to the internal cursor in the
 * tree.  Its lifespan is that of the tree or of the item (if removed).
 */
void *
rbtree_lookup_node(const rbtree_t *rbt, const void *key, rbnode_t **node)
{
	struct rbdata *rd;
	struct rbdata item;

	rbtree_check(rbt);
	g_assert(key != NULL);

	item.data = deconstify_pointer(key);
	rd = erbtree_lookup(ERBTREE(rbt), &item);

	if (NULL == rd)
		return NULL;

	if (node != NULL)
		*node = &rd->node;

	return rd->data;
}

/**
 * Attempt to insert new item in tree.
 *
 * @param rbt		the red-black tree
 * @param item		the item to insert
 *
 * @return TRUE if insertion was successful, FALSE if an item with the
 * same key already exists.
 */
bool
rbtree_insert_try(rbtree_t *rbt, const void *item)
{
	struct rbdata *rd;

	rbtree_check(rbt);
	g_assert(item != NULL);

	WALLOC0(rd);
	rd->data = deconstify_pointer(item);

	if (NULL == erbtree_insert(ERBTREE(rbt), &rd->node)) {
		rbt->stamp++;
		return TRUE;
	}

	WFREE(rd);
	return FALSE;
}

/**
 * Insert new item in tree.
 *
 * An item with the same key must not already exist in the tree.  If it
 * could be existing, either perform a rbtree_contains() check first,
 * or use rbtree_insert_try().
 *
 * @param rbt		the red-black tree
 * @param item		the item to insert
 */
void
rbtree_insert(rbtree_t *rbt, const void *item)
{
	struct rbdata *rd;

	rbtree_check(rbt);
	g_assert(item != NULL);

	WALLOC0(rd);
	rd->data = deconstify_pointer(item);

	if (NULL == erbtree_insert(ERBTREE(rbt), &rd->node)) {
		rbt->stamp++;
		return;
	}

	g_error("%s(): duplicate key already exists", G_STRFUNC);
}

/**
 * Replace item in the tree if it exists, otherwise insert.
 *
 * @param rbt		the red-black tree
 * @param item		the item to insert
 * @param old_item	where the old item is written back, if not NULL
 *
 * @return TRUE if we replaced an existing item (with old_item set), FALSE
 * if we only inserted.
 */
bool
rbtree_replace(rbtree_t *rbt, const void *item, void **old_item)
{
	struct rbdata *rd, *old;

	rbtree_check(rbt);
	g_assert(item != NULL);

	WALLOC0(rd);
	rd->data = deconstify_pointer(item);

	old = erbtree_lookup(ERBTREE(rbt), rd);

	if (NULL == old) {
		void *ok = erbtree_insert(ERBTREE(rbt), &rd->node);
		g_assert(NULL == ok);
		rbt->stamp++;
		return FALSE;		/* Not a replacement */
	}

	/*
	 * A replacement does not change the tree, so do not update the stamp.
	 */

	erbtree_replace(ERBTREE(rbt), &old->node, &rd->node);

	if (old_item != NULL)
		*old_item = old->data;
	WFREE(old);

	return TRUE;			/* Replaced item */
}

/**
 * Remove key from the tree.
 *
 * @param rbt		the red-black tree
 * @param item		the item to insert
 * @param old_item	where the old item is written back, if not NULL
 *
 * @return TRUE if key was found and item removed, with old_item set, FALSE
 * if the key was not present.
 */
bool
rbtree_remove(rbtree_t *rbt, const void *key, void **old_item)
{
	struct rbdata *rd;
	struct rbdata item;

	rbtree_check(rbt);
	g_assert(key != NULL);

	item.data = deconstify_pointer(key);
	rd = erbtree_lookup(ERBTREE(rbt), &item);

	if (NULL == rd)
		return FALSE;

	erbtree_remove(ERBTREE(rbt), &rd->node);
	rbt->stamp++;

	if (old_item != NULL)
		*old_item = rd->data;
	WFREE(rd);

	return TRUE;
}

/**
 * Fetch next item in the tree.
 *
 * This is OK for infrequent traversals.  Otherwise, better fetch a cursor
 * via rbtree_lookup_node() and traverse with rbtree_next_node().
 *
 * @param rbt		the red-black tree
 * @param key		the item in the tree where we start
 *
 * @return NULL if there is no successor, the next item otherwise.
 */
void *
rbtree_next(const rbtree_t *rbt, const void *key)
{
	struct rbdata *rd;
	struct rbdata item;
	rbnode_t *rn;

	rbtree_check(rbt);
	g_assert(key != NULL);

	item.data = deconstify_pointer(key);
	rd = erbtree_lookup(ERBTREE(rbt), &item);

	if G_UNLIKELY(NULL == rd)
		return NULL;

	rn = erbtree_next(&rd->node);
	if (NULL == rn)
		return NULL;

	rd = erbtree_data(ERBTREE(rbt), rn);

	return rd->data;
}

/**
 * Fetch item in the tree following supplied node.
 *
 * @param rbt		the red-black tree
 * @param key		the node key to look up
 *
 * @return NULL if there is no successor, the next item otherwise.
 * The key parameter is updated with the node of the following item.
 */
void *
rbtree_next_node(const rbtree_t *rbt, rbnode_t **key)
{
	struct rbdata *rd;
	rbnode_t *rn;

	rbtree_check(rbt);
	g_assert(key != NULL);

	rn = erbtree_next(*key);
	if (NULL == rn)
		return NULL;

	rd = erbtree_data(ERBTREE(rbt), rn);
	*key = rn;

	return rd->data;
}

/**
 * Fetch previous item in the tree.
 *
 * This is OK for infrequent traversals.  Otherwise, better fetch a cursor
 * via rbtree_lookup_node() and traverse with rbtree_prev_node().
 *
 * @param rbt		the red-black tree
 * @param key		the item in the tree where we start
 *
 * @return NULL if there is no predecessor, the previous item otherwise.
 */
void *
rbtree_prev(const rbtree_t *rbt, const void *key)
{
	struct rbdata *rd;
	struct rbdata item;
	rbnode_t *rn;

	rbtree_check(rbt);
	g_assert(key != NULL);

	item.data = deconstify_pointer(key);
	rd = erbtree_lookup(ERBTREE(rbt), &item);

	if G_UNLIKELY(NULL == rd)
		return NULL;

	rn = erbtree_prev(&rd->node);
	if (NULL == rn)
		return NULL;

	rd = erbtree_data(ERBTREE(rbt), rn);

	return rd->data;
}

/**
 * Fetch item in the tree preceding supplied node.
 *
 * @param rbt		the red-black tree
 * @param key		the node key to look up
 *
 * @return NULL if there is no predecessor, the previous item otherwise.
 * The key parameter is updated with the node of the preceding item.
 */
void *
rbtree_prev_node(const rbtree_t *rbt, rbnode_t **key)
{
	struct rbdata *rd;
	rbnode_t *rn;

	rbtree_check(rbt);
	g_assert(key != NULL);

	rn = erbtree_prev(*key);
	if (NULL == rn)
		return NULL;

	rd = erbtree_data(ERBTREE(rbt), rn);
	*key = rn;

	return rd->data;
}

struct rbtree_foreach_ctx {
	data_fn_t cb;
	void *data;
};

/**
 * Traversal trampoline.
 */
static void
rbtree_foreach_trampoline(void *item, void *data)
{
	struct rbdata *rd = item;
	struct rbtree_foreach_ctx *ctx = data;

	(*ctx->cb)(rd->data, ctx->data);
}

/**
 * Traverse all the items in the tree, invoking the callback on each item.
 */
void
rbtree_foreach(rbtree_t *rbt, data_fn_t cb, void *data)
{
	struct rbtree_foreach_ctx ctx;

	rbtree_check(rbt);

	ctx.cb = cb;
	ctx.data = data;
	erbtree_foreach(ERBTREE(rbt), rbtree_foreach_trampoline, &ctx);
}

struct rbtree_foreach_remove_ctx {
	rbtree_t *rbt;
	data_rm_fn_t cbr;
	void *data;
};

/**
 * Traversal with possible removal trampoline.
 */
static bool
rbtree_foreach_rm_trampoline(void *item, void *data)
{
	struct rbdata *rd = item;
	struct rbtree_foreach_remove_ctx *ctx = data;

	if ((*ctx->cbr)(rd->data, ctx->data)) {
		WFREE(rd);
		ctx->rbt->stamp++;
		return TRUE;
	}

	return FALSE;
}

/**
 * Traverse all the items in the tree, invoking the callback on each item
 * and removing items for which the callback returns TRUE.
 *
 * @return the amount of removed items.
 */
size_t
rbtree_foreach_remove(rbtree_t *rbt, data_rm_fn_t cbr, void *data)
{
	struct rbtree_foreach_remove_ctx ctx;

	rbtree_check(rbt);
	g_assert(0 == rbt->refcnt);		/* No iteration pending */

	ctx.cbr = cbr;
	ctx.data = data;
	ctx.rbt = rbt;

	return erbtree_foreach_remove(ERBTREE(rbt),
		rbtree_foreach_rm_trampoline, &ctx);
}

static void
rbtree_free_node(void *data)
{
	struct rbdata *rd = data;

	WFREE(rd);
}

/**
 * Clear the tree, discarding all its items without freeing them.
 *
 * @attention
 * Use rbtree_discard() to clear the tree and free the items.
 */
void
rbtree_clear(rbtree_t *rbt)
{
	rbtree_check(rbt);

	/*
	 * We don't free the items but we have to free the nodes.
	 */

	erbtree_discard(ERBTREE(rbt), rbtree_free_node);
	rbt->stamp++;
}

/**
 * Destroy the tree, nullifying its pointer.
 *
 * @attention
 * Note that this does not free up the items still held in the tree.
 * Use rbtree_discard() first if there are remaining items.
 */
void
rbtree_free_null(rbtree_t **tree_ptr)
{
	rbtree_t *rbt = *tree_ptr;

	if (rbt != NULL) {
		rbtree_check(rbt);
		g_assert(0 == rbt->refcnt);		/* No iteration pending */

		rbtree_clear(rbt);
		rbt->magic = 0;
		WFREE(rbt);
		*tree_ptr = NULL;
	}
}

struct rbtree_discard_ctx {
	free_fn_t fcb;
};

static void
rbtree_discard_trampoline(void *p, void *data)
{
	struct rbdata *rd = p;
	struct rbtree_discard_ctx *ctx = data;

	(*ctx->fcb)(rd->data);
	WFREE(rd);
}

/**
 * Discard all the items in the tree, freeing them using the supplied routine.
 *
 * @attention
 * The tree descriptor is not freed.  Use rbtree_free_null() afterwards if
 * it needs to be reclaimed as well.
 */
void
rbtree_discard(rbtree_t *rbt, free_fn_t fcb)
{
	struct rbtree_discard_ctx ctx;
	rbtree_check(rbt);

	ctx.fcb = fcb;

	erbtree_discard_with_data(ERBTREE(rbt), rbtree_discard_trampoline, &ctx);
	rbt->stamp++;
}

struct rbtree_discard_data_ctx {
	free_data_fn_t fcb;
	void *data;
};

static void
rbtree_discard_data_trampoline(void *p, void *data)
{
	struct rbdata *rd = p;
	struct rbtree_discard_data_ctx *ctx = data;

	(*ctx->fcb)(rd->data, ctx->data);
	WFREE(rd);
}

/**
 * Discard all the items in the tree, freeing them using the supplied routine
 * which takes an additional argument.
 *
 * @attention
 * The tree descriptor is not freed.  Use rbtree_free_null() afterwards if
 * it needs to be reclaimed as well.
 */
void
rbtree_discard_with_data(rbtree_t *rbt, free_data_fn_t fcb, void *data)
{
	struct rbtree_discard_data_ctx ctx;

	rbtree_check(rbt);

	ctx.fcb = fcb;
	ctx.data = data;

	erbtree_discard_with_data(ERBTREE(rbt),
		rbtree_discard_data_trampoline, &ctx);

	rbt->stamp++;
}

/**
 * Create a new red-black tree iterator.
 */
rbtree_iter_t *
rbtree_iter_new(const rbtree_t *rbt)
{
	rbtree_iter_t *ri;

	rbtree_check(rbt);

	WALLOC0(ri);
	ri->magic = RBTREE_ITER_MAGIC;
	ri->tree = rbt;
	ri->next = erbtree_first(ERBTREE(rbt));
	ri->stamp = rbt->stamp;

	{
		rbtree_t *wrbt = deconstify_pointer(rbt);
		wrbt->refcnt++;		/* Internal state, OK to change */
	}

	return ri;
}

/**
 * Release iterator and nullify its pointer.
 */
void
rbtree_iter_release(rbtree_iter_t **iter_ptr)
{
	rbtree_iter_t *ri = *iter_ptr;

	if (ri != NULL) {
		rbtree_t *rbt;

		rbtree_iter_check(ri);

		rbt = deconstify_pointer(ri->tree);
		g_assert(size_is_positive(rbt->refcnt));
		rbt->refcnt--;

		ri->magic = 0;
		WFREE(ri);
		*iter_ptr = NULL;
	}
}

/**
 * Fetch next entry from iterator.
 *
 * @param ri		the red-black tree iterator
 * @param keyptr	where the next key is returned
 *
 * @return TRUE if a new entry exists, FALSE if traversal is completed.
 */
bool
rbtree_iter_next(rbtree_iter_t *ri, const void **keyptr)
{
	rbtree_iter_check(ri);
	g_assert(ri->stamp == ri->tree->stamp);		/* No modification done */
	g_assert(keyptr != NULL);

	/*
	 * If traversal is completed, return FALSE.
	 */

	if (NULL == ri->next) {
		g_soft_assert_log(rbtree_count(ri->tree) + ri->removed == ri->visited,
			"%s(): count=%zu, visited=%zu (removed=%zu)",
			G_STRFUNC, rbtree_count(ri->tree), ri->visited, ri->removed);
		return FALSE;
	}

	ri->item = erbtree_data(ERBTREE(ri->tree), ri->next);
	ri->next = erbtree_next(ri->next);
	ri->visited++;

	*keyptr = ri->item->data;
	return TRUE;
}

/**
 * Remove current item being iterated over.
 *
 * @return pointer to key removed, NULL if there is no item to remove.
 */
void *
rbtree_iter_remove(rbtree_iter_t *ri)
{
	void *key;

	rbtree_iter_check(ri);
	g_assert(ri->stamp == ri->tree->stamp);		/* No modification done */

	/*
	 * The current item being iterated over is cleared once we have removed it.
	 */

	if (NULL == ri->item)
		return NULL;

	/*
	 * We do not update the tree stamp here because this deletion is authorized
	 * during the tree traversal: it will not perturb the iteration order and
	 * we already pre-fetched the next item.
	 */

	key = ri->item->data;
	erbtree_remove(ERBTREE(ri->tree), &ri->item->node);
	WFREE_TYPE_NULL(ri->item);
	ri->removed++;

	return key;
}

/* vi: set ts=4 sw=4 cindent: */
