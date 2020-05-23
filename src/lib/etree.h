/*
 * Copyright (c) 2012, 2014-2015 Raphael Manfredi
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
 * Embedded n-ary trees (within another data structure).
 *
 * @author Raphael Manfredi
 * @date 2012, 2014-2015
 */

#ifndef _etree_h_
#define _etree_h_

/**
 * Get the enclosing data item from an embedded node.
 */
#ifdef __GNUC__
#define etree_item(lnk, type, field) G_EXTENSION({		\
	const struct node *__mptr = (lnk);						\
	(type *)((char *) __mptr - offsetof(type, field));})
#else
#define etree_item(lnk, type, field)						\
	((type *)((char *) (node) - offsetof(type, field)))
#endif

/**
 * A tree structure.
 */
typedef struct node {
	struct node *parent, *child, *sibling;
} node_t;

/**
 * An extended tree structure for optimized child appending.
 *
 * @attention
 * Structure equivalence allows us to have pointers to node_t within a nodex_t.
 */
typedef struct nodex {
	struct node *parent, *child, *sibling, *last_child;
} nodex_t;

enum etree_magic {
	ETREE_MAGIC = 0x70b0b6c7,		/**< uses struct node */
	ETREE_EXT_MAGIC = 0x44a57f69	/**< uses struct nodex */
};

/**
 * An embedded tree is represented by this structure.
 */
typedef struct etree {
	enum etree_magic magic;
	node_t *root;		/* Can be a nodex_t * for extended trees */
	size_t offset;		/* Offset of embedded node in the item structure */
	size_t count;		/* Amount of nodes held (0 means possibly unknown) */
} etree_t;

static inline void
etree_check(const etree_t * const et)
{
	g_assert(et != NULL);
	g_assert(ETREE_MAGIC == et->magic || ETREE_EXT_MAGIC == et->magic);
}

/**
 * Traversal flags.
 */
#define ETREE_TRAVERSE_LEAVES		(1U << 0)
#define ETREE_TRAVERSE_NON_LEAVES	(1U << 1)
#define ETREE_CALL_AFTER			(1U << 2)
#define ETREE_CALL_BEFORE			(1U << 3)

#define ETREE_TRAVERSE_ALL \
	(ETREE_TRAVERSE_LEAVES | ETREE_TRAVERSE_NON_LEAVES)

#define ETREE_MAX_DEPTH				((unsigned) -1)

/**
 * Public interface.
 */

/**
 * Initialize tree from root item.
 */
static inline void
etree_init_root(etree_t *tree, const void *root, bool extended, size_t offset)
{
	tree->magic = extended ? ETREE_EXT_MAGIC : ETREE_MAGIC;
	tree->root = ptr_add_offset(deconstify_pointer(root), offset);
	tree->offset = offset;
	tree->count = (NULL == tree->root->child) ? 1 : 0;
}

/**
 * Is tree using "extended nodes"?
 */
static inline bool
etree_is_extended(const etree_t *tree)
{
	etree_check(tree);

	return ETREE_EXT_MAGIC == tree->magic;
}

/**
 * @return pointer to root of tree, as indicated by the tree descriptor,
 * NULL if empty.
 */
static inline void *
etree_root(const etree_t * const et)
{
	etree_check(et);
	return NULL == et->root ? NULL : ptr_add_offset(et->root, -et->offset);
}

/**
 * @return pointer to parent of node, NULL if root node.
 */
static inline void *
etree_parent(const etree_t * const et, const void *item)
{
	const node_t *n;

	etree_check(et);

	n = const_ptr_add_offset(item, et->offset);
	return NULL == n->parent ? NULL : ptr_add_offset(n->parent, -et->offset);
}

/**
 * @return pointer to first child of item, NULL if leaf item.
 */
static inline void *
etree_first_child(const etree_t * const et, const void *item)
{
	const node_t *n;

	etree_check(et);

	n = const_ptr_add_offset(item, et->offset);
	return NULL == n->child ? NULL : ptr_add_offset(n->child, -et->offset);
}

/**
 * @return pointer to the next sibling of item, NULL if item has no more
 * siblings.
 */
static inline void *
etree_next_sibling(const etree_t * const et, const void *item)
{
	const node_t *n;

	etree_check(et);

	n = const_ptr_add_offset(item, et->offset);
	return NULL == n->sibling ? NULL : ptr_add_offset(n->sibling, -et->offset);
}

/**
 * @return the data associated with the curernt node, NULL if none.
 */
static inline void *
etree_data(const etree_t *et, const node_t * const node)
{
	etree_check(et);

	return NULL == node ? NULL :
		deconstify_pointer(const_ptr_add_offset(node, -et->offset));
}

void etree_foreach(const etree_t *tree, data_fn_t cb, void *data);
void etree_foreach_children(const etree_t *tree, void *parent,
	data_fn_t cb, void *data);
size_t etree_traverse(const etree_t *tree, unsigned flags,
	unsigned mindepth, unsigned maxdepth,
	match_fn_t enter, data_fn_t action, void *data);

/**
 * Get (possibly cached) amount of items in the tree.
 *
 * @return amount of items in tree.
 */
static inline size_t
etree_count(const etree_t *et)
{
	etree_t *wet;

	etree_check(et);

	if G_UNLIKELY(NULL == et->root)
		return 0;

	/*
	 * Cache count in the object.
	 */

	if G_LIKELY(0 != et->count)
		return et->count;

	wet = deconstify_pointer(et);

	return wet->count = etree_traverse(et,
		ETREE_TRAVERSE_ALL, 0, ETREE_MAX_DEPTH,
		NULL, NULL, NULL);
}

void etree_init(etree_t *tree, bool extended, size_t offset);
void etree_set_root(etree_t *tree, const void *root);

bool etree_is_standalone(const etree_t *tree, const void *item);
bool etree_is_orphan(const etree_t *tree, const void *item);

void *etree_find(const etree_t *tree, match_fn_t match, void *data);
void *etree_find_depth(const etree_t *tree, unsigned maxdepth,
	match_fn_t match, void *data);
void *etree_find_root(const etree_t *tree, const void *item);
void *etree_find_sibling(const etree_t *tree, const void *item,
	match_fn_t match, void *data);

void etree_append_child(etree_t *tree, void *parent, void *child);
void etree_prepend_child(etree_t *tree, void *parent, void *child);
void etree_reverse_children(etree_t *tree, void *node);

void etree_add_right_sibling(etree_t *tree, void *node, void *item);
void etree_add_left_sibling(etree_t *tree, void *node, void *item);

void *etree_last_child(const etree_t *tree, const void *item);

void etree_detach(etree_t *tree, void *item);

void etree_sort(etree_t *tree, cmp_fn_t cmp);
void etree_sort_with_data(etree_t *tree, cmp_data_fn_t cmp, void *data);

void etree_free_data(etree_t *tree, free_data_fn_t fcb, void *data);
void etree_free(etree_t *tree, free_fn_t fcb);
void etree_sub_free_data(etree_t *tree, void *item,
	free_data_fn_t fcb, void *data);
void etree_sub_free(etree_t *tree, void *item, free_fn_t fcb);

#endif /* _etree_h_ */

/* vi: set ts=4 sw=4 cindent: */
