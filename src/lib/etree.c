/*
 * Copyright (c) 2012, 2014 Raphael Manfredi
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
 * Embedded trees are created when the linking pointers are directly
 * held within the data structure.
 *
 * Embedded trees are intrusive in the sense that the objects have an explicit
 * node_t field, but this saves one pointer per item being held compared
 * to glib's trees.
 *
 * Due to the nature of the data structure, the definition of the internal
 * structures is visible in the header file but users must refrain from
 * peeking and poking into the structures.  Using embedded data structures
 * requires more discipline than opaque data structures.
 *
 * The API of embedded trees has been derived from the need of the user's
 * code and as evolved incrementally.  It was then extended with some of
 * glib's API for trees, which is a good one.
 *
 * This library handles arbitrary n-ary trees, not balanced binary trees or
 * other kind of specialized trees, but with a single root (i.e. the root
 * has no siblings).
 *
 * There are two node structures available for trees, and the type of structure
 * used must be given when the etree_t is initialized: the node_t is the usual
 * tree representation with { parent, child, sibling } pointers.  The nodex_t
 * is an extended node which also stores the last_child to make appending of
 * new children faster.
 *
 *                   +[x]
 *                  +/ | \        | is a parent link [b] -> [x]
 *                 +/  |  \       + is a child link [x] +> [a]
 *               [a]==[b]==[c]    = is a sibling link [a] => [b] => [c]
 *
 * All links are one-way, so it is not possible to iterate freely on the tree
 * with ideal performance for all types of traversal.  The aim is reasonable
 * performance given the memory trade-offs we're taking.
 *
 * @author Raphael Manfredi
 * @date 2012, 2014
 */

#include "common.h"

#include "etree.h"

#include "unsigned.h"
#include "xslist.h"

#include "override.h"			/* Must be the last header included */

/**
 * Initialize embedded tree.
 *
 * Assuming items in the tree are defined as:
 *
 *     struct item {
 *         <data fields>
 *         node_t n;
 *     };
 *
 * then the last argument can be given as:
 *
 *     offsetof(struct item, n)
 *
 * to indicate the place of the node field within the item.
 *
 * Extended trees are available to make etree_append_child() efficient but if
 * children can only be prepended, use normal trees (less overhead per node).
 *
 * @param tree		the tree structure to initialize
 * @param extended	whether extended nodex_t are used instead of node_t
 * @param offset	the offset of the embedded link field within items
 */
void
etree_init(etree_t *tree, bool extended, size_t offset)
{
	g_assert(tree != NULL);
	g_assert(size_is_non_negative(offset));

	tree->magic = extended ? ETREE_EXT_MAGIC : ETREE_MAGIC;
	tree->root = NULL;
	tree->offset = offset;
	tree->count = 0;
}

/**
 * Set initial root of empty tree.
 */
void
etree_set_root(etree_t *tree, const void *root)
{
	etree_check(tree);
	g_assert(NULL == tree->root);

	tree->root = ptr_add_offset(deconstify_pointer(root), tree->offset);
	if (NULL == tree->root->child)
		tree->count = 1;
}

/**
 * Discard tree, making the tree object invalid.
 *
 * This does not free any of the items, it just discards the tree descriptor.
 * The underlying items remain chained though, so retaining a pointer to one
 * of the node_t of one item still allows limited tree traversal.
 */
void
etree_discard(etree_t *tree)
{
	etree_check(tree);

	tree->magic = 0;
}

/**
 * Is item the root node?
 */
bool
etree_is_root(const etree_t *tree, const void *item)
{
	const node_t *n;

	etree_check(tree);

	n = const_ptr_add_offset(item, tree->offset);
	return NULL == n->parent && n == tree->root;
}

/**
 * Is item an "orphan" node? (no parent, no sibling)
 */
bool
etree_is_orphan(const etree_t *tree, const void *item)
{
	const node_t *n;

	etree_check(tree);

	n = const_ptr_add_offset(item, tree->offset);
	return NULL == n->parent && NULL == n->sibling;
}

/**
 * Is item an "standalone" node? (no parent, no sibling, no children)
 */
bool
etree_is_standalone(const etree_t *tree, const void *item)
{
	const node_t *n;

	etree_check(tree);

	n = const_ptr_add_offset(item, tree->offset);
	return NULL == n->parent && NULL == n->sibling && NULL == n->child;
}

/**
 * @return last sibling of node, NULL if node is NULL.
 */
static node_t *
etree_node_last_sibling(const node_t *n)
{
	const node_t *sn, *next;

	if (NULL == n)
		return NULL;

	for (sn = n; /* empty */; sn = next) {
		next = sn->sibling;
		if (NULL == next)
			break;
	}

	g_assert(sn != NULL);	/* Found last sibling */

	return deconstify_pointer(sn);
}

/**
 * @return pointer to last child of item, NULL if leaf item.
 */
void *
etree_last_child(const etree_t *tree, const void *item)
{
	etree_check(tree);

	if (etree_is_extended(tree)) {
		const nodex_t *n = const_ptr_add_offset(item, tree->offset);
		if (NULL == n->last_child)
			return NULL;
		return ptr_add_offset(n->last_child, -tree->offset);
	} else {
		const node_t *n = const_ptr_add_offset(item, tree->offset);
		node_t *sn = etree_node_last_sibling(n->child);

		if (NULL == sn)
			return NULL;

		return ptr_add_offset(sn, -tree->offset);
	}
}

/**
 * Computes the root of the tree, starting from any item.
 *
 * This disregards the actual root in the etree_t structure passed, which may
 * be inaccurate, i.e. a sub-node of the actual tree.  The only accurate
 * information that etree_t must contain is the offset of the node_t within
 * the items.
 *
 * @param tree		the tree descriptor (with possible inaccurate root)
 * @param item		an item belonging to the tree
 *
 * @return the root of the tree to which item belongs.
 */
void *
etree_find_root(const etree_t *tree, const void *item)
{
	const node_t *n, *p;
	void *root;

	etree_check(tree);
	g_assert(item != NULL);

	n = const_ptr_add_offset(item, tree->offset);

	for (p = n; p != NULL; p = n->parent)
		n = p;

	root = ptr_add_offset(deconstify_pointer(n), -tree->offset);

	g_assert(etree_is_orphan(tree, root));	/* No parent, no sibling */

	return root;
}

/**
 * Given an item, find the first matching sibling starting with this item,
 * NULL if none.
 *
 * @param tree		the tree descriptor (with possible inaccurate root)
 * @param item		item at which search begins
 * @param match		matching predicate
 * @param data		additional callback argument
 */
void *
etree_find_sibling(const etree_t *tree, const void *item,
	match_fn_t match, void *data)
{
	const node_t *s;

	etree_check(tree);
	g_assert(item != NULL);
	g_assert(match != NULL);

	for (
		s = const_ptr_add_offset(item, tree->offset);
		s != NULL;
		s = s->sibling
	) {
		const void *node = const_ptr_add_offset(s, -tree->offset);
		if ((*match)(node, data))
			return deconstify_pointer(node);
	}

	return NULL;	/* No matching item */
}

/**
 * Detach item and all its sub-tree from a tree, making it the new root
 * of a smaller tree.
 */
void
etree_detach(etree_t *tree, void *item)
{
	node_t *n;

	etree_check(tree);
	g_assert(item != NULL);

	n = ptr_add_offset(item, tree->offset);

	if (NULL == n->parent) {
		/* Root node already, cannot have any sibling */
		g_assert(NULL == n->sibling);
		g_assert(n == tree->root);
		tree->root = NULL;			/* Root node is now detached */
		tree->count = 0;
	} else {
		node_t *parent = n->parent;

		if (n == parent->child) {
			if (etree_is_extended(tree)) {
				nodex_t *px = (nodex_t *) parent;
				if (n == px->last_child) {
					g_assert(NULL == n->sibling);	/* Last child! */
					px->child = px->last_child = NULL;
				} else {
					g_assert(NULL != n->sibling);	/* Not last child */
					parent->child = n->sibling;
				}
			} else {
				parent->child = n->sibling;
			}
		} else {
			node_t *cn;
			bool found = FALSE;

			/*
			 * Not removing first child of parent, so locate its previous
			 * sibling in the list of the parent's immediate children.
			 */

			for (cn = parent->child; cn != NULL; cn = cn->sibling) {
				if (cn->sibling == n) {
					found = TRUE;
					break;
				}
			}

			g_assert(found);			/* Must find it or tree is corrupted */

			cn->sibling = n->sibling;	/* Remove node ``n'' from list */

			/*
			 * Update ``last_child'' in the parent node if we removed the
			 * last child node.
			 */

			if (etree_is_extended(tree)) {
				nodex_t *px = (nodex_t *) parent;

				if (n == px->last_child) {
					g_assert(NULL == n->sibling);
					px->last_child = cn;
				}
			}
		}

		n->sibling = NULL;			/* Node is now a root node */
		tree->count = 0;			/* Count is now unknown */
	}
}

/**
 * Increment tree count if known and added node is a leaf.
 */
static inline void
etree_count_update_added(etree_t *tree, const node_t *node)
{
	if (NULL == node->child && 0 != tree->count)
		tree->count++;			/* Adding leaf node */
	else
		tree->count = 0;		/* Tree count is now unknown */
}

/**
 * Append child to parent.
 *
 * If this is a frequent operation, consider using an extended tree.
 */
void
etree_append_child(etree_t *tree, void *parent, void *child)
{
	node_t *cn, *pn;

	etree_check(tree);
	g_assert(parent != NULL);
	g_assert(child != NULL);
	g_assert(etree_is_orphan(tree, child));

	cn = ptr_add_offset(child, tree->offset);
	pn = ptr_add_offset(parent, tree->offset);

	if (etree_is_extended(tree)) {
		nodex_t *px = ptr_add_offset(parent, tree->offset);

		if (px->last_child != NULL) {
			node_t *lcn = px->last_child;

			g_assert(0 == ptr_cmp(lcn->parent, px));
			g_assert(NULL == lcn->sibling);

			lcn->sibling = cn;
		} else {
			g_assert(NULL == px->child);

			px->child = cn;
		}

		px->last_child = cn;
	} else {
		if (NULL == pn->child) {
			pn->child = cn;
		} else {
			node_t *lcn = etree_node_last_sibling(pn->child);
			lcn->sibling = cn;
		}
	}

	cn->parent = pn;

	etree_count_update_added(tree, cn);
}

/**
 * Prepend child to parent.
 *
 * This is always a fast operation.
 */
void
etree_prepend_child(etree_t *tree, void *parent, void *child)
{
	node_t *cn, *pn;

	etree_check(tree);
	g_assert(parent != NULL);
	g_assert(child != NULL);
	g_assert(etree_is_orphan(tree, child));

	cn = ptr_add_offset(child, tree->offset);
	pn = ptr_add_offset(parent, tree->offset);

	cn->parent = pn;
	cn->sibling = pn->child;
	pn->child = cn;

	if (etree_is_extended(tree)) {
		nodex_t *px = (nodex_t *) pn;

		if (NULL == px->last_child) {
			g_assert(NULL == cn->sibling);	/* Parent did not have any child */
			px->last_child = cn;
		}
	}

	etree_count_update_added(tree, cn);
}

/**
 * Reverse the order of children in a given node.
 */
void
etree_reverse_children(etree_t *tree, void *node)
{
	node_t *cn, *n, *prev;

	etree_check(tree);
	g_assert(node != NULL);

	n = ptr_add_offset(node, tree->offset);

	/*
	 * This is a classic one-way list reversal alogrithm, with the head
	 * of the list being n->child and each item being linked via ``sibling''.
	 */

	for (cn = n->child, prev = NULL; cn != NULL; /* empty */) {
		node_t *next = cn->sibling;

		cn->sibling = prev;
		prev = cn;
		cn = next;
	}

	if (etree_is_extended(tree)) {
		nodex_t *nx = (nodex_t *) n;
		nx->last_child = n->child;		/* Last child is the previous head */
	}

	n->child = prev;		/* New head of list */
}

/**
 * Add item as right-sibling of node (cannot be the root node).
 */
void
etree_add_right_sibling(etree_t *tree, void *node, void *item)
{
	node_t *n, *i;

	etree_check(tree);
	g_assert(node != NULL);
	g_assert(item != NULL);
	g_assert(etree_is_orphan(tree, item));
	g_assert(!etree_is_root(tree, node));

	n = ptr_add_offset(node, tree->offset);
	i = ptr_add_offset(item, tree->offset);

	i->parent = n->parent;
	i->sibling = n->sibling;
	n->sibling = i;

	if (NULL == i->sibling && etree_is_extended(tree)) {
		nodex_t *px = (nodex_t *) n->parent;
		px->last_child = i;
	}

	etree_count_update_added(tree, i);
}

/**
 * Add item as left-sibling of node (cannot be the root node).
 *
 * This is inefficient if the node is not the first child (the head of the
 * sibling list) given that the siblings are linked through a one-way list.
 */
void
etree_add_left_sibling(etree_t *tree, void *node, void *item)
{
	node_t *n, *i;

	etree_check(tree);
	g_assert(node != NULL);
	g_assert(item != NULL);
	g_assert(etree_is_orphan(tree, item));
	g_assert(!etree_is_root(tree, node));

	n = ptr_add_offset(node, tree->offset);
	i = ptr_add_offset(item, tree->offset);

	i->parent = n->parent;
	i->sibling = n;

	if (n == n->parent->child) {
		/* node is first child, optimized case */
		n->parent->child = i;
	} else {
		node_t *p;

		for (p = n->parent->child; p->sibling != n; p = p->sibling)
			/* empty */;

		g_assert(p != NULL);		/* previous node found */

		p->sibling = i;
	}

	etree_count_update_added(tree, i);
}

/**
 * Recursively sort all the children of each tree node.
 *
 * This does NOT sort the tree so that traversal is in a given order implied
 * by the comparison routine.  It only deals with the immediate children of
 * each parent node.
 *
 * @param tree		the tree to sort
 * @param root		the parent node whose children we want to sort
 * @param cmp		the comparison routine for two items in the tree
 * @param data		additional argument to supply to comparison routine
 *
 * @return amount of nodes visited.
 */
static size_t
etree_sort_internal(etree_t *tree, node_t *root, cmp_data_fn_t cmp, void *data)
{
	void *child;
	node_t *n, *next;
	xslist_t siblings;
	bool is_extended;
	size_t visited;

	etree_check(tree);

	if (NULL == root->child)
		return 1;

	/*
	 * Sort the siblings before iterating over them to recurse.
	 *
	 * We're going to treat the sibling list (one-way linked via n->sibling)
	 * as an expanded single list whose link offset is the offset of the
	 * ``sibling'' field in the node_t structure.
	 */

	child = ptr_add_offset(root->child, -tree->offset);
	xslist_load(&siblings, child, tree->offset, offsetof(node_t, sibling));
	xslist_sort_with_data(&siblings, cmp, data);
	root->child = xslist_first(&siblings);

	is_extended = etree_is_extended(tree);
	visited = 1;

	for (n = root->child; n != NULL; n = next) {
		g_assert(root == n->parent);	/* Sorting did not alter structure */

		next = n->sibling;
		visited += etree_sort_internal(tree, n, cmp, data);

		if G_UNLIKELY(is_extended && NULL == next) {
			nodex_t *nx = (nodex_t *) root;
			nx->last_child = n;
		}
	}

	return visited;
}

/**
 * Sort the children of each tree node with the item-comparison routine.
 *
 * @param tree	the tree whose children we want to sort
 * @param cmp	the comparison routine to compare two items
 */
void
etree_sort(etree_t *tree, cmp_fn_t cmp)
{
	etree_check(tree);

	if (NULL == tree->root)
		return;

	tree->count = etree_sort_internal(
		tree, tree->root, func_cast(cmp_data_fn_t, cmp), NULL);
}

/**
 * Sort the children of each tree node with the item-comparison routine,
 * which is extended to take an additional user-supplied context.
 *
 * @param tree	the tree whose children we want to sort
 * @param cmp	the comparison routine to compare two items
 * @param data	additional argument to supply to comparison routine
 */
void
etree_sort_with_data(etree_t *tree, cmp_data_fn_t cmp, void *data)
{
	etree_check(tree);

	if (NULL == tree->root)
		return;

	tree->count = etree_sort_internal(tree, tree->root, cmp, data);
}

/**
 * General tree traversal routine, in depth-first order.
 *
 * The "enter" function is called when we enter a node, and its returned
 * value is monitored: a FALSE indicates that the node should be skipped
 * (which includes its children) and that the action callback should not be
 * invoked.  When missing, it is as if the "enter" callback had returned TRUE.
 *
 * The "action" callback can be invoked before or after processing the node's
 * children, as indicated by the flags. That callback is allowed to free the
 * traversed node.
 *
 * @param tree		the tree descriptor
 * @param root		the item at which traversal starts
 * @param flags		nodes to visit + when to invoke action callback
 * @param curdepth	current depth
 * @param mindepth	depth when callbacks start (0 = now, 1 = children, etc...)
 * @param maxdepth	0 = root node only, 1 = root + its children, etc...
 * @param enter		(optional) callback when we enter a node
 * @param action	(mandatory) action on the node
 * @param data		user-defined argument passed to callbacks
 *
 * @return amount of nodes visited.
 */
static size_t
etree_traverse_internal(const etree_t *tree, node_t *root,
	unsigned flags, unsigned curdepth, unsigned mindepth, unsigned maxdepth,
	match_fn_t enter, data_fn_t action, void *data)
{
	size_t visited = 1;		/* 1 for this node */
	void *item;
	bool actionable;
	node_t *child;

	etree_check(tree);

	if (curdepth > maxdepth)
		return 0;

	/*
	 * Check whether we need to execute action on the node.
	 */

	child = root->child;

	if (curdepth < mindepth)
		actionable = FALSE;
	else if ((flags & ETREE_TRAVERSE_NON_LEAVES) && NULL != child)
		actionable = TRUE;
	else if ((flags & ETREE_TRAVERSE_LEAVES) && NULL == child)
		actionable = TRUE;
	else
		actionable = FALSE;

	item = ptr_add_offset(root, -tree->offset);

	/*
	 * The optional "enter" callback is only activated when we have reached
	 * the minimal depth.
	 */

	if (enter != NULL && curdepth >= mindepth && !(*enter)(item, data))
		return 0;

	if (actionable && (flags & ETREE_CALL_BEFORE))
		(*action)(item, data);		/* MUST NOT free node */

	/*
	 * Only visit children when we've not reached the maximum depth.
	 */

	if (curdepth != maxdepth) {
		node_t *n, *next;

		for (n = child; n != NULL; n = next) {
			next = n->sibling;
			visited += etree_traverse_internal(tree, n, flags,
				curdepth + 1, mindepth, maxdepth, enter, action, data);
		}
	}

	if (actionable && (flags & ETREE_CALL_AFTER))
		(*action)(item, data);		/* Can safely free node */

	return visited;
}

/**
 * Recursively apply function on each node, in depth-first mode.
 *
 * Traversal is done in such a way that the applied function can safely
 * free up the local node.
 *
 * @param tree		the tree descriptor
 * @param cb		the callback to invoke on each item
 * @param data		user-defined additional callback argument
 */
void
etree_foreach(const etree_t *tree, data_fn_t cb, void *data)
{
	etree_check(tree);
	g_assert(cb != NULL);

	if G_UNLIKELY(NULL == tree->root)
		return;

	etree_traverse_internal(tree, tree->root,
		ETREE_TRAVERSE_ALL | ETREE_CALL_AFTER,
		0, 0, ETREE_MAX_DEPTH, NULL, cb, data);
}

/**
 * Apply function to the immediate children of the node.
 *
 * Traversal is done in such a way that the applied function can safely
 * free up the local node.
 *
 * The root node is NOT traversed, and it MUST belong to the tree.
 *
 * @param tree		the tree descriptor
 * @param parent	the parent node of the children to traverse
 * @param cb		the callback to invoke on each item
 * @param data		user-defined additional callback argument
 */
void
etree_foreach_children(const etree_t *tree, void *parent,
	data_fn_t cb, void *data)
{
	node_t *root;

	etree_check(tree);
	g_assert(cb != NULL);
	g_assert(parent != NULL);

	if G_UNLIKELY(NULL == tree->root)
		return;

	root = ptr_add_offset(parent, tree->offset);

	etree_traverse_internal(tree, root,
		ETREE_TRAVERSE_ALL | ETREE_CALL_AFTER,
		0, 1, 1, NULL, cb, data);
}

/**
 * Recursively traverse tree, in depth-first mode.
 *
 * Traversal can be pruned with an optional "enter" callback, and/or by depth.
 *
 * The "action" callback can be invoked before or after processing children.
 * It can be triggered on non-leaf nodes, on leaves only, or on both.
 * It is always allowed to free-up the node.
 *
 * The function returns the number of visited nodes, regardless of whether the
 * action was run on them.  This allows them to know how many nodes were
 * selected by the "enter" callback and see the effect of depth-pruning.
 *
 * @param tree		the tree descriptor
 * @param flags		nodes to visit + when to invoke action callback
 * @param mindepth	0 = immediately, 1 = children, 2 = grand-children, etc...
 * @param maxdepth	0 = root node only, 1 = root + its children, etc...
 * @param enter		(optional) callback when we enter a node
 * @param action	(optional) action on the node
 * @param data		user-defined argument passed to callbacks
 *
 * @return amount of nodes visited, regardless of whether action was run.
 */
size_t
etree_traverse(const etree_t *tree, unsigned flags,
	unsigned mindepth, unsigned maxdepth,
	match_fn_t enter, data_fn_t action, void *data)
{
	etree_check(tree);
	g_assert(uint_is_non_negative(mindepth));
	g_assert(uint_is_non_negative(maxdepth) || ETREE_MAX_DEPTH == maxdepth);
	g_assert(NULL == action ||
		(flags & ETREE_CALL_BEFORE) ^ (flags & ETREE_CALL_AFTER));
	g_assert(NULL != action ||
		0 == (flags & (ETREE_CALL_BEFORE | ETREE_CALL_AFTER)));
	g_assert(0 != (flags & ETREE_TRAVERSE_ALL));

	if G_UNLIKELY(NULL == tree->root)
		return 0;

	return etree_traverse_internal(tree, tree->root, flags,
		0, mindepth, maxdepth,
		enter, action, data);
}

/**
 * Internal recursive matching routine.
 */
static void *
etree_find_depth_internal(const etree_t *tree, node_t *root,
	unsigned curdepth, unsigned maxdepth, match_fn_t match, void *data)
{
	node_t *n, *next;
	void *item;

	etree_check(tree);

	item = ptr_add_offset(root, -tree->offset);

	if ((*match)(item, data))
		return item;

	if (maxdepth == curdepth)
		return NULL;

	for (n = root->child; n != NULL; n = next) {
		next = n->sibling;
		item = etree_find_depth_internal(tree, n,
			curdepth + 1, maxdepth, match, data);
		if (item != NULL)
			return item;
	}

	return NULL;
}

/**
 * Recursively apply matching function on each node, in depth-first order,
 * until it returns TRUE or the maximum depth is reached, at which time we
 * return the matching node.
 *
 * A depth of 0 limits searching to the root node, 1 to the root node plus
 * its immediate children, etc...
 *
 * @param tree		the tree descriptor
 * @param maxdepth	maximum search depth
 * @param match		the item matching function
 * @param data		user-defined argument passed to the matching callback
 *
 * @return the first matching node in the traversal path, NULL if none matched.
 */
void *
etree_find_depth(const etree_t *tree, unsigned maxdepth,
	match_fn_t match, void *data)
{
	etree_check(tree);
	g_assert(uint_is_non_negative(maxdepth) || ETREE_MAX_DEPTH == maxdepth);
	g_assert(match != NULL);

	return etree_find_depth_internal(tree, tree->root, 0, maxdepth,
		match, data);
}

/**
 * Recursively apply matching function on each node, in depth-first order,
 * until it returns TRUE, at which time we return the matching node.
 *
 * @param tree		the tree descriptor
 * @param match		the item matching function
 * @param data		user-defined argument passed to the matching callback
 *
 * @return the first matching node in the traversal path, NULL if none matched.
 */
void *
etree_find(const etree_t *tree, match_fn_t match, void *data)
{
	etree_check(tree);
	g_assert(match != NULL);

	return etree_find_depth_internal(tree, tree->root, 0, ETREE_MAX_DEPTH,
		match, data);
}

struct etree_item_free_data_ctx {
	free_data_fn_t fcb;
	void *data;
};

/**
 * Helper routine for etree_free_data() to free up each item.
 */
static void
etree_item_free_data(void *item, void *data)
{
	struct etree_item_free_data_ctx *ctx = data;

	(*ctx->fcb)(item, ctx->data);
}

/**
 * Helper routine for etree_free() to free up each item.
 */
static void
etree_item_free(void *item, void *data)
{
	free_fn_t fcb = cast_pointer_to_func(data);

	(*fcb)(item);
}

/**
 * Free whole tree, discarding each node with the supplied free routine.
 *
 * @param tree		the tree descriptor
 * @param fcb		free routine for each item
 * @param data		user-supplied argument to the free routine
 */
void
etree_free_data(etree_t *tree, free_data_fn_t fcb, void *data)
{
	struct etree_item_free_data_ctx ctx;

	ctx.fcb = fcb;
	ctx.data = data;

	etree_foreach(tree, etree_item_free_data, &ctx);
	tree->root = NULL;
	tree->count = 0;
}

/**
 * Free whole tree, discarding each node with the supplied free routine.
 *
 * @param tree		the tree descriptor
 * @param fcb		free routine for each item
 */
void
etree_free(etree_t *tree, free_fn_t fcb)
{
	etree_foreach(tree, etree_item_free, cast_func_to_pointer(fcb));
	tree->root = NULL;
	tree->count = 0;
}

/**
 * Free sub-tree, destroying all its items and removing the reference in
 * the parent node, if any.
 *
 * @param tree		the tree descriptor
 * @param item		root item of sub-tree to remove
 * @param fcb		free routine for each item
 * @param data		user-supplied argument to the free routine
 */
void
etree_sub_free_data(etree_t *tree, void *item, free_data_fn_t fcb, void *data)
{
	etree_t dtree;

	etree_check(tree);

	etree_detach(tree, item);
	etree_init_root(&dtree, item, etree_is_extended(tree), tree->offset);
	etree_free_data(&dtree, fcb, data);
}

/**
 * Free sub-tree, destroying all its items and removing the reference in
 * the parent node, if any.
 *
 * @param tree		the tree descriptor
 * @param item		root item of sub-tree to remove
 * @param fcb		free routine for each item
 */
void
etree_sub_free(etree_t *tree, void *item, free_fn_t fcb)
{
	etree_t dtree;

	etree_check(tree);

	etree_detach(tree, item);
	etree_init_root(&dtree, item, etree_is_extended(tree), tree->offset);
	etree_free(&dtree, fcb);
}

/* vi: set ts=4 sw=4 cindent: */
