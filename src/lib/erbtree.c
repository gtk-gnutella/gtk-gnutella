/*
 * Copyright (C) 2010 Franck Bui-Huu <fbuihuu@gmail.com>
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
 * This implementation of embedded red-black trees comes from the libtree
 * package authored by Franck Bui-Huu, which can be found at:
 *
 *		https://github.com/fbuihuu/libtree.git
 *
 * Inclusion in gtk-gnutella was done by Raphael Manfredi, with mostly cosmetic
 * changes: addition of magic number, counting of items in the tree, order
 * of parameters (the target always comes first), assertions, routine
 * signatures, etc...
 *
 * The most radical change is that the comparison routine compares items, not
 * embedded nodes, and lookups are done by passing pointers to items, not nodes
 * and lookups return pointers to items.  This requires the offset of the
 * embedded node pointer to be given to the erbtree_init() routine.
 *
 * Additions were made to introduce generic iterators that handle all the
 * items through callbacks: erbtree_foreach() and erbtree_foreach_remove(),
 * efficient tree disposal erbtree_discard() and erbtree_discard_with_data()
 * and extensions to have a comparison callback take one additional argument
 * to suppply context (to allow implementation of red-black trees that can
 * store arbitrary data not embedding the rbnode_t structure).
 *
 * Inspired by the README of libtree:
 *
 * 1. DESIGN
 *
 * Here's a list of the major points:
 *
 * - Nodes of the tree aim to be embedded inside your own structure.
 *   This removes the need to do some malloc/free during insertion/removal
 *   operations and saves some space since no allocation infrastructure
 *   (such as object descriptors or object alignment) is required.
 *
 * - On most architectures (at least the ones I'm using), pointers have some
 *   unused bits which can be used to store node's meta-data. This allows us to
 *   reduce the size of the node structure, and make them as small as possible.
 *
 * - Traversals in both direction are efficient.
 * 
 * - The trees don't store duplicate keys. It's fairly easy to implement
 *   duplicate from the user point of view (by having a list at the node for
 *   instance) and this enables a simple but efficient API (see below).
 *
 * 2. API
 *
 * You should never actually need to play with the internal members of
 * either tree or node structures.
 *
 * Nodes are embedded inside your own structure, for example:
 *
 *     struct my_struct {
 *		   int key;
 *         rbnode_t node;
 *     };
 *
 * A tree needs to be initialized before being used. For example:
 *
 *     erbtree_t tree;
 *
 *     erbtree_init(&tree, cmp_routine, offsetof(struct my_struct, node));
 *
 * The user must provide a comparison function. This function will be called
 * by the library with two arguments that point to the structures embeding
 * the nodes, not the nodes themselves.
 *
 * For instance, the user must provide a function like this:
 *
 *     int my_cmp(const void *a, const void *b)
 *     {
 *         const struct my_struct *p = a, *q = b;
 *
 *         return p->key - q->key;
 *     }
 *
 * A set of functions is provided to manipulate trees. All of them take
 * only pointers to tree and node structures. They have no idea about the
 * user's structures which contain them.
 *
 * The only exception are lookup routines which take a key, i.e. a pointer
 * to the base of the structure that contains the node, NOT the nodes
 * themselves.
 *
 * 3. LOOKUP
 *
 * If you need to search for the node having a specific key then you need
 * to fill up a dummy structure with the key initialized to the value so
 * your compare function will successfully compare the passed dummy structure
 * with the ones inside the tree.
 *
 * The lookup routine takes a key as parameter, and returns a pointer to
 * the item, or NULL if the key does not exist.  It is then possible to get
 * the node directly, which is more convenient for traversing.
 *
 * 4. INSERTION
 *
 * Trees don't store duplicate keys, since rotations don't preserve the
 * binary search tree property in that case. If the user needs to do so,
 * then he can keep a separate list of all records having the same key.
 *
 * This is the reason why the insertion functions do insert a key only if
 * the key hasn't been already inserted. Otherwise it's equivalent to a
 * lookup operation and the insertion operation just returns the node
 * with the same key already inserted, and no insertion happened. At this
 * point the user can use a list and append the new node to the list
 * given by the returned node.
 *
 * 5. REMOVAL
 *
 * For speed reasons, the remove operation assumes that the node was
 * already inserted into the tree.
 *
 * Indeed tree implementations using parent pointers don't need to do any
 * lookups to retrieve the node's parent needed during the remove operation.
 *
 * Therefore you must use the remove operation with an already inserted node.
 *
 * 6. REPLACE
 *
 * Since trees don't store duplicate keys, the library provides an operation
 * to replace a node with another one whose key is equal to the replaced node.
 *
 * This operation is faster than remove/insert operations for balanced trees
 * since it doesn't need to rebalance the tree.
 *
 * 7. TRAVERSAL
 *
 * The API allows you to walk through the tree in sorted order.
 *
 * For that, you can retrieve the next or the previous of any inserted node.
 * You can also get the first (leftmost) and the last (rightmost) node of
 * a tree in O(1) because these values are maintained..
 * 
 * @author Franck Bui-Huu <fbuihuu@gmail.com>
 * @date 2010
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "erbtree.h"
#include "unsigned.h"

#include "override.h"			/* Must be the last header included */

/*
 * rbtree - Implements a red-black tree with parent pointers.
 *
 * Copyright (C) 2010 Franck Bui-Huu <fbuihuu@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; version 2 of the
 * License.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

/*
 * For recall, a red-black tree has the following properties:
 *
 *     1. All nodes are either BLACK or RED
 *     2. The root is BLACK
 *     3. Leaves are BLACK
 *     4. A RED node has only BLACK children
 *     5. Paths from a node to any leaf have the same number of BLACK nodes
 *
 * These properties ensure O(log2 n) complexity for lookups, insertions and
 * removals, whilst retaining an O(n) storage space.
 *
 * This implementation takes a node for removal, not a key, hence it can skip
 * the initial node lookup operation.
 */

enum rbcolor {
	RB_INVALID = 0,
	RB_BLACK = 1,
	RB_RED = 3,
};

#define RB_COLOR_MASK	3UL		/* Last 2 bits of parent pointer hold color */

#define ERBTREE_E(x)	((erbtree_ext_t *) (x))

static inline bool
erbtree_is_extended(const erbtree_t * const t)
{
	return t->magic & 0x1;
}

static inline enum rbcolor
get_color(const rbnode_t *node)
{
	return pointer_to_ulong(node->parent) & RB_COLOR_MASK;
}

static inline
void set_color(rbnode_t *node, enum rbcolor color)
{
	g_assert(RB_BLACK == color || RB_RED == color);

	node->parent = ulong_to_pointer(
		(pointer_to_ulong(node->parent) & ~RB_COLOR_MASK) | color);
}

static inline
void invalidate(rbnode_t *node)
{
	node->parent = ulong_to_pointer(
		(pointer_to_ulong(node->parent) & ~RB_COLOR_MASK));
}


static inline rbnode_t *
get_parent(const rbnode_t *node)
{
	return ulong_to_pointer(pointer_to_ulong(node->parent) & ~RB_COLOR_MASK);
}

static inline void
set_parent(rbnode_t *node, rbnode_t *parent)
{
	node->parent = ulong_to_pointer(
		pointer_to_ulong(parent) |
		(pointer_to_ulong(node->parent) & RB_COLOR_MASK)
	);
}

static inline bool
is_root(const rbnode_t *node)
{
	return get_parent(node) == NULL;
}

static inline bool
is_black(const rbnode_t *node)
{
	return get_color(node) == RB_BLACK;
}

static inline bool
is_red(const rbnode_t *node)
{
	return get_color(node) == RB_RED;
}

static inline bool
is_valid(const rbnode_t *node)
{
	return get_color(node) != RB_INVALID;
}

/**
 * @return amount of items in the tree.
 */
size_t
erbtree_count(const erbtree_t *tree)
{
	erbtree_check(tree);

	return tree->count;
}

/*
 * Iterators
 */

static inline rbnode_t *
get_first(rbnode_t *node)
{
	while (node->left != NULL)
		node = node->left;
	return node;
}

static inline rbnode_t *
get_last(rbnode_t *node)
{
	while (node->right != NULL)
		node = node->right;
	return node;
}

/**
 * Get first (smallest) item in the tree.
 */
rbnode_t *
erbtree_first(const erbtree_t *tree)
{
	erbtree_check(tree);

	return tree->first;
}

/**
 * Get last (bigest) item in the tree.
 */
rbnode_t *
erbtree_last(const erbtree_t *tree)
{
	erbtree_check(tree);

	return tree->last;
}

/**
 * Get next item in the tree, following natural order.
 */
rbnode_t *
erbtree_next(const rbnode_t *node)
{
	rbnode_t *parent;

	g_assert(node != NULL);

	if (node->right != NULL)
		return get_first(node->right);

	while (NULL != (parent = get_parent(node)) && parent->right == node)
		node = parent;

	return parent;
}

/**
 * Get previous item in the tree, following natural order.
 */
rbnode_t *
erbtree_prev(const rbnode_t *node)
{
	rbnode_t *parent;

	g_assert(node != NULL);

	if (node->left != NULL)
		return get_last(node->left);

	while (NULL != (parent = get_parent(node)) && parent->left == node)
		node = parent;
	return parent;
}

/**
 * Lookup key in the tree.
 *
 * 'pparent' and 'is_left' are only used for insertions. Normally GCC
 * will notice this and get rid of them for lookups.
 */
static inline rbnode_t *
do_lookup(const erbtree_t *tree, const void *key,
	rbnode_t **pparent, bool *is_left)
{
	rbnode_t *node = tree->root;

	*pparent = NULL;
	*is_left = FALSE;

	while (node != NULL) {
		int res;
		const void *nbase = const_ptr_add_offset(node, -tree->offset);
		res = (*tree->u.cmp)(nbase, key);
		if (0 == res)
			return node;
		*pparent = node;
		if ((*is_left = res > 0))
			node = node->left;
		else
			node = node->right;
	}

	return NULL;
}

/**
 * Lookup key in the (extended) tree.
 *
 * 'pparent' and 'is_left' are only used for insertions. Normally GCC
 * will notice this and get rid of them for lookups.
 */
static inline rbnode_t *
do_lookup_ext(const erbtree_ext_t *tree, const void *key,
	rbnode_t **pparent, bool *is_left)
{
	rbnode_t *node = tree->root;

	*pparent = NULL;
	*is_left = FALSE;

	while (node != NULL) {
		int res;
		const void *nbase = const_ptr_add_offset(node, -tree->offset);
		res = (*tree->u.dcmp)(nbase, key, tree->data);
		if (0 == res)
			return node;
		*pparent = node;
		if ((*is_left = res > 0))
			node = node->left;
		else
			node = node->right;
	}

	return NULL;
}


/*
 * Rotate operations (they preserve the binary search tree property,
 * assuming the keys are unique).
 */

static void
rotate_left(erbtree_t *tree, rbnode_t *node)
{
	rbnode_t *p = node;
	rbnode_t *q = node->right; /* can't be NULL */
	rbnode_t *parent = get_parent(p);

	g_assert(q != NULL);

	if (!is_root(p)) {
		if (parent->left == p)
			parent->left = q;
		else
			parent->right = q;
	} else
		tree->root = q;
	set_parent(q, parent);
	set_parent(p, q);

	p->right = q->left;
	if (p->right)
		set_parent(p->right, p);
	q->left = p;
}

static void
rotate_right(erbtree_t *tree, rbnode_t *node)
{
	rbnode_t *p = node;
	rbnode_t *q = node->left; /* can't be NULL */
	rbnode_t *parent = get_parent(p);

	g_assert(q != NULL);

	if (!is_root(p)) {
		if (parent->left == p)
			parent->left = q;
		else
			parent->right = q;
	} else
		tree->root = q;
	set_parent(q, parent);
	set_parent(p, q);

	p->left = q->right;
	if (p->left != NULL)
		set_parent(p->left, p);
	q->right = p;
}

/**
 * @param tree		the red-black tree
 * @param key		pointer to the key structure (NOT a node)
 *
 * @return whether tree contains key.
 */
bool
erbtree_contains(const erbtree_t *tree, const void *key)
{
	rbnode_t *parent;
	bool is_left;

	erbtree_check(tree);
	g_assert(key != NULL);

	if (erbtree_is_extended(tree)) {
		return NULL != do_lookup_ext(ERBTREE_E(tree), key, &parent, &is_left);
	} else {
		return NULL != do_lookup(tree, key, &parent, &is_left);
	}
}

/**
 * Look up key in the tree, returning the associated key item if found.
 *
 * @param tree		the red-black tree
 * @param key		pointer to the key structure (NOT a node)
 *
 * @return found item associated with key, NULL if not found.
 */
void *
erbtree_lookup(const erbtree_t *tree, const void *key)
{
	rbnode_t *parent;
	bool is_left;
	rbnode_t *rn;

	erbtree_check(tree);
	g_assert(key != NULL);

	if (erbtree_is_extended(tree)) {
		rn = do_lookup_ext(ERBTREE_E(tree), key, &parent, &is_left);
	} else {
		rn = do_lookup(tree, key, &parent, &is_left);
	}

	return NULL == rn ? NULL : ptr_add_offset(rn, -tree->offset);
}

/**
 * Look up key in the tree, returning the associated node pointer.
 *
 * This interface returns a node and not a key pointer to allow for direct
 * traversal or manipulation of the node (removal from tree for instance).
 * To simply get the key structure, use erbtree_lookup().
 *
 * To get back at the key from the returned node pointer, and assuming items
 * in the tree are defined as:
 *
 *     struct item {
 *         int key;
 *         <other fields>
 *         rbnode_t node;
 *     };
 *
 * use the following method:
 *
 *     struct item *item;
 *     rbnode_t *rn;
 *     struct item key;
 *
 *     key.key = <some value>;
 *     rn = erbtreee_getnode(tree, &key);
 *     item = NULL == rn ? NULL : erbtree_key(rn, struct item, node);
 *
 * Usage of erbtree_key() should be avoided whenever possible by using
 * erbtree_lookup(), and high-level iterators that handle keys directly.
 *
 * @param tree		the red-black tree
 * @param key		pointer to the key structure (NOT a node)
 *
 * @return node associated with key, NULL if not found.
 */
rbnode_t *
erbtree_getnode(const erbtree_t *tree, const void *key)
{
	rbnode_t *parent;
	bool is_left;

	erbtree_check(tree);
	g_assert(key != NULL);

	if (erbtree_is_extended(tree)) {
		return do_lookup_ext(ERBTREE_E(tree), key, &parent, &is_left);
	} else {
		return do_lookup(tree, key, &parent, &is_left);
	}
}

static void
set_child(rbnode_t *node, rbnode_t *child, bool left)
{
	if (left)
		node->left = child;
	else
		node->right = child;
}

/**
 * Insert node in tree.
 *
 * @return the existing key if the key already existed, NULL if the node
 * was properly inserted.
 */
G_GNUC_HOT void *
erbtree_insert(erbtree_t *tree, rbnode_t *node)
{
	rbnode_t *key, *parent;
	const void *kbase;
	bool is_left;

	erbtree_check(tree);
	g_assert(node != NULL);

	kbase = const_ptr_add_offset(node, -tree->offset);

	if (erbtree_is_extended(tree)) {
		key = do_lookup_ext(ERBTREE_E(tree), kbase, &parent, &is_left);
	} else {
		key = do_lookup(tree, kbase, &parent, &is_left);
	}

	if (key != NULL)
		return ptr_add_offset(key, -tree->offset);

	g_assert(!is_valid(node));	/* Not yet part of the tree */

	node->left = NULL;
	node->right = NULL;
	set_color(node, RB_RED);
	set_parent(node, parent);
	tree->count++;

	if (parent != NULL) {
		if (is_left) {
			if (parent == tree->first)
				tree->first = node;
		} else {
			if (parent == tree->last)
				tree->last = node;
		}
		set_child(parent, node, is_left);
	} else {
		tree->root = node;
		tree->first = node;
		tree->last = node;
	}

	/*
	 * Fixup the modified tree by recoloring nodes and performing
	 * rotations (2 at most) hence the red-black tree properties are
	 * preserved.
	 */

	while (NULL != (parent = get_parent(node)) && is_red(parent)) {
		rbnode_t *grandpa = get_parent(parent);

		if (parent == grandpa->left) {
			rbnode_t *uncle = grandpa->right;

			if (uncle != NULL && is_red(uncle)) {
				set_color(parent, RB_BLACK);
				set_color(uncle, RB_BLACK);
				set_color(grandpa, RB_RED);
				node = grandpa;
			} else {
				if (node == parent->right) {
					rotate_left(tree, parent);
					node = parent;
					parent = get_parent(node);
				}
				set_color(parent, RB_BLACK);
				set_color(grandpa, RB_RED);
				rotate_right(tree, grandpa);
			}
		} else {
			rbnode_t *uncle = grandpa->left;

			if (uncle != NULL && is_red(uncle)) {
				set_color(parent, RB_BLACK);
				set_color(uncle, RB_BLACK);
				set_color(grandpa, RB_RED);
				node = grandpa;
			} else {
				if (node == parent->left) {
					rotate_right(tree, parent);
					node = parent;
					parent = get_parent(node);
				}
				set_color(parent, RB_BLACK);
				set_color(grandpa, RB_RED);
				rotate_left(tree, grandpa);
			}
		}
	}
	set_color(tree->root, RB_BLACK);
	return NULL;
}

/**
 * Remove node from tree.
 *
 * @attention
 * It is assumed that the node is already part of the tree.
 */
G_GNUC_HOT void
erbtree_remove(erbtree_t *tree, rbnode_t *node)
{
	rbnode_t *removed = node;
	rbnode_t *parent = get_parent(node);
	rbnode_t *left = node->left;
	rbnode_t *right = node->right;
	rbnode_t *next;
	enum rbcolor color;

	erbtree_check(tree);
	g_assert(size_is_positive(tree->count));
	g_assert(node != NULL);
	g_assert(is_valid(node));	/* Does not verify it is part of THIS tree */

	tree->count--;

	if (node == tree->first)
		tree->first = erbtree_next(node);
	if (node == tree->last)
		tree->last = erbtree_prev(node);

	if (NULL == left)
		next = right;
	else if (NULL == right)
		next = left;
	else
		next = get_first(right);

	if (parent != NULL)
		set_child(parent, next, parent->left == node);
	else
		tree->root = next;

	if (left != NULL && right != NULL) {
		color = get_color(next);
		set_color(next, get_color(node));

		next->left = left;
		set_parent(left, next);

		if (next != right) {
			parent = get_parent(next);
			set_parent(next, get_parent(node));

			node = next->right;
			parent->left = node;

			next->right = right;
			set_parent(right, next);
		} else {
			set_parent(next, parent);
			parent = next;
			node = next->right;
		}
	} else {
		color = get_color(node);
		node = next;
	}

	/*
	 * 'node' is now the sole successor's child and 'parent' its
	 * new parent (since the successor can have been moved).
	 */

	if (node != NULL)
		set_parent(node, parent);

	invalidate(removed);

	/*
	 * The "easy" cases.
	 */

	if (color == RB_RED)
		return;
	if (node != NULL && is_red(node)) {
		set_color(node, RB_BLACK);
		return;
	}

	do {
		if (node == tree->root)
			break;

		if (node == parent->left) {
			rbnode_t *sibling = parent->right;

			if (is_red(sibling)) {
				set_color(sibling, RB_BLACK);
				set_color(parent, RB_RED);
				rotate_left(tree, parent);
				sibling = parent->right;
			}
			if (
				(NULL == sibling->left  || is_black(sibling->left)) &&
			    (NULL == sibling->right || is_black(sibling->right))
			) {
				set_color(sibling, RB_RED);
				node = parent;
				parent = get_parent(parent);
				continue;
			}
			if (NULL == sibling->right || is_black(sibling->right)) {
				set_color(sibling->left, RB_BLACK);
				set_color(sibling, RB_RED);
				rotate_right(tree, sibling);
				sibling = parent->right;
			}
			set_color(sibling, get_color(parent));
			set_color(parent, RB_BLACK);
			set_color(sibling->right, RB_BLACK);
			rotate_left(tree, parent);
			node = tree->root;
			break;
		} else {
			rbnode_t *sibling = parent->left;

			if (is_red(sibling)) {
				set_color(sibling, RB_BLACK);
				set_color(parent, RB_RED);
				rotate_right(tree, parent);
				sibling = parent->left;
			}
			if (
				(NULL == sibling->left  || is_black(sibling->left)) &&
			    (NULL == sibling->right || is_black(sibling->right))
			) {
				set_color(sibling, RB_RED);
				node = parent;
				parent = get_parent(parent);
				continue;
			}
			if (NULL == sibling->left || is_black(sibling->left)) {
				set_color(sibling->right, RB_BLACK);
				set_color(sibling, RB_RED);
				rotate_left(tree, sibling);
				sibling = parent->left;
			}
			set_color(sibling, get_color(parent));
			set_color(parent, RB_BLACK);
			set_color(sibling->left, RB_BLACK);
			rotate_right(tree, parent);
			node = tree->root;
			break;
		}
	} while (is_black(node));

	if (node != NULL)
		set_color(node, RB_BLACK);
}

static int
erbtree_cmp(erbtree_t *tree, rbnode_t *a, rbnode_t *b)
{
	const void *p = const_ptr_add_offset(a, -tree->offset);
	const void *q = const_ptr_add_offset(b, -tree->offset);

	if (erbtree_is_extended(tree)) {
		erbtree_ext_t *etree = ERBTREE_E(tree);
		return (*etree->u.dcmp)(p, q, etree->data);
	} else {
		return (*tree->u.cmp)(p, q);
	}
}

static inline void
erbtree_replace_internal(erbtree_t *tree,
	rbnode_t *parent, rbnode_t *old, rbnode_t *new)
{
	if (parent != NULL)
		set_child(parent, new, parent->left == old);
	else
		tree->root = new;

	if (old->left != NULL)
		set_parent(old->left, new);
	if (old->right != NULL)
		set_parent(old->right, new);

	if (tree->first == old)
		tree->first = new;
	if (tree->last == old)
		tree->last = new;
}

/**
 * Replace node in the tree.
 *
 * Great care must be taken to make sure the order in the tree is preserved.
 */
void
erbtree_replace(erbtree_t *tree, rbnode_t *old, rbnode_t *new)
{
	rbnode_t *prev, *next;

	erbtree_check(tree);
	g_assert(old != NULL);
	g_assert(new != NULL);
	g_assert(old != new);
	g_assert(is_valid(old));
	g_assert(!is_valid(new));

	prev = erbtree_prev(old);
	next = erbtree_next(old);

	g_assert(NULL == prev || erbtree_cmp(tree, prev, old) < 0);
	g_assert(NULL == next || erbtree_cmp(tree, next, old) > 0);
	g_assert(NULL == prev || erbtree_cmp(tree, prev, new) < 0);
	g_assert(NULL == next || erbtree_cmp(tree, next, new) > 0);

	erbtree_replace_internal(tree, get_parent(old), old, new);

	*new = *old;
	invalidate(old);
}

struct erbtree_foreach_args {
	size_t offset;
	data_fn_t cb;
	void *data;
};

static void
erbtree_foreach_recursive(rbnode_t *rn, const struct erbtree_foreach_args *args)
{
	if (rn->left != NULL)
		erbtree_foreach_recursive(rn->left, args);

	(*args->cb)(ptr_add_offset(rn, args->offset), args->data);

	if (rn->right != NULL)
		erbtree_foreach_recursive(rn->right, args);
}

/**
 * Traverse all the items in the tree, invoking the callback on each item.
 */
void
erbtree_foreach(erbtree_t *tree, data_fn_t cb, void *data)
{
	erbtree_check(tree);

	/*
	 * Since there is no tree modification during traversal, we can hardwire
	 * the descent to be more efficient than the non-recursive traversal we
	 * do in erbtree_foreach_remove().
	 */

	if (tree->root != NULL) {
		struct erbtree_foreach_args args;

		args.offset = -tree->offset;
		args.cb = cb;
		args.data = data;

		erbtree_foreach_recursive(tree->root, &args);
	}
}

/**
 * Traverse all the items in the tree, invoking the callback on each item
 * and removing it when the callback returns TRUE.
 *
 * @return the amount of removed items.
 */
size_t
erbtree_foreach_remove(erbtree_t *tree, data_rm_fn_t cbr, void *data)
{
	rbnode_t *rn, *next;
	size_t removed = 0, visited = 0;

	erbtree_check(tree);

	for (rn = erbtree_first(tree); rn != NULL; rn = next) {
		void *key;
		rbnode_t node;

		next = erbtree_next(rn);
		key = ptr_add_offset(rn, -tree->offset);

		/*
		 * Copy node to allow the callback to free the item (since the node
		 * is embedded within the item structure).  This works because the
		 * erbtree_remove() operation only handles the node and does not care
		 * about the structure containing it.
		 */

		node = *rn;					/* Struct copy */
		visited++;

		if ((*cbr)(key, data)) {
			/* Tweak tree to remove all references to freed address ``rn'' */
			erbtree_replace_internal(tree, get_parent(&node), rn, &node);
			erbtree_remove(tree, &node);
			removed++;
		}
	}

	/*
	 * Due to rebalancing of tree during removals, it might be possible we do
	 * not visit all the items due to a traversal bug, so only do a soft assert
	 * to get a loud trace when that happens.  This will not detect duplicate
	 * node visits negating unvisited nodes, but we're not asserting correctness
	 * here, just trying to spot obvious misbehaviour.
	 */

	g_soft_assert_log(tree->count + removed == visited,
		"%s(): count=%zu, visited=%zu (removed=%zu)",
		G_STRFUNC, tree->count, visited, removed);

	return removed;
}

/**
 * Recursively free items in the tree via application of given free routine.
 */
static void
erbtree_discard_recursive(erbtree_t *tree, rbnode_t *node, free_fn_t fcb)
{
	void *item;

	if (node->left != NULL)
		erbtree_discard_recursive(tree, node->left, fcb);
	if (node->right != NULL)
		erbtree_discard_recursive(tree, node->right, fcb);

	item = ptr_add_offset(node, -tree->offset);
	(*fcb)(item);
}

/**
 * Recursively free items in the tree via application of given free routine
 * which takes an additional context argument.
 */
static void
erbtree_discard_recursive_data(erbtree_t *tree, rbnode_t *node,
	free_data_fn_t fcb, void *data)
{
	void *item;

	if (node->left != NULL)
		erbtree_discard_recursive_data(tree, node->left, fcb, data);
	if (node->right != NULL)
		erbtree_discard_recursive_data(tree, node->right, fcb, data);

	item = ptr_add_offset(node, -tree->offset);
	(*fcb)(item, data);
}

/**
 * Reset tree to the empty state.
 */
static inline void
erbtree_reset(erbtree_t *tree)
{
	tree->root = NULL;
	tree->first = NULL;
	tree->last = NULL;
	tree->count = 0;
}

/**
 * Clear the tree, without discarding the allocated items.
 */
void
erbtree_clear(erbtree_t *tree)
{
	erbtree_check(tree);

	erbtree_reset(tree);
}

/**
 * Free all items in the tree with supplied callback routine.
 *
 * This is more efficient than running erbtree_foreach_remove() on the
 * tree because there is no need to rebalance the tree after each item
 * removal.
 *
 * @param tree		the tree where we want to free all the items
 * @param fcb		free routine invoked on each item
 *
 * Upon return, the tree is completely empty.
 */
void
erbtree_discard(erbtree_t *tree, free_fn_t fcb)
{
	erbtree_check(tree);

	if (tree->root != NULL)
		erbtree_discard_recursive(tree, tree->root, fcb);

	erbtree_reset(tree);
}

/**
 * Free all items in the tree with supplied callback routine.
 *
 * This is more efficient than running erbtree_foreach_remove() on the
 * tree because there is no need to rebalance the tree after each item
 * removal.
 *
 * @param tree		the tree where we want to free all the items
 * @param fcb		free routine invoked on each item
 * @param data		allocation context passed to the free routine
 *
 * Upon return, the tree is completely empty.
 */
void
erbtree_discard_with_data(erbtree_t *tree, free_data_fn_t fcb, void *data)
{
	erbtree_check(tree);

	if (tree->root != NULL)
		erbtree_discard_recursive_data(tree, tree->root, fcb, data);

	erbtree_reset(tree);
}

/**
 * Initialize embedded tree.
 *
 * Assuming items in the tree are defined as:
 *
 *     struct item {
 *         int key;
 *         <other fields>
 *         rbnode_t node;
 *     };
 *
 * then the last argument can be given as:
 *
 *     offsetof(struct item, node)
 *
 * to indicate the place of the node field within the item.
 *
 * @param tree		the tree structure to initialize
 * @param cmp		the item comparison routine
 * @param offset	the offset of the embedded node field within items
 */
void
erbtree_init(erbtree_t *tree, cmp_fn_t cmp, size_t offset)
{
	g_assert(tree != NULL);
	g_assert(cmp != NULL);
	g_assert(size_is_non_negative(offset));

	tree->magic = ERBTREE_MAGIC;
	tree->u.cmp = cmp;
	tree->offset = offset;
	erbtree_reset(tree);
}

/**
 * Initialize embedded tree with extended comparison function.
 *
 * This is used for red-black tree containers which can store any data
 * and therefore need an additinal argument passed to the comparison routine.
 *
 * @param tree		the tree structure to initialize
 * @param cmp		the item comparison routine
 * @param data		the additional argument for the item comparison routine
 * @param offset	the offset of the embedded node field within items
 */
void erbtree_init_data(erbtree_ext_t *tree,
	cmp_data_fn_t cmp, void *data, size_t offset)
{
	g_assert(tree != NULL);
	g_assert(cmp != NULL);
	g_assert(size_is_non_negative(offset));

	tree->magic = ERBTREE_EXT_MAGIC;
	tree->u.dcmp = cmp;
	tree->data = data;
	tree->offset = offset;
	erbtree_reset((erbtree_t *) tree);
}

/* vi: set ts=4 sw=4 cindent: */
