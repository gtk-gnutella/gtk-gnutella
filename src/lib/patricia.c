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
 * Practical Algorithm To Retrieve Information Coded In Alphanumeric.
 *
 * See http://www.csse.monash.edu.au/~lloyd/tildeAlgDS/Tree/PATRICIA/
 *
 * The following example shows the growth of a PATRICIA tree under a
 * sequence of insertions (the alphabet here is {a,b} instead of {0,1}):
 * 
 *     empty             -- initial state
 * 
 *        12345          -- number character positions
 * insert ababb          -- the key
 *
 * (differences are shown by upper-casing the alphabet letter)
 * 
 *     ----> ababb
 * 
 * insert ababa;
 *     search ends at ababB~=ababA; 
 *     1st difference is at position 5, so... 
 * 
 *     ----> [5]         -- i.e. test position #5
 *          .   .
 *      "a".     ."b"    -- left path taken bit #5 is "a", right if "b"
 *        .       .
 *       ababa     ababb
 * 
 * insert ba;
 *     has no position #5; 
 *     can skip key positions but must test in order, so... 
 * 
 *     --------> [1]
 *              .   .
 *             .     .
 *            .       .
 *         [5]         ba
 *        .   .
 *       .     .
 *      .       .
 *     ababa     ababb
 * 
 * insert aaabba;
 *     search ends at aBabb~=aAabba; 
 *     can skip key positions but must test in order, so... 
 * 
 *     --------> [1]
 *              .   .
 *             .     .
 *            .       .
 *         [2]         ba
 *        .   .
 *       .     .
 *      .       .
 *     aaabba    [5]
 *              .   .
 *             .     .
 *            .       .
 *           ababa     ababb
 *
 * (WARNING: below text differs from original text on the URL quoted above)
 * 
 * insert ab;
 *     ab is also a prefix of ababa and ababb; 
 *     must have ability to terminate at an intermediate node, as with Tries. 
 * 
 *     -------> [1]
 *             .   .
 *            .     .
 *           .       .
 *         [2]        ba
 *        .   .
 *       .     .
 *      .       .
 *     aaabba    [3]---> ab   -- valid "stop-point" in search: contains value
 *              .   .
 *             .     .
 *            .       .
 *           [5]      NULL    -- no "right" child: no key starting with abb yet
 *          .   .
 *         .     .
 *        .       .
 *       ababa     ababb
 * 
 * It is the position in the tree that defines the key, for lookups. No
 * comparison of keys are done other than testing individual bits.
 *
 * To indicate that the node flagged "[3]" above contains the key "ab" (i.e.
 * it is a valid stop-point), the node is storing the key pointer. This
 * differs from a typical PATRICIA where only fragments of the keys are
 * stored in various nodes. But that would prevent keys from being actually
 * reclaimed and freed.
 *
 * When traversing the tree from the root with key "ab", the node flagged "[2]"
 * will bring us to node "[3]" and it is because the key length 2 is less than
 * 3 AND because the node is flagged a containing embedded data that it
 * indicates "ab" is a valid key with an attached value.  This can happen only
 * when the keys stored in the tree are of variable length.
 *
 * Compared to a hash table, a PATRICIA tree has more overhead per key/value
 * item stored (due to the chaining overhead of the tree) but has much more
 * efficient lookups (only a few bits of the key are compared, once, as opposed
 * to many key comparisons in a hash table due to hashing collisions).  For a
 * small amount of items stored, this must be compared to the extra overhead in
 * the hash table to initially hash keys (either the whole arena size in the
 * case of Knuth-like hash tables, or the size of the arena containing pointers
 * to sub-lists in the case of a hash-list type of hash table, which is what
 * GHashTable implements).
 *
 * A PATRICIA tree allows for efficient storage of variable length keys
 * (e.g. CIDR IP ranges), which a hash table cannot handle and can answer
 * queries about keys starting with a common prefix, which a hash table
 * cannot efficiently answer to.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "patricia.h"
#include "endian.h"
#include "misc.h"
#include "walloc.h"
#include "override.h"			/* Must be the last header included */

struct patricia_parent;

/**
 * A PATRICIA node in the tree.
 */
struct patricia_node {
	union {
		struct patricia_node *parent;	/**< Parent node (NULL if root node) */
		struct patricia_parent *ext;	/**< Extended: parent + data */
	} p;
	union {
		struct {						/**< Non-leaf nodes */
			struct patricia_node *z;	/**< The "zero" child (left) */
			struct patricia_node *o;	/**< The "one" child (right) */
		} children;
		struct {						/**< Leaf nodes */
			const void *key;			/**< The item key */
			const void *value;			/**< Data stored in this node */
		} item;
	} u;
	guint8 bit;						/**< Bit to test for choosing "z" or "o" */
	guint8 last_kbit;				/**< Last bit # in key (7 if 8-bit key) */
	gboolean leaf;					/**< Is a leaf node */
	gboolean has_embedded_data;		/**< Non-leaf node has data */
};

/**
 * For non-leaf nodes holding data items, an extra indirection is required to
 * reach the parent node.
 */
struct patricia_parent {
	struct patricia_node *parent;	/**< Parent node (NULL if root node) */
	const void *key;				/**< The item key */
	const void *value;				/**< Data stored for the key in this node */
};

/*
 * Accessing shortcuts.
 */

#define child_zero(n_)			((n_)->u.children.z)
#define child_one(n_)			((n_)->u.children.o)
#define leaf_item_key(n_)		((n_)->u.item.key)
#define leaf_item_value(n_)		((n_)->u.item.value)
#define leaf_item_keybits(n_)	(size_t) ((n_)->last_kbit + 1)

#define parent_node(n_) \
	((n_)->has_embedded_data ? (n_)->p.ext->parent : (n_)->p.parent)

#define embedded_item_key(n_)		((n_)->p.ext->key)
#define embedded_item_value(n_)		((n_)->p.ext->value)
#define embedded_item_keybits(n_)	(size_t) ((n_)->bit)

/**
 * The PATRICIA tree.
 */
struct patricia {
	struct patricia_node *root;		/**< Root of tree (lazily allocated) */
	size_t maxbits;					/**< Maximum bitsize of key */
	size_t count;					/**< Amount of keys stored */
	size_t nodes;					/**< Total amount of nodes used */
	size_t embedded;				/**< Nodes holding embedded data */
	guint stamp;					/**< Stamp to protect iterators */
};

/**
 * Create a new PATRICIA tree.
 *
 * @param maxbits			Maximum key size, in bits (must be <= 256)
 *
 * @return the created PATRICIA tree.
 */
patricia_t *
patricia_create(size_t maxbits)
{
	patricia_t *pt;

	g_assert(maxbits <= PATRICIA_MAXBITS);
	g_assert(maxbits != 0);

	pt = walloc(sizeof *pt);
	pt->root = NULL;
	pt->count = pt->nodes = pt->embedded = 0;
	pt->maxbits = maxbits;
	pt->stamp = 0;

	return pt;
}

/**
 * Returns amount of items held in the PATRICIA tree.
 */
size_t
patricia_count(const patricia_t *pt)
{
	g_assert(pt);

	return pt->count;
}

/**
 * Allocate a new PATRICIA node.
 */
static struct patricia_node *
allocate_node(patricia_t *pt)
{
	g_assert(pt);

	pt->nodes++;
	return walloc(sizeof(struct patricia_node));
}

/**
 * Free a PATRICIA node.
 */
static void
free_node(patricia_t *pt, struct patricia_node *pn)
{
	g_assert(pt);
	g_assert(pn);
	g_assert(pt->nodes > 0);

	pt->nodes--;
	wfree(pn, sizeof *pn);
}

/**
 * Compute the key prefix matched by a given node.
 *
 * @param pn		the PATRICIA node which we want to compute the prefix for
 *
 * @return a pointer to a key stored in a sub node, so it has more bits
 * than the actual prefix and fills.
 */
static gconstpointer
node_prefix(const struct patricia_node *pn)
{
	const struct patricia_node *n;
	int i;
	gconstpointer result = NULL;

	g_assert(pn);

	for (n = pn, i = 0; i < PATRICIA_MAXBITS; i++) {
		const struct patricia_node *child;

		g_assert(n);

		/*
		 * If the node holds a value, then by construction its leading key
		 * bits (up to the bit before the one tested in this node) form a
		 * valid prefix.
		 */

		if (n->has_embedded_data) {
			g_assert(!n->leaf);
			result = embedded_item_key(n);
			goto found;
		}

		/*
		 * If the node is a leaf node, then by construction it holds a value
		 * whose size in bits is n->last_kbit + 1 and whose leading bits
		 * form a valid prefix for the parent nodes.
		 */

		if (n->leaf) {
			result = leaf_item_key(n);
			goto found;
		}

		/*
		 * One of the two children can point to NULL, if we haven't seen a
		 * key for the node's prefix and this branch.  However, one of the
		 * two children is necessarily non-NULL or this node would not exist.
		 *
		 * If one of the children contains embedded data, we pick it, otherwise
		 * we pick the first one non-NULL.  This is because embedded data will
		 * have us terminate the tree traversal.
		 */

		child = child_zero(n);
		if (child == NULL)
			child = child_one(n);
		else if (!child->has_embedded_data) {
			const struct patricia_node *sibling = child_one(n);
			if (sibling != NULL && sibling->has_embedded_data)
				child = sibling;
		}

		g_assert(child != NULL);	/* No node can exist with 2 NULL children */

		n = child;
	}

	g_assert_not_reached();			/* A value must have been found */

found:
	g_assert(result != NULL);

	return result;
}

/**
 * Set parent's pointer, taking care of nodes with embedded data.
 */
static inline void
set_parent(struct patricia_node *pn, struct patricia_node *parent)
{
	g_assert(pn);

	if (pn->has_embedded_data) {
		g_assert(!pn->leaf);
		pn->p.ext->parent = parent;
	} else {
		pn->p.parent = parent;
	}

	g_assert(parent_node(pn) == parent);
}

/**
 * Is the current node test bit matched by the key?
 */
static inline gboolean
node_matches(const struct patricia_node *pn, gconstpointer key, size_t keybits)
{
	const guint8 *k = key;

	g_assert(pn);
	g_assert(key);
	g_assert(keybits >= (size_t) pn->bit + 1);

	return 0 != (k[pn->bit >> 3] & (0x80 >> (pn->bit & 0x7)));
}

/**
 * Determine how many leading bits the two keys have in common.
 *
 * @param k1		the first key
 * @param k1bits	size of the first key in bits
 * @param k2		the second key
 * @param k2bits	size of the second key in bits
 *
 * @return the number of common leading bits, which is at most
 * min(k1bits, k2bits) if everything matches.
 */
static size_t
common_leading_bits(
	gconstpointer k1, size_t k1bits, gconstpointer k2, size_t k2bits)
{
	const guint8 *p1 = k1;
	const guint8 *p2 = k2;
	size_t cbits;			/* Total amount of bits to compare */
	size_t bytes;			/* Amount of bytes to compare */
	size_t bits;			/* Remaining bits in last byte */
	size_t i;

	g_assert(k1);
	g_assert(k2);
	g_assert(k1bits);
	g_assert(k2bits);

	cbits = MIN(k1bits, k2bits);

	if (k1 == k2)
		return cbits;

	bytes = cbits >> 3;

	for (i = 0; i < bytes; i++) {
		guint8 xor = *p1++ ^ *p2++;
		if (xor)
			return i * 8 + 7 - highest_bit_set(xor);
	}

	bits = cbits & 0x7;

	if (bits != 0) {
		guint8 mask = ~((1 << (8 - bits)) - 1);
		guint8 xor = (*p1 & mask) ^ (*p2 & mask);
		if (xor)
			return bytes * 8 + 7 - highest_bit_set(xor);
	}

	return cbits;		/* All the bits we compared matched */
}

/**
 * Determine whether two keys of equal size are equal.
 *
 * @param k1		the first key
 * @param k2		the second key
 * @param keybits	size of both keys in bits
 *
 * @return TRUE if keys are identical.
 */
static gboolean
key_eq(gconstpointer k1, gconstpointer k2, size_t keybits)
{
	size_t bytes;			/* Amount of bytes to compare */
	size_t bits;			/* Remaining bits in last byte */

	if (k1 == k2)
		return TRUE;

	bytes = keybits >> 3;

	if (0 != memcmp(k1, k2, bytes))
		return FALSE;

	bits = keybits & 0x7;

	if (bits != 0) {
		/* Compare trailing byte, but only meaningful bits */
		guint8 mask = ~((1 << (8 - bits)) - 1);
		const guint8 *p1 = k1;
		const guint8 *p2 = k2;
		guint8 xor = (p1[bytes] & mask) ^ (p2[bytes] & mask);

		return 0 == xor;
	}

	return TRUE;
}

/**
 * Number of bits for the node's prefix.
 */
static inline size_t
node_prefix_bits(const struct patricia_node *pn)
{
	return pn->leaf ? leaf_item_keybits(pn) : embedded_item_keybits(pn);
}

/**
 * Given a node and a key, determine how many leading bits in the key are
 * matched by the node returned by match_best().
 *
 * @param pn		the PATRICIA node returned by match_best()
 * @param key		the key we looked up
 * @param keybits	the size of the key in bits
 * @param pprefix	where to write the prefix for the match, if not NULL
 */
static size_t
matched_bits(
	const struct patricia_node *pn, gconstpointer key, size_t keybits,
	gconstpointer *pprefix)
{
	gconstpointer prefix;

	g_assert(pn);

	prefix = node_prefix(pn);
	if (pprefix)
		*pprefix = prefix;

	return common_leading_bits(prefix, node_prefix_bits(pn), key, keybits);
}

/**
 * Look in the tree for the node which matches as many bits as possible from
 * the key.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 * @param keybits	the amount of significant bits in the key
 *
 * @return the node under which all entries share a common prefix (the amount
 * of matching leading bits within the key can be determined by calling
 * matched_bits() on the resulting node).
 */
static struct patricia_node *
match_best(patricia_t *pt, gconstpointer key, size_t keybits)
{
	const struct patricia_node *pn;
	int i;

	g_assert(pt);
	g_assert(pt->root);
	g_assert(key);
	g_assert(keybits);
	g_assert(keybits <= pt->maxbits);

	for (pn = pt->root, i = 0; i < PATRICIA_MAXBITS; i++) {
		const struct patricia_node *child;

		g_assert(pn);

		/*
		 * If we have less bits in the key than the first bit to test for at
		 * this node to branch between children, then clearly we have to stop.
		 * Likewise if we reached a leaf node.
		 *
		 * It does not mean we matched any bit from the key though.
		 */

		if (keybits - 1 < pn->bit || pn->leaf)
			return deconstify_gpointer(pn);

		child = node_matches(pn, key, keybits) ? child_one(pn) : child_zero(pn);
		if (child == NULL)
			return deconstify_gpointer(pn);

		g_assert(child->leaf || child->bit > pn->bit);

		pn = child;
	}

	g_assert_not_reached();
}

/**
 * Look in the tree for the node which matches exactly the key.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 * @param keybits	the amount of significant bits in the key
 *
 * @return the node which is an exact match, or NULL if not found.
 */
static const struct patricia_node *
match_exact(const patricia_t *pt, gconstpointer key, size_t keybits)
{
	const struct patricia_node *pn;
	int i;

	g_assert(pt);
	g_assert(key);
	g_assert(keybits);
	g_assert(keybits <= pt->maxbits);

	if (pt->root == NULL)
		return NULL;

	for (pn = pt->root, i = 0; i < PATRICIA_MAXBITS; i++) {
		const struct patricia_node *child;

		g_assert(pn);

		/*
		 * If we have exactly the same amount of bits and the node contains
		 * an embedded data, stop.
		 */

		if (keybits == pn->bit && pn->has_embedded_data)
			return key_eq(key, embedded_item_key(pn), keybits) ? pn : NULL;

		/*
		 * If we reach a leaf node, compare the key with the value.
		 */

		if (pn->leaf) {
			if (leaf_item_keybits(pn) != keybits)
				return NULL;
			return key_eq(key, leaf_item_key(pn), keybits) ? pn : NULL;
		}

		/*
		 * Stop if we have less bits in the key than the first bit to test.
		 */

		if (keybits - 1 < pn->bit)
			return NULL;

		child = node_matches(pn, key, keybits) ? child_one(pn) : child_zero(pn);
		if (child == NULL)
			return NULL;

		g_assert(child->leaf || child->bit > pn->bit);

		pn = child;
	}

	g_assert_not_reached();
}

/**
 * Fill leaf PATRICIA node with key/value.
 */
static void
fill_leaf(struct patricia_node *pn, struct patricia_node *parent,
	gconstpointer key, size_t keybits, gconstpointer value)
{
	pn->leaf = TRUE;
	pn->has_embedded_data = FALSE;
	pn->p.parent = parent;
	pn->u.item.key = key;
	pn->u.item.value = value;
	pn->last_kbit = keybits - 1;
	pn->bit = 0;				/* Does not matter for leaves */
}

/**
 * Remove embedded data information from node.
 */
static void
clear_embedded_data(struct patricia_node *pn)
{
	struct patricia_node *parent;

	g_assert(pn);
	g_assert(pn->has_embedded_data);

	parent = parent_node(pn);
	pn->has_embedded_data = FALSE;
	wfree(pn->p.ext, sizeof *pn->p.ext);
	pn->p.parent = parent;

	g_assert(parent_node(pn) == parent);
}

/**
 * Remove node deemed useless from the tree.
 */
static void
remove_useless_node(patricia_t *pt, struct patricia_node *pn)
{
	struct patricia_node *parent;
	struct patricia_node *child = NULL;

	g_assert(pt);
	g_assert(pn);

	parent = parent_node(pn);

	if (!pn->leaf) {
		child = child_one(pn);
		if (child == NULL)
			child = child_zero(pn);
		g_assert(child);
	}

	if (child) {
		g_assert(parent_node(child) == pn);
		set_parent(child, parent);
	}

	if (parent) {
		if (child_one(parent) == pn) {
			parent->u.children.o = child;
		} else {
			g_assert(child_zero(parent) == pn);
			parent->u.children.z = child;
		}
	} else {
		pt->root = child;
	}
		
	free_node(pt, pn);
}

/**
 * Remove embedded data, making node a leaf node.
 */
static void
unembed_data(patricia_t *pt, struct patricia_node *pn)
{
	gconstpointer old_key;
	gconstpointer old_value;
	size_t old_keybits;
	struct patricia_node *parent;

	g_assert(pt);
	g_assert(pn);
	g_assert(!pn->leaf);
	g_assert(pn->has_embedded_data);
	g_assert(child_one(pn) == NULL && child_zero(pn) == NULL);

	old_key = embedded_item_key(pn);
	old_value = embedded_item_value(pn);
	old_keybits = embedded_item_keybits(pn);
	parent = parent_node(pn);

	wfree(pn->p.ext, sizeof *pn->p.ext);

	g_assert(old_keybits < pt->maxbits);

	pt->embedded--;
	pn->p.parent = parent;
	pn->leaf = TRUE;
	pn->has_embedded_data = FALSE;
	pn->last_kbit = old_keybits - 1;
	pn->bit = 0;
	pn->u.item.key = old_key;
	pn->u.item.value = old_value;

	g_assert(parent_node(pn) == parent);
	g_assert(leaf_item_key(pn) == old_key);
	g_assert(leaf_item_keybits(pn) == old_keybits);
	g_assert(leaf_item_value(pn) == old_value);
}

/**
 * Insert key/value pair at or below the given current node.
 * We are called only when ALL the bits of the key matched the node's prefix.
 *
 * @param pt		the PATRICIA tree
 * @param pn		the PATRICIA node
 * @param key		pointer to the start of the key bits
 * @param keybits	amount of bits to consider in the key
 * @param value		value to insert in the tree for this key.
 */
static void
insert_at(
	patricia_t *pt, struct patricia_node *pn,
	gconstpointer key, size_t keybits, gconstpointer value)
{
	g_assert(keybits >= node_prefix_bits(pn));

	if (!pn->leaf) {
		g_assert(keybits == (size_t) pn->bit);
		g_assert(keybits < pt->maxbits);

		/*
		 * Node is not a leaf.
		 * Insertion "at" can only happen as embedded data.
		 */

		if (pn->has_embedded_data) {
			/* Replacement of existing item */
			pn->p.ext->key = key;
			pn->p.ext->value = value;
		} else {
			struct patricia_parent *ext;

			/* New item */
			ext = walloc(sizeof *ext);
			ext->parent = pn->p.parent;
			ext->key = key;
			ext->value = value;
			pn->p.ext = ext;
			pn->has_embedded_data = TRUE;
			pt->count++;
			pt->embedded++;
		}
	} else if (leaf_item_keybits(pn) == keybits) {
		/* Same amount of bits, all matched: replace old key/value. */
		pn->u.item.key = key;
		pn->u.item.value = value;
	} else {
		/* Differing amount of bits: need a new node */

		struct patricia_node *new = allocate_node(pt);
		struct patricia_node *parent = parent_node(pn);
		struct patricia_parent *ext = walloc(sizeof *ext);

		pt->count++;

		g_assert(keybits < leaf_item_keybits(pn));	/* ALL keybits matched */

		/*
		 * New key is smaller than the previous one: we need to
		 * discriminate between this new key and the old one by inserting
		 * a new test on the bit right after the new key, and the new
		 * value will be stored as embedded data in this new node placed
		 * above the existing leaf.
		 */

		g_assert(keybits < pt->maxbits);
		g_assert(parent == NULL || parent->bit < keybits);

		new->leaf = FALSE;
		new->has_embedded_data = TRUE;
		new->last_kbit = 0;			/* Does not matter for non-leaves */
		new->bit = keybits;
		new->p.ext = ext;
		ext->key = key;
		ext->value = value;
		ext->parent = parent;
		pt->embedded++;

		if (parent == NULL)
			pt->root = new;

		if (node_matches(new, leaf_item_key(pn), leaf_item_keybits(pn))) {
			/* Old node is the "o" child of the new */
			new->u.children.z = NULL;
			new->u.children.o = pn;
		} else {
			/* Old node is the "z" child of the new */
			new->u.children.z = pn;
			new->u.children.o = NULL;
		}
		pn->p.parent = new;			/* Stays a leaf => no embedded data */
	}
}

/**
 * Insert key/value pair below the given current node.
 * We are called only when ALL the node's prefix bits are found at the
 * beginning of the key, but the key is larger because not all its bits
 * matched the prefix.
 *
 * @param pt		the PATRICIA tree
 * @param pn		the PATRICIA node
 * @param key		pointer to the start of the key bits
 * @param keybits	amount of bits to consider in the key
 * @param value		value to insert in the tree for this key.
 * @param common	amount of common bits between key and node's prefix
 */
static void
insert_below(
	patricia_t *pt, struct patricia_node *pn,
	gconstpointer key, size_t keybits, gconstpointer value, size_t common)
{
	struct patricia_node *new = allocate_node(pt);

	g_assert(common < keybits);

	fill_leaf(new, pn, key, keybits, value);
	pt->count++;

	if (pn->leaf) {
		size_t diffbit = common;
		gconstpointer old_key = leaf_item_key(pn);
		gconstpointer old_value = leaf_item_value(pn);
		size_t old_keybits = leaf_item_keybits(pn);
		struct patricia_node *old = NULL;

		g_assert(diffbit < pt->maxbits);
		g_assert(!pn->has_embedded_data);

		pn->leaf = FALSE;
		pn->last_kbit = 0;
		pn->bit = diffbit;

		/*
		 * If the item held in the leaf node is exactly of size "diffbit",
		 * then it cannot be put in a child and it will have to be stored
		 * as embedded data in the new node.
		 */

		g_assert(old_keybits >= diffbit);

		if (old_keybits == diffbit) {
			struct patricia_parent *ext = walloc(sizeof *ext);

			g_assert(keybits < pt->maxbits);

			ext->parent = pn->p.parent;
			ext->key = old_key;
			ext->value = old_value;
			pn->has_embedded_data = TRUE;
			pn->p.ext = ext;
			pt->embedded++;
		} else {
			old = allocate_node(pt);
			fill_leaf(old, pn, old_key, old_keybits, old_value);
		}

		if (node_matches(pn, key, keybits)) {
			g_assert(old == NULL || !node_matches(pn, old_key, old_keybits));
			pn->u.children.z = old;
			pn->u.children.o = new;
		} else {
			g_assert(old == NULL || node_matches(pn, old_key, old_keybits));
			pn->u.children.z = new;
			pn->u.children.o = old;
		}
	} else {
		/*
		 * One of the children is NULL and this is where we need to
		 * insert the new value.
		 */

		g_assert(common == pn->bit);	/* "tested" bit */

		if (node_matches(pn, key, keybits)) {
			g_assert(pn->u.children.o == NULL);
			g_assert(pn->u.children.z != NULL);
			pn->u.children.o = new;
		} else {
			g_assert(pn->u.children.z == NULL);
			g_assert(pn->u.children.o != NULL);
			pn->u.children.z = new;
		}
	}
}

/**
 * Insert key/value pair above the given current node.
 * We are called only the node's prefix only partially matches the beginning
 * of the key.
 *
 * @param pt		the PATRICIA tree
 * @param pn		the PATRICIA node
 * @param key		pointer to the start of the key bits
 * @param keybits	amount of bits to consider in the key
 * @param value		value to insert in the tree for this key.
 * @param common	amount of common bits between key and node's prefix
 * @param prefix	the node's prefix at the original "pn" point
 */
static void
insert_above(
	patricia_t *pt, struct patricia_node *pn,
	gconstpointer key, size_t keybits, gconstpointer value, size_t common,
	gconstpointer prefix)
{
	struct patricia_node *new = allocate_node(pt);
	struct patricia_node *up;
	struct patricia_node *child;

	g_assert(common <= keybits);

	/*
     * Go up in the tree to find a node where we test for bit common or less
	 * (the bit at index "common" is one bit after the last common bit).
	 */

	for (
		child = pn, up = parent_node(pn);
		up;
		child = up, up = parent_node(up)
	) {
		g_assert(up->bit != common);		/* Or we would insert below it */
		g_assert(!up->leaf);				/* We went up at least once */
		if (up->bit < common)
			break;
	}

	/*
	 * Now we are either at the root (up == NULL) or at a node testing
	 * a bit before the "common" bit.  We are going to insert a new
	 * intermediate node underneath and connect "child" (the node we used
	 * to reach "up" when going up) to the right side of the tree.
	 */

	new->leaf = FALSE;
	new->has_embedded_data = FALSE;
	new->bit = common;
	new->last_kbit = 0;
	new->p.parent = up;

	if (node_matches(new, prefix, common + 1)) {
		new->u.children.z = NULL;
		new->u.children.o = child;
	} else {
		new->u.children.z = child;
		new->u.children.o = NULL;
	}

	/*
	 * If we had a parent, we need to connect its child link that was
	 * pointing to the child to go to the new node instead.
	 * Otherwise, the new node becomes the root of the PATRICIA tree.
	 */

	if (up == NULL) {
		pt->root = new;
	} else {
		if (up->u.children.z == child)
			up->u.children.z = new;
		else if (up->u.children.o == child)
			up->u.children.o = new;
		else
			g_assert_not_reached();
	}

	/*
	 * Link the child to its new parent.
	 */

	set_parent(child, new);

	/*
	 * We can now insert the value at or underneath the new node, since we know
	 * that common <= keybits.
	 */

	if (common == keybits)
		insert_at(pt, new, key, keybits, value);
	else
		insert_below(pt, new, key, keybits, value, common);
}

/**
 * Insert new key/value pair in the PATRICIA tree.
 * Any previously existing value for the key is replaced by the new one.
 * NULL is a valid value.
 *
 * The tree stores the key and value pointers so these must not be freed
 * whilst the value is held in the PATRICIA tree.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits
 * @param keybits	amount of bits to consider in the key
 * @param value		value to insert in the tree for this key.
 */
void
patricia_insert(patricia_t *pt,
	gconstpointer key, size_t keybits, gconstpointer value)
{
	struct patricia_node *pn;
	size_t common_bits;
	gconstpointer prefix;

	g_assert(pt);
	g_assert(key);
	g_assert(keybits);
	g_assert(keybits <= pt->maxbits);

	pt->stamp++;

	/*
	 * If tree is empty, item is stored at the root node.
	 */

	if (NULL == pt->root) {
		g_assert(0 == pt->count);
		pn = pt->root = allocate_node(pt);
		fill_leaf(pn, NULL, key, keybits, value);
		pt->count++;
		return;
	}

	/*
	 * Find node in the tree which is the longest (partial) match for the key.
	 */

	pn = match_best(pt, key, keybits);
	common_bits = matched_bits(pn, key, keybits, &prefix);

	if (common_bits == keybits && keybits >= node_prefix_bits(pn)) {
		/* All bits from key matched: found node where insertion can be done */
		insert_at(pt, pn, key, keybits, value);
	} else if (common_bits == node_prefix_bits(pn)) {
		/* The common bits are the node's prefix: insertion must occur below */
		g_assert(common_bits < keybits);
		insert_below(pt, pn, key, keybits, value, common_bits);
	} else {
		g_assert(common_bits < node_prefix_bits(pn));
		insert_above(pt, pn, key, keybits, value, common_bits, prefix);
	}
}

/**
 * Check whether the PATRICIA tree contains a key.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits
 * @param keybits	amount of bits to consider in the key
 */
gboolean
patricia_contains(const patricia_t *pt, gconstpointer key, size_t keybits)
{
	return match_exact(pt, key, keybits) != NULL;
}

/**
 * Fetch a value from the PATRICIA tree, or NULL if not found.
 *
 * @attention
 * NOTE: Since NULL is a valid value for storage, one cannot distinguish
 * from the returned value whether the data is NULL or the key was not
 * found, unless one knows that NULL values are not inserted.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits
 * @param keybits	amount of bits to consider in the key
 *
 * @return the value for the key, or NULL if not found.
 */
gpointer
patricia_lookup(const patricia_t *pt, gconstpointer key, size_t keybits)
{
	const struct patricia_node *pn = match_exact(pt, key, keybits);

	if (NULL == pn)
		return NULL;

	if (pn->leaf)
		return deconstify_gpointer(leaf_item_value(pn));
	else if (pn->has_embedded_data)
		return deconstify_gpointer(embedded_item_value(pn));

	g_assert_not_reached();
	return NULL;
}

/**
 * Fetch key/value from the PATRICIA tree, returning whether the key
 * was found.  If it was, the original key/value pointers are written
 * back in keyptr and valueptr.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits
 * @param keybits	amount of bits to consider in the key
 * @param keyptr	if non-NULL, where the original key pointer is written
 * @param valptr	if non-NULL, where the original value pointer is written
 *
 * @return whether the key was found and keyptr/valueptr written back.
 */
gboolean
patricia_lookup_extended(
	const patricia_t *pt, gconstpointer key, size_t keybits,
	gpointer *keyptr, gpointer *valptr)
{
	const struct patricia_node *pn = match_exact(pt, key, keybits);

	if (NULL == pn)
		return FALSE;

	if (pn->leaf) {
		if (keyptr)
			*keyptr = deconstify_gpointer(leaf_item_key(pn));
		if (valptr)
			*valptr = deconstify_gpointer(leaf_item_value(pn));
	} else if (pn->has_embedded_data) {
		if (keyptr)
			*keyptr = deconstify_gpointer(embedded_item_key(pn));
		if (valptr)
			*valptr = deconstify_gpointer(embedded_item_value(pn));
	} else
		g_assert_not_reached();

	return TRUE;
}

/**
 * Remove node from the PATRICIA tree, cleaning up the tree to also remove
 * the possible useless node created by the removal of the first.
 */
static void
remove_node(patricia_t *pt, struct patricia_node *pn)
{
	g_assert(pt);
	g_assert(pn);

	pt->stamp++;
	pt->count--;

	if (pn->has_embedded_data) {
		g_assert(!pn->leaf);
		pt->embedded--;
		clear_embedded_data(pn);
		if (child_zero(pn) == NULL || child_one(pn) == NULL)
			remove_useless_node(pt, pn);
	} else if (pn->leaf) {
		struct patricia_node *parent = parent_node(pn);
		remove_useless_node(pt, pn);
		if (parent) {
			if (!parent->has_embedded_data)
				remove_useless_node(pt, parent);	/* Has only one leaf now */
			else if (child_one(parent) == NULL && child_zero(parent) == NULL)
				unembed_data(pt, parent);
		}
	} else
		g_assert_not_reached();
}

/**
 * Remove key from the PATRICIA tree.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits
 * @param keybits	amount of bits to consider in the key
 *
 * @return TRUE if the key was found and removed from the PATRICIA tree.
 */
gboolean
patricia_remove(patricia_t *pt, gconstpointer key, size_t keybits)
{
	struct patricia_node *pn;

	pn = deconstify_gpointer(match_exact(pt, key, keybits));

	if (NULL == pn)
		return FALSE;

	remove_node(pt, pn);

	return TRUE;
}

/**
 * Callback for nodes in traverse().
 */
typedef void (*node_cb_t)(struct patricia_node *pn, gpointer un);

/**
 * Iterate over all the key/value pairs, invoking the callback on each item.
 *
 * @param pt		the PATRICIA tree to traverse
 * @param ncb		the callback to invoke on each node if not NULL
 * @param un		additional user argument for the ncb callback
 * @param cb		the callback to invoke on each key/value pair if not NULL
 * @param u			additional user argument for the cb callback
 * 
 */
static void
traverse(patricia_t *pt,
	node_cb_t ncb, gpointer un,
	patricia_cb_t cb, gpointer u)
{
	g_assert(pt);

	/*
	 * Traverse without recursing for maximum efficiency.
	 * We maintain a stack of un-visited "one" nodes.
	 */

	if (pt->root) {
		struct patricia_node *stack[PATRICIA_MAXBITS];
		struct patricia_node **sp = stack;
		struct patricia_node *n = pt->root;

		while (n) {
			struct patricia_node *z = NULL;
			struct patricia_node *o = NULL;

			if (!n->leaf) {
				z = child_zero(n);
				o = child_one(n);
			}

			if (n->leaf && cb) {
				(*cb)(deconstify_gpointer(leaf_item_key(n)),
					leaf_item_keybits(n),
					deconstify_gpointer(leaf_item_value(n)), u);
			} else if (n->has_embedded_data && cb) {
				(*cb)(deconstify_gpointer(embedded_item_key(n)),
					embedded_item_keybits(n),
					deconstify_gpointer(embedded_item_value(n)), u);
			}

			/* Callback may free the node */
			if (ncb)
				(*ncb)(n, un);

			if (z) {
				if (o) {
					g_assert(sp < &stack[PATRICIA_MAXBITS]);
					*sp++ = o;
				}
				n = z;
			} else if (o) {
				n = o;
			} else if (sp != stack) {
				n = *(--sp);
			} else {
				n = NULL;
			}
		}
	}
}

/**
 * Node callback for traverse().
 */
static void
traverse_remove_node(struct patricia_node *pn, gpointer u)
{
	patricia_t *pt = u;

	free_node(pt, pn);
}

/**
 * Destroy the PATRICIA tree.
 */
void
patricia_destroy(patricia_t *pt)
{
	g_assert(pt);

	traverse(pt, traverse_remove_node, pt, NULL, NULL);
	g_assert(pt->nodes == 0);

	wfree(pt, sizeof *pt);
}

/**
 * Call the given function on all the key/value pairs in the PATRICIA tree.
 *
 * @param pt	the PATRICIA tree
 * @param cb	the callback to invoke
 * @param u		additional opaque user data for the callback
 */
void
patricia_foreach(const patricia_t *pt, patricia_cb_t cb, gpointer u)
{
	g_assert(pt);
	g_assert(cb);

	traverse(deconstify_gpointer(pt), NULL, NULL, cb, u);
}

/**
 * Context for patricia_foreach_remove().
 */
struct remove_ctx {
	GSList *sl;						/* List of nodes to remove */
	gboolean last_was_removed;		/* Last key/value traversed is removed */
	patricia_cbr_t cb;				/* User callback to invoke */
	gpointer u;						/* User data for callback */
	size_t removed;					/* Counts amount of items removed */
};

/**
 * Node callback for traverse().
 * Relies on the fact that it is invoked right after the user callback.
 */
static void
traverse_foreach_node(struct patricia_node *pn, gpointer u)
{
	struct remove_ctx *ctx = u;

	/*
	 * ctx->last_was_removed was set possibly by previous call to the
	 * user-supplied callback, through the traverse_foreach_item() trampoline.
	 */

	if (ctx->last_was_removed) {
		/*
		 * Prepend node to remove, so that we start removing nodes that are
		 * the deepest in the tree.
		 */
		ctx->sl = g_slist_prepend(ctx->sl, pn);
		ctx->last_was_removed = FALSE;
	}
}

/**
 * Intercept user callback in traverse() during patricia_foreach_remove().
 */
static void
traverse_foreach_item(gpointer key, size_t keybits, gpointer value, gpointer u)
{
	struct remove_ctx *ctx = u;

	/*
	 * Warning: action at distance.
	 * Set ctx->last_was_removed for traverse_foreach_node().
	 */

	if (ctx->cb(key, keybits, value, ctx->u)) {
		ctx->last_was_removed = TRUE;
		ctx->removed++;
	}
}

/**
 * Call the given function on all the key/value pairs in the PATRICIA tree.
 * If it returns TRUE, the key/value pair is removed from the PATRICIA tree.
 *
 * @param pt	the PATRICIA tree
 * @param cb	the callback to invoke
 * @param u		additional opaque user data for the callback
 *
 * @return the number of key/value pairs removed from the PATRICIA tree.
 */
size_t
patricia_foreach_remove(patricia_t *pt, patricia_cbr_t cb, gpointer u)
{
	struct remove_ctx ctx;
	GSList *sl;

	g_assert(pt);
	g_assert(cb);

	ctx.sl = NULL;
	ctx.last_was_removed = FALSE;
	ctx.cb = cb;
	ctx.u = u;
	ctx.removed = 0;

	traverse(pt,
		traverse_foreach_node, &ctx,
		traverse_foreach_item, &ctx);

	sl = ctx.sl;
	while (sl) {
		struct patricia_node *pn = sl->data;
		remove_node(pt, pn);
		sl = g_slist_next(sl);
	}

	return ctx.removed;
}

/***
 *** Unit tests.
 ***/

struct counter {
	size_t items;
	size_t even_keys;
};

static void
count_items(gpointer key, size_t keybits, gpointer uv, gpointer u)
{
	struct counter *ctx = u;
	guint8 *p = key;

	(void) uv;

	g_assert(key);
	g_assert(keybits == 32);

	ctx->items++;
	if (!(p[3] & 0x1))
		ctx->even_keys++;
}

static gboolean
remove_odd_key(gpointer key, size_t keybits, gpointer uv, gpointer uu)
{
	guint8 *p = key;

	g_assert(keybits == 32);

	(void) uv; (void) uu;

	return (p[3] & 0x1) ? TRUE : FALSE;
}

/**
 * Perform unit tests of PATRICIA trees.
 */
void
patricia_test(void)
{
	size_t i;
	static guint32 keys[] = {
		0x00800000U,
		0x00800001U,
		0x00810001U,
		0x00830001U,
		0x00820001U,
		0x01111111U,
		0x00000001U,
		0x00000011U,
		0x00000111U,
		0x00001111U,
		0x00011111U,
		0x00111111U,
		0x11111111U,
		0x31111111U,
		0x32111111U,
		0x33111111U,
		0x80111111U,
		0x83111111U,
		0xa0000000U,
		0xc0000000U,
		0x40111111U,
	};
	guint32 *data = g_malloc(G_N_ELEMENTS(keys) * sizeof(guint32));
	patricia_t *pt = patricia_create(32);
	guint32 *p = data;

	for (i = 0, p = data; i <  G_N_ELEMENTS(keys); i++, p++) {
		poke_be32(p, keys[i]);
	}

	/* inserting keys... */

	for (i = 0; i < G_N_ELEMENTS(keys); i++) {
		g_assert(!patricia_contains(pt, &data[i], 32));
		patricia_insert(pt, &data[i], 32, NULL);
		g_assert(pt->count == i + 1);
		g_assert(patricia_contains(pt, &data[i], 32));
	}

	g_assert(pt->count == G_N_ELEMENTS(keys));
	g_assert(pt->embedded == 0);

	/* re-inserting keys... */

	for (i = 0; i < G_N_ELEMENTS(keys); i++) {
		patricia_insert(pt, &data[i], 32, NULL);
		g_assert(pt->count == G_N_ELEMENTS(keys));
	}

	patricia_destroy(pt);
	pt = patricia_create(32);

	/* inserting keys in reverse order... */

	for (i = 0; i < G_N_ELEMENTS(keys); i++) {
		size_t idx = G_N_ELEMENTS(keys)-1 - i;
		g_assert(!patricia_contains(pt, &data[idx], 32));
		patricia_insert(pt, &data[idx], 32, NULL);
		g_assert(pt->count == i + 1);
		g_assert(patricia_contains(pt, &data[idx], 32));
	}

	g_assert(patricia_count(pt) == G_N_ELEMENTS(keys));
	g_assert(pt->embedded == 0);

	/* iterating to count items... */

	{
		struct counter ctx;

		ctx.items = 0;
		ctx.even_keys = 0;
		patricia_foreach(pt, count_items, &ctx);
		g_assert(ctx.items == patricia_count(pt));
		g_assert(ctx.even_keys == 3);
	}

	/* removing odd keys... */

	i = patricia_foreach_remove(pt, remove_odd_key, NULL);
	g_assert(i == G_N_ELEMENTS(keys) - 3);
	g_assert(patricia_count(pt) == 3);

	/* removing remaining keys in order... */

	for (i = 0; i < G_N_ELEMENTS(keys); i++) {
		if (patricia_contains(pt, &data[i], 32)) {
			gboolean removed = patricia_remove(pt, &data[i], 32);
			g_assert(removed);
			g_assert(!patricia_contains(pt, &data[i], 32));
		}
	}

	g_assert(patricia_count(pt) == 0);
	g_assert(pt->root == NULL);
	g_assert(pt->nodes == 0);
	g_assert(pt->embedded == 0);

	for (i = 0, p = data; i <  G_N_ELEMENTS(keys); i++, p++) {
		size_t bitsize = 1 + highest_bit_set(keys[i]);
		poke_be32(p, keys[i] << (32 - bitsize));
	}

	/* inserting keys of variable size... */

	for (i = 0; i < G_N_ELEMENTS(keys); i++) {
		size_t bitsize = 1 + highest_bit_set(keys[i]);
		g_assert(!patricia_contains(pt, &data[i], bitsize));
		patricia_insert(pt, &data[i], bitsize, NULL);
		g_assert(pt->count == i + 1);
		g_assert(patricia_contains(pt, &data[i], bitsize));
	}

	g_assert(pt->count == G_N_ELEMENTS(keys));
	g_assert(pt->embedded != 0);

	/* removing keys of variable size... */

	for (i = 0; i < G_N_ELEMENTS(keys); i++) {
		gboolean removed;
		size_t bitsize = 1 + highest_bit_set(keys[i]);

		g_assert(patricia_contains(pt, &data[i], bitsize));
		removed = patricia_remove(pt, &data[i], bitsize);
		g_assert(removed);
		g_assert(!patricia_contains(pt, &data[i], bitsize));
		g_assert(patricia_count(pt) == G_N_ELEMENTS(keys) - i - 1);
	}

	g_assert(patricia_count(pt) == 0);
	g_assert(pt->root == NULL);
	g_assert(pt->nodes == 0);
	g_assert(pt->embedded == 0);

	/* all tests passed */
}

/* vi: set ts=4 sw=4 cindent: */
