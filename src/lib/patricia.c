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
 * 3 AND because the node is flagged as containing embedded data that it
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

#include "patricia.h"

#include "endian.h"
#include "misc.h"
#include "pow2.h"
#include "pslist.h"
#include "random.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

/**
 * When defined, extra magic numbers are insert in PATRICIA nodes, to make
 * sure the internal data structures never become corrupted.  This adds some
 * memory overhead to each item stored in the tree, so this is not enabled
 * by default: only the main externally visible data structure is protected.
 */
#if 0
#define PATRICIA_MEMCHECK
#endif

#ifdef PATRICIA_MEMCHECK
enum patricia_node_magic   { PATRICIA_NODE_MAGIC   = 0x1cabac44U };
enum patricia_parent_magic { PATRICIA_PARENT_MAGIC = 0x4d928669U };
#endif

struct patricia_parent;

/**
 * A PATRICIA node in the tree.
 */
struct patricia_node {

#ifdef PATRICIA_MEMCHECK
	enum patricia_node_magic magic;
#endif

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
	uint8 bit;						/**< Bit to test for choosing "z" or "o" */
	uint8 last_kbit;				/**< Last bit # in key (7 if 8-bit key) */
	uint8 leaf;						/**< Is a leaf node */
	uint8 has_embedded_data;		/**< Non-leaf node has data */
};

/**
 * For non-leaf nodes holding data items, an extra indirection is required to
 * reach the parent node.
 */
struct patricia_parent {

#ifdef PATRICIA_MEMCHECK
	enum patricia_parent_magic magic;
#endif

	struct patricia_node *parent;	/**< Parent node (NULL if root node) */
	const void *key;				/**< The item key */
	const void *value;				/**< Data stored for the key in this node */
};

#ifdef PATRICIA_MEMCHECK
static inline void
patricia_node_set_magic(struct patricia_node *pn)
{
	pn->magic = PATRICIA_NODE_MAGIC;
}

static inline void
patricia_node_check_magic(const struct patricia_node *pn)
{
	g_assert(PATRICIA_NODE_MAGIC == pn->magic);
}

static inline void
patricia_node_clear_magic(struct patricia_node *pn)
{
	pn->magic = 0;
}

static inline void
patricia_parent_set_magic(struct patricia_parent *pp)
{
	pp->magic = PATRICIA_PARENT_MAGIC;
}

static inline void
patricia_parent_clear_magic(struct patricia_parent *pp)
{
	pp->magic = 0;
}

static inline void
patricia_parent_check_magic(const struct patricia_parent *pp)
{
	g_assert(PATRICIA_PARENT_MAGIC == pp->magic);
}

#else  /* !PATRICIA_MEMCHECK */
#define patricia_node_set_magic(n_)
#define patricia_node_clear_magic(n_)
#define patricia_node_check_magic(n_)
#define patricia_parent_set_magic(p_)
#define patricia_parent_clear_magic(p_)
#define patricia_parent_check_magic(p_)
#endif /* PATRICIA_MEMCHECK */

static inline void
patricia_node_check(const struct patricia_node *pn)
{
	g_assert(pn != NULL);
	patricia_node_check_magic(pn);
}

static inline void
patricia_parent_check(const struct patricia_parent *pp)
{
	g_assert(pp != NULL);
	patricia_parent_check_magic(pp);
}

/*
 * Accessing shortcuts.
 */

#define child_zero(n_)			((n_)->u.children.z)
#define child_one(n_)			((n_)->u.children.o)
#define leaf_item_key(n_)		((n_)->u.item.key)
#define leaf_item_value(n_)		((n_)->u.item.value)
#define leaf_item_keybits(n_)	((size_t) ((n_)->last_kbit + 1))

#define parent_node(n_) \
	((n_)->has_embedded_data ? (n_)->p.ext->parent : (n_)->p.parent)

#define embedded_item_key(n_)		((n_)->p.ext->key)
#define embedded_item_value(n_)		((n_)->p.ext->value)
#define embedded_item_keybits(n_)	((size_t) ((n_)->bit))

enum patricia_magic { PATRICIA_MAGIC = 0x42123004U };

/**
 * The PATRICIA tree.
 */
struct patricia {
	enum patricia_magic magic;		/**< Magic number */
	struct patricia_node *root;		/**< Root of tree (lazily allocated) */
	size_t maxbits;					/**< Maximum bitsize of key */
	size_t count;					/**< Amount of keys stored */
	size_t nodes;					/**< Total amount of nodes used */
	size_t embedded;				/**< Nodes holding embedded data */
	uint stamp;						/**< Stamp to protect iterators */
	int refcnt;						/**< Reference count */
};

static inline void
patricia_check(const patricia_t *pt)
{
	g_assert(pt != NULL);
	g_assert(PATRICIA_MAGIC == pt->magic);
}

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

	WALLOC(pt);
	pt->magic = PATRICIA_MAGIC;
	pt->root = NULL;
	pt->count = pt->nodes = pt->embedded = 0;
	pt->maxbits = maxbits;
	pt->stamp = 0;
	pt->refcnt = 1;

	return pt;
}

/**
 * Returns amount of items held in the PATRICIA tree.
 */
size_t
patricia_count(const patricia_t *pt)
{
	patricia_check(pt);

	return pt->count;
}

/**
 * Returns the maximum key size in bits.
 */
size_t
patricia_max_keybits(const patricia_t *pt)
{
	patricia_check(pt);

	return pt->maxbits;
}

/**
 * Allocate a new PATRICIA node.
 */
static struct patricia_node *
allocate_node(patricia_t *pt)
{
	struct patricia_node *pn;

	patricia_check(pt);

	pt->nodes++;
	WALLOC(pn);
	patricia_node_set_magic(pn);

	return pn;
}

/**
 * Free a PATRICIA node.
 */
static void
free_node(patricia_t *pt, struct patricia_node *pn)
{
	patricia_check(pt);
	patricia_node_check(pn);
	g_assert(pt->nodes > 0);

	pt->nodes--;
	patricia_node_clear_magic(pn);
	WFREE(pn);
}

/**
 * Set parent's pointer, taking care of nodes with embedded data.
 */
static inline void
set_parent(struct patricia_node *pn, struct patricia_node *parent)
{
	patricia_node_check(pn);

	if (pn->has_embedded_data) {
		g_assert(!pn->leaf);
		pn->p.ext->parent = parent;
	} else {
		pn->p.parent = parent;
	}

	g_assert(parent_node(pn) == parent);
}

/**
 * Convert key size in bits to key size in bytes.
 */
static inline size_t
bits2bytes(size_t keybits)
{
	return (keybits >> 3) + ((keybits & 0x7) ? 1 : 0);
}

/**
 * Compute the key prefix matched by a given node.
 *
 * @param pn		the PATRICIA node which we want to compute the prefix for
 *
 * @return a pointer to a key stored in a sub node, so it has more bits
 * than the actual prefix and fills.
 */
static const void *
patricia_node_prefix(const struct patricia_node *pn)
{
	const struct patricia_node *n;
	int i;
	const void *result = NULL;

	patricia_node_check(pn);

	for (n = pn, i = 0; i < PATRICIA_MAXBITS; i++) {
		const struct patricia_node *child;

		patricia_node_check(n);

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
 * Number of bits for the node's prefix.
 */
static inline G_PURE size_t
node_prefix_bits(const struct patricia_node *pn)
{
	patricia_node_check(pn);

	return pn->leaf ? leaf_item_keybits(pn) : pn->bit;
}

/**
 * Whether node holds data.
 */
static inline G_PURE bool
node_has_data(const struct patricia_node *pn)
{
	patricia_node_check(pn);

	return pn->leaf || pn->has_embedded_data;
}

/**
 * The key of the data held in the node.
 */
static inline G_PURE const void *
node_key(const struct patricia_node *pn)
{
	patricia_node_check(pn);

	if (pn->leaf)
		return leaf_item_key(pn);
	else if (pn->has_embedded_data)
		return embedded_item_key(pn);
	else
		g_assert_not_reached();
}

/**
 * The key size in bits of the data held in the node.
 */
static inline G_PURE size_t
node_keybits(const struct patricia_node *pn)
{
	patricia_node_check(pn);

	if (pn->leaf)
		return leaf_item_keybits(pn);
	else if (pn->has_embedded_data)
		return embedded_item_keybits(pn);
	else
		g_assert_not_reached();
}

/**
 * The value of the data held in the node.
 */
static inline G_PURE const void *
node_value(const struct patricia_node *pn)
{
	patricia_node_check(pn);

	if (pn->leaf)
		return leaf_item_value(pn);
	else if (pn->has_embedded_data)
		return embedded_item_value(pn);
	else
		g_assert_not_reached();
}

/**
 * Is the current node test bit matched by the key?
 */
static inline G_PURE bool
node_matches(const struct patricia_node *pn, const void *key, size_t keybits)
{
	const uint8 *k = key;

	patricia_node_check(pn);
	g_assert(key);
	g_assert(keybits >= (size_t) pn->bit + 1);

	return 0 != (k[pn->bit >> 3] & (0x80 >> (pn->bit & 0x7)));
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
static bool G_PURE
key_eq(const void *k1, const void *k2, size_t keybits)
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
		uint8 mask = ~((1 << (8 - bits)) - 1);
		const uint8 *p1 = k1;
		const uint8 *p2 = k2;
		uint8 diff = (p1[bytes] & mask) ^ (p2[bytes] & mask);

		return 0 == diff;
	}

	return TRUE;
}

/**
 * Given a node and a key, determine how many leading bits in the key are
 * matched by the node returned by patricia_match_best().
 *
 * @param pn		the PATRICIA node returned by patricia_match_best()
 * @param key		the key we looked up
 * @param keybits	the size of the key in bits
 * @param pprefix	where to write the prefix for the match, if not NULL
 */
static size_t
patricia_matched_bits(
	const struct patricia_node *pn, const void *key, size_t keybits,
	const void **pprefix)
{
	const void *prefix;

	patricia_node_check(pn);

	prefix = patricia_node_prefix(pn);
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
 * patricia_matched_bits() on the resulting node).
 */
static struct patricia_node * G_HOT
patricia_match_best(patricia_t *pt, const void *key, size_t keybits)
{
	const struct patricia_node *pn;
	int i;

	patricia_check(pt);
	g_assert(pt->root);
	g_assert(key);
	g_assert(keybits <= pt->maxbits);

	if (keybits == 0)
		return pt->root;

	for (pn = pt->root, i = 0; i <= PATRICIA_MAXBITS; i++) {
		const struct patricia_node *child;

		patricia_node_check(pn);

		/*
		 * If we have less bits in the key than the first bit to test for at
		 * this node to branch between children, then clearly we have to stop.
		 * Likewise if we reached a leaf node.
		 *
		 * It does not mean we matched any bit from the key though.
		 */

		if (keybits - 1 < pn->bit || pn->leaf)
			return deconstify_pointer(pn);

		child = node_matches(pn, key, keybits) ? child_one(pn) : child_zero(pn);
		if (child == NULL)
			return deconstify_pointer(pn);

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
static const struct patricia_node * G_HOT
match_exact(const patricia_t *pt, const void *key, size_t keybits)
{
	const struct patricia_node *pn;
	int i;

	patricia_check(pt);
	g_assert(key);
	g_assert(keybits <= pt->maxbits);

	if (pt->root == NULL)
		return NULL;

	/*
	 * If the key size is the maximum, then we can implement a faster search
	 * because we have less to check at each level: the item cannot be held
	 * as embedded data, only in leaf nodes.
	 */

	if (keybits == pt->maxbits) {
		/* Quicker version */
		for (pn = pt->root, i = 0; i <= PATRICIA_MAXBITS; i++) {
			const struct patricia_node *child;

			patricia_node_check(pn);

			/*
			 * If we reach a leaf node, compare the key with the value.
			 */

			if (pn->leaf) {
				if (leaf_item_keybits(pn) != keybits)
					return NULL;
				return key_eq(key, leaf_item_key(pn), keybits) ? pn : NULL;
			}

			child = node_matches(pn, key, keybits) ?
				child_one(pn) : child_zero(pn);

			if (child == NULL)
				return NULL;

			g_assert(child->leaf || child->bit > pn->bit);

			pn = child;
		}
	} else {
		/* Slower version: more tests */
		for (pn = pt->root, i = 0; i <= PATRICIA_MAXBITS; i++) {
			const struct patricia_node *child;

			patricia_node_check(pn);

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

			if (keybits == 0 || keybits - 1 < pn->bit)
				return NULL;

			child = node_matches(pn, key, keybits) ?
				child_one(pn) : child_zero(pn);

			if (child == NULL)
				return NULL;

			g_assert(child->leaf || child->bit > pn->bit);

			pn = child;
		}
	}

	g_assert_not_reached();
}

/**
 * Find the leftmost node in the tree, or the rightmost depending on
 * the boolean parameter.
 *
 * @param root			the root node of the tree
 * @param leftmost		whether we should follow the left side of branches
 *
 * @return the deepest node on the left side or the right side of the tree
 * spanned by the given root.
 */
static const struct patricia_node *
find_deepest(const struct patricia_node *root, bool leftmost)
{
	const struct patricia_node *pn;
	int i;

	if (NULL == root)
		return NULL;

	for (pn = root, i = 0; i <= PATRICIA_MAXBITS; i++) {
		const struct patricia_node *child;

		patricia_node_check(pn);

		if (pn->leaf)
			return pn;

		/*
		 * Stick to the general orientation (leftmost or rightmost)
		 * unless there is only one child for the node (possible only
		 * when there is attached embedded data for the node).
		 */

		child = leftmost ? child_zero(pn) : child_one(pn);
		if (child == NULL)
			child = leftmost ? child_one(pn) : child_zero(pn);

		g_assert(child);
		g_assert(child->leaf || child->bit > pn->bit);

		pn = child;
	}

	g_assert_not_reached();
}

/**
 * Look in the tree for a node which holds data that is a best match for
 * the key.  All the bits of the key in the found data key must match the
 * corresponding leading part of the key, but it does not mean it is an
 * exact match: the found key can be smaller than the queried key.
 * However we try to match as many possible leading bits as we can.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 * @param keybits	the amount of significant bits in the key
 *
 * @return the node which holds the best match, or NULL if not found.
 */
static const struct patricia_node *
lookup_best(const patricia_t *pt, const void *key, size_t keybits)
{
	const struct patricia_node *stack[PATRICIA_MAXBITS + 1];
	const struct patricia_node **sp = stack;
	const struct patricia_node *pn;
	int i;

	patricia_check(pt);
	g_assert(key);
	g_assert(keybits <= pt->maxbits);

	if (pt->root == NULL)
		return NULL;

	pn = pt->root;
	patricia_node_check(pn);

	if (keybits == 0)
		return (node_has_data(pn) && 0 == node_keybits(pn)) ?  pn : NULL;

	for (i = 0; i <= PATRICIA_MAXBITS; i++) {
		const struct patricia_node *child;

		patricia_node_check(pn);

		/*
		 * If we're already too deep in the tree, the keys we'll find will
		 * be larger than the one we're trying to match against.  Stop.
		 */

		if (node_prefix_bits(pn) > keybits)
			break;

		/*
		 * Remember any node that holds data, as we go deeper into the
		 * tree.  We'll attempt matches in LIFO order to find the longest
		 * possible match.
		 */

		if (node_has_data(pn)) {
			g_assert(sp < &stack[PATRICIA_MAXBITS + 1]);
			*sp++ = pn;
		}

		/*
		 * Stop as soon as we would have to test bits larger than the key
		 * we're trying to match, or when we hit a leaf.
		 *
		 * This is not duplicating the earlier test with node_prefix_bits(pn)
		 * because we must catch embedded data (a node testing bit #5 can
		 * hold a 5-bit long key).
		 */

		if (keybits - 1 < pn->bit || pn->leaf)
			break;

		child = node_matches(pn, key, keybits) ? child_one(pn) : child_zero(pn);
		if (child == NULL)
			break;

		pn = child;
	}

	g_assert(i <= PATRICIA_MAXBITS);	/* Did not exit above loop via for() */

	/*
	 * Now look at the stacked nodes which are holding data, trying to match
	 * them against the supplied key, starting with the longest keys.
	 */

	while (sp != stack) {
		const struct patricia_node *n = *sp--;
		size_t nbits = node_keybits(n);

		patricia_node_check(n);
		g_assert(nbits <= keybits);

		if (nbits == common_leading_bits(node_key(n), nbits, key, keybits))
			return n;
	}

	return NULL;
}

/**
 * Look in the tree for the node containing a key which shares the most/smallest
 * amount of bits with the search key, albeit not necessarily in a consecutive
 * way. This is the closest or furthest node in the tree to the search key,
 * under the XOR metric.
 *
 * @attention
 * This call is restricted to PATRICIA trees holding a set of keys with
 * the same size: the maximum allowed in the tree.
 *
 * @param pt		the PATRICIA tree, for assertion on keybits
 * @param root		the
 * @param key		the key we're looking for
 * @param keybits	the amount of significant bits in the key
 * @param closest	whether to look for the closest or furthest node
 *
 * @return the node which is the furthest match, or NULL if none was found
 * under the given root node.
 */
static const struct patricia_node *
find_closest(const patricia_t *pt, const struct patricia_node *root,
	const void *key, size_t keybits, bool closest)
{
	const struct patricia_node *pn;
	int i;

	patricia_check(pt);
	g_assert(key);
	g_assert(keybits == pt->maxbits);
	g_assert(pt->embedded == 0);		/* All keys must have the same size */

	if (root == NULL)
		return NULL;

	/*
	 * Because all keys have the same size, we know the PATRICIA tree cannot
	 * hold any embedded data in non-leaf nodes, and each non-leaf node has
	 * exactly two children or it would not exist.
	 */

	for (pn = root, i = 0; i <= PATRICIA_MAXBITS; i++) {
		const struct patricia_node *child;
		bool matches;

		patricia_node_check(pn);

		if (pn->leaf)
			return pn;						/* We found the closest node */

		g_assert(!pn->has_embedded_data);	/* No key shorter than maxbits */

		matches = node_matches(pn, key, keybits);
		child = (matches != closest) ? child_zero(pn) : child_one(pn);

		g_assert(child);		/* Must have two children */
		g_assert(child->leaf || child->bit > pn->bit);

		pn = child;
	}

	g_assert_not_reached();
}

/**
 * Look in the tree for the node containing a key which shares the largest
 * amount of bits with the search key, albeit not necessarily in a consecutive
 * way. This is the "closest" node in the tree to the search key, under the
 * XOR metric.
 *
 * When `closest' is FALSE, the match is actually inverted, i.e. we find
 * the furthest node in the tree.
 *
 * @attention
 * This call is restricted to PATRICIA trees holding a set of keys with
 * the same size: the maximum allowed in the tree.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 * @param keybits	the amount of significant bits in the key
 * @param closest	whether to look for the closest or furthest node
 *
 * @return the node which is the closest match, or NULL if not found (i.e.
 * the PATRICIA tree was empty).
 */
static const struct patricia_node *
match_closest(
	const patricia_t *pt, const void *key, size_t keybits, bool closest)
{
	return find_closest(pt, pt->root, key, keybits, closest);
}

/**
 * Fill leaf PATRICIA node with key/value.
 */
static void
fill_leaf(struct patricia_node *pn, struct patricia_node *parent,
	const void *key, size_t keybits, const void *value)
{
	patricia_node_check(pn);

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

	patricia_node_check(pn);
	g_assert(pn->has_embedded_data);

	parent = parent_node(pn);

	pn->has_embedded_data = FALSE;

	patricia_parent_check(pn->p.ext);
	patricia_parent_clear_magic(pn->p.ext);

	WFREE(pn->p.ext);
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

	patricia_check(pt);
	patricia_node_check(pn);

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
		patricia_node_check(parent);
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
	const void *old_key;
	const void *old_value;
	size_t old_keybits;
	struct patricia_node *parent;

	patricia_check(pt);
	patricia_node_check(pn);
	g_assert(!pn->leaf);
	g_assert(pn->has_embedded_data);
	g_assert(child_one(pn) == NULL && child_zero(pn) == NULL);

	old_key = embedded_item_key(pn);
	old_value = embedded_item_value(pn);
	old_keybits = embedded_item_keybits(pn);
	parent = parent_node(pn);

	patricia_parent_check(pn->p.ext);
	patricia_parent_clear_magic(pn->p.ext);

	WFREE(pn->p.ext);

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
patricia_insert_at(
	patricia_t *pt, struct patricia_node *pn,
	const void *key, size_t keybits, const void *value)
{
	patricia_check(pt);
	patricia_node_check(pn);
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
			WALLOC(ext);
			patricia_parent_set_magic(ext);
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
		struct patricia_parent *ext;

		WALLOC(ext);
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
		patricia_parent_set_magic(ext);
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
patricia_insert_below(
	patricia_t *pt, struct patricia_node *pn,
	const void *key, size_t keybits, const void *value, size_t common)
{
	struct patricia_node *new = allocate_node(pt);

	patricia_check(pt);
	patricia_node_check(pn);
	patricia_node_check(new);
	g_assert(common < keybits);

	fill_leaf(new, pn, key, keybits, value);
	pt->count++;

	if (pn->leaf) {
		size_t diffbit = common;
		const void *old_key = leaf_item_key(pn);
		const void *old_value = leaf_item_value(pn);
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
			struct patricia_parent *ext;

			g_assert(old_keybits < pt->maxbits);

			WALLOC(ext);
			patricia_parent_set_magic(ext);
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
patricia_insert_above(
	patricia_t *pt, struct patricia_node *pn,
	const void *key, size_t keybits, const void *value, size_t common,
	const void *prefix)
{
	struct patricia_node *new = allocate_node(pt);
	struct patricia_node *up;
	struct patricia_node *child;

	patricia_check(pt);
	patricia_node_check(pn);
	patricia_node_check(new);
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
		patricia_insert_at(pt, new, key, keybits, value);
	else
		patricia_insert_below(pt, new, key, keybits, value, common);
}

/**
 * Insert new fixed-size key/value pair in the PATRICIA tree.
 * Any previously existing value for the key is replaced by the new one.
 * NULL is a valid value.
 *
 * The tree stores the key and value pointers so these must not be freed
 * whilst the value is held in the PATRICIA tree.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits (configured length)
 * @param value		value to insert in the tree for this key.
 */
void
patricia_insert(patricia_t *pt, const void *key, const void *value)
{
	patricia_insert_k(pt, key, pt->maxbits, value);
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
patricia_insert_k(patricia_t *pt,
	const void *key, size_t keybits, const void *value)
{
	struct patricia_node *pn;
	size_t common_bits;
	const void *prefix;

	patricia_check(pt);
	g_assert(key);
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

	pn = patricia_match_best(pt, key, keybits);
	common_bits = patricia_matched_bits(pn, key, keybits, &prefix);

	/*
	 * Insert at the right position, relative to the found node.
	 */

	if (common_bits == keybits && keybits >= node_prefix_bits(pn)) {
		/* All bits from key matched: found node where insertion can be done */
		patricia_insert_at(pt, pn, key, keybits, value);
	} else if (common_bits == node_prefix_bits(pn)) {
		/* The common bits are the node's prefix: insertion must occur below */
		g_assert(common_bits < keybits);
		patricia_insert_below(pt, pn, key, keybits, value, common_bits);
	} else {
		g_assert(common_bits < node_prefix_bits(pn));
		patricia_insert_above(pt, pn, key, keybits, value, common_bits, prefix);
	}
}

/**
 * Check whether the PATRICIA tree contains a fixed-size key.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits (configured length)
 *
 * @return whether key is held in the PATRICIA tree.
 */
bool
patricia_contains(const patricia_t *pt, const void *key)
{
	return match_exact(pt, key, pt->maxbits) != NULL;
}

/**
 * Check whether the PATRICIA tree contains a key.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 * @param keybits	size of key in bits
 *
 * @return whether key is held in the PATRICIA tree.
 */
bool
patricia_contains_k(const patricia_t *pt, const void *key, size_t keybits)
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
 * @param key		pointer to the start of the key bits (configured length)
 *
 * @return the value for the key, or NULL if not found.
 */
void *
patricia_lookup(const patricia_t *pt, const void *key)
{
	const struct patricia_node *pn = match_exact(pt, key, pt->maxbits);

	if (NULL == pn)
		return NULL;

	g_assert(node_has_data(pn));

	return deconstify_pointer(node_value(pn));
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
 * @param key		the key we're looking for
 * @param keybits	size of key in bits
 *
 * @return the value for the key, or NULL if not found.
 */
void *
patricia_lookup_k(const patricia_t *pt, const void *key, size_t keybits)
{
	const struct patricia_node *pn = match_exact(pt, key, keybits);

	if (NULL == pn)
		return NULL;

	g_assert(node_has_data(pn));

	return deconstify_pointer(node_value(pn));
}

/**
 * Fetch key/value from the PATRICIA tree, returning whether the key
 * was found.  If it was, the original key/value pointers are written
 * back in keyptr and valptr.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits (configured length)
 * @param keyptr	if non-NULL, where the original key pointer is written
 * @param valptr	if non-NULL, where the original value pointer is written
 *
 * @return whether the key was found and keyptr/valptr written back.
 */
bool
patricia_lookup_extended(
	const patricia_t *pt, const void *key, void **keyptr, void **valptr)
{
	const struct patricia_node *pn = match_exact(pt, key, pt->maxbits);

	if (NULL == pn)
		return FALSE;

	g_assert(node_has_data(pn));

	if (keyptr)
		*keyptr = deconstify_pointer(node_key(pn));
	if (valptr)
		*valptr = deconstify_pointer(node_value(pn));

	return TRUE;
}

/**
 * Fetch key/value from the PATRICIA tree, returning whether the key
 * was found.  If it was, the original key/value pointers are written
 * back in keyptr and valptr.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 * @param keybits	size of key in bits
 * @param keyptr	if non-NULL, where the original key pointer is written
 * @param valptr	if non-NULL, where the original value pointer is written
 *
 * @return whether the key was found and keyptr/valptr written back.
 */
bool
patricia_lookup_extended_k(
	const patricia_t *pt, const void *key, size_t keybits,
	void **keyptr, void **valptr)
{
	const struct patricia_node *pn = match_exact(pt, key, keybits);

	if (NULL == pn)
		return FALSE;

	g_assert(node_has_data(pn));

	if (keyptr)
		*keyptr = deconstify_pointer(node_key(pn));
	if (valptr)
		*valptr = deconstify_pointer(node_value(pn));

	return TRUE;
}

/**
 * Lookup data whose key is the best (longest) one that matches the given
 * search key, i.e. which starts with the same leading bits, and whose size
 * is at most that of the search key.
 *
 * This is meaningful only when items with variable key lengths are inserted
 * into the PATRICIA tree (e.g. CIDR ranges).  Otherwise, a call to
 * patricia_lookup_best() is strictly equivalent to patricia_lookup_extended().
 *
 * Example: If the PATRICIA tree contains CIDR ranges associated to routing
 * information, and if a default routing is entered with a key of 0 bits,
 * then a patricia_lookup_best() on an IP address would yield the best (i.e.
 * most specialized) routing entry for that IP.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 * @param keybits	size of key in bits
 * @param keyptr	if non-NULL, where the found key pointer is written
 * @param lenptr	if non-NULL, where the found key length in bit is written
 * @param valptr	if non-NULL, where the associated value pointer is written
 *
 * @return whether a key was found and keyptr/lenptr/valptr written back.
 */
bool
patricia_lookup_best(
	const patricia_t *pt, const void *key, size_t keybits,
	void **keyptr, size_t *lenptr, void **valptr)
{
	const struct patricia_node *pn;

	pn = lookup_best(pt, key, keybits);

	if (pn == NULL)
		return FALSE;

	g_assert(node_has_data(pn));

	if (keyptr)
		*keyptr = deconstify_pointer(node_key(pn));
	if (valptr)
		*valptr = deconstify_pointer(node_value(pn));
	if (lenptr)
		*lenptr = node_keybits(pn);

	return TRUE;
}

/**
 * Common implementation for patricia_closest() and patricia_furthest().
 */
static void *
lookup_closest(
	const patricia_t *pt, const void *key, size_t keybits, bool closest)
{
	const struct patricia_node *pn = match_closest(pt, key, keybits, closest);

	if (NULL == pn) {
		g_assert(0 == patricia_count(pt));
		return NULL;
	}

	g_assert(node_has_data(pn));

	return deconstify_pointer(node_value(pn));
}

/**
 * Common implementation for patricia_closest_extended() and
 * patricia_furthest_extended().
 */
static bool
lookup_closest_extended(
	const patricia_t *pt, const void *key, size_t keybits,
	void **keyptr, void **valptr, bool closest)
{
	const struct patricia_node *pn = match_closest(pt, key, keybits, closest);

	if (NULL == pn) {
		g_assert(0 == patricia_count(pt));
		return FALSE;
	}

	g_assert(node_has_data(pn));
	g_assert(node_keybits(pn) == pt->maxbits);

	if (keyptr)
		*keyptr = deconstify_pointer(node_key(pn));
	if (valptr)
		*valptr = deconstify_pointer(node_value(pn));

	return TRUE;
}

/**
 * Fetch value from the PATRICIA tree attached to an item which is the
 * closest to the specified lookup key, under the XOR distance.
 *
 * @attention
 * NOTE: Since NULL is a valid value for storage, one cannot distinguish
 * from the returned value whether the data is NULL or the key was not
 * found, unless one knows that NULL values are not inserted.
 * However, this call is guaranteed to return a value if the tree is not
 * empty, so a NULL would be a value unless the PATRICIA tree was empty.
 *
 * @attention
 * This call is restricted to trees where all the keys inserted have the
 * same length, and that length must be the maximum length specified at the
 * creation of the tree.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 *
 * @return the value for the key, or NULL if not found.
 */
void *
patricia_closest(const patricia_t *pt, const void *key)
{
	return lookup_closest(pt, key, pt->maxbits, TRUE);
}

/**
 * Same as patricia_closest(), only a boolean indication of whether an item
 * was found is given, and the actual key that was deemed the closest is
 * also returned.  This is useful when the values do not point back to the
 * keys used for inserting them.
 *
 * @attention
 * This call is restricted to trees where all the keys inserted have the
 * same length, and that length must be the maximum length specified at the
 * creation of the tree.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 * @param keyptr	if non-NULL, where the original key pointer is written
 * @param valptr	if non-NULL, where the original value pointer is written
 *
 * @return whether the key was found and keyptr/valptr written back.
 */
bool
patricia_closest_extended(
	const patricia_t *pt, const void *key,
	void **keyptr, void **valptr)
{
	return lookup_closest_extended(pt, key, pt->maxbits, keyptr, valptr, TRUE);
}

/**
 * Fetch value from the PATRICIA tree attached to an item which is the
 * furthest to the specified lookup key, under the XOR distance.
 *
 * @attention
 * NOTE: Since NULL is a valid value for storage, one cannot distinguish
 * from the returned value whether the data is NULL or the key was not
 * found, unless one knows that NULL values are not inserted.
 * However, this call is guaranteed to return a value if the tree is not
 * empty, so a NULL would be a value unless the PATRICIA tree was empty.
 *
 * @attention
 * This call is restricted to trees where all the keys inserted have the
 * same length, and that length must be the maximum length specified at the
 * creation of the tree.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 *
 * @return the value for the key, or NULL if not found.
 */
void *
patricia_furthest(const patricia_t *pt, const void *key)
{
	return lookup_closest(pt, key, pt->maxbits, FALSE);
}

/**
 * Same as patricia_furthest(), only a boolean indication of whether an item
 * was found is given, and the actual key that was deemed the furthest is
 * also returned.  This is useful when the values do not point back to the
 * keys used for inserting them.
 *
 * @attention
 * This call is restricted to trees where all the keys inserted have the
 * same length, and that length must be the maximum length specified at the
 * creation of the tree.
 *
 * @param pt		the PATRICIA tree
 * @param key		the key we're looking for
 * @param keyptr	if non-NULL, where the original key pointer is written
 * @param valptr	if non-NULL, where the original value pointer is written
 *
 * @return whether the key was found and keyptr/valptr written back.
 */
bool
patricia_furthest_extended(
	const patricia_t *pt, const void *key,
	void **keyptr, void **valptr)
{
	return lookup_closest_extended(pt, key, pt->maxbits, keyptr, valptr, FALSE);
}

/**
 * Remove node from the PATRICIA tree, cleaning up the tree to also remove
 * the possible useless node created by the removal of the first.
 */
static void
remove_node(patricia_t *pt, struct patricia_node *pn)
{
	patricia_check(pt);
	patricia_node_check(pn);

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
			patricia_node_check(parent);
			if (!parent->has_embedded_data)
				remove_useless_node(pt, parent);	/* Has only one leaf now */
			else if (child_one(parent) == NULL && child_zero(parent) == NULL)
				unembed_data(pt, parent);
		}
	} else
		g_assert_not_reached();
}

/**
 * Remove fixed-size key from the PATRICIA tree.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits (configured length)
 *
 * @return TRUE if the key was found and removed from the PATRICIA tree.
 */
bool
patricia_remove(patricia_t *pt, const void *key)
{
	return patricia_remove_k(pt, key, pt->maxbits);
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
bool
patricia_remove_k(patricia_t *pt, const void *key, size_t keybits)
{
	struct patricia_node *pn;

	pn = deconstify_pointer(match_exact(pt, key, keybits));

	if (NULL == pn)
		return FALSE;

	remove_node(pt, pn);

	return TRUE;
}

/**
 * Common implementation for patricia_remove_closest() and
 * patricia_remove_furthest().
 */
static bool
remove_closest(
	patricia_t *pt, const void *key, size_t keybits, bool closest)
{
	struct patricia_node *pn;

	pn = deconstify_pointer(match_closest(pt, key, keybits, closest));

	if (NULL == pn)
		return FALSE;

	remove_node(pt, pn);

	return TRUE;
}

/**
 * Remove the key which is the closest to the one specified.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits
 * @param keybits	amount of bits to consider in the key
 *
 * @attention
 * This call is restricted to trees where all the keys inserted have the
 * same length, and that length must be the maximum length specified at the
 * creation of the tree.
 *
 * @return TRUE if the key was found and removed from the PATRICIA tree,
 * which is always the case unless the tree was empty.
 */
bool
patricia_remove_closest(patricia_t *pt, const void *key, size_t keybits)
{
	return remove_closest(pt, key, keybits, TRUE);
}

/**
 * Remove the key which is the furthest to the one specified.
 *
 * @param pt		the PATRICIA tree
 * @param key		pointer to the start of the key bits
 * @param keybits	amount of bits to consider in the key
 *
 * @attention
 * This call is restricted to trees where all the keys inserted have the
 * same length, and that length must be the maximum length specified at the
 * creation of the tree.
 *
 * @return TRUE if the key was found and removed from the PATRICIA tree,
 * which is always the case unless the tree was empty.
 */
bool
patricia_remove_furthest(patricia_t *pt, const void *key, size_t keybits)
{
	return remove_closest(pt, key, keybits, FALSE);
}

/**
 * Callback for nodes in patricia_traverse().
 */
typedef void (*node_cb_t)(struct patricia_node *pn, void *un);

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
patricia_traverse(patricia_t *pt,
	node_cb_t ncb, void *un, patricia_cb_t cb, void *u)
{
	patricia_check(pt);

	/*
	 * Traverse without recursing for maximum efficiency.
	 * We maintain a stack of un-visited "one" nodes.
	 */

	if (pt->root) {
		const struct patricia_node *stack[PATRICIA_MAXBITS];
		const struct patricia_node **sp = stack;
		const struct patricia_node *n = pt->root;

		while (n) {
			const struct patricia_node *z = NULL;
			const struct patricia_node *o = NULL;

			patricia_node_check(n);

			if (!n->leaf) {
				z = child_zero(n);
				o = child_one(n);
			}

			if (cb && node_has_data(n))
				(*cb)(deconstify_pointer(node_key(n)), node_keybits(n),
					deconstify_pointer(node_value(n)), u);

			/* Callback may free the node */
			if (ncb)
				(*ncb)(deconstify_pointer(n), un);

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
 * Node callback for patricia_traverse().
 */
static void
patricia_traverse_remove_node(struct patricia_node *pn, void *u)
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
	patricia_check(pt);

	if (--pt->refcnt > 0)
		return;			/* Still referenced by something internally */

	patricia_traverse(pt, patricia_traverse_remove_node, pt, NULL, NULL);
	g_assert(pt->nodes == 0);

	pt->magic = 0;
	WFREE(pt);
}

/**
 * Call the given function on all the key/value pairs in the PATRICIA tree.
 *
 * @param pt	the PATRICIA tree
 * @param cb	the callback to invoke
 * @param u		additional opaque user data for the callback
 */
void
patricia_foreach(const patricia_t *pt, patricia_cb_t cb, void *u)
{
	patricia_check(pt);
	g_assert(cb);

	patricia_traverse(deconstify_pointer(pt), NULL, NULL, cb, u);
}

/**
 * Context for patricia_foreach_remove().
 */
struct remove_ctx {
	pslist_t *sl;					/* List of nodes to remove */
	bool last_was_removed;			/* Last key/value traversed is removed */
	patricia_cbr_t cb;				/* User callback to invoke */
	void *u;						/* User data for callback */
	size_t removed;					/* Counts amount of items removed */
};

/**
 * Node callback for patricia_traverse().
 * Relies on the fact that it is invoked right after the user callback.
 */
static void
patricia_traverse_foreach_node(struct patricia_node *pn, void *u)
{
	struct remove_ctx *ctx = u;

	patricia_node_check(pn);

	/*
	 * ctx->last_was_removed was set possibly by previous call to the
	 * user-supplied callback, through the patricia_traverse_foreach_item()
	 * trampoline.
	 */

	if (ctx->last_was_removed) {
		/*
		 * Prepend node to remove, so that we start removing nodes that are
		 * the deepest in the tree.
		 */
		ctx->sl = pslist_prepend(ctx->sl, pn);
		ctx->last_was_removed = FALSE;
	}
}

/**
 * Intercept user callback in patricia_traverse() during
 * patricia_foreach_remove().
 */
static void
patricia_traverse_foreach_item(void *key, size_t keybits, void *value, void *u)
{
	struct remove_ctx *ctx = u;

	/*
	 * Warning: action at distance.
	 * Set ctx->last_was_removed for patricia_traverse_foreach_node().
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
patricia_foreach_remove(patricia_t *pt, patricia_cbr_t cb, void *u)
{
	struct remove_ctx ctx;
	pslist_t *sl;

	patricia_check(pt);
	g_assert(cb);

	ctx.sl = NULL;
	ctx.last_was_removed = FALSE;
	ctx.cb = cb;
	ctx.u = u;
	ctx.removed = 0;

	patricia_traverse(pt,
		patricia_traverse_foreach_node, &ctx,
		patricia_traverse_foreach_item, &ctx);

	sl = ctx.sl;
	while (sl) {
		struct patricia_node *pn = sl->data;
		remove_node(pt, pn);
		sl = pslist_next(sl);
	}

	pslist_free_null(&ctx.sl);

	return ctx.removed;
}

/***
 *** PATRICIA iterators.
 ***/

enum patricia_iter_type {
	PATRICIA_ITER_TREE	= 1,		/**< "lexicographic" traversal */
	PATRICIA_ITER_XOR,				/**< "xor metric" traversal */
	PATRICIA_ITER_XOR_LAZY			/**< idem, key not copied */
};

enum patricia_iter_magic { PATRICIA_ITER_MAGIC = 0x64083edeU };

/**
 * A PATRICIA iterator.
 */
struct patricia_iter {
	enum patricia_iter_magic magic;		/**< Magic number */
	enum patricia_iter_type type;		/**< Type of iterator */
	patricia_t *pt;						/**< The PATRICIA tree */
	const struct patricia_node *last;	/**< Last visited node */
	const struct patricia_node *next;	/**< Cached next node to visit */
	void *key;						/**< Target key, in metric iterators */
	size_t keybits;					/**< Size of key, in metric iterators */
	uint stamp;						/**< Tree stamp at iterator creation */
	bool knows_next;				/**< Whether we determined the next node */
	bool forward;					/**< Whether iterator is moving forward */
};

static inline void
patricia_iter_check(const patricia_iter_t *iter)
{
	g_assert(iter != NULL);
	g_assert(PATRICIA_ITER_MAGIC == iter->magic);
}

/**
 * Common iterator field initialization.
 */
static patricia_iter_t *
patricia_common_iter_init(patricia_iter_t *iter, patricia_t *pt, bool forward)
{
	iter->magic = PATRICIA_ITER_MAGIC;
	iter->pt = pt;
	iter->last = NULL;
	iter->stamp = pt->stamp;
	iter->knows_next = TRUE;
	iter->forward = forward;
	pt->refcnt++;

	return iter;
}

/**
 * Create a PATRICIA tree iterator (lexicographic order, aka depth-first).
 *
 * @param pt		the PATRICIA tree
 * @param forward	whether iteration should move forward or backwards
 */
patricia_iter_t *
patricia_tree_iterator(patricia_t *pt, bool forward)
{
	struct patricia_iter *iter;

	patricia_check(pt);

	WALLOC0(iter);
	iter->type = PATRICIA_ITER_TREE;
	iter->next = find_deepest(pt->root, forward);

	return patricia_common_iter_init(iter, pt, forward);
}

/**
 * Create a PATRICIA metric iterator, starting for the closest (resp. furthest)
 * location relative to the supplied key if forward is TRUE (resp. FALSE).
 *
 * In other words, when forward is TRUE, the distance to the target will
 * increase at each step, whereas it will decrease at each step if forward
 * is FALSE.
 *
 * @param pt		the PATRICIA tree
 * @param key		initial key for iterator initialization
 * @param forward	whether iteration should move forward or backwards
 *
 * @attention
 * This iterator is restricted to PATRICIA trees holding constant-width
 * keys only.
 *
 * A copy of the key is made and is released in patricia_iterator_release().
 */
patricia_iter_t *
patricia_metric_iterator(patricia_t *pt, const void *key, bool forward)
{
	struct patricia_iter *iter;
	size_t keybytes = bits2bytes(pt->maxbits);

	patricia_check(pt);
	g_assert(pt->embedded == 0);

	WALLOC(iter);
	iter->type = PATRICIA_ITER_XOR;
	iter->next = find_closest(pt, pt->root, key, pt->maxbits, forward);
	iter->key = walloc(keybytes);
	memcpy(iter->key, key, keybytes);
	iter->keybits = pt->maxbits;

	return patricia_common_iter_init(iter, pt, forward);
}

/**
 * Same as patricia_metric_iterator() but the initial key is not copied.
 * It must therefore remain allocated until the iterator is released, which
 * is usually the case when the iteration is done within a single routine.
 */
patricia_iter_t *
patricia_metric_iterator_lazy(
	patricia_t *pt, const void *key, bool forward)
{
	struct patricia_iter *iter;

	patricia_check(pt);
	g_assert(pt->embedded == 0);

	WALLOC(iter);
	iter->type = PATRICIA_ITER_XOR_LAZY;
	iter->next = find_closest(pt, pt->root, key, pt->maxbits, forward);
	iter->key = deconstify_pointer(key);
	iter->keybits = pt->maxbits;

	return patricia_common_iter_init(iter, pt, forward);
}

/**
 * Compute the next tree node in a lexicographic traversal (forward or
 * backwards).
 */
static const struct patricia_node *
patricia_next_tree_node(const struct patricia_node *prev, bool forward)
{
	const struct patricia_node *pn;
	int i;

	g_assert(prev);

	for (pn = prev, i = 0; i <= PATRICIA_MAXBITS; i++) {
		const struct patricia_node *parent = parent_node(pn);
		const struct patricia_node *next = NULL;

		patricia_node_check(pn);

		if (!parent)
			return NULL;
		else if (forward && parent->u.children.z == pn)
			next = parent->u.children.o;
		else if (!forward && parent->u.children.o == pn)
			next = parent->u.children.z;

		if (next)
			return find_deepest(next, forward);

		/*
		 * Embedded data processed only when both children have been
		 * traversed by the iterator.
		 */

		if (parent->has_embedded_data)
			return parent;

		pn = parent;
	}

	g_assert_not_reached();
}

/**
 * Compute the next tree node in a metric traversal (forward meaning moving
 * away from the original key, backwards meaning moving towards it).
 */
static const struct patricia_node *
patricia_next_metric_node(const patricia_t *pt,
	const struct patricia_node *prev, void *key, size_t keybits, bool forward)
{
	const struct patricia_node *pn;
	int i;

	g_assert(prev);

	for (pn = prev, i = 0; i <= PATRICIA_MAXBITS; i++) {
		const struct patricia_node *parent = parent_node(pn);

		patricia_node_check(pn);

		if (!parent) {
			return NULL;
		} else {
			bool matches = node_matches(parent, key, keybits);
			const struct patricia_node *next = NULL;

			g_assert(!parent->has_embedded_data);

			/*
			 * Go visit the sibling tree if we haven't yet, otherwise
			 * we'll move up and make the same test in the parent node.
			 */

			if ((forward == matches) && parent->u.children.o == pn)
				next = parent->u.children.z;
			else if (forward != matches && parent->u.children.z == pn)
				next = parent->u.children.o;

			if (next) {
				g_assert(parent_node(next) == parent);
				return find_closest(pt, next, key, keybits, forward);
			}
		}

		g_assert(parent->bit < node_prefix_bits(pn));

		pn = parent;
	}

	g_assert_not_reached();
}

/**
 * Compute next item for the iterator, given the previous one.
 */
static const struct patricia_node *
patricia_next_item(patricia_iter_t *iter, const struct patricia_node *prev)
{
	const struct patricia_node *next = NULL;

	patricia_iter_check(iter);

	switch (iter->type) {
	case PATRICIA_ITER_TREE:
		next = patricia_next_tree_node(prev, iter->forward);
		break;
	case PATRICIA_ITER_XOR:
	case PATRICIA_ITER_XOR_LAZY:
		next = patricia_next_metric_node(iter->pt, prev,
			iter->key, iter->keybits, iter->forward);
		break;
	}

	g_assert(next == NULL || node_has_data(next));

	return next;
}

/**
 * Do we have a next item to iterate to?
 *
 * This routine computes the next item as a side effect, if not already
 * done.  It can be called several times with no further side effect,
 * until patricia_iter_next() is called to actually consume the next item.
 */
bool
patricia_iter_has_next(patricia_iter_t *iter)
{
	patricia_iter_check(iter);

	if (!iter->knows_next) {
		g_assert(iter->stamp == iter->pt->stamp);
		g_assert(iter->last != NULL);
		iter->next = patricia_next_item(iter, iter->last);
		iter->knows_next = TRUE;
	}

	return iter->next != NULL;
}

/**
 * Iterate on the next value, returning the data held there, or NULL if
 * we reached the end of the iterator.
 *
 * @attention
 * NULL is a valid value in PATRICIA trees.  Therefore, one should call
 * patricia_iter_has_next() before to make sure there is indeed a next
 * value, instead of relying on patricia_iter_next() to return NULL to
 * signify the end of the iteration...
 */
void *
patricia_iter_next_value(patricia_iter_t *iter)
{
	bool has_next;

	patricia_iter_check(iter);

	has_next = iter->knows_next ?
		iter->next != NULL : patricia_iter_has_next(iter);

	g_assert(iter->stamp == iter->pt->stamp);

	if (!has_next)
		return NULL;

	iter->last = iter->next;
	iter->knows_next = FALSE;

	return deconstify_pointer(node_value(iter->last));
}

/**
 * Iterate on the next item, returning the key/value held there through
 * supplied non-NULL pointers.
 *
 * @return TRUE if we advanced to the next item, FALSE if we reached the
 * end of the iteration.
 */
bool
patricia_iter_next(patricia_iter_t *iter,
	void **key, size_t *keybits, void **value)
{
	bool has_next;

	patricia_iter_check(iter);

	has_next = iter->knows_next ?
		iter->next != NULL : patricia_iter_has_next(iter);

	if (!has_next)
		return FALSE;

	iter->last = iter->next;
	iter->knows_next = FALSE;

	if (key)     *key     = deconstify_pointer(node_key(iter->last));
	if (keybits) *keybits = node_keybits(iter->last);
	if (value)   *value   = deconstify_pointer(node_value(iter->last));

	return TRUE;
}

/**
 * Release PATRICIA iterator, nullify iterator variable.
 */
void
patricia_iterator_release(patricia_iter_t **iter_ptr)
{
	patricia_iter_t *iter;

	g_assert(iter_ptr);

	iter = *iter_ptr;

	if (iter) {
		patricia_iter_check(iter);

		patricia_destroy(iter->pt);
		if (iter->type == PATRICIA_ITER_XOR) {
			wfree(iter->key, bits2bytes(iter->keybits));
			iter->key = NULL;
		}
		iter->magic = 0;
		WFREE(iter);
		*iter_ptr = NULL;
	}
}

/***
 *** Unit tests.
 ***/

struct counter {
	size_t items;
	size_t even_keys;
};

static void
count_items(void *key, size_t keybits, void *uv, void *u)
{
	struct counter *ctx = u;
	uint8 *p = key;

	(void) uv;

	g_assert(key);
	g_assert(keybits == 32);

	ctx->items++;
	if (!(p[3] & 0x1))
		ctx->even_keys++;
}

static bool
remove_odd_key(void *key, size_t keybits, void *uv, void *uu)
{
	uint8 *p = key;

	g_assert(keybits == 32);

	(void) uv; (void) uu;

	return (p[3] & 0x1) ? TRUE : FALSE;
}

static void G_COLD
test_keys(uint32 keys[], size_t nkeys)
{
	size_t i;
	uint32 *data;
	patricia_t *pt = patricia_create(32);
	uint32 *p;
	size_t even;

	XMALLOC_ARRAY(data, nkeys);
	p = data;

	/* count even keys... */

	for (even = 0, i = 0; i <  nkeys; i++) {
		if (!(keys[i] & 0x1))
			even++;
	}

	/* prepare keys in memory (big-endian format)... */

	for (i = 0, p = data; i <  nkeys; i++, p++) {
		poke_be32(p, keys[i]);
	}

	/* inserting keys... */

	for (i = 0; i < nkeys; i++) {
		g_assert(!patricia_contains(pt, &data[i]));
		patricia_insert(pt, &data[i], NULL);
		g_assert(pt->count == i + 1);
		g_assert(patricia_contains(pt, &data[i]));
	}

	g_assert(pt->count == nkeys);
	g_assert(pt->embedded == 0);

	/* re-inserting keys... */

	for (i = 0; i < nkeys; i++) {
		patricia_insert(pt, &data[i], NULL);
		g_assert(pt->count == nkeys);
	}

	/* lookup for closest entries to random keys, then remove them... */

	for (i = 0; i < nkeys; i++) {
		void *key;
		bool found;
		char target[4];
		bool removed;

		random_bytes(ARYLEN(target));
		found = patricia_closest_extended(pt, target, &key, NULL);
		g_assert(found);
		g_assert(key);
		g_assert(patricia_contains(pt, key));
		removed = patricia_remove(pt, key);
		g_assert(removed);
	}

	patricia_destroy(pt);
	pt = patricia_create(32);

	/* inserting keys in reverse order... */

	for (i = 0; i < nkeys; i++) {
		size_t idx = nkeys - 1 - i;
		g_assert(!patricia_contains(pt, &data[idx]));
		patricia_insert(pt, &data[idx], NULL);
		g_assert(pt->count == i + 1);
		g_assert(patricia_contains(pt, &data[idx]));
	}

	g_assert(patricia_count(pt) == nkeys);
	g_assert(pt->embedded == 0);

	/* lookup for closest entries that exist... */

	for (i = 0; i < nkeys; i++) {
		void *key;
		bool found;

		found = patricia_closest_extended(pt, &data[i], &key, NULL);
		g_assert(found);
		g_assert(key == &data[i]);
	}

	/* iterating to count items, first with patricia_foreach()... */

	{
		struct counter ctx;

		ctx.items = 0;
		ctx.even_keys = 0;
		patricia_foreach(pt, count_items, &ctx);
		g_assert(ctx.items == patricia_count(pt));
		g_assert(ctx.even_keys == even);
	}

	/* iterating to count items, secondly with lexicographic traversal... */

	{
		patricia_iter_t *iter;
		size_t count = 0;
		size_t even_keys = 0;
		void *key;

		iter = patricia_tree_iterator(pt, TRUE);
		while (patricia_iter_next(iter, &key, NULL, NULL)) {
			uint8 *k = key;
			count++;
			if (!(k[3] & 0x1))
				even_keys++;
		}
		patricia_iterator_release(&iter);

		g_assert(count == patricia_count(pt));
		g_assert(even_keys == even);
	}

	/* iterating to count items, thirdly with reverse metric traversal... */

	{
		patricia_iter_t *iter;
		size_t count = 0;
		size_t even_keys = 0;
		void *key;
		uint32 distance;
		uint32 previous_distance = 0;
		bool first = TRUE;
		size_t idx = random_value(nkeys - 1);
		void *furthest;
		bool found;

		found = patricia_furthest_extended(pt, &data[idx], &furthest, NULL);

		g_assert(found);		/* Since we have at least 1 item in tree */

		iter = patricia_metric_iterator(pt, &data[idx], FALSE);
		while (patricia_iter_next(iter, &key, NULL, NULL)) {
			uint8 *k = key;
			count++;
			if (!(k[3] & 0x1))
				even_keys++;
			if (first) {
				previous_distance = peek_be32(key) ^ peek_be32(&data[idx]);
				first = FALSE;
				g_assert(0 == memcmp(furthest, key, 4));
			} else {
				distance = peek_be32(key) ^ peek_be32(&data[idx]);
				g_assert(distance < previous_distance);
				previous_distance = distance;
			}
		}
		patricia_iterator_release(&iter);

		g_assert(count == patricia_count(pt));
		g_assert(even_keys == even);

		/* remove the furthest node. the first one we traversed above */

		found = patricia_remove_furthest(pt, &data[idx], 32);

		g_assert(found);		/* Since we have at least 1 item in tree */
		g_assert(count - 1 == patricia_count(pt));
		g_assert(!patricia_contains(pt, furthest));

		patricia_insert(pt, furthest, NULL);	/* Key expected below */
	}

	/* removing odd keys... */

	i = patricia_foreach_remove(pt, remove_odd_key, NULL);
	g_assert(i == nkeys - even);
	g_assert(patricia_count(pt) == even);

	/* removing remaining keys in order... */

	for (i = 0; i < nkeys; i++) {
		if (patricia_contains(pt, &data[i])) {
			bool removed = patricia_remove(pt, &data[i]);
			g_assert(removed);
			g_assert(!patricia_contains(pt, &data[i]));
		}
	}

	g_assert(patricia_count(pt) == 0);
	g_assert(pt->root == NULL);
	g_assert(pt->nodes == 0);
	g_assert(pt->embedded == 0);

	for (i = 0, p = data; i <  nkeys; i++, p++) {
		size_t bitsize = 1 + highest_bit_set(keys[i]);
		poke_be32(p, keys[i] << (32 - bitsize));
	}

	/* inserting keys of variable size... */

	for (i = 0; i < nkeys; i++) {
		size_t bitsize = 1 + highest_bit_set(keys[i]);
		g_assert(!patricia_contains_k(pt, &data[i], bitsize));
		patricia_insert_k(pt, &data[i], bitsize, NULL);
		g_assert(pt->count == i + 1);
		g_assert(patricia_contains_k(pt, &data[i], bitsize));
	}

	g_assert(pt->count == nkeys);
	g_assert(pt->embedded != 0);

	/* removing keys of variable size... */

	for (i = 0; i < nkeys; i++) {
		bool removed;
		size_t bitsize = 1 + highest_bit_set(keys[i]);

		g_assert(patricia_contains_k(pt, &data[i], bitsize));
		removed = patricia_remove_k(pt, &data[i], bitsize);
		g_assert(removed);
		g_assert(!patricia_contains_k(pt, &data[i], bitsize));
		g_assert(patricia_count(pt) == nkeys - i - 1);
	}

	g_assert(patricia_count(pt) == 0);
	g_assert(pt->root == NULL);
	g_assert(pt->nodes == 0);
	g_assert(pt->embedded == 0);

	XFREE_NULL(data);
	patricia_destroy(pt);
}

/**
 * Perform unit tests of PATRICIA trees.
 */
void G_COLD
patricia_test(void)
{
	size_t i;
	static uint32 keys[] = {
		0x00800000U,
		0x00800001U,
		0x00810001U,
		0x00830001U,
		0x00820001U,
		0x01111111U,
		0x00000000U,
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
	patricia_t *pt = patricia_create(32);

	test_keys(keys, N_ITEMS(keys));

	keys[0] = 0x1U;		/* Ensure 1 embedded data at least */

	patricia_insert(pt, &keys[0], NULL);

	for (i = 1; i < N_ITEMS(keys); i++) {
		int j;

		for (j = 0; j < 10; j++) {
			random_bytes(VARLEN(keys[i]));
			if (!patricia_contains(pt, &keys[i]) && keys[i] != 0)
				break;
		}

		if (j == 10)
			g_error("bad luck with random numbers");

		patricia_insert(pt, &keys[i], NULL);
	}

	test_keys(keys, N_ITEMS(keys));

	/* all tests passed */

	patricia_destroy(pt);
}

/* vi: set ts=4 sw=4 cindent: */
