/*
 * Copyright (c) 2018, Raphael Manfredi
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
 * String trie (tree with 256 children per node at most).
 *
 * This implementation can function as a string set, or as a
 * string hash table.
 *
 * String keys are not stored in the trie (they are implicit) and
 * only fragments are stored in the collapsed form.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#include "common.h"

#include "trie.h"

#include "array_util.h"
#include "bit_array.h"
#include "halloc.h"
#include "hstrfn.h"
#include "htable.h"
#include "log.h"
#include "pow2.h"
#include "pslist.h"
#include "str.h"
#include "stringify.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

#define TRIE_ALPHABET		256
#define TRIE_UINT32_BITS	(CHAR_BIT * sizeof(uint32))
#define TRIE_CHILD_BYTES	(TRIE_ALPHABET / TRIE_UINT32_BITS)

/**
 * A trie node.
 *
 * We use a space-efficient sparse array to store children.
 *
 * Instead of using an array of 256 pointers at each trie node, which is
 * going to be mostly full of NULL, we only allocate the memory required.
 *
 * The bit field is used to store which letters are present and have
 * a corresponding child listed in the children[] array.
 *
 * It is the number of set bits (up to the bit we're testing, not included)
 * that determines the index within children[] for the corresponding child.
 *
 * To allow the trie to act like a string-keyed table and not just a string
 * set, we allow room for storing value in matching points (terminal leaves
 * or intermediate nodes flagged as a matching point). To avoid inflating
 * the intermediate nodes with a "value" pointer, the value, if any, is
 * stored as children[0].  The children[] array is therefore one item larger
 * than the indicated child_count.
 *
 * On a 64-bit machine, a trie_node structure is 64 bytes (including padding
 * for alignment), and also uses space for the children pointer array.
 * Compared to a 256-pointer array that would use 2 KiB alone!
 */
struct trie_node {
	bit_array_t field[BIT_ARRAY_SIZE(TRIE_ALPHABET)]; /* One bit per valid child */
	struct trie_node **children;		/* Dynamically allocated */
	struct trie_node *parent;			/* Parent node, for traversal */
	uint16 child_count;					/* For verifications and traversal */
	uint8 arc;							/* This node's arc from parent */
	uint8 is_match:1;					/* Whether node is a valid match point */
	uint8 to_delete:1;					/* Deleted during traversal */
	uint8 is_shared:1;					/* Shared node */
	uint8 is_collapsed:1;				/* Holds a collapsed string */
	uint8 has_value:1;					/* Holds value in children[0] */
};

/*
 * Abstract the fact that children[0] can be a value, not an actual child.
 */

#define TRIE_NODE_IS_LEAF(n)	(0 == (n)->child_count)
#define TRIE_NODE_CHILD_CAP(n)	((n)->child_count + (n)->has_value)
#define TRIE_NODE_CHILD_BASE(n)	(&(n)->children[(n)->has_value])
#define TRIE_NODE_LAST_CHILD(n) \
	UNSIGNED((n)->child_count + (n)->has_value - 1)

/**
 * Extended structure used when a node is shared.
 *
 * Due to structural equivalence, it can be cast to a trie_node_t to access
 * the fields there as if the structure was a trie_node_t.
 */
typedef struct trie_node_shared {
	struct trie_node node;				/* Must be first member */
	size_t refcnt;						/* Amount of references */
} trie_node_shared_t;

/**
 * Extended structure used when a node was collapsed.
 *
 * Due to structural equivalence, it can be cast to a trie_node_t to access
 * the fields there as if the structure was a trie_node_t.
 *
 * A collapsed string is an extended shared node, but the refcnt field is
 * only maintained when `is_shared' is set.
 *
 * The reasons we embark the refcnt in collapsed nodes are:
 * 1. it avoids further code complexity dealing with collapsed but not
 *    being "shared" hence not having the refcnt field...
 * 2. the additional memory used is well compensated for by the lack of
 *    other nodes for every character in the `radix' string!
 */
typedef struct trie_node_collapsed {
	struct trie_node node;				/* Must be first member */
	size_t refcnt;						/* Amount of references */
	char *radix;						/* What comes after leading "arc" */
} trie_node_collapsed_t;

enum trie_magic { TRIE_MAGIC = 0x39747712 };

/**
 * A trie object.
 */
struct trie {
	enum trie_magic magic;		/* Magic number */
	trie_node_t *root;			/* Root node */
	size_t count;				/* Amount of entries held */
	size_t node_count;			/* Amount of nodes held */
	bool compacted:1;			/* Trie was compacted */
	bool collapsed:1;			/* Trie was collapsed */
};

static inline void
trie_check(const struct trie * const t)
{
	g_assert(t != NULL);
	g_assert(TRIE_MAGIC == t->magic);
}

/**
 * Allocate a new node.
 */
static trie_node_t *
trie_node_alloc(void)
{
	trie_node_t *tn;

	WALLOC0(tn);
	return tn;
}

/**
 * Free a new node.
 *
 * @return TRUE if we freed the node, FALSE it is still shared.
 */
static bool
trie_node_free(trie_node_t * tn)
{
	/*
	 * Only free a shared node when it is no longer referenced.
	 */

	if (tn->is_shared) {
		trie_node_shared_t *stn = (void *) tn;

		g_assert(0 != stn->refcnt);

		if (stn->refcnt > 1) {
			stn->refcnt--;
			return FALSE;
		}
	}

	if (tn->children != NULL)
		hfree(tn->children);

	if (tn->is_collapsed) {
		trie_node_collapsed_t *coln = (void *) tn;
		hfree(coln->radix);
		WFREE0(coln);
	} else if (tn->is_shared) {
		trie_node_shared_t *stn = (void *) tn;
		WFREE0(stn);
	} else {
		WFREE0(tn);
	}

	return TRUE;
}

/**
 * Allocate a new trie.
 */
trie_t *
trie_create(void)
{
	trie_t *t;

	WALLOC0(t);
	t->magic = TRIE_MAGIC;
	t->root = trie_node_alloc();
	t->node_count = 1;		/* The root node */

	return t;
}

/**
 * Count how many bits are set up to a given letter.
 *
 * This provides the position of that child in the children[] array of
 * a trie node.
 *
 * @param tn		the tree node where we look for children node
 * @param c			the name of the arc to the child we seek
 * @param must_have	if TRUE, then this child must exist
 */
static uint G_FAST
trie_get_index(const trie_node_t *tn, int c, bool must_have)
{
	uint i;

	g_assert(tn != NULL);
	g_assert(c >= 0 && c < TRIE_ALPHABET);

	g_assert_log(equiv(must_have, bit_array_get(tn->field, c)),
		"%s(): must_have=%s, child #%d '%c'",
		G_STRFUNC, bool_to_string(must_have), c, c);

	/*
	 * We need to count how many bits are set up to this letter.
	 */

	i = bit_array_count_set(tn->field, 0, MAX(0, c - 1));

	g_assert_log(i < tn->child_count + UNSIGNED(!must_have),
		"%s(): i=%u, child_count=%u, must_have=%s",
		G_STRFUNC, i, tn->child_count, bool_to_string(must_have));

	/*
	 * `i' now holds the amount of children that precede `c'.
	 *
	 * We shift by one more if there is a value, to reserve children[0]
	 * for that node value.
	 */

	return i + tn->has_value;
}

/**
 * Fetch child for the given letter.
 *
 * @param tn	the trie node
 * @param c		the letter
 *
 * @return NULL if no child for this letter.
 */
const trie_node_t *
trie_node_child(const trie_node_t *tn, int c)
{
	uint i;

	g_assert(tn != NULL);
	g_assert(c >= 0 && c < TRIE_ALPHABET);

	if (!bit_array_get(tn->field, c))
		return NULL;

	i = trie_get_index(tn, c, TRUE);

	g_assert(tn->children[i] != NULL);	/* Or bit would have been cleared */

	return tn->children[i];
}

/**
 * Replace child node for given letter with supplied shared node and
 * discard the old child node.
 *
 * @param tn	the parent node of the shared node
 * @param sn	the shared node that must replace the old one.
 */
static void
trie_node_share_child(trie_node_t *tn, trie_node_shared_t *sn)
{
	uint i;
	trie_node_t *cn;

	g_assert(sn->node.is_shared);

	i = trie_get_index(tn, sn->node.arc, TRUE);
	cn = tn->children[i];

	g_assert(!cn->is_shared);

	tn->children[i] = &sn->node;
	sn->refcnt++;
	trie_node_free(cn);
}

/**
 * Replace child node for given letter with supplied collapsed node and
 * discard the old child node.
 *
 * @param tn		the parent node of the shared node
 * @param coln		the collapsed node that must replace the old one.
 * @param free_old	whether to free old node
 */
static void
trie_node_replace_child(
	trie_node_t *tn, trie_node_collapsed_t *coln, bool free_old)
{
	uint i;
	trie_node_t *oldchild;

	g_assert(tn != NULL);
	g_assert(coln->node.is_collapsed);

	i = trie_get_index(tn, coln->node.arc, TRUE);
	oldchild = tn->children[i];

	tn->children[i] = &coln->node;
	if (coln->node.is_shared)
		coln->refcnt++;			/* A collapsed node can be shared */

	if (free_old)
		trie_node_free(oldchild);
}

/**
 * @return whether node is the root node.
 */
bool
trie_node_is_root(const trie_node_t *tn)
{
	g_assert(tn != NULL);
	return NULL == tn->parent;
}

/**
 * @return whether node is a leaf.
 */
bool
trie_node_is_leaf(const trie_node_t *tn)
{
	g_assert(tn != NULL);
	return 0 == tn->child_count;
}

/**
 * @return whether node is a matching point.
 */
bool
trie_node_is_match(const trie_node_t *tn)
{
	g_assert(tn != NULL);
	return tn->is_match;
}

/**
 * @return whether node is a shared node.
 */
bool
trie_node_is_shared(const trie_node_t *tn)
{
	g_assert(tn != NULL);
	return tn->is_shared;
}

/**
 * @return whether node is a collapsed node.
 */
bool
trie_node_is_collapsed(const trie_node_t *tn)
{
	g_assert(tn != NULL);
	return tn->is_collapsed;
}

/**
 * @return whether node holds a value.
 */
bool
trie_node_has_value(const trie_node_t *tn)
{
	g_assert(tn != NULL);
	return tn->has_value;
}

/**
 * @return radix of collapsed nodes, NULL if not collapsed.
 */
const char *
trie_node_radix(const trie_node_t *tn)
{
	g_assert(tn != NULL);

	if (tn->is_collapsed) {
		trie_node_collapsed_t *coln = (void *) tn;
		return coln->radix;
	}

	return NULL;
}

/**
 * @return the "arc" in the tree for the node.
 */
uint8
trie_node_arc(const trie_node_t *tn)
{
	g_assert(tn != NULL);
	return tn->arc;
}

/**
 * Get all children from node.
 *
 * @param tn		the parent node
 * @param count		where amount of entries in array is returned
 *
 * @return array of children for the node, NULL if there are none.
 */
const trie_node_t * const *
trie_node_children(const trie_node_t *tn, size_t *count)
{
	g_assert(tn != NULL);
	g_assert(count != NULL);

	*count = tn->child_count;
	return (const trie_node_t **) TRIE_NODE_CHILD_BASE(tn);
}

/**
 * Return amount of children under node.
 */
size_t
trie_node_child_count(const trie_node_t *tn)
{
	g_assert(tn != NULL);
	return tn->child_count;
}

/**
 * Fetch first child of node, NULL if leaf node.
 */
const trie_node_t *
trie_first_child(const trie_node_t *tn)
{
	g_assert(tn != NULL);

	if (NULL == tn->children) {
		g_assert(0 == tn->child_count);
		return NULL;
	} else if (TRIE_NODE_IS_LEAF(tn)) {
		return NULL;
	}

	return TRIE_NODE_CHILD_BASE(tn)[0];
}

/**
 * Fetch next sibling of node, NULL if item has no more siblings.
 *
 * @note: if trie_compact() is used, nodes can be shared and the parent
 * pointer will not refer to the logical parent of the shared node but to
 * the physical parent of the initial node that we started to share.
 * That's why we loudly warn if accessing this on a shared node.
 */
const trie_node_t *
trie_next_sibling(const trie_node_t *tn)
{
	trie_node_t *pn;	/* Parent node */
	size_t i;

	g_assert(tn != NULL);

	if G_UNLIKELY(tn->is_shared) {
		s_carp_once("%s(): called on shared node: result unpredictable",
			G_STRFUNC);
	}

	pn = tn->parent;
	if (NULL == pn)
		return NULL;	/* Root node has no siblings */

	/*
	 * Compute the index of the current node in the children[]
	 * array of its parent node.
	 */

	i = trie_get_index(pn, tn->arc, TRUE);
	g_assert(tn == pn->children[i]);

	if (++i > TRIE_NODE_LAST_CHILD(pn))
		return NULL;

	return pn->children[i];
}

/**
 * Get parent node.
 *
 * Note that if the tree was compacted, the parent node is not necessarily
 * the original parent the node had before the common sub-node tree was
 * shared.
 *
 * @return parent node, NULL if node was the trie root node.
 */
const trie_node_t *
trie_node_parent(const trie_node_t *tn)
{
	if (NULL == tn)
		return NULL;		/* Convenience for the root node */

	if G_UNLIKELY(tn->is_shared) {
		s_carp_once("%s(): called on shared node: result unpredictable",
			G_STRFUNC);
	}

	return tn->parent;
}

/**
 * Add a child to the node.
 *
 * @param tn	the trie node to which we need to add a child
 * @param cn	the child node to connect
 * @param c		the arc key in the parent to reference the child
 */
static void G_FAST
trie_add_child(trie_node_t *tn, trie_node_t *cn, int c)
{
	uint i, capacity;

	g_assert(tn != NULL);
	g_assert(cn != NULL);
	g_assert(tn->child_count < TRIE_ALPHABET);
	g_assert(c >= 0 && c < TRIE_ALPHABET);

	g_assert(NULL == trie_node_child(tn, c));

	/* trie_get_index() accounts for possible value held in node */

	i = trie_get_index(tn, c, FALSE);		/* Where insertion happens */

	tn->child_count++;
	capacity = TRIE_NODE_CHILD_CAP(tn);
	HREALLOC_ARRAY(tn->children, capacity);
	ARRAY_INSERT(tn->children, i, capacity, cn);
	bit_array_set(tn->field, c);
	cn->parent = tn;

	g_assert(cn == trie_node_child(tn, c));
}

/**
 * Remove a child from the node.
 *
 * @param tn	the trie node from which we need to remove a child
 * @param cn	the child node to remove
 * @param c		the arc key in the parent to reference the child
 */
static void
trie_remove_child(trie_node_t *tn, trie_node_t *cn, int c)
{
	uint i, capacity;

	g_assert(tn != NULL);
	g_assert(cn != NULL);
	g_assert(tn->child_count < TRIE_ALPHABET);
	g_assert(c >= 0 && c < TRIE_ALPHABET);

	g_assert(NULL != trie_node_child(tn, c));

	/* trie_get_index() accounts for possible value held in node */

	i = trie_get_index(tn, c, TRUE);		/* Where removal happens */

	capacity = TRIE_NODE_CHILD_CAP(tn);
	ARRAY_REMOVE(tn->children, i, capacity);
	tn->child_count--;
	capacity--;
	HREALLOC_ARRAY(tn->children, capacity);
	bit_array_clear(tn->field, c);

	g_assert(NULL == trie_node_child(tn, c));

	trie_node_free(cn);
}

/**
 * @return how many items we have stored in the trie.
 */
size_t
trie_count(const trie_t *t)
{
	trie_check(t);

	return t->count;
}

/**
 * @return how many nodes we have in the trie.
 */
size_t
trie_node_count(const trie_t *t)
{
	trie_check(t);

	return t->node_count;
}

/**
 * Expand node so that it can now hold a value.
 *
 * The value slot is initialized with NULL.
 */
static void
trie_node_expand(trie_node_t *tn)
{
	uint capacity;

	g_assert(tn != NULL);
	g_assert(!tn->has_value);

	/*
	 * We store the value in the children[0] slot.
	 */

	tn->has_value = TRUE;
	capacity = TRIE_NODE_CHILD_CAP(tn);
	HREALLOC_ARRAY(tn->children, capacity);
	ARRAY_INSERT(tn->children, 0, capacity, NULL);
}

/**
 * Set value for node.
 */
void
trie_node_set_value(trie_node_t *tn, void *value)
{
	g_assert(tn != NULL);

	if (!tn->has_value)
		trie_node_expand(tn);

	tn->children[0] = value;
}

/**
 * Get value for node, NULL if it has no value.
 */
void *
trie_node_value(const trie_node_t *tn)
{
	g_assert(tn != NULL);

	return tn->has_value ? tn->children[0] : NULL;
}

/**
 * Find last node in the path described by the string.
 *
 * @param rn		root node
 * @param string	the string we're searching
 * @param endp		if non-NULL, updated with address of last char consumed
 */
static trie_node_t * G_FAST
trie_node_find_last(
	const trie_node_t *rn, const char *string, const uchar **endp)
{
	register const uchar *p = (uchar *) string;
	const trie_node_t *tn, *n;

	g_assert(rn != NULL);
	g_assert(string != NULL);

	/*
	 * Walk down the tree until we find no child or we reach
	 * the end of the string.
	 */

	tn = rn;

	while ('\0' != *p && NULL != (n = trie_node_child(tn, *p))) {
		p++;

		/*
		 * If the node is collapsed, we need to advance along the radix
		 * to make sure it matches the given string.
		 */

		if G_UNLIKELY(n->is_collapsed) {
			const trie_node_collapsed_t *cn = (void *) n;
			register const uchar *r = (uchar *) cn->radix;

			while (*r && *p && *r == *p) {
				r++;
				p++;
			}

			if ('\0' != *r) {
				p--;			/* Ensure *p != '\0' to flag non-match */
				break;			/* Did not reach end of radix! */
			}
		}

		tn = n;
	}

	if (endp != NULL)
		*endp = p;

	return deconstify_pointer(tn);
}

static void
trie_assert_not_optimized(const trie_t *t, const char *caller)
{
	g_assert_log(!t->compacted,
		"%s(): cannot alter a compacted trie", caller);
	g_assert_log(!t->collapsed,
		"%s(): cannot alter a collapsed trie", caller);
}

/**
 * Add string to trie, associated with given value.
 *
 * If there was already a value associated with the string key, it is
 * simply replaced by the new value.
 *
 * @param t			the trie
 * @param string	the string key
 * @param value		value attached to the key
 *
 * @return TRUE if string was added, FALSE if it was already present.
 */
bool
trie_insert_value(trie_t *t, const char *string, void *value)
{
	const uchar *p;
	trie_node_t *tn;

	trie_check(t);
	g_assert(string != NULL);
	trie_assert_not_optimized(t, G_STRFUNC);

	tn = trie_node_find_last(t->root, string, &p);

	/*
	 * At this stage, `tn' holds the node under which insertion must
	 * happen and `p' is the position in the string not present already
	 * in the tree.
	 *
	 * Add new children until we reach the end of the string.
	 */

	while (*p != '\0') {
		trie_node_t *n = trie_node_alloc();
		n->arc = *p++;
		trie_add_child(tn, n, n->arc);
		tn = n;
		t->node_count++;
	}

	/*
	 * We're at the node where we need to insert the value.
	 *
	 * If the node does not already have a value, and the value is NULL,
	 * do nothing: NULL is the default value we return when there was
	 * no value added to a node.
	 */

	if (!tn->has_value && value != NULL)
		trie_node_expand(tn);

	if (tn->has_value)
		trie_node_set_value(tn, value);

	if (tn->is_match)
		return FALSE;

	/* The final node we reached is now a valid stop point */

	t->count++;
	return tn->is_match = TRUE;
}

/**
 * Add string to trie.
 *
 * @return TRUE if string was added, FALSE if it was already present.
 */
bool
trie_insert(trie_t *t, const char *string)
{
	trie_check(t);
	g_assert(string != NULL);
	trie_assert_not_optimized(t, G_STRFUNC);

	return trie_insert_value(t, string, NULL);
}

/**
 * Get trie node associated with string.
 *
 * @return trie node if found, NULL if string is not part of the trie.
 */
const trie_node_t *
trie_node(const trie_t *t, const char *string)
{
	const uchar *p;
	const trie_node_t *tn;

	trie_check(t);
	g_assert(string != NULL);

	tn = trie_node_find_last(t->root, string, &p);

	return ('\0' == *p && tn->is_match) ? tn : NULL;
}

/**
 * @return whether string belongs to the trie.
 */
bool
trie_contains(const trie_t *t, const char *string)
{
	return trie_node(t, string) != NULL;
}

/**
 * Fetch node value.
 *
 * Use trie_lookup_extended() to be able to differentiate between a node
 * with no value from a non-existing key string.
 *
 * @return value of node, NULL if no value recorded or node is absent.
 */
void *
trie_lookup(const trie_t *t, const char *key)
{
	const uchar *p;
	const trie_node_t *tn;

	trie_check(t);
	g_assert(key != NULL);

	tn = trie_node_find_last(t->root, key, &p);

	if ('\0' != *p || !tn->is_match || !tn->has_value)
		return NULL;

	return tn->children[0];
}

/**
 * Fetch value associated with key string from trie, returning whether the
 * key string exists.  If it does, the value is written in valptr.
 *
 * If no value was recorded for the key string, a NULL value is assumed.
 *
 * @param t			the trie
 * @param key		the key string
 * @param valptr	if non-NULL, where the value is written
 */
bool
trie_lookup_extended(trie_t *t, const char *key, void **valptr)
{
	const uchar *p;
	const trie_node_t *tn;

	trie_check(t);
	g_assert(key != NULL);

	tn = trie_node_find_last(t->root, key, &p);

	if ('\0' != *p || !tn->is_match)
		return FALSE;

	if (valptr != NULL)
		*valptr = trie_node_value(tn);

	return TRUE;
}

/**
 * Remove string from trie.
 *
 * To accommodate removal of strings within traversal, we allow a "fake" removal
 * of the nodes: instead of deleting them physically, we flag them as deleted
 * and they will be collected by the traversal logic.
 *
 * @param t			the trie
 * @param node		the node to remove
 * @param real		if FALSE, this is a "fake" removal
 *
 * @return TRUE if string was removed, FALSE if it was not present.
 */
static bool
trie_remove_internal(trie_t *t, trie_node_t *node, bool real)
{
	trie_node_t *tn = node, *pn;

	trie_check(t);
	g_assert(tn->is_match);

	if (!real) {
		tn->to_delete = TRUE;
		tn->is_match = FALSE;
		/* Traversal will figure out whether parents need to be removed */
		goto remove_parents;
	}

	/*
	 * The root node is always kept, regardless of whether it has
	 * children nodes.
	 */

	if G_UNLIKELY(tn == t->root) {
		tn->is_match = FALSE;		/* Root no longer a valid match */
		goto done;
	}

	/*
	 * If node has children, simply remove the indication that it is
	 * a valid matching point.
	 */

	if (0 != tn->child_count) {
		tn->is_match = FALSE;
		goto done;
	}

	/*
	 * We have no children, remove ourselves from the parent node.
	 */

	/* FALL THROUGH */

remove_parents:

	pn = tn->parent;

	if (pn != NULL) {
		if (real) {
			trie_remove_child(pn, tn, tn->arc);
			t->node_count--;
		} else {
			tn->to_delete = TRUE;
		}
	}

	/*
	 * Now remove nodes up in the tree if they have no children and
	 * are not a matching point, until we reach the root.
	 */

	while (NULL != (tn = pn)) {
		pn = tn->parent;
		if (NULL == pn || tn->is_match)
			break;

		if (real) {
			if (tn->child_count != 0)
				break;
			trie_remove_child(pn, tn, tn->arc);
			t->node_count--;
		} else {
			/*
			 * We may be too aggressive here: since nodes are not physically
			 * deleted, we cannot terminate pruning when there are remaining
			 * children in a node.
			 *
			 * Flag the node for deletion and let the traversal logic figure
			 * out whether to clear that flag if children remain.
			 */
			tn->to_delete = TRUE;
		}
	}

done:
	t->count--;
	return TRUE;
}

/**
 * Remove string from trie.
 *
 * @return TRUE if string was removed, FALSE if it was not present.
 */
bool
trie_remove(trie_t *t, const char *string)
{
	const uchar *p;
	trie_node_t *tn;

	trie_check(t);
	g_assert(string != NULL);
	trie_assert_not_optimized(t, G_STRFUNC);

	tn = trie_node_find_last(t->root, string, &p);

	if (!tn->is_match)
		return FALSE;

	/*
	 * Because "" is a valid string, we need to special-case matches
	 * at the root node.
	 */

	if G_UNLIKELY(tn == t->root) {
		if ('\0' != *string)
			return FALSE;
	} else {
		if ('\0' != *p)
			return FALSE;
	}

	return trie_remove_internal(t, tn, TRUE);
}

/**
 * Traversal context.
 *
 * Note that the path from root is only maintained when traversing with the
 * TRIE_TRAVERSE_NEED_PATH flag.
 */
typedef struct trie_traverse_ctx {
	str_t *path;			/* Where path from root is maintained */
	trie_context_t user;	/* User context passed to callbacks */
} trie_traverse_t;

/**
 * General trie traversal routine, in depth-first order.
 *
 * When the "enter" function is specified and returns FALSE, the node and
 * all its children is skipped -- no action is invoked either on the node.
 *
 * @param trie		the trie we are iterating over
 * @param root		node at which traversal starts
 * @param ctx		the traversal context
 * @param flags		node to visit + when to invoke action callback
 * @param enter		(optional) callback when we enter a node
 * @param action	(optional) action on the node
 * @param udata		user-defined argument passed to callbacks
 *
 * @return the amount of visited nodes.
 */
static size_t
trie_traverse_internal(trie_t *trie, trie_node_t *root,
	trie_traverse_t *ctx, uint flags,
	trie_match_fn_t enter, trie_data_fn_t action, void *udata)
{
	size_t visited;
	bool actionable = FALSE;
	uint i;
	trie_context_t user;
	size_t pathlen;

	trie_check(trie);
	g_assert(root != NULL);

	/*
	 * We maintain the parent node manually because shared nodes cannot
	 * point correctly to their parent during traversal!
	 */

	ctx->user.node = root;

	/*
	 * The enter callback, if careful, can change ctx->user.node to
	 * alter the tree.  It will need to deconstify the parameter,
	 * so that normal callbacks cannot just blindly change the
	 * structure of the tree.
	 */

	if (enter != NULL && !(*enter)(&ctx->user, udata))
		return 0;

	root = ctx->user.node;	/* Reload root, in case it changed */

	if (NULL == action)
		goto no_action;		/* Avoid indenting long lines below */

	if (0 != root->child_count && (flags & TRIE_TRAVERSE_NON_LEAVES))
		actionable = TRUE;
	else if (0 == root->child_count && (flags & TRIE_TRAVERSE_LEAVES))
		actionable = TRUE;
	else if (root->is_match && (flags & TRIE_TRAVERSE_MATCHING))
		actionable = TRUE;
	else if (!root->is_match && (flags & TRIE_TRAVERSE_NON_MATCHING))
		actionable = TRUE;

no_action:

	/* Only count as visited the nodes for which a callback is invoked */

	visited = actionable ? 1 : 0;
	user = ctx->user;			/* Struct copy */

	/* The action, if ran, MUST NOT free node yet */

	if (actionable && (flags & TRIE_CALL_BEFORE)) {
		ctx->user.is_before = TRUE;
		(*action)(&ctx->user, udata);
		ctx->user.is_before = FALSE;
	}

	if (flags & TRIE_TRAVERSE_NEED_PATH)
		pathlen = str_len(ctx->path);

	/*
	 * Traversal of the children[] array starts at 1 if there is a
	 * value stored in the children[0] slot.
	 */

	for (i = 0; i < root->child_count; i++) {
		uint j = i + root->has_value;			/* Offset by 1 if value */
		trie_node_t *cn = root->children[j];
		size_t cc;
		trie_node_t *nn;

		if G_UNLIKELY(flags & TRIE_SAFE_DELETE) {
			/*
			 * Save current count and next node in case some nodes are
			 * removed whilst visiting the current child.
			 */
			cc = root->child_count;
			nn = (i + 1) == root->child_count ?  NULL : root->children[i + 1];
		}

		g_assert(cn != NULL);

		/* Prepare user context */

		if (flags & TRIE_TRAVERSE_NEED_PATH) {
			str_putc(ctx->path, cn->arc);
			if (cn->is_collapsed) {
				trie_node_collapsed_t *coln = (void *) cn;
				str_cat(ctx->path, coln->radix);
			}
		}

		ctx->user.is_before      = FALSE;
		ctx->user.parent         = root;
		ctx->user.depth          = user.depth + 1;
		ctx->user.path           = str_2c(ctx->path);
		ctx->user.pathlen        = str_len(ctx->path);
		ctx->user.is_first_child = 0 == i;
		ctx->user.is_last_child  = (i + 1) == root->child_count;

		/* Recursive visit of child node */

		visited += trie_traverse_internal(
						trie, cn, ctx, flags, enter, action, udata);

		if (flags & TRIE_TRAVERSE_NEED_PATH)
			str_setlen(ctx->path, pathlen);

		if G_UNLIKELY(flags & TRIE_SAFE_DELETE) {
			/*
			 * When traversing with TRIE_SAFE_DELETE, some nodes may be deleted
			 * in the process, so be careful.
			 *
			 * The next node pointer we have figured out above must still be
			 * present in the children array, albeit it may not be at the
			 * same location as before!
			 */

			if (cc != root->child_count && nn != NULL) {
				uint k;

				for (k = 0; k < root->child_count; k++) {
					if (root->children[k + root->has_value] == nn)
						goto found;
				}
				g_assert_not_reached();	/* Next node cannot be gone */
			found:
				i = k - 1;	/* To compensate for the i++ in the loop */
			}
		}
	}

	/* The action, if ran at this stage, can free the node if needed */

	if (actionable && (flags & TRIE_CALL_AFTER)) {
		/* Restore user context we had upon entry */
		ctx->user = user;						/* Struct copy */
		ctx->user.path = str_2c(ctx->path);		/* In case it moved */

		(*action)(&ctx->user, udata);
	}

	/*
	 * When they request TRIE_SAFE_DELETE, callbacks are allowed to
	 * flag nodes as being deleted.  Process with deletion now.
	 *
	 * Note that TRIE_SAFE_DELETE is incompatible with callbacks
	 * that can physically destroy nodes.
	 */

	if G_UNLIKELY(flags & TRIE_SAFE_DELETE) {
		if (root->to_delete) {
			if (
				root != trie->root &&
				0 == root->child_count &&
				!root->is_match
			) {
				trie_remove_child(root->parent, root, root->arc);
				trie->node_count--;
			}
			root->to_delete = FALSE;
		}
	}

	return visited;
}

/**
 * Recursively traverse tree, in depth-first mode.
 *
 * Traversal can be pruned with an optional "enter" callback.
 *
 * The "action" callback can be invoked before or after processing children,
 * It can be triggered on non-leaf nodes, on leaves only, or on both.
 * It can also be triggered only on nodes that are a matching point, or
 * those which are not a matching point.
 * Matching and leaf status flags can be combined together.
 *
 * These "action" flags are:
 *
 *  TRIE_TRAVERSE_LEAVES          traverse only leaf nodes
 *  TRIE_TRAVERSE_NON_LEAVES      traverse only non-leaf nodes
 *  TRIE_TRAVERSE_MATCHING        traverse only matching nodes
 *  TRIE_TRAVERSE_NON_MATCHING    traverse only non-matching nodes
 *  TRIE_TRAVERSE_ALL             traverse all nodes
 *  TRIE_TRAVERSE_NEED_PATH       maintain path from root string
 *  TRIE_CALL_AFTER               invoke action after traversing children
 *  TRIE_CALL_BEFORE              invoke action before traversing children
 *
 * If neither TRIE_CALL_AFTER nor TRIE_CALL_BEFORE is specified, the
 * former is assumed.
 *
 * It is possible to specify both TRIE_CALL_BEFORE and TRIE_CALL_AFTER,
 * to invoke the action callback twice.  The callback can inspect the
 * value of the `is_before' field in its trie_context_t argument to determine
 * whether the call is made before or after traversal of the children nodes.
 *
 * The function returns the number of visited nodes, regardless of whether
 * the action was run on them.  This lets the caller know how many nodes
 * were selected by the "enter" callback.
 *
 * @param trie		the trie descriptor
 * @param flags		node to visit + when to invoke action callback
 * @param enter		(optional) callback when we enter a node
 * @param action	(optional) action on the node
 * @param udata		user-defined argument passed to callbacks
 *
 * @return amount of visited nodes.
 */
size_t
trie_traverse(trie_t *trie, uint flags,
	trie_match_fn_t enter, trie_data_fn_t action, void *udata)
{
	trie_traverse_t ctx;
	size_t visited;

	trie_check(trie);
	g_assert(NULL != action ||
		0 == (flags & (TRIE_CALL_BEFORE | TRIE_CALL_AFTER)));

	/*
	 * If neither TRIE_CALL_BEFORE nor TRIE_CALL_AFTER was given
	 * and they supplied an action callback, use post-order callback.
	 */

	if (
		0 == (flags & (TRIE_CALL_BEFORE | TRIE_CALL_AFTER)) &&
		action != NULL
	)
		flags |= TRIE_CALL_AFTER;	/* Call after by default */

	ZERO(&ctx);
	ctx.path = str_new(0);
	ctx.user.path = str_2c(ctx.path);

	/* The root node is the only sibling */
	ctx.user.is_first_child = ctx.user.is_last_child = TRUE;

	visited = trie_traverse_internal(
		trie, trie->root, &ctx, flags, enter, action, udata);

	str_destroy_null(&ctx.path);
	return visited;
}

/**
 * Traversal callback.
 *
 * Delete node but the root node.
 */
static void
trie_node_delete_but_root(const trie_context_t *uc, void *udata)
{
	(void) udata;

	/* Don't bother clearing parent's children */

	if (uc->parent != NULL)
		trie_node_free(uc->node);
}

/**
 * Traversal callback.
 *
 * Delete node.
 */
static void
trie_node_delete(const trie_context_t *uc, void *udata)
{
	size_t *freed = udata;

	if (trie_node_free(uc->node))
		(*freed)++;
}

/**
 * @return trie root node.
 */
const trie_node_t *
trie_root(const trie_t *t)
{
	trie_check(t);
	return t->root;
}

/**
 * Clear trie.
 */
void
trie_clear(trie_t *t)
{
	trie_node_t *rn;

	trie_check(t);

	trie_traverse(
		deconstify_pointer(t),
		TRIE_CALL_AFTER | TRIE_TRAVERSE_ALL,
		NULL, trie_node_delete_but_root, NULL);

	/* Clear root node */

	rn = t->root;
	HFREE_NULL(rn->children);
	ZERO(rn);

	/* Reset counts */

	t->count = 0;
	t->node_count = 1;	/* The root node */

	/* Reset state */

	t->collapsed = t->compacted = FALSE;
}

/**
 * Free trie.
 */
void
trie_free(trie_t *t)
{
	size_t freed = 0;

	trie_check(t);

	trie_traverse(t,
		TRIE_CALL_AFTER | TRIE_TRAVERSE_ALL,
		NULL, trie_node_delete, &freed);

	g_assert_log(freed == t->node_count,
		"%s(): trie had %zu node%s, freed %zu",
		G_STRFUNC, PLURAL(t->node_count), freed);

	t->magic = 0;
	WFREE(t);
}

/**
 * Free trie and nullify pointer.
 */
void
trie_free_null(trie_t **t_ptr)
{
	trie_t *t = *t_ptr;

	if (t != NULL) {
		trie_free(t);
		*t_ptr = NULL;
	}
}

struct trie_depth_ctx {
	size_t max;		/* Maximum depth */
};

/**
 * Traversal entry callback for trie depth computation.
 */
static bool
trie_depth_enter(const trie_context_t *uc, void *udata)
{
	struct trie_depth_ctx *ctx = udata;

	if (uc->depth > ctx->max)
		ctx->max = uc->depth;

	return TRUE;	/* Traverse node */
}

/**
 * Compute the trie depth.
 *
 * @return the trie depth, 0 meaning only the root node is present.
 */
size_t
trie_depth(const trie_t *t)
{
	struct trie_depth_ctx ctx;

	trie_check(t);

	ZERO(&ctx);

	trie_traverse(deconstify_pointer(t),
		TRIE_TRAVERSE_ALL,
		trie_depth_enter, NULL, &ctx);

	return ctx.max;
}

/**
 * Traversal entry callback for trie value discarding.
 */
static bool
trie_discard_enter(const trie_context_t *uc, void *udata)
{
	trie_node_t *tn = deconstify_pointer(uc->node);

	(void) udata;

	if (tn->has_value) {
		size_t capacity = TRIE_NODE_CHILD_CAP(tn);

		/* Value is stored as children[0] */
		ARRAY_REMOVE(tn->children, 0, capacity);
		capacity--;
		HREALLOC_ARRAY(tn->children, capacity);
		tn->has_value = FALSE;
	}

	return TRUE;	/* Traverse node */
}

/**
 * Discard all the values stored in the trie but keep the keys.
 */
void
trie_discard_values(trie_t *t)
{
	trie_traverse(deconstify_pointer(t),
		TRIE_TRAVERSE_ALL,
		trie_discard_enter, NULL, NULL);
}

/**
 * Data callback encapsulation for trampolines.
 */

struct trie_trampoline_ctx {
	data_fn_t cb;		/* User-supplied callback */
	void *udata;		/* Their own user data */
};

struct trie_trampoline_remove_ctx {
	trie_t *t;			/* The trie over which we are iterating */
	data_rm_fn_t cb;	/* User-supplied callback */
	void *udata;		/* Their own user data */
};

struct trie_value_trampoline_ctx {
	ckeyval_fn_t cb;	/* User-supplied callback */
	void *udata;		/* Their own user data */
};

struct trie_value_trampoline_remove_ctx {
	trie_t *t;			/* The trie over which we are iterating */
	ckeyval_rm_fn_t cb;	/* User-supplied callback */
	void *udata;		/* Their own user data */
};

/**
 * Trampoline callback to invoke the user-supplied data traversal callback
 * with not a node but with a string!
 */
static void
trie_foreach_trampoline(const trie_context_t *uc, void *udata)
{
	struct trie_trampoline_ctx *ctx = udata;

	g_assert(uc->node->is_match);

	(*ctx->cb)(deconstify_char(uc->path), ctx->udata);
}

/**
 * Trampoline callback to invoke the user-supplied data traversal callback
 * with not a node but with a string!
 */
static void
trie_foreach_remove_trampoline(const trie_context_t *uc, void *udata)
{
	struct trie_trampoline_remove_ctx *ctx = udata;

	g_assert(uc->node->is_match);

	if ((*ctx->cb)(deconstify_char(uc->path), ctx->udata))
		trie_remove_internal(ctx->t, uc->node, FALSE);

}

/**
 * Trampoline callback to invoke the user-supplied data traversal callback
 * with not a node but with a string!
 */
static void
trie_foreach_value_trampoline(const trie_context_t *uc, void *udata)
{
	struct trie_value_trampoline_ctx *ctx = udata;
	trie_node_t *tn = uc->node;

	g_assert(tn->is_match);

	(*ctx->cb)(
		deconstify_char(uc->path), trie_node_value(tn), ctx->udata);
}

/**
 * Trampoline callback to invoke the user-supplied data traversal callback
 * with not a node but with a string!
 */
static void
trie_foreach_value_remove_trampoline(const trie_context_t *uc, void *udata)
{
	struct trie_value_trampoline_remove_ctx *ctx = udata;
	trie_node_t *tn = uc->node;

	g_assert(tn->is_match);

	if ((*ctx->cb)(
		deconstify_char(uc->path), trie_node_value(tn), ctx->udata)
	)
		trie_remove_internal(ctx->t, tn, FALSE);
}

/**
 * Recursively apply function on each string, in depth-first mode.
 *
 * It is totally UNPREDICTABLE to remove strings from the trie as it
 * is being traversed.  Use trie_foreach_remove() for that!
 *
 * @return amount of visited nodes.
 */
size_t
trie_foreach(const trie_t *trie, data_fn_t cb, void *data)
{
	struct trie_trampoline_ctx ctx;
	size_t count, node_count, visited;

	trie_check(trie);

	/* For coarse grain assertions after traversal */

	count      = trie->count;
	node_count = trie->node_count;

	ctx.cb    = cb;
	ctx.udata = data;

	/* Using TRIE_CALL_BEFORE guarantees lexicographic traversal */

	visited = trie_traverse(
		deconstify_pointer(trie),
		TRIE_CALL_BEFORE |
			TRIE_TRAVERSE_MATCHING | TRIE_TRAVERSE_NEED_PATH,
		NULL, trie_foreach_trampoline, &ctx);

	/* Assertion protecting against accidental changes during traversal */

	g_assert_log(count == trie->count && node_count == trie->node_count,
		"%s(): trie changed during traversal; "
		"trie->count=%zu (was %zu), trie->node_count=%zu (was %zu)",
		G_STRFUNC, trie->count, count, trie->node_count, node_count);

	return visited;
}

/**
 * Recursively apply function on each string, in depth-first mode.
 *
 * If the callback returns TRUE, the entry is deleted.
 *
 * @return the amount of entries removed from the trie.
 */
size_t
trie_foreach_remove(trie_t *trie, data_rm_fn_t cb, void *data)
{
	struct trie_trampoline_remove_ctx ctx;
	size_t old_count = trie->count;

	trie_check(trie);
	/* FIXME: could relax to not compacted (i.e. no shared node)? */
	trie_assert_not_optimized(trie, G_STRFUNC);

	ctx.t = trie;
	ctx.cb = cb;
	ctx.udata = data;

	trie_traverse(
		deconstify_pointer(trie),
		TRIE_CALL_BEFORE |
			TRIE_TRAVERSE_MATCHING | TRIE_TRAVERSE_NEED_PATH |
			TRIE_SAFE_DELETE,
		NULL, trie_foreach_remove_trampoline, &ctx);

	return old_count - trie->count;	/* Amount of deleted nodes */
}

/**
 * Recursively apply function on each key/value, in depth-first mode.
 *
 * It is totally UNPREDICTABLE to remove keys from the trie as it
 * is being traversed.  Use trie_foreach_value_remove() for that!
 *
 * @return amount of visited nodes.
 */
size_t
trie_foreach_value(const trie_t *trie, ckeyval_fn_t cb, void *data)
{
	struct trie_value_trampoline_ctx ctx;
	size_t count, node_count, visited;

	trie_check(trie);

	/* For coarse grain assertions after traversal */

	count      = trie->count;
	node_count = trie->node_count;

	ctx.cb = cb;
	ctx.udata = data;

	/* Using TRIE_CALL_BEFORE guarantees lexicographic traversal */

	visited = trie_traverse(
		deconstify_pointer(trie),
		TRIE_CALL_BEFORE |
			TRIE_TRAVERSE_MATCHING | TRIE_TRAVERSE_NEED_PATH,
		NULL, trie_foreach_value_trampoline, &ctx);

	/* Assertion protecting against accidental changes during traversal */

	g_assert_log(count == trie->count && node_count == trie->node_count,
		"%s(): trie changed during traversal; "
		"trie->count=%zu (was %zu), trie->node_count=%zu (was %zu)",
		G_STRFUNC, trie->count, count, trie->node_count, node_count);

	return visited;
}

/**
 * Recursively apply function on each string, in depth-first mode.
 *
 * If the callback returns TRUE, the entry is deleted.
 *
 * @return the amount of entries removed from the trie.
 */
size_t
trie_foreach_value_remove(trie_t *trie, ckeyval_rm_fn_t cb, void *data)
{
	struct trie_value_trampoline_remove_ctx ctx;
	size_t old_count = trie->count;

	trie_check(trie);
	/* FIXME: could relax to not compacted (i.e. no shared node)? */
	trie_assert_not_optimized(trie, G_STRFUNC);

	ctx.t = trie;
	ctx.cb = cb;
	ctx.udata = data;

	trie_traverse(
		deconstify_pointer(trie),
		TRIE_CALL_BEFORE |
			TRIE_TRAVERSE_MATCHING | TRIE_TRAVERSE_NEED_PATH |
			TRIE_SAFE_DELETE,
		NULL, trie_foreach_value_remove_trampoline, &ctx);

	return old_count - trie->count;	/* Amount of deleted nodes */
}

/**
 * Traversal iterator to add leaf node to the appropriate heads[] lists.
 */
static void
trie_add_leaf(const trie_context_t *uc, void *udata)
{
	pslist_t **heads = udata;
	trie_node_t *tn = uc->node;

	/*
	 * We cannot share leaf nodes that have values, even if they hold
	 * the same value currently: sharing is a space optimization that
	 * must be transparent to users.
	 */

	if (tn->has_value)
		return;

	g_assert(NULL == tn->children);
	g_assert(0 == tn->child_count);
	g_assert(!tn->is_shared);

	/*
	 * Remember that we saw leaf "arc" as node `tn'.
	 */

	heads[tn->arc] = pslist_prepend(heads[tn->arc], tn);
}

/**
 * Get sole child, NULL when we reached a leaf node.
 */
static trie_node_t *
trie_get_sole_child(const trie_node_t *tn)
{
	g_assert(tn != NULL);

	if (0 == tn->child_count)
		return NULL;

	g_assert(tn->children != NULL);
	g_assert_log(1 == tn->child_count,
		"%s(): %snode '%c' has %u children",
		G_STRFUNC, tn->is_shared ? "shared " : "",
		tn->arc, tn->child_count);

	return tn->children[tn->has_value];
}

/**
 * Build string corresponding to the sequence starting at given node.
 * All nodes must have one child.
 *
 * The resulting string must be freed with hfree().
 */
static char *
trie_sequence_string(const trie_node_t *root)
{
	str_t *s = str_new(0);
	const trie_node_t *tn;

	g_assert(root != NULL);
	g_assert(1 == root->child_count);

	for (tn = root; tn != NULL; tn = trie_get_sole_child(tn)) {
		str_putc(s, tn->arc);
	}

	return str_s2c_null(&s);
}

/**
 * Traversal iterator to find nodes whose only child is a shared node
 * and which do not bear any value.
 */
static void
trie_find_above_shared(const trie_context_t *uc, void *udata)
{
	htable_t *ht = udata;
	trie_node_t *tn = uc->node;
	trie_node_t *pn = uc->parent;
	char *s;
	pslist_t *sl;
	const void *key;
	void *value;

	if (NULL == pn || NULL == pn->parent)
		return;			/* `tn' was the root node, or `pn' is root */

	if (!tn->is_shared || pn->is_shared)
		return;			/* `pn' not above shared node, or already shared */

	if (pn->is_match || pn->child_count != 1)
		return;			/* `pn' is match point or has many children */

	if (pn->has_value)
		return;			/* cannot factorize if it has a value */

   	s = trie_sequence_string(pn);

	if (htable_lookup_extended(ht, s, &key, &value)) {
		sl = pslist_prepend(value, pn);	/* Records start of sequence */
		htable_insert(ht, key, sl);
		HFREE_NULL(s);					/* Key string already in table */
	} else {
		htable_insert(ht, s, pslist_prepend(NULL, pn));
	}
}

/**
 * Perform leaf node factorization.
 *
 * @param trie	the trie the nodes belong to
 * @param tn	is a node we can factorize
 * @param slp	single-list pointer listing all the similar leaves
 */
static void
trie_factorize_nodes(trie_t *trie, trie_node_t *tn, pslist_t **slp)
{
	trie_node_shared_t *stn;
	trie_node_t *in;

	g_assert(tn != NULL);
	g_assert(!tn->is_shared);
	g_assert(tn->parent != NULL);	/* Not the root node */

	/* Duplicate tn as a shared node */

	WALLOC0(stn);
	stn->node = *tn;			/* Struct copy */
	stn->node.is_shared = TRUE;
	tn->children = NULL;		/* Must not be freed, belongs to stn */

	/* Replace `tn' with new shared node in its parent */

	trie_node_share_child(tn->parent, stn);		/* Will free `tn' */
	g_assert(1 == stn->refcnt);

	/* Replace all other identical nodes in the list with the shared node */

	while (NULL != (in = pslist_shift(slp))) {
		g_assert(in->parent != NULL);
		trie_node_share_child(in->parent, stn);		/* Will free `in' */
		trie->node_count--;
	}
}

struct trie_add_shared_ctx {
	trie_t *trie;
	bool factorized;
};

/**
 * Hash table iterating callback to perform factorization of nodes above
 * a shared set of nodes that exhibit the same suffix string.
 */
static bool
trie_add_shared(const void *key, void *value, void *data)
{
	char *suffix = deconstify_pointer(key);
	pslist_t *sl = value;
	struct trie_add_shared_ctx *ctx = data;
	trie_node_t *tn;

	trie_check(ctx->trie);
	g_assert(sl != NULL);

	tn = pslist_shift(&sl);
	if (NULL == sl)
		goto done;		/* Had only one node! */

	ctx->factorized = TRUE;
	trie_factorize_nodes(ctx->trie, tn, &sl);
	g_assert(NULL == sl);

done:
	HFREE_NULL(suffix);
	return TRUE;		/* Remove from hash table */
}

/**
 * Factorize common leaf nodes.
 *
 * @return TRUE if we performed any factorization.
 */
static void
trie_factorize(trie_t *trie)
{
	size_t i;
	bool factorized = FALSE;
	pslist_t **heads;
	htable_t *string_nodes;
	struct trie_add_shared_ctx ctx;

	HALLOC0_ARRAY(heads, TRIE_ALPHABET);

	/*
	 * Identify all leaves (which are necessary match points)
	 * and store them by letter in a list.
	 *
	 * heads['a'] will therefore list all the leaves that we found
	 * which are an arc for 'a'.
	 */

	trie_traverse(
		deconstify_pointer(trie),
		TRIE_CALL_AFTER | TRIE_TRAVERSE_LEAVES,
		NULL, trie_add_leaf, heads);

	/*
	 * Loop over all the list heads, and if there is more than one item
	 * in a list, it means we can create a shared node and have all the
	 * parent reference this shared node instead.
	 */

	for (i = 0; i < TRIE_ALPHABET; i++) {
		trie_node_t *tn;

		if (NULL == heads[i])
			continue;

		tn = pslist_shift(&heads[i]);
		if (NULL == heads[i])
			continue;		/* List had only one node, nothing to share */

		/*
		 * We are going to factorize the letter i (say it is 'a') by
		 * creating a shared node for the leaf node 'a' and have all the
		 * parents reference this shared node instead of the original.
		 */

		trie_factorize_nodes(trie, tn, &heads[i]);

		g_assert(NULL == heads[i]);
		factorized = TRUE;
	}

	hfree(heads);

	if (!factorized)
		return;

	/*
	 * The `string_nodes' table is indexed by strings (say "mma") and
	 * yields a pslist_t of all the different nodes that end-up representing
	 * that string (say all the 'm' nodes that are followed by "ma").
	 */

	string_nodes = htable_create(HASH_KEY_STRING, 0);

	do {
		trie_traverse(
			deconstify_pointer(trie),
			TRIE_CALL_BEFORE | TRIE_TRAVERSE_LEAVES,
			NULL, trie_find_above_shared, string_nodes);

		ZERO(&ctx);
		ctx.trie = trie;

		htable_foreach_remove(string_nodes, trie_add_shared, &ctx);

	} while (ctx.factorized);

	htable_free_null(&string_nodes);
}

/**
 * Compact trie by sharing nodes when we can.
 *
 * Once compacted, the trie can no longer be modified: no insertion nor
 * deletion and no traversal for removal.
 *
 * Moreover, since compacting will introduce shared nodes in the tree,
 * calls like trie_next_sibling() will have unpredictable results since
 * they rely on moving up to the parent node, which is now one of the
 * original parents, but not necessarily the original parent the node had
 * in the un-compacted form.
 *
 * @return the amount of nodes removed due to sharing.
 */
size_t
trie_compact(trie_t *trie)
{
	size_t old_node_count;

	trie_check(trie);

	if (trie->collapsed || trie->compacted)
		return 0;

	old_node_count = trie->node_count;
	trie_factorize(trie);

	/*
	 * If we have the same node count, then we did not create any shared
	 * node, hence the parent structure of the tree is intact and we do
	 * no need to flag the trie as being compacted.
	 */

	trie->compacted = old_node_count != trie->node_count;

	return old_node_count - trie->node_count;
}

/*
 * Traversal context for trie_collapse().
 */
struct trie_collapse_ctx {
	trie_t *trie;
	htable_t *node2str;		/* shared node -> collapsed node */
};

/**
 * Collapse a sequence of shared nodes.
 */
static void
trie_collapse_sequence(
	const trie_context_t *uc, struct trie_collapse_ctx *ctx)
{
	trie_node_t *tn = uc->node, *cn;
	trie_node_collapsed_t *coln;

	g_assert(tn->is_shared);

	/*
	 * If we know the sequence, find the node we used for it previously,
	 * which is necessarily shared, and use it to replace the current
	 * node.
	 */

	coln = htable_lookup(ctx->node2str, tn);
	if (coln != NULL) {
		g_assert(coln->node.is_shared);
		g_assert(coln->node.arc == tn->arc);
	} else {
		str_t *s = str_new(0);

		/*
		 * We have to create a new collapsed node since this is the first time
		 * we encounter this sequence.  It will be a leaf node, no children.
		 */

		WALLOC0(coln);
		coln->node.is_collapsed = TRUE;
		coln->node.is_shared = TRUE;
		coln->node.is_match = TRUE;
		coln->node.arc = tn->arc;

		/* Collect the radix from children nodes */

		for (
			cn = trie_get_sole_child(tn);
			cn != NULL;
			cn = trie_get_sole_child(cn)
		) {
			str_putc(s, cn->arc);
		}

		coln->radix = str_s2c_null(&s);
		ctx->trie->node_count++;

		/* Register the collapsed node, keyed by the `tn' node start */

		htable_insert(ctx->node2str, tn, coln);
	}

	/*
	 * The current node's slot in the parent children[] array is going
	 * to be replaced by the collapsed node.
	 */

	trie_node_replace_child(uc->parent, coln, FALSE); /* Do not free `tn' */

	/*
	 * Free the sequence starting at `tn', since we have now replaced
	 * it with a shared collapsed node.
	 */

	do {
		g_assert(tn->is_shared);

		cn = trie_get_sole_child(tn);

		if (trie_node_free(tn))
			ctx->trie->node_count--;

	} while (NULL != (tn = cn));
}

/**
 * Selection callback for trie traversal.
 *
 * This callback may be changing the current node, held in uc->node, to
 * replace a node with a collapsed one.  The traversal routine is prepared
 * for that and will reload the new root upon return.
 */
static bool
trie_collapse_enter(const trie_context_t *uc, void *udata)
{
	struct trie_collapse_ctx *ctx = udata;
	trie_node_t *tn = uc->node;
	str_t *s = NULL;

	/*
	 * If we reach a node with a single child, we can merge that
	 * child with the current node.  And retry merging, until
	 * we reach a match point or a shared node that is not a leaf.
	 *
	 * A shared node that is a leaf can be swallowed -- the gain we
	 * have with it being shared is far less than the single additional
	 * byte it will occupy in a collapsed node.
	 *
	 * A shared node that is not a leaf is the beginning of a common
	 * suffix that also appears somewhere else.  This suffix is going
	 * to be shared and its starting address is stored into the node2str
	 * hash table, so that further occurrence can reuse the same node.
	 */

	if (NULL == uc->parent)
		return TRUE;		/* At root node */

	if (tn->is_match)
		return TRUE;

	if (tn->is_shared) {
		if (!TRIE_NODE_IS_LEAF(tn))
			trie_collapse_sequence(uc, ctx);
		return TRUE;
	}

	while (1 == tn->child_count && !tn->is_match) {
		trie_node_t *cn = trie_get_sole_child(tn);
		size_t i;

		/*
		 * Node cannot hold a value because it is not a match point and
		 * it is not a leaf node (since it has 1 child node).
		 */

		g_assert(!tn->has_value);

		if (cn->is_shared && !TRIE_NODE_IS_LEAF(cn))
			break;	/* Reached beginning of common suffix */

		if (!tn->is_collapsed) {
			trie_node_collapsed_t *coln;
			/* We're patching the context, we know what we're doing! */
			trie_context_t *ucw = deconstify_pointer(uc);

			WALLOC0(coln);
			coln->node = *tn;		/* Struct copy */
			coln->node.is_collapsed = TRUE;
			tn->children = NULL;	/* Must not be freed, belongs to coln */

			/*
			 * Replace `tn' with new collapsed node in its parent,
			 * freeing the old `tn' node.
			 */

			trie_node_replace_child(uc->parent, coln, TRUE);
			ucw->node = tn = (void *) coln;	/* Patch context! */
			s = str_new(0);
		}

		/* Swallow child node into collapsed node */

		g_assert(tn->is_collapsed);

		str_putc(s, cn->arc);		/* Append to radix */
		memcpy(tn->field, cn->field, sizeof(cn->field));	/* Copy bitmap */
		hfree(tn->children);		/* Had only one child */
		tn->children = cn->children;
		tn->child_count = cn->child_count;
		tn->is_match = cn->is_match;
		tn->has_value = cn->has_value;
		cn->children = NULL;

		/* Re-parent children of swallowed node */

		for (i = 0; i < tn->child_count; i++)
			tn->children[i + tn->has_value]->parent = tn;

		if (trie_node_free(cn))
			ctx->trie->node_count--;
	}

	g_assert(equiv(tn->is_collapsed, s != NULL));

	/* If we have begun collecting a radix, freeze the radix string */

	if (s != NULL) {
		trie_node_collapsed_t *coln = (void *) tn;
		coln->radix = str_s2c_null(&s);
	}

	str_destroy_null(&s);
	return TRUE;
}

/**
 * If a leaf node is shared and has a reference count of 1, make it plain.
 */
static void
trie_unshare_orphan_leaf(const trie_context_t *ctx, void *udata)
{
	trie_node_t *tn = ctx->node;

	(void) udata;

	if (NULL == ctx->parent)
		return;		/* The root node, the tree must be empty */

	if (tn->is_shared && !tn->is_collapsed) {
		trie_node_shared_t *sn = (void *) tn;
		if (1 == sn->refcnt) {
			size_t i = trie_get_index(ctx->parent, tn->arc, TRUE);
			trie_node_t *un;
			bool freed;

			WALLOC(un);
			*un = sn->node;			/* Struct copy */
			un->is_shared = FALSE;

			ctx->parent->children[i] = un;	/* Install new unshared node */
			freed = trie_node_free(tn);
			g_assert(freed);				/* Was last reference */
		}
	}
}

/**
 * Collapse series of nodes with one child into a single node.
 *
 * To be able to share common suffixes, it is best to compact the tree
 * before collapsing it.
 *
 * @return the amount of nodes removed due to collapsing.
 */
size_t
trie_collapse(trie_t *trie)
{
	size_t old_node_count;
	struct trie_collapse_ctx ctx;

	trie_check(trie);

	if (trie->collapsed)
		return 0;

	old_node_count = trie->node_count;

	ZERO(&ctx);
	ctx.trie = trie;
	ctx.node2str = htable_create(HASH_KEY_SELF, 0);

	/*
	 * First pass -- collapse nodes by having nodes swallow their only
	 * child, under some conditions.
	 */

	trie_traverse(
		deconstify_pointer(trie),
		TRIE_TRAVERSE_ALL,
		trie_collapse_enter, NULL, &ctx);

	/*
	 * Second pass -- if we have shared leaves with only one reference,
	 * make them unshared to save space.
	 *
	 * Indeed, shared leaves may have been swallowed by the first pass
	 * above.
	 *
	 * This is only needed if the trie was compacted before.
	 */

	if (trie->compacted) {
		trie_traverse(
			deconstify_pointer(trie),
			TRIE_TRAVERSE_LEAVES,
			NULL, trie_unshare_orphan_leaf, NULL);
	}

	trie->collapsed = TRUE;
	htable_free_null(&ctx.node2str);

	return old_node_count - trie->node_count;
}

/* vi: set ts=4 sw=4 cindent: */
