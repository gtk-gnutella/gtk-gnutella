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
 * @author Raphael Manfredi
 * @date 2018
 */

#ifndef _trie_h_
#define _trie_h_

struct trie;
typedef struct trie trie_t;

struct trie_node;
typedef struct trie_node trie_node_t;

/**
 * Structure passed to iterators.
 *
 * The `path' argument is only maintained when traversing with the
 * TRIE_TRAVERSE_NEED_PATH flag, otherwise it will be an empty string.
 */
typedef struct trie_context {
	const char *path;			/* Path from root -> node */
	size_t pathlen;				/* Length of path string */
	size_t depth;				/* Node depth */
	trie_node_t *parent;		/* Parent node */
	trie_node_t *node;			/* Current node */
	/* Data that cannot be computed for shared nodes */
	bool is_first_child:1;		/* Node is first child of parent node */
	bool is_last_child:1;		/* Node is last child of parent node */
	/* For action callback */
	bool is_before:1;			/* Calling before traversing children */
} trie_context_t;

/**
 * Iterator callback for general trie traversal.
 *
 * @param ctx		the trie iterating context
 * @param udata		user-supplied opaque data
 */
typedef void (*trie_data_fn_t)(const trie_context_t *ctx, void *udata);

/**
 * Selection callback for general trie traversal.
 *
 * @param path		the string derived from the path root -> node.
 * @param node		the node
 * @param udata		user-supplied opaque data
 */
typedef bool (*trie_match_fn_t)(const trie_context_t *ctx, void *udata);

/**
 * Traversal flags.
 */
#define TRIE_TRAVERSE_LEAVES		(1U << 0)
#define TRIE_TRAVERSE_NON_LEAVES	(1U << 1)
#define TRIE_TRAVERSE_MATCHING		(1U << 2)
#define TRIE_TRAVERSE_NON_MATCHING	(1U << 3)
#define TRIE_CALL_AFTER				(1U << 4)
#define TRIE_CALL_BEFORE			(1U << 5)
#define TRIE_SAFE_DELETE			(1U << 6)
#define TRIE_TRAVERSE_NEED_PATH		(1U << 7)

#define TRIE_TRAVERSE_ALL \
	(TRIE_TRAVERSE_LEAVES | TRIE_TRAVERSE_NON_LEAVES)

/*
 * Public interface
 */

const trie_node_t *trie_node_child(const trie_node_t *tn, int c);
const trie_node_t *trie_node_parent(const trie_node_t *tn);
const trie_node_t *trie_first_child(const trie_node_t *tn);
const trie_node_t *trie_next_sibling(const trie_node_t *tn);
bool trie_node_is_root(const trie_node_t *tn);
bool trie_node_is_leaf(const trie_node_t *tn);
bool trie_node_is_match(const trie_node_t *tn);
bool trie_node_is_shared(const trie_node_t *tn);
bool trie_node_is_collapsed(const trie_node_t *tn);
bool trie_node_has_value(const trie_node_t *tn);
void *trie_node_value(const trie_node_t *tn);
void trie_node_set_value(trie_node_t *tn, void *value);
uint8 trie_node_arc(const trie_node_t *tn);
const char *trie_node_radix(const trie_node_t *tn);
size_t trie_node_child_count(const trie_node_t *tn);
const trie_node_t * const * trie_node_children(
	const trie_node_t *tn, size_t *count);
const trie_node_t *trie_node(const trie_t *t, const char *string);

trie_t *trie_create(void);
bool trie_insert(trie_t *t, const char *string);
bool trie_insert_value(trie_t *t, const char *string, void *value);
bool trie_contains(const trie_t *t, const char *string);
void *trie_lookup(const trie_t *t, const char *key);
bool trie_lookup_extended(trie_t *t, const char *key, void **valptr);
bool trie_remove(trie_t *t, const char *string);
size_t trie_count(const trie_t *t) G_PURE;
size_t trie_node_count(const trie_t *t) G_PURE;
size_t trie_depth(const trie_t *t);
const trie_node_t *trie_root(const trie_t *t);
void trie_clear(trie_t *t);
void trie_free(trie_t *t);
void trie_free_null(trie_t **t_ptr);
void trie_discard_values(trie_t *t);
size_t trie_compact(trie_t *trie);
size_t trie_collapse(trie_t *trie);

size_t trie_foreach(const trie_t *trie, data_fn_t cb, void *data);
size_t trie_foreach_remove(trie_t *trie, data_rm_fn_t cb, void *data);
size_t trie_foreach_value(const trie_t *trie, ckeyval_fn_t cb, void *data);
size_t trie_foreach_value_remove(
	trie_t *trie, ckeyval_rm_fn_t cb, void *data);

size_t trie_traverse(trie_t *trie, uint flags,
	trie_match_fn_t enter, trie_data_fn_t action, void *udata);

#endif	/* _trie_h_ */

/* vi: set ts=4 sw=4 cindent: */
