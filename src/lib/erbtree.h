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
 * Embedded red-black tree (within another data structure).
 *
 * @author Franck Bui-Huu <fbuihuu@gmail.com>
 * @date 2010
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _erbtree_h_
#define _erbtree_h_

/**
 * These definitions have been stolen from the Linux kernel.
 *
 * Given a pointer to ``node'', an expanded structure in ``type'' declared
 * as ``field'', computes the starting address of the enclosing type.
 *
 * In other words, if x is a variable of type ``type'', compute &x
 * given &x.field, knowing this is the address of the field named ``field''.
 *
 * @param node	the address of ``field'' within ``type''
 * @param type	the type of the containing structure containing ``field''
 * @param field	the name of the field within ``type'' whose address is ``node''
 *
 * @return the starting address of the container for the node, aka the key.
 */
#ifdef __GNUC__
#define erbtree_key(node, type, field) G_GNUC_EXTENSION({	\
	const struct rbnode *__mptr = (node);					\
	(type *)((char *) __mptr - offsetof(type, field));})
#else
#define erbtree_key(node, type, field)						\
	((type *)((char *) (node) - offsetof(type, field)))
#endif

/**
 * A node in a red-black tree.
 */
typedef struct rbnode {
	struct rbnode *left, *right, *parent;
} G_GNUC_ALIGNED(4) rbnode_t;

enum erbtree_magic {
	ERBTREE_MAGIC		= 0x6483afd6,		/* bit 0 clear */
	ERBTREE_EXT_MAGIC	= 0x6483afd7		/* bit 0 set */
};

#define ERBTREE_COMMON_ATTRIBUTES \
	enum erbtree_magic magic; \
	rbnode_t *root, *first, *last; \
	union { \
		cmp_fn_t cmp;		/* Item comparison routine */ \
		cmp_data_fn_t dcmp;	/* Item comparison routine with data */ \
	} u; \
	size_t offset;		/* Offset of embedded node in the item structure */ \
	size_t count;		/* Amount of items held in tree */

/**
 * An embedded red-black tree is represented by this structure.
 */
typedef struct erbtree {
	ERBTREE_COMMON_ATTRIBUTES
} erbtree_t;

/**
 * An extended embedded red-black tree is represented by this structure.
 */
typedef struct erbtree_ext {
	ERBTREE_COMMON_ATTRIBUTES
	void *data;			/* Additional data for comparison routine */
} erbtree_ext_t;

static inline void
erbtree_check(const erbtree_t * const t)
{
	g_assert(t != NULL);
	g_assert(ERBTREE_MAGIC == (t->magic & ~0x1));	/* bit 0 is a flag */
}

/**
 * Public interface.
 */

void erbtree_init(erbtree_t *tree, cmp_fn_t cmp, size_t offset);
void erbtree_init_data(erbtree_ext_t *tree,
	cmp_data_fn_t cmp, void *data, size_t offset);
void erbtree_clear(erbtree_t *tree);

size_t erbtree_count(const erbtree_t *tree);
rbnode_t *erbtree_next(const rbnode_t *node);
rbnode_t *erbtree_prev(const rbnode_t *node);
bool erbtree_contains(const erbtree_t *tree, const void *key);
void *erbtree_lookup(const erbtree_t *tree, const void *key);
rbnode_t *erbtree_getnode(const erbtree_t *tree, const void *key);
void *erbtree_insert(erbtree_t *tree, rbnode_t *node);
void erbtree_remove(erbtree_t *tree, rbnode_t *node);
void erbtree_replace(erbtree_t *tree, rbnode_t *old, rbnode_t *new);
void erbtree_foreach(const erbtree_t *tree, data_fn_t cb, void *data);
size_t erbtree_foreach_remove(erbtree_t *tree, data_rm_fn_t cbr, void *data);
void erbtree_discard(erbtree_t *tree, free_fn_t fcb);
void erbtree_discard_with_data(erbtree_t *tree, free_data_fn_t fcb, void *data);

/**
 * Computes the data item address given the embedded node pointer.
 */
static inline void *
erbtree_data(const erbtree_t *t, rbnode_t *node)
{
	erbtree_check(t);
	return NULL == node ? NULL : ptr_add_offset(node, -t->offset);
}

/**
 * @return pointer to the first item of the tree, NULL if empty.
 */
static inline void *
erbtree_head(const erbtree_t * const t)
{
	erbtree_check(t);
	return NULL == t->first ? NULL : ptr_add_offset(t->first, -t->offset);
}

/**
 * @return pointer to the last item of the tree, NULL if empty.
 */
static inline void *
erbtree_tail(const erbtree_t * const t)
{
	erbtree_check(t);
	return NULL == t->last ? NULL : ptr_add_offset(t->last, -t->offset);
}

/**
 * Get first (smallest) item in the tree.
 */
static inline rbnode_t *
erbtree_first(const erbtree_t * const t)
{
	erbtree_check(t);
	return t->first;
}

/**
 * Get last (bigest) item in the tree.
 */
static inline rbnode_t *
erbtree_last(const erbtree_t * const t)
{
	erbtree_check(t);
	return t->last;
}

#define ERBTREE_FOREACH(tree, rn) \
	for ((rn) = erbtree_first(tree); (rn) != NULL; (rn) = erbtree_next(rn))

#endif /* _erbtree_h_ */

/* vi: set ts=4 sw=4 cindent: */
