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
#define erbtree_key(node, type, field) ({				\
	const struct rbnode *__mptr = (node);				\
	(type *)((char *) __mptr - offsetof(type, field));})
#else
#define erbtree_key(node, type, field)					\
	((type *)((char *) (node) - offsetof(type, field)))
#endif

/**
 * A node in a red-black tree.
 */
typedef struct rbnode {
	struct rbnode *left, *right, *parent;
} G_GNUC_ALIGNED(4) rbnode_t;

/**
 * Comparison routine for items in the red-black tree.
 *
 * Assuming items in the tree are defined as:
 *
 *     struct item {
 *         int key;
 *         <other fields>
 *         rbnode_t node;
 *     };
 *
 * Then a comparison function can be written as:
 *
 *     int item_cmp(const void *a, const void *b)
 *     {
 *         const struct item *p = a;
 *         const struct item *q = b;
 *
 *         return p->key - q->key;
 *     }
 *
 * Note that the comparison routine takes pointers to the structures containing
 * the nodes, not the nodes themselves.
 */
typedef int (*erbtree_cmp_t)(const void *, const void *);

typedef void (*erbtree_cb_t)(void *key, void *data);
typedef bool (*erbtree_cbr_t)(void *key, void *data);

enum erbtree_magic { ERBTREE_MAGIC = 0x6483afd6 };

/**
 * An embedded red-black tree is represented by this structure.
 */
typedef struct erbtree {
	enum erbtree_magic magic;
	rbnode_t *root, *first, *last;
	erbtree_cmp_t cmp;	/* Item comparison routine */
	size_t offset;		/* Offset of embedded node in the item structure */
	size_t count;		/* Amount of items held in tree */
} erbtree_t;

/**
 * Public interface.
 */

void erbtree_init(erbtree_t *tree, erbtree_cmp_t cmp, size_t offset);

size_t erbtree_count(const erbtree_t *tree);
rbnode_t *erbtree_first(const erbtree_t *tree);
rbnode_t *erbtree_last(const erbtree_t *tree);
rbnode_t *erbtree_next(const rbnode_t *node);
rbnode_t *erbtree_prev(const rbnode_t *node);
bool erbtree_contains(const erbtree_t *tree, const void *key);
void *erbtree_lookup(const erbtree_t *tree, const void *key);
rbnode_t *erbtree_getnode(const erbtree_t *tree, const void *key);
void *erbtree_insert(erbtree_t *tree, rbnode_t *node);
void erbtree_remove(erbtree_t *tree, rbnode_t *node);
void erbtree_replace(erbtree_t *tree, rbnode_t *old, rbnode_t *new);
void erbtree_foreach(erbtree_t *tree, erbtree_cb_t cb, void *data);
size_t erbtree_foreach_remove(erbtree_t *tree, erbtree_cbr_t cbr, void *data);

#endif /* _erbtree_h_ */

/* vi: set ts=4 sw=4 cindent: */
