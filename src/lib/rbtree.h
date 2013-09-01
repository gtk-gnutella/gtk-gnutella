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
 * Red-Black Tree, container of arbitrary sortable data items.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _rbtree_h_
#define _rbtree_h_

#include "erbtree.h"		/* For rbnode_t */

struct rbtree;
typedef struct rbtree rbtree_t;

struct rbtree_iter;
typedef struct rbtree_iter rbtree_iter_t;

/**
 * Public interface.
 */

rbtree_t *rbtree_create(cmp_fn_t cmp);
size_t rbtree_count(const rbtree_t *tree);
bool rbtree_contains(const rbtree_t *tree, const void *key);
void *rbtree_lookup(const rbtree_t *tree, const void *key);
bool rbtree_insert_try(rbtree_t *tree, const void *item);
void rbtree_insert(rbtree_t *tree, const void *item);
bool rbtree_replace(rbtree_t *tree, const void *item, void **old_item);
bool rbtree_remove(rbtree_t *tree, const void *key, void **old_item);
void *rbtree_next(const rbtree_t *rbt, const void *key);
void *rbtree_prev(const rbtree_t *rbt, const void *key);
void rbtree_foreach(rbtree_t *tree, data_fn_t cb, void *data);
size_t rbtree_foreach_remove(rbtree_t *tree, data_rm_fn_t cbr, void *data);
void rbtree_clear(rbtree_t *tree);
void rbtree_free_null(rbtree_t **tree_ptr);
void rbtree_discard(rbtree_t *tree, free_fn_t fcb);
void rbtree_discard_with_data(rbtree_t *tree, free_data_fn_t fcb, void *data);

void *rbtree_lookup_node(const rbtree_t *rbt, const void *key, rbnode_t **node);
void *rbtree_next_node(const rbtree_t *rbt, rbnode_t **key);
void *rbtree_prev_node(const rbtree_t *rbt, rbnode_t **key);

rbtree_iter_t *rbtree_iter_new(const rbtree_t *tree);
bool rbtree_iter_next(rbtree_iter_t *iter, const void **keyptr);
void *rbtree_iter_remove(rbtree_iter_t *iter);
void rbtree_iter_release(rbtree_iter_t **iter_ptr);

#endif /* _erbtree_h_ */

/* vi: set ts=4 sw=4 cindent: */
