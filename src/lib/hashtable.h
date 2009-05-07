/*
 * $Id$
 *
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006, Christian Biere
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
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006
 */

#ifndef _hash_table_h_
#define _hash_table_h_

#include "common.h"

typedef struct hash_table hash_table_t;

typedef void (*hash_table_foreach_func)(
	const void *key, void *value, void *data);
typedef size_t (*hash_table_hash_func)(const void *key);
typedef gboolean (*hash_table_eq_func)(const void *a, const void *b);

hash_table_t *hash_table_new(void);
hash_table_t *hash_table_new_full(
	hash_table_hash_func hash, hash_table_eq_func eq);
void hash_table_destroy(hash_table_t *ht);

#ifdef MALLOC_SOURCE
/* These routines are reserved for the tracking malloc code */
hash_table_t *hash_table_new_real(void);
hash_table_t *hash_table_new_full_real(
	hash_table_hash_func hash, hash_table_eq_func eq);
void hash_table_destroy_real(hash_table_t *ht);
#endif /* MALLOC_SOURCE */

size_t hash_table_size(const hash_table_t *ht);
gboolean hash_table_insert(hash_table_t *ht,
	const void *key, const void *value);
void hash_table_replace(hash_table_t *ht, const void *key, const void *value);
void *hash_table_lookup(const hash_table_t *ht, const void *key);
gboolean hash_table_lookup_extended(const hash_table_t *ht,
	const void *key, const void **kp, void **vp);
gboolean hash_table_remove(hash_table_t *ht, const void *key);
void hash_table_foreach(hash_table_t *ht, hash_table_foreach_func func,
		void *data);

#endif /* _hash_table_h_ */
/* vi: set ts=4 sw=4 cindent: */
