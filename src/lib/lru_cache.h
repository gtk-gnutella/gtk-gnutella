/*
 * Copyright (c) 2023 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * LRU general purpose cache.
 *
 * @author Raphael Manfredi
 * @date 2023
 */

#ifndef _lru_cache_h_
#define _lru_cache_h_

#include "common.h"

typedef struct lru_cache lru_cache_t;

/*
 * Public interface.
 */

lru_cache_t *lru_cache_make(
	size_t maxsize, hash_fn_t hash, eq_fn_t eq, free_keyval_fn_t kvfree);
void lru_cache_thread_safe(lru_cache_t *lc);
void lru_cache_destroy(lru_cache_t **lc_ptr);
void *lru_cache_lookup(lru_cache_t *lc, const void *key);
void lru_cache_insert(lru_cache_t *lc, const void *key, void *object);

#endif /* _lru_cache_h_ */

/* vi: set ts=4 sw=4 cindent: */
