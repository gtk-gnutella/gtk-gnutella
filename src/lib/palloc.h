/*
 * $Id$
 *
 * Copyright (c) 2005, Raphael Manfredi
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
 * Memory pool, keeping track of malloc()'ed blocks of fixed size and
 * thereby avoiding too frequent malloc()/free()..  This is to be used
 * for large enough blocks, otherwise walloc() or even zalloc() should
 * be preferred.
 *
 * @author Raphael Manfredi
 * @date 2005
 */

#ifndef _palloc_h_
#define _palloc_h_

#include "common.h"

typedef gpointer (*pool_alloc_t)(size_t len);
typedef void (*pool_free_t)(gpointer addr);

/**
 * A memory pool descriptor.
 */
typedef struct pool {
	size_t size;			/**< Size of blocks held in the pool */
	int max;				/**< Maximum amount of blocks to keep around */
	GSList *buffers;		/**< Allocated buffers in the pool */
	int allocated;			/**< Amount of allocated buffers */
	int held;				/**< Amount of available buffers */
	pool_alloc_t alloc;		/**< Memory allocation routine */
	pool_free_t	dealloc;	/**< Memory release routine */
} pool_t;

/*
 * Public interface
 */

pool_t *pool_create(
	size_t size, int max, pool_alloc_t alloc, pool_free_t dealloc);
void pool_free(pool_t *pool);

gpointer palloc(pool_t *pool);
void pfree(pool_t *pool, gpointer obj);

#endif	/* _palloc_h_ */

/* vi: set ts=4: */
