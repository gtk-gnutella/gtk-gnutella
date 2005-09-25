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

#include <glib.h>

/**
 * A memory pool descriptor.
 */
typedef struct pool {
	size_t size;			/**< Size of blocks held in the pool */
	gint max;				/**< Maximum amount of blocks to keep around */
	GSList *buffers;		/**< Allocated buffers in the pool */
	gint allocated;			/**< Amount of allocated buffers */
	gint held;				/**< Amount of available buffers */
} pool_t;

/*
 * Public interface
 */

pool_t *pool_create(size_t size, gint max);
void pool_free(pool_t *pool);

gpointer palloc(pool_t *pool);
void pfree(pool_t *pool, gpointer obj);

#endif	/* _palloc_h_ */

/* vi: set ts=4: */
