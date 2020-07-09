/*
 * Copyright (c) 2004, 2013 Raphael Manfredi
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
 * A FIFO.
 *
 * As of 2013-11-09, a FIFO is simply a facade of slist_t.
 *
 * @author Raphael Manfredi
 * @date 2004, 2013
 */

#ifndef _fifo_h_
#define _fifo_h_

#include "slist.h"

typedef slist_t fifo_t;

/**
 * Create new FIFO.
 */
static inline fifo_t *
fifo_make(void)
{
	return slist_new();
}

/**
 * Destroy FIFO.
 */
static inline void
fifo_free(fifo_t *f)
{
	slist_free(&f);
}

/**
 * Destroy FIFO, invoking freeing callback on all items still held.
 *
 * @param f		the FIFO to free
 * @param cb	the freeing callback to invoke on all items
 * @param udata	the extra user data passed as-is to the freeing callback
 */
static inline void
fifo_free_all(fifo_t *f, free_data_fn_t cb, void *udata)
{
	slist_foreach(f, cb, udata);
	slist_free(&f);
}

/**
 * Destroy FIFO, invoking freeing callback on all items, then nullify pointer.
 */
static inline void
fifo_free_all_null(fifo_t **f_ptr, free_data_fn_t cb, void *udata)
{
	fifo_t *f = *f_ptr;

	if (f != NULL) {
		slist_foreach(f, cb, udata);
		slist_free(f_ptr);
	}
}

/**
 * @return the amount of items queued in FIFO.
 */
static inline uint
fifo_count(const fifo_t *f)
{
	return slist_length(f);
}

/**
 * Add entry to FIFO.
 */
static inline void
fifo_put(fifo_t *f, const void *data)
{
	slist_append(f, deconstify_pointer(data));
}

/**
 * Remove entry from FIFO.
 *
 * @return the oldest item still held in FIFO, NULL if no item remains.
 */
static inline void *
fifo_remove(fifo_t *f)
{
	return slist_shift(f);
}

#endif /* _fifo_h_ */

/* vi: set ts=4 sw=4 cindent: */
