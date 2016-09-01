/*
 * Copyright (c) 2016 Raphael Manfredi
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
 * List cell allocator interface for plist and pslist.
 *
 * @author Raphael Manfredi
 * @date 2016
 */

#ifndef _pcell_h_
#define _pcell_h_

/**
 * The optional cell allocator contains generic function pointers to allocate
 * or free a cell for a list.
 *
 * There is no size information: the routines to call must be specific for
 * each list.
 *
 * A pointer to that structure must be passed to *_ext() routines so that
 * the proper cell allocators / de-allocators be used, consistently.
 */
typedef struct pcell_allocator {
	void *(*pcell_alloc)(void);		/**< Return new zeroed cell for the list */
	void (*pcell_free)(void *);		/**< Dispose of cell */
} pcell_alloc_t;

#endif	/* _pcell_h_ */

/* vi: set ts=4 sw=4 cindent: */
