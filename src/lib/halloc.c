/*
 * $Id$
 *
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
 * Hashtable-tracked allocator. Small chunks are allocated via walloc(),
 * whereas large chunks are served via compat_page_align(). The interface
 * is the same as that of malloc()/free(). The hashtable keeps track of
 * the sizes which should gain a more compact memory layout and is
 * considered more cache-friendly. compat_page_align() may cause an overhead
 * up to (pagesize - 1) per allocation. The advantage is that the pages
 * will be unmapped on hfree().
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include "halloc.h"
#include "misc.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

/*
 * Under REMAP_ZALLOC, do not define walloc(), wfree() and wrealloc().
 */

#ifndef REMAP_ZALLOC

static GHashTable *hallocations;

static inline size_t
halloc_get_size(gpointer p)
{
	gpointer value;

	value = g_hash_table_lookup(hallocations, p);
	g_assert(value);
	return (size_t) value;		
}

/**
 * Allocate memory from a zone suitable for the given size.
 *
 * @return a pointer to the start of the allocated block.
 */
gpointer
halloc(size_t size)
{
	gpointer p;

	g_assert(size > 0);

	if (!hallocations) {
		hallocations = g_hash_table_new(NULL, NULL);
	}
	if (size < compat_pagesize()) {
		p = walloc(size);
	} else {
		p = compat_page_align(size);
	}
	g_hash_table_insert(hallocations, p, (gpointer) size);
	return p;
}

/**
 * Same as halloc(), but fills the allocated memory with zeros before returning.
 */
gpointer
halloc0(size_t size)
{
	gpointer p = halloc(size);
	memset(p, 0, size);
	return p;
}

/**
 * Free a block allocated via halloc().
 */
void
hfree(gpointer p)
{
	if (p) {
		size_t size = halloc_get_size(p);

		if (size < compat_pagesize()) {
			wfree(p, size);
		} else {
			compat_page_free(p, size);
		}
	}
}

/**
 * Reallocate a block allocated via halloc().
 *
 * @return new block address.
 */
gpointer
hrealloc(gpointer old, size_t new_size)
{
	gpointer p;

	p = halloc(new_size);
	if (old) {
		size_t old_size = halloc_get_size(old);

		memcpy(p, old, MIN(new_size, old_size));
		hfree(old);
	}
	return p;
}

/**
 * Copy a memory block via halloc().
 *
 * @return new block address.
 */
gpointer
hmemdup(gconstpointer data, size_t size)
{
	gpointer p;
   
	g_assert(data);

	p = halloc(size);
	memcpy(p, data, size);
	return p;
}

/**
 * Copy a string via halloc().
 *
 * @return new block address.
 */
gpointer
hstrdup(const gchar *s)
{
	g_assert(s);
	return hmemdup(s, 1 + strlen(s));
}
#endif	/* !REMAP_ZALLOC */

static void
hdestroy_item(gpointer key, gpointer value, gpointer unused_udata)
{
	(void) unused_udata;
	g_assert(value);
	hfree(key);
}

/**
 * Destroy all the zones we allocated so far.
 */
void
hdestroy(void)
{
	g_hash_table_foreach(hallocations, hdestroy_item, NULL);
}

/* vi: set ts=4 sw=4 cindent: */
