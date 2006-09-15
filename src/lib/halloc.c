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

#include <assert.h>

#include "halloc.h"
#include "hashtable.h"
#include "misc.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

/*
 * Under REMAP_ZALLOC, do not define walloc(), wfree() and wrealloc().
 */

#ifndef REMAP_ZALLOC

static hash_table_t *hallocations;

static inline size_t
halloc_get_size(void *p)
{
	void *value;

	value = hash_table_lookup(hallocations, p);
	assert(value);
	return (size_t) value;		
}

/**
 * Allocate memory from a zone suitable for the given size.
 *
 * @return a pointer to the start of the allocated block.
 */
void *
halloc(size_t size)
{
	void *p;

	assert(size > 0);

	if (!hallocations)
		hallocations = hash_table_new();

	p = (size < compat_pagesize()) ? walloc(size) : alloc_pages(size);
	hash_table_insert(hallocations, p, (void *) size);

	return p;
}

/**
 * Same as halloc(), but fills the allocated memory with zeros before returning.
 */
void *
halloc0(size_t size)
{
	void *p = halloc(size);

	memset(p, 0, size);
	return p;
}

/**
 * Free a block allocated via halloc().
 */
void
hfree(void *p)
{
	size_t size;

	if (NULL == p)
		return;

	size = halloc_get_size(p);
	hash_table_remove(hallocations, p);
	if (size < compat_pagesize()) {
		wfree(p, size);
	} else {
		free_pages(p, size);
	}
}

/**
 * Reallocate a block allocated via halloc().
 *
 * @return new block address.
 */
void *
hrealloc(void *old, size_t new_size)
{
	void *p;

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
void *
hmemdup(const void *data, size_t size)
{
	void *p;
   
	assert(data);

	p = halloc(size);
	memcpy(p, data, size);
	return p;
}

/**
 * Copy a string via halloc().
 *
 * @return new block address.
 */
void *
hstrdup(const char *s)
{
	assert(s);
	return hmemdup(s, 1 + strlen(s));
}
#endif	/* !REMAP_ZALLOC */

static void
hdestroy_item(void *key, void *value, void *unused_udata)
{
	(void) unused_udata;
	assert(value);
	hfree(key);
}

/**
 * Destroy all the zones we allocated so far.
 */
void
hdestroy(void)
{
	if (hallocations) {
		hash_table_foreach(hallocations, hdestroy_item, NULL);
		hash_table_destroy(hallocations);
		hallocations = NULL;
	}
}

void
halloc_init(void)
{
#if GLIB_CHECK_VERSION(2, 0, 0)
	static GMemVTable vtable;

	vtable.malloc = halloc;
	vtable.realloc = hrealloc;
	vtable.free = hfree;

	g_mem_set_vtable(&vtable);
#endif	/* GLib >= 2.0 */
}

/* vi: set ts=4 sw=4 cindent: */
