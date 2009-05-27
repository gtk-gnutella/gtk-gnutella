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
 * whereas large chunks are served via vmm_alloc(). The interface
 * is the same as that of malloc()/free(). The hashtable keeps track of
 * the sizes which should gain a more compact memory layout and is
 * considered more cache-friendly. vmm_alloc() may cause an overhead
 * up to (pagesize - 1) per allocation. The advantage is that the pages
 * will be unmapped on hfree().
 *
 * Define USE_HALLOC to use this instead of the default memory allocation
 * functions used.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include "halloc.h"
#include "hashtable.h"
#include "pagetable.h"
#include "misc.h"
#include "malloc.h"
#include "walloc.h"

#include "glib-missing.h"
#include "override.h"		/* Must be the last header included */

/*
 * Under REMAP_ZALLOC or TRACK_MALLOC, do not define halloc(), hfree(), etc...
 */

#if defined(USE_HALLOC)
#if defined(REMAP_ZALLOC) || defined(TRACK_MALLOC) || defined(MALLOC_STATS)
#undef USE_HALLOC
#endif	/* REMAP_ZALLOC || TRACK_MALLOC */
#endif	/* USE_HALLOC */

static size_t bytes_allocated;	/* Amount of bytes allocated */
static size_t chunks_allocated;	/* Amount of chunks allocated */

#if !defined(REMAP_ZALLOC) && !defined(TRACK_MALLOC)

static int use_page_table;
static page_table_t *pt_pages;
static hash_table_t *ht_pages;
size_t page_threshold;

union align {
  size_t	size;
  char		bytes[MEM_ALIGNBYTES];
};

static inline size_t
page_lookup(void *p)
{
	if (use_page_table) {
		return page_table_lookup(pt_pages, p);
	} else {
		return (size_t) hash_table_lookup(ht_pages, p);
	}
}

static inline int
page_insert(void *p, size_t size)
{
	if (use_page_table) {
		return page_table_insert(pt_pages, p, size);
	} else {
		return hash_table_insert(ht_pages, p, (void *) size);
	}
}

static inline int
page_remove(void *p)
{
	if (use_page_table) {
		return page_table_remove(pt_pages, p);
	} else {
		return hash_table_remove(ht_pages, p);
	}
}

static void
hdestroy_page_table_item(void *key, size_t size, void *unused_udata)
{
	(void) unused_udata;
	RUNTIME_ASSERT(size > 0);
	hfree(key);
}

static void
hdestroy_hash_table_item(const void *key, void *value, void *unused_udata)
{
	(void) unused_udata;
	RUNTIME_ASSERT((size_t) value > 0);
	hfree(deconstify_gpointer(key));
}

static inline void
page_destroy(void)
{
	if (use_page_table) {
		page_table_foreach(pt_pages, hdestroy_page_table_item, NULL);
		page_table_destroy(pt_pages);
		pt_pages = NULL;
	} else {
		hash_table_foreach(ht_pages, hdestroy_hash_table_item, NULL);
		hash_table_destroy(ht_pages);
		ht_pages = NULL;
	}
}

static inline size_t
halloc_get_size(void *p)
{
	size_t size;

	size = page_lookup(p);
	if (size) {
		RUNTIME_ASSERT(size >= page_threshold);
	} else {
		union align *head = p;

		head--;
		RUNTIME_ASSERT(head->size > 0);
		RUNTIME_ASSERT(head->size < page_threshold);
		size = head->size;
	}
	return size;
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
	size_t allocated;

	if (0 == size)
		return NULL;

	if (size < page_threshold) {
		union align *head;

		allocated = size + sizeof head[0];
		head = walloc(allocated);
		head->size = size;
		p = &head[1];
	} else {
		int inserted;

		allocated = round_pagesize(size);
		p = vmm_alloc(allocated);
		inserted = page_insert(p, allocated);
		RUNTIME_ASSERT(inserted);
	}
	bytes_allocated += allocated;
	chunks_allocated++;
	return p;
}

/**
 * Same as halloc(), but fills the allocated memory with zeros before returning.
 */
void *
halloc0(size_t size)
{
	void *p = halloc(size);
	if (p) {
		memset(p, 0, size);
	}
	return p;
}

/**
 * Free a block allocated via halloc().
 */
void
hfree(void *p)
{
	size_t size;
	size_t allocated;

	if (NULL == p)
		return;

	size = halloc_get_size(p);
	RUNTIME_ASSERT(size > 0);

	if (size < page_threshold) {
		union align *head = p;

		head--;
		allocated = size + sizeof(union align);
		wfree(head, allocated);
	} else {
		allocated = size;
		page_remove(p);
		vmm_free(p, size);
	}
	bytes_allocated -= allocated;
	chunks_allocated--;
}

/**
 * Reallocate a block allocated via halloc().
 *
 * @return new block address.
 */
void *
hrealloc(void *old, size_t new_size)
{
	size_t old_size;
	void *p;

	if (NULL == old)
		return halloc(new_size);

	if (0 == new_size) {
		hfree(old);
		return NULL;
	}

	old_size = halloc_get_size(old);
	RUNTIME_ASSERT(size_is_positive(old_size));

	/*
	 * This is our chance to move a virtual memory fragment out of the way.
	 */

	if (old_size >= page_threshold && vmm_is_fragment(old, old_size))
		goto relocate;

	if (old_size >= new_size && old_size / 2 < new_size)
		return old;

	if (new_size >= page_threshold && round_pagesize(new_size) == old_size)
		return old;

relocate:
	p = halloc(new_size);
	RUNTIME_ASSERT(NULL != p);

	memcpy(p, old, MIN(new_size, old_size));
	hfree(old);

	return p;
}

/**
 * Destroy all the zones we allocated so far.
 */
void
hdestroy(void)
{
	page_destroy();
}

#else	/* REMAP_ZALLOC || TRACK_MALLOC */

void
hdestroy(void)
{
	/* EMPTY */
}

#endif	/* !REMAP_ZALLOC && !TRACK_MALLOC */

#ifdef USE_HALLOC

gpointer
gm_malloc(gsize size)
{
	return halloc(size);
}

gpointer
gm_realloc(gpointer p, gsize size)
{
	return hrealloc(p, size);
}

void
gm_free(gpointer p)
{
	hfree(p);
}

static void
halloc_glib12_check(void)
{
#if !GLIB_CHECK_VERSION(2,0,0)
	gpointer p;

	/*
	 * Check whether the remapping is effective. This may not be
	 * the case for our GLib 1.2 hack. This is required for Darwin,
	 * for example.
	 */
	p = g_strdup("");
	if (0 == halloc_get_size(p)) {
		static GMemVTable zero_vtable;
		fprintf(stderr, "WARNING: Resetting g_mem_set_vtable\n");
		g_mem_set_vtable(&zero_vtable);
	} else {
		G_FREE_NULL(p);
	}
#endif	/* GLib < 2.0.0 */
}

static void
halloc_init_vtable(void)
{
	static GMemVTable vtable;

#if GLIB_CHECK_VERSION(2,0,0)
	{
		/* NOTE: This string is not read-only because it will be overwritten
		 *		 by gm_setproctitle() as it becomes part of the environment.
		 *	     This happens at least on some Linux systems.
		 */
		static char variable[] = "G_SLICE=always-malloc";
		putenv(variable);
	}
	
	vtable.malloc = gm_malloc;
	vtable.realloc = gm_realloc;
	vtable.free = gm_free;
#else	/* GLib < 2.0.0 */
	vtable.gmvt_malloc = gm_malloc;
	vtable.gmvt_realloc = gm_realloc;
	vtable.gmvt_free = gm_free;
#endif	/* GLib >= 2.0.0 */

	g_mem_set_vtable(&vtable);

	halloc_glib12_check();
}

#else	/* !USE_HALLOC */

static void
halloc_init_vtable(void)
{
}

#endif	/* USE_HALLOC */

#if !defined(REMAP_ZALLOC) && !defined(TRACK_MALLOC)

void
halloc_init(gboolean replace_malloc)
{
	static int initialized;

	RUNTIME_ASSERT(!initialized);
	initialized = TRUE;

	use_page_table = (size_t)-1 == (guint32)-1 && compat_pagesize() == 4096;
	page_threshold = compat_pagesize() - sizeof(union align);

	if (use_page_table) {
		pt_pages = page_table_new();
	} else {
		ht_pages = hash_table_new();
	}

	if (replace_malloc)
		halloc_init_vtable();
}
#else	/* REMAP_ZALLOC || TRACK_MALLOC */

void
halloc_init(gboolean unused_replace_malloc)
{
	(void) unused_replace_malloc;

	/* EMPTY */
}

#endif	/* !REMAP_ZALLOC && !TRACK_MALLOC */

size_t
halloc_bytes_allocated(void)
{
	return bytes_allocated;
}

size_t
halloc_chunks_allocated(void)
{
	return chunks_allocated;
}

/* vi: set ts=4 sw=4 cindent: */
