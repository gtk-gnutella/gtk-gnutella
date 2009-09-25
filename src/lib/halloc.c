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
#include "concat.h"
#include "misc.h"
#include "malloc.h"
#include "walloc.h"
#include "unsigned.h"
#include "vmm.h"

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

		/* round_pagesize() is unsafe and wraps! */
		allocated = round_pagesize(size);
		RUNTIME_ASSERT(allocated >= size);

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

	if (old_size >= page_threshold) {
		if (vmm_is_fragment(old, old_size))
			goto relocate;
	} else {
		if (new_size < page_threshold) {
			union align *old_head = old;
			union align *new_head;
			size_t old_allocated = old_size + sizeof old_head[0];
			size_t new_allocated = new_size + sizeof new_head[0];

			old_head--;
			new_head = wrealloc(old_head, old_allocated, new_allocated);
			new_head->size = new_size;
			bytes_allocated += new_allocated - old_allocated;
			return &new_head[1];
		}
	}

	if (new_size >= page_threshold && round_pagesize(new_size) == old_size)
		return old;

	if (old_size >= new_size && old_size / 2 < new_size)
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

static inline void
halloc_init_vtable(void)
{
}

#endif	/* USE_HALLOC */

#if !defined(REMAP_ZALLOC) && !defined(TRACK_MALLOC)
static gboolean replacing_malloc;

void
halloc_init(gboolean replace_malloc)
{
	static int initialized;

	RUNTIME_ASSERT(!initialized);
	initialized = TRUE;
	replacing_malloc = replace_malloc;

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

/**
 * Did they request that halloc() be a malloc() replacement?
 */
gboolean
halloc_replaces_malloc(void)
{
	return replacing_malloc;
}
#else	/* REMAP_ZALLOC || TRACK_MALLOC */

void
halloc_init(gboolean unused_replace_malloc)
{
	(void) unused_replace_malloc;

	/* EMPTY */
}

gboolean
halloc_replaces_malloc(void)
{
	return FALSE;
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

#ifndef TRACK_MALLOC
/**
 * A clone of strdup() using halloc().
 * The resulting string must be freed via hfree().
 *
 * @param str		the string to duplicate (can be NULL)
 *
 * @return a pointer to the new string.
 */
char *
h_strdup(const char *str)
{
	return str ? hcopy(str, 1 + strlen(str)) : NULL;
}

/**
 * A clone of strndup() using halloc().
 * The resulting string must be freed via hfree().
 *
 * @param str		the string to duplicate a part of (can be NULL)
 * @param n			the maximum number of characters to copy from string
 *
 * @return a pointer to the new string.
 */
char *
h_strndup(const char *str, size_t n)
{
	if (str != NULL) {
		size_t len = clamp_strlen(str, n);
		char *result = halloc(len + 1);
		
		/* Not hcopy() because we shouldn't even read the nth byte of src. */
		memcpy(result, str, len);
		result[len] = '\0';

		return result;
	} else {
		return NULL;
	}
}

/**
 * A clone of g_strjoinv() which uses halloc().
 * The resulting string must be freed via hfree().
 *
 * Joins a number of strings together to form one long string, with the
 * optional separator inserted between each of them.
 *
 * @param separator		string to insert between each strings, or NULL
 * @param str_array		a NULL-terminated array of strings to join
 *
 * @return a newly allocated string joining all the strings from the array,
 * with the separator between them.
 */
char *
h_strjoinv(const char *separator, char **str_array)
{
	const char *sep = separator;
	char *result;

	g_assert(str_array != NULL);

	if (NULL == sep)
		sep = "";

	if (str_array[0] != NULL) {
		size_t seplen = strlen(sep);
		size_t i, len, pos;

		len = size_saturate_add(1, strlen(str_array[0]));
		for (i = 1; str_array[i] != NULL; i++) {
			len = size_saturate_add(len, seplen);
			len = size_saturate_add(len, strlen(str_array[i]));
		}

		g_assert(len < SIZE_MAX);

		result = halloc(len);
		pos = strcpy_len(result, str_array[0]);

		/* We can freely add to pos, we know it cannot saturate now */

		for (i = 1; str_array[i] != NULL; i++) {
			pos += strcpy_len(&result[pos], sep);
			pos += strcpy_len(&result[pos], str_array[i]);
		}

		g_assert(pos + 1 == len);
	} else {
		result = h_strdup("");
	}

	return result;
}

/**
 * A clone of g_strfreev().
 *
 * Frees (via hfree()) a NULL-terminated array of strings, and the array itself.
 * If called on a NULL value, does nothing.
 */
void
h_strfreev(char **str_array)
{
	if (str_array != NULL) {
		size_t i;

		for (i = 0; str_array[i] != NULL; i++) {
			hfree(str_array[i]);
		}

		hfree(str_array);
	}
}

/**
 * A clone of g_strconcat() using halloc().
 * The resulting string must be freed via hfree().
 *
 * Concatenates all of the given strings into one long string.
 *
 * @attention
 * The argument list must end with (void *) 0.
 */
char *
h_strconcat(const char *first, ...)
{
	va_list ap;
	size_t len, ret;
	char *dst;

	va_start(ap, first);
	len = concat_strings_v(NULL, 0, first, ap);
	va_end(ap);

	dst = halloc(len + 1);
	va_start(ap, first);
	ret = concat_strings_v(dst, len + 1, first, ap);
	va_end(ap);
	g_assert(ret == len);

	return dst;
}

/**
 * Calculate the size of the buffer required to hold the string
 * resulting from vnsprintf().
 * 
 * @param format The printf format string.
 * @param ap The argument list.
 *
 * @return The size of the buffer required to hold the resulting
 *         string including the terminating NUL.
 */
static size_t
vprintf_get_size(const char *format, va_list ap)
{
	char *buf;
	size_t size;
	int ret;

	/**
	 * NOTE: ISO C99 ensures that vsnprintf(NULL, 0, ...) calculates the size
	 * of the required buffer but older vsnprintf() return an unspecified value
	 * less than 1 (one) if size is zero. That could be zero which is also
	 * returned for an empty string, so don't try that. Older vsnprintf()
	 * may silently truncate the string if the buffer is insufficient but
	 * don't return the required size.
	 */

	size = 1024;
	buf = walloc(size);

	for (;;) {
		va_list ap2;
		size_t old_size;

		VA_COPY(ap2, ap);
		ret = vsnprintf(buf, size, format, ap2);
		va_end(ap2);

		if (ret < 0) {
			/* Keep trying */
		} else if (UNSIGNED(ret) > size) {
			/* Assume conforming C99 vsnprintf() */
			break;
		} else if (size - ret > 1) {
			/* Only trust this if there's more than 1 byte left. */
			break;
		}

		/* Since vsnprintf() returns an int, INT_MAX is the limit */
		g_assert(size < UNSIGNED(INT_MAX));

		old_size = size;
		size = size_saturate_mult(size, 2);

		buf = wrealloc(buf, old_size, size);
	}

	WFREE_NULL(buf, size);
	return ret < 0 ? (size_t)-1 : size_saturate_add(ret, 1);
}

/**
 * A clone of g_strdup_vprintf() using halloc().
 * The resulting string must be freed by hfree().
 */
static char *
h_strdup_vprintf(const char *format, va_list ap)
{
	va_list ap2;
	char *buf;
	size_t size;
	int ret;

	VA_COPY(ap2, ap);
	size = vprintf_get_size(format, ap2);
	va_end(ap2);

	buf = halloc(size);
	ret = vsnprintf(buf, size, format, ap);
	va_end(ap);

	g_assert(UNSIGNED(ret) == size - 1);

	return buf;
}

/**
 * A clone of g_strdup_printf(), using halloc().
 * The resulting string must be freed by hfree().
 */
char *
h_strdup_printf(const char *format, ...)
{
	char *buf;
	va_list args;

	va_start(args, format);
	buf = h_strdup_vprintf(format, args);
	va_end(args);

	return buf;
}
#endif /* !TRACK_MALLOC */

/* vi: set ts=4 sw=4 cindent: */
