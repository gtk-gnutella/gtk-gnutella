/*
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

#include "halloc.h"

#include "atomic.h"
#include "concat.h"
#include "dump_options.h"
#include "glib-missing.h"
#include "hashtable.h"
#include "malloc.h"
#include "mempcpy.h"
#include "misc.h"
#include "once.h"
#include "pagetable.h"
#include "spinlock.h"
#include "stringify.h"
#include "thread.h"
#include "unsigned.h"
#include "vmm.h"
#include "walloc.h"
#include "zalloc.h"			/* For zalloc_shift_pointer() */

#include "override.h"		/* Must be the last header included */

/*
 * Under REMAP_ZALLOC or TRACK_MALLOC, do not define halloc(), hfree(), etc...
 */

#if defined(USE_HALLOC)
#if defined(REMAP_ZALLOC) || defined(TRACK_MALLOC) || defined(MALLOC_STATS)
#undef USE_HALLOC
#endif	/* REMAP_ZALLOC || TRACK_MALLOC */
#endif	/* USE_HALLOC */

/**
 * Internal statistics collected.
 */
static struct hstats {
	uint64 allocations;					/**< Total # of allocations */
	AU64(allocations_zeroed);			/**< Total # of zeroed allocations */
	uint64 alloc_via_walloc;			/**< Allocations from walloc() */
	uint64 alloc_via_vmm;				/**< Allocations from VMM */
	uint64 freeings;					/**< Total # of freeings */
	AU64(reallocs);						/**< Total # of reallocs */
	AU64(realloc_noop);					/**< Nothing to do */
	uint64 realloc_via_wrealloc;		/**< Reallocs handled by wrealloc() */
	AU64(realloc_via_vmm);				/**< Reallocs handled by VMM */
	uint64 realloc_via_vmm_shrink;		/**< Shrunk VMM region */
	AU64(realloc_noop_same_vmm);		/**< Same VMM size */
	AU64(realloc_relocatable);			/**< Forced relocation for VMM */
	uint64 wasted_cumulative;			/**< Cumulated allocation waste */
	uint64 wasted_cumulative_walloc;	/**< Cumulated waste for walloc */
	uint64 wasted_cumulative_vmm;		/**< Cumulated waste for VMM allocs */
	size_t memory;						/**< Amount of bytes allocated */
	size_t blocks;						/**< Amount of blocks allocated */
	/* Counter to prevent digest from being the same twice in a row */
	AU64(halloc_stats_digest);
} hstats;
static spinlock_t hstats_slk = SPINLOCK_INIT;

#define HSTATS_LOCK			spinlock_hidden(&hstats_slk)
#define HSTATS_UNLOCK		spinunlock_hidden(&hstats_slk)

#define HSTATS_INCX(x)		AU64_INC(&hstats.x)

enum halloc_type {
	HALLOC_WALLOC,
	HALLOC_VMM
};

#if !defined(REMAP_ZALLOC) && !defined(TRACK_MALLOC)

static int use_page_table;
static page_table_t *pt_pages;
static hash_table_t *ht_pages;
static size_t walloc_threshold;		/* walloc() size upper limit */
static size_t halloc_pagesize;

union align {
  size_t	size;
  char		bytes[MEM_ALIGNBYTES];
};

static spinlock_t hpage_slk = SPINLOCK_INIT;

#define HPAGE_LOCK			spinlock(&hpage_slk)
#define HPAGE_UNLOCK		spinunlock(&hpage_slk)

static inline size_t
page_lookup(const void *p)
{
	size_t result;

	HPAGE_LOCK;
	if (use_page_table) {
		result = page_table_lookup(pt_pages, p);
	} else {
		result = (size_t) hash_table_lookup(ht_pages, p);
	}
	HPAGE_UNLOCK;

	return result;
}

static inline int
page_insert(const void *p, size_t size)
{
	int result;

	g_assert(size != 0);

	HPAGE_LOCK;
	if (use_page_table) {
		result = page_table_insert(pt_pages, p, size);
	} else {
		result = hash_table_insert(ht_pages, p, size_to_pointer(size));
	}
	HPAGE_UNLOCK;

	return result;
}

static inline void
page_replace(const void *p, size_t size)
{
	g_assert(size != 0);

	HPAGE_LOCK;
	if (use_page_table) {
		page_table_replace(pt_pages, p, size);
	} else {
		hash_table_replace(ht_pages, p, size_to_pointer(size));
	}
	HPAGE_UNLOCK;
}

static inline int
page_remove(const void *p)
{
	int result;

	HPAGE_LOCK;
	if (use_page_table) {
		result = page_table_remove(pt_pages, p);
	} else {
		result = hash_table_remove(ht_pages, p);
	}
	HPAGE_UNLOCK;

	return result;
}

static void
hdestroy_page_table_item(void *key, size_t size, void *unused_udata)
{
	(void) unused_udata;
	g_assert(size > 0);
	vmm_free(key, size);
}

static void
hdestroy_hash_table_item(const void *key, void *value, void *unused_udata)
{
	(void) unused_udata;
	g_assert((size_t) value > 0);
	vmm_free(deconstify_pointer(key), pointer_to_size(value));
}

static inline void
page_destroy(void)
{
	HPAGE_LOCK;
	if (use_page_table) {
		page_table_foreach(pt_pages, hdestroy_page_table_item, NULL);
		page_table_destroy(pt_pages);
		pt_pages = NULL;
	} else {
		hash_table_foreach(ht_pages, hdestroy_hash_table_item, NULL);
		hash_table_destroy(ht_pages);
		ht_pages = NULL;
	}
	HPAGE_UNLOCK;
}

static inline size_t
halloc_get_size(const void *p, enum halloc_type *type)
{
	size_t size;

	size = page_lookup(p);
	if (size != 0) {
		g_assert(size >= walloc_threshold);
		*type = HALLOC_VMM;
	} else {
		const union align *head = p;

		head--;
		g_assert(size_is_positive(head->size));
		g_assert(head->size < walloc_threshold);
		size = head->size + sizeof *head;
		*type = HALLOC_WALLOC;
	}
	return size;
}

/**
 * Allocate memory from a zone suitable for the given size.
 *
 * @return a pointer to the start of the allocated block.
 */
#ifdef TRACK_ZALLOC
void *
halloc_track(size_t size, const char *file, int line)
#else
void *
halloc(size_t size)
#endif
{
	void *p;
	size_t allocated;

	if (0 == size)
		return NULL;

	if G_UNLIKELY(0 == walloc_threshold)
		halloc_init(TRUE);

	if G_LIKELY(size < walloc_threshold) {
		union align *head;

		allocated = size + sizeof head[0];
#ifdef TRACK_ZALLOC
		head = walloc_track(allocated, file, line);
#else
		head = walloc(allocated);
#endif
		head->size = size;
		p = &head[1];
#if defined(TRACK_ZALLOC) || defined(MALLOC_STATS)
		zalloc_shift_pointer(head, p);
#endif
		HSTATS_LOCK;
		hstats.alloc_via_walloc++;
		hstats.wasted_cumulative_walloc += sizeof head[0];
	} else {
		int inserted;

		/* round_pagesize() is unsafe and wraps! */
		allocated = round_pagesize(size);
		g_assert(allocated >= size);

		p = vmm_alloc(allocated);
		inserted = page_insert(p, allocated);
		g_assert(inserted);

		HSTATS_LOCK;
		hstats.alloc_via_vmm++;
		hstats.wasted_cumulative_vmm += allocated - size;
	}

	/* Stats are still locked at this point */

	hstats.allocations++;;
	hstats.wasted_cumulative += allocated - size;
	hstats.memory += allocated;
	hstats.blocks++;
	HSTATS_UNLOCK;

	return p;
}

/**
 * Same as halloc(), but fills the allocated memory with zeros before returning.
 */
#ifdef TRACK_ZALLOC
void *
halloc0_track(size_t size, const char *file, int line)
#else
void *
halloc0(size_t size)
#endif
{
#ifdef TRACK_ZALLOC
	void *p = halloc_track(size, file, line);
#else
	void *p = halloc(size);
#endif
	if G_LIKELY(p != NULL) {
		memset(p, 0, size);
	}

	HSTATS_INCX(allocations_zeroed);
	return p;
}

/**
 * Free a block allocated via halloc().
 */
void
hfree(void *p)
{
	size_t allocated;
	enum halloc_type type;

	if G_UNLIKELY(NULL == p)
		return;

	allocated = halloc_get_size(p, &type);
	g_assert(size_is_positive(allocated));

	if (HALLOC_WALLOC == type) {
		union align *head = p;

		head--;
		wfree(head, allocated);
	} else {
		page_remove(p);
		vmm_free(p, allocated);
	}

	HSTATS_LOCK;
	hstats.freeings++;
	hstats.memory -= allocated;
	hstats.blocks--;
	HSTATS_UNLOCK;
}

/**
 * Reallocate a block allocated via halloc().
 *
 * @return new block address.
 */
void *
hrealloc(void *old, size_t new_size)
{
	size_t old_size, allocated;
	void *p;
	enum halloc_type type;

	if G_UNLIKELY(NULL == old)
		return halloc(new_size);

	if G_UNLIKELY(0 == new_size) {
		hfree(old);
		return NULL;
	}

	allocated = halloc_get_size(old, &type);
	g_assert(size_is_positive(allocated));

	/*
	 * This is our chance to move a virtual memory fragment out of the way.
	 */

	HSTATS_INCX(reallocs);

	if (HALLOC_VMM == type) {
		size_t rounded_new_size = round_pagesize(new_size);

		old_size = allocated;

		if (vmm_is_relocatable(old, rounded_new_size)) {
			HSTATS_INCX(realloc_relocatable);
			goto relocate;
		}

		if (new_size >= walloc_threshold) {
			if (rounded_new_size == old_size) {
				HSTATS_INCX(realloc_noop);
				HSTATS_INCX(realloc_noop_same_vmm);
				return old;
			}
			if (old_size > rounded_new_size) {
				vmm_shrink(old, old_size, rounded_new_size);
				page_replace(old, rounded_new_size);
				HSTATS_LOCK;
				hstats.memory += rounded_new_size - old_size;
				hstats.realloc_via_vmm_shrink++;
				HSTATS_UNLOCK;

				return old;
			}
		}
	} else {
		union align *old_head;

		old_size = allocated - sizeof *old_head;		/* User size */

		if (new_size < walloc_threshold) {
			union align *new_head;
			size_t new_allocated = new_size + sizeof *new_head;

			old_head = old;
			old_head--;
			new_head = wrealloc(old_head, allocated, new_allocated);
			new_head->size = new_size;

			HSTATS_LOCK;
			hstats.realloc_via_wrealloc++;
			hstats.memory += new_allocated - allocated;
			HSTATS_UNLOCK;

			return &new_head[1];
		}
	}

	if (old_size >= new_size && old_size / 2 < new_size) {
		HSTATS_INCX(realloc_noop);
		return old;
	}

relocate:
	p = halloc(new_size);
	g_assert(NULL != p);

	memcpy(p, old, MIN(new_size, old_size));
	hfree(old);
	HSTATS_INCX(realloc_via_vmm);
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

#ifdef REMAP_ZALLOC
void *
halloc(size_t size)
{
	return g_malloc(size);
}

void *
halloc0(size_t size)
{
	return g_malloc0(size);
}

void
hfree(void *ptr)
{
	g_free(ptr);
}

void *
hrealloc(void *old, size_t size)
{
	return g_realloc(old, size);
}
#endif	/* REMAP_ZALLOC */

#endif	/* !REMAP_ZALLOC && !TRACK_MALLOC */

#ifdef USE_HALLOC

static void *
ha_malloc(gsize size)
{
	return halloc(size);
}

static void *
ha_realloc(void *p, gsize size)
{
	return hrealloc(p, size);
}

static void
ha_free(void *p)
{
	hfree(p);
}

static void
halloc_glib12_check(void)
{
#if !GLIB_CHECK_VERSION(2,0,0)
	void *p;
	enum halloc_type type;

	/*
	 * Check whether the remapping is effective. This may not be
	 * the case for our GLib 1.2 hack. This is required for Darwin,
	 * for example.
	 */
	p = g_strdup("");
	if (0 == halloc_get_size(p, &type)) {
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

#undef malloc
#undef realloc
#undef free

#if GLIB_CHECK_VERSION(2,0,0)
	{
		/* NOTE: This string is not read-only because it will be overwritten
		 *		 by gm_setproctitle() as it becomes part of the environment.
		 *	     This happens at least on some Linux systems.
		 */
		static char variable[] = "G_SLICE=always-malloc";
		putenv(variable);
	}
#endif	/* GLib >= 2.0.0 */

	vtable.malloc = ha_malloc;
	vtable.realloc = ha_realloc;
	vtable.free = ha_free;

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
static bool replacing_malloc;
static bool halloc_is_compiled = TRUE;

static void
halloc_init_once(void)
{
	vmm_init();		/* Just in case, since we're built on top of VMM */

	halloc_pagesize = compat_pagesize();
	use_page_table = (size_t) -1 == (uint32) -1 && 4096 == halloc_pagesize;
	walloc_threshold = walloc_maxsize() - sizeof(union align) + 1;

	HPAGE_LOCK;
	if (use_page_table) {
		pt_pages = page_table_new();
	} else {
		ht_pages = hash_table_new();
	}
	HPAGE_UNLOCK;
}

void
halloc_init(bool replace_malloc)
{
	static once_flag_t initialized;
	static once_flag_t vtable_inited;

	once_flag_run(&initialized, halloc_init_once);
	replacing_malloc = replace_malloc;

	if (replace_malloc)
		once_flag_run(&vtable_inited, halloc_init_vtable);
}

/**
 * Did they request that halloc() be a malloc() replacement?
 */
bool
halloc_replaces_malloc(void)
{
	return replacing_malloc;
}
#else	/* REMAP_ZALLOC || TRACK_MALLOC */

static bool halloc_is_compiled = FALSE;

void
halloc_init(bool unused_replace_malloc)
{
	(void) unused_replace_malloc;

	/* EMPTY */
}

bool
halloc_replaces_malloc(void)
{
	return FALSE;
}

#endif	/* !REMAP_ZALLOC && !TRACK_MALLOC */

bool
halloc_is_available(void)
{
	return halloc_is_compiled;
}

size_t
halloc_bytes_allocated(void)
{
	return hstats.memory;
}

size_t
halloc_chunks_allocated(void)
{
	return hstats.blocks;
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
		char *p;

		/* Not hcopy() because we shouldn't even read the nth byte of src. */
		p = mempcpy(result, str, len);
		*p = '\0';

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
h_strjoinv(const char *separator, char * const *str_array)
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

	len = size_saturate_add(len, 1);
	dst = halloc(len);
	va_start(ap, first);
	ret = concat_strings_v(dst, len, first, ap);
	va_end(ap);

	g_assert(ret == len - 1);		/* Do not count the trailing NUL */

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
static size_t G_GNUC_PRINTF(1, 0)
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
	return size_saturate_add(ret, 1);
}

/**
 * A clone of g_strdup_vprintf() using halloc().
 * The resulting string must be freed by hfree().
 */
char *
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

	g_assert(UNSIGNED(ret) == size - 1);

	return buf;
}

/**
 * Like h_strdup_vprintf() but returns the length of the generated string.
 * The resulting string must be freed by hfree().
 */
char *
h_strdup_len_vprintf(const char *format, va_list ap, size_t *len)
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

	g_assert(UNSIGNED(ret) == size - 1);

	if (len != NULL)
		*len = UNSIGNED(ret);

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

enum hpriv_magic { HPRIV_MAGIC = 0x683e6188 };

struct hpriv {
	enum hpriv_magic magic;	/**< Magic number */
	void *p;				/**< Thread-private pointer (halloc-ed) */
};

static inline void
hpriv_check(const struct hpriv * const hp)
{
	g_assert(hp != NULL);
	g_assert(HPRIV_MAGIC == hp->magic);
}

/**
 * Reclaim a thread-private pointer when the thread is exiting.
 */
static void
h_private_reclaim(void *data, void *unused)
{
	struct hpriv *hp = data;

	(void) unused;

	hpriv_check(hp);

	HFREE_NULL(hp->p);
	hp->magic = 0;
	WFREE(hp);
}

/**
 * Record a pointer as being an halloc-ed() memory zone that needs to be freed
 * when the thread exists or when a new value is recorded.
 *
 * This is used to provide thread-private "lazy memory" whose lifetime does not
 * exceeed that of the next call to the routine that produces these pointers.
 *
 * @param key		the key to use to identify this pointer value
 * @param p			the allocated pointer
 *
 * @return the pointer, as a convenience.
 */
void *
h_private(const void *key, void *p)
{
	struct hpriv *hp;

	hp = thread_private_get(key);

	if G_LIKELY(hp != NULL) {
		hpriv_check(hp);

		HFREE_NULL(hp->p);		/* Free old pointer */
		return hp->p = p;		/* Will be freed next time or at thread exit */
	}

	/*
	 * Allocate a new thread-private pointer object, with a specialized free
	 * routine to be able to reclaim the allocated memory when the thread
	 * exits.
	 */

	WALLOC0(hp);
	hp->magic = HPRIV_MAGIC;

	thread_private_add_extended(key, hp, h_private_reclaim, NULL);

	return hp->p = p;
}

/**
 * Generate a SHA1 digest of the current halloc statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
halloc_stats_digest(sha1_t *digest)
{
	/*
	 * Don't take locks to read the statistics, to enhance unpredictability.
	 */

	HSTATS_INCX(halloc_stats_digest);
	SHA1_COMPUTE(hstats, digest);
}

/**
 * Dump halloc statistics to specified log agent.
 */
G_GNUC_COLD void
halloc_dump_stats_log(logagent_t *la, unsigned options)
{
	struct hstats stats;
	uint64 wasted_average, wasted_average_walloc, wasted_average_vmm;

	HSTATS_LOCK;
	stats = hstats;			/* struct copy under lock protection */
	HSTATS_UNLOCK;

#define DUMP(x) log_info(la, "HALLOC %s = %s", #x,		\
	(options & DUMP_OPT_PRETTY) ?						\
		 uint64_to_gstring(stats.x) : uint64_to_string(stats.x))

#define DUMP64(x) G_STMT_START {							\
	uint64 v = AU64_VALUE(&hstats.x);						\
	log_info(la, "HALLOC %s = %s", #x,							\
		(options & DUMP_OPT_PRETTY) ?						\
			uint64_to_gstring(v) : uint64_to_string(v));	\
} G_STMT_END

#define DUMS(x) log_info(la, "HALLOC %s = %s", #x,		\
	(options & DUMP_OPT_PRETTY) ?						\
		 size_t_to_gstring(stats.x) : size_t_to_string(stats.x))

#define DUMV(x) log_info(la, "HALLOC %s = %s", #x,		\
	(options & DUMP_OPT_PRETTY) ?						\
		 uint64_to_gstring(x) : uint64_to_string(x))

	wasted_average = stats.wasted_cumulative /
		(0 == stats.allocations ? 1 : stats.allocations);
	wasted_average_walloc = stats.wasted_cumulative_walloc /
		(0 == stats.alloc_via_walloc ?  1 : stats.alloc_via_walloc);
	wasted_average_vmm = stats.wasted_cumulative_vmm /
		(0 == stats.alloc_via_vmm ?  1 : stats.alloc_via_vmm);

	DUMP(allocations);
	DUMP64(allocations_zeroed);
	DUMP(alloc_via_walloc);
	DUMP(alloc_via_vmm);
	DUMP(freeings);
	DUMP64(reallocs);
	DUMP64(realloc_noop);
	DUMP64(realloc_noop_same_vmm);
	DUMP(realloc_via_wrealloc);
	DUMP64(realloc_via_vmm);
	DUMP(realloc_via_vmm_shrink);
	DUMP64(realloc_relocatable);
	DUMP(wasted_cumulative);
	DUMP(wasted_cumulative_walloc);
	DUMP(wasted_cumulative_vmm);
	DUMV(wasted_average);
	DUMV(wasted_average_walloc);
	DUMV(wasted_average_vmm);
	DUMS(memory);
	DUMS(blocks);

	DUMP64(halloc_stats_digest);

#undef DUMP
#undef DUMP64
#undef DUMS
#undef DUMV
}

/* vi: set ts=4 sw=4 cindent: */
