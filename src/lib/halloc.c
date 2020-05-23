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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "dump_options.h"
#include "entropy.h"
#include "hashtable.h"
#include "once.h"
#include "pagetable.h"
#include "spinlock.h"
#include "stringify.h"
#include "thread.h"
#include "unsigned.h"
#include "vmm.h"
#include "walloc.h"
#include "xmalloc.h"		/* In case halloc() is disabled at runtime */
#include "zalloc.h"			/* For zalloc_shift_pointer() */

#include "override.h"		/* Must be the last header included */

/*
 * Under REMAP_ZALLOC or TRACK_MALLOC, do not define halloc(), hfree(), etc...
 */

#if defined(REMAP_ZALLOC) || defined(TRACK_MALLOC) || defined(MALLOC_STATS)
#undef USE_HALLOC
#endif	/* REMAP_ZALLOC || TRACK_MALLOC */

/**
 * Internal statistics collected.
 */
static struct hstats {
	uint64 allocations;					/**< Total # of allocations */
	AU64(allocations_zeroed);			/**< Total # of zeroed allocations */
	uint64 alloc_via_walloc;			/**< Allocations from walloc() */
	uint64 alloc_via_xpmalloc;			/**< Allocations from xpmalloc() */
	uint64 alloc_via_vmm;				/**< Allocations from VMM */
	uint64 freeings;					/**< Total # of freeings */
	AU64(reallocs);						/**< Total # of reallocs */
	AU64(realloc_noop);					/**< Nothing to do */
	uint64 realloc_via_wrealloc;		/**< Reallocs handled by wrealloc() */
	uint64 realloc_via_xprealloc;		/**< Reallocs handled by xprealloc() */
	AU64(realloc_via_copy);				/**< Reallocs handled by copy */
	uint64 realloc_via_vmm_shrink;		/**< Shrunk VMM region */
	uint64 realloc_via_vmm_move_shrink;	/**< Shrunk VMM region after moving it */
	AU64(realloc_noop_same_vmm);		/**< Same VMM size */
	AU64(realloc_vmm_moved);			/**< Same VMM size, was able to move it */
	AU64(realloc_vmm_try_post_move);	/**< Try post-optimization of VM address */
	AU64(realloc_vmm_post_moved);		/**< Post-optimization successful */
	uint64 wasted_cumulative;			/**< Cumulated allocation waste */
	uint64 wasted_cumulative_walloc;	/**< Cumulated waste for walloc */
	uint64 wasted_cumulative_xpmalloc;	/**< Cumulated waste for xpmalloc */
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
	HALLOC_VMM,
	HALLOC_XPMALLOC
};

#if !defined(REMAP_ZALLOC) && !defined(TRACK_MALLOC)

static int use_page_table;
static page_table_t *pt_pages;
static hash_table_t *ht_pages;
static size_t walloc_threshold;		/* walloc() size upper limit */
static size_t xpmalloc_threshold;	/* xpmalloc() size upper limit */
static size_t halloc_pagesize;
static bool halloc_disabled;

union halign {
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
		const union halign *head = p;

		/*
		 * xmalloc() and halloc() use similar headers, so regardless of
		 * whether this is a halloc()'ed block through walloc() or an
		 * xmalloc()'ed block, we get the same blocksize information
		 * at the same place.  To ensure the presence of such a header,
		 * we use xpmalloc().
		 *		--RAM, 2015-11-17
		 */

		head--;
		g_assert(size_is_positive(head->size));

		if (head->size < walloc_threshold) {
			size = head->size + sizeof *head;
			*type = HALLOC_WALLOC;
		} else {
			size = xpallocated(p);
			*type = HALLOC_XPMALLOC;
		}
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

	if G_UNLIKELY(0 == walloc_threshold) {
		if (halloc_disabled)
			return xmalloc(size);
		halloc_init(TRUE);
	}

	if G_LIKELY(size < walloc_threshold) {
		union halign *head;

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
	} else if (size < xpmalloc_threshold) {
		p = xpmalloc(size);
		allocated = xpallocated(p);
		HSTATS_LOCK;
		hstats.alloc_via_xpmalloc++;
		hstats.wasted_cumulative_xpmalloc += allocated - size;
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

	if G_UNLIKELY(halloc_disabled) {
		xfree(p);
		return;
	}

	allocated = halloc_get_size(p, &type);
	g_assert(size_is_positive(allocated));

	if (HALLOC_WALLOC == type) {
		union halign *head = p;

		head--;
		wfree(head, allocated);
	} else if (HALLOC_XPMALLOC == type) {
		xfree(p);
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
 * Attempt to move VMM region to a better VM position.
 */
static void *
hrealloc_vmm_move(void *old, size_t size)
{
	void *p;
	size_t rounded = round_pagesize(size);

	page_remove(old);				/* Could be invalidated by vmm_move() */
	p = vmm_move(old, size);
	page_insert(p, rounded);

	if G_UNLIKELY(p != old)
		HSTATS_INCX(realloc_vmm_moved);

	return p;
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

	if G_UNLIKELY(halloc_disabled)
		return xrealloc(old, new_size);

	allocated = halloc_get_size(old, &type);
	g_assert(size_is_positive(allocated));

	/*
	 * This is our chance to move a virtual memory fragment out of the way.
	 */

	HSTATS_INCX(reallocs);

	if (HALLOC_VMM == type) {
		size_t rounded_new_size;

		old_size = allocated;

		if (new_size < walloc_threshold)
			goto relocate;		/* Will change allocation type */

		/*
		 * Allocation type will stay VMM.
		 */

		rounded_new_size = round_pagesize(new_size);

		if (rounded_new_size == old_size) {
			p = hrealloc_vmm_move(old, new_size);
			if (old == p) {
				HSTATS_INCX(realloc_noop);
				HSTATS_INCX(realloc_noop_same_vmm);
			}
			return p;
		}

		/*
		 * Attempt in-place shrinking of VMM region, after possible move.
		 */

		if (old_size > rounded_new_size) {
			p = hrealloc_vmm_move(old, old_size);
			vmm_shrink(p, old_size, rounded_new_size);
			page_replace(p, rounded_new_size);
			HSTATS_LOCK;
			hstats.memory += rounded_new_size - old_size;
			if (p != old)
				hstats.realloc_via_vmm_move_shrink++;
			else
				hstats.realloc_via_vmm_shrink++;
			HSTATS_UNLOCK;

			return p;
		}
	} else if (HALLOC_XPMALLOC == type) {
		size_t new_allocated;

		old_size = allocated;

		if (new_size < walloc_threshold || new_size >= xpmalloc_threshold)
			goto relocate;		/* Will change allocation type */

		p = xprealloc(old, new_size);
		new_allocated = xpallocated(p);

		HSTATS_LOCK;
		hstats.realloc_via_xprealloc++;
		hstats.memory += new_allocated - allocated;
		HSTATS_UNLOCK;

		return p;
	} else {
		union halign *old_head;

		old_size = allocated - sizeof *old_head;		/* User size */

		if (new_size < walloc_threshold) {
			union halign *new_head;
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

	/* FALL THROUGH */

relocate:
	p = halloc(new_size);
	g_assert(NULL != p);
	memcpy(p, old, MIN(new_size, old_size));
	hfree(old);
	HSTATS_INCX(realloc_via_copy);

	/*
	 * If handling a VM region, try to move it now that we freed the old region,
	 * when the old pointer was better than the new one we got.
	 */

	if G_UNLIKELY(
		HALLOC_VMM == type &&
		new_size >= walloc_threshold &&	/* Still allocated as a VMM region */
		vmm_pointer_is_better(p, old)	/* Old was better */
	) {
		void *q;

		HSTATS_INCX(realloc_vmm_try_post_move);
		q = hrealloc_vmm_move(p, new_size);
		if (p != q) {
			HSTATS_INCX(realloc_vmm_post_moved);
			p = q;
		}
		/* FALL THROUGH */
	}

	return p;
}

/**
 * Attempt to disable halloc(), remapping it to xmalloc() dynamically.
 *
 * This is only possible before any halloc() has been performed, otherwise
 * we would not be able to correctly hfree() blocks allocated before disabling
 * the allocator.
 *
 * @return TRUE if we managed to disable halloc().
 */
bool
halloc_disable(void)
{
	bool result = FALSE;

	thread_suspend_others(TRUE);

	if (0 == walloc_threshold) {
		result = TRUE;			/* No halloc_init() yet */
	} else if (hstats.allocations == hstats.freeings) {
		hdestroy();
		walloc_threshold = 0;
		result = TRUE;
	}

	if (result)
		halloc_disabled = TRUE;

	thread_unsuspend_others();

	return result;
}

/**
 * @return whether halloc() was disabled.
 */
bool
halloc_is_disabled(void)
{
	return halloc_disabled;
}

/**
 * Destroy all the zones we allocated so far.
 */
void
hdestroy(void)
{
	page_destroy();
	halloc_disabled = TRUE;
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

bool
halloc_disable(void)
{
	return TRUE;
}

bool
halloc_is_disabled(void)
{
	return TRUE;
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

/**
 * Is halloc() possible given current walloc() limits?
 */
bool
halloc_is_possible(void)
{
	return walloc_maxsize() > sizeof(union halign);
}

#if !defined(REMAP_ZALLOC) && !defined(TRACK_MALLOC)
static bool replacing_malloc;
static bool halloc_is_compiled = TRUE;

static void
halloc_init_once(void)
{
	vmm_init();		/* Just in case, since we're built on top of VMM */

	halloc_pagesize = compat_pagesize();

	if (halloc_disabled || !halloc_is_possible()) {
		g_assert(0 == walloc_threshold);
		halloc_disabled = TRUE;
		return;
	}

	use_page_table = (size_t) -1 == (uint32) -1 && 4096 == halloc_pagesize;
	walloc_threshold = walloc_maxsize() - sizeof(union halign) + 1;
	xpmalloc_threshold = 2 * halloc_pagesize - sizeof(union halign) + 1;

	g_assert(size_is_positive(walloc_threshold));
	g_assert(size_is_positive(xpmalloc_threshold));

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

	if G_UNLIKELY(halloc_disabled)
		return;

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

/**
 * Generate a SHA1 digest of the current halloc statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
halloc_stats_digest(sha1_t *digest)
{
	uint32 n = entropy_nonce();

	/*
	 * Don't take locks to read the statistics, to enhance unpredictability.
	 */

	HSTATS_INCX(halloc_stats_digest);
	SHA1_COMPUTE_NONCE(hstats, &n, digest);
}

/**
 * Dump halloc statistics to specified log agent.
 */
void G_COLD
halloc_dump_stats_log(logagent_t *la, unsigned options)
{
	struct hstats stats;
	uint64 wasted_average, wasted_average_walloc, wasted_average_vmm;
	uint64 wasted_average_xpmalloc;
	bool groupped = booleanize(options & DUMP_OPT_PRETTY);

	HSTATS_LOCK;
	stats = hstats;			/* struct copy under lock protection */
	HSTATS_UNLOCK;

#define DUMP(x) log_info(la, "HALLOC %s = %s", #x,		\
	uint64_to_string_grp(stats.x, groupped))

#define DUMP64(x) G_STMT_START {							\
	uint64 v = AU64_VALUE(&hstats.x);						\
	log_info(la, "HALLOC %s = %s", #x,						\
		uint64_to_string_grp(v, groupped));					\
} G_STMT_END

#define DUMS(x) log_info(la, "HALLOC %s = %s", #x,		\
	size_t_to_string_grp(stats.x, groupped))

#define DUMV(x) log_info(la, "HALLOC %s = %s", #x,		\
	uint64_to_string_grp(x, groupped))

	wasted_average = stats.wasted_cumulative /
		(0 == stats.allocations ? 1 : stats.allocations);
	wasted_average_walloc = stats.wasted_cumulative_walloc /
		(0 == stats.alloc_via_walloc ?  1 : stats.alloc_via_walloc);
	wasted_average_xpmalloc = stats.wasted_cumulative_xpmalloc /
		(0 == stats.alloc_via_xpmalloc ?  1 : stats.alloc_via_xpmalloc);
	wasted_average_vmm = stats.wasted_cumulative_vmm /
		(0 == stats.alloc_via_vmm ?  1 : stats.alloc_via_vmm);

	DUMP(allocations);
	DUMP64(allocations_zeroed);
	DUMP(alloc_via_walloc);
	DUMP(alloc_via_xpmalloc);
	DUMP(alloc_via_vmm);
	DUMP(freeings);
	DUMP64(reallocs);
	DUMP64(realloc_noop);
	DUMP64(realloc_noop_same_vmm);
	DUMP64(realloc_vmm_moved);
	DUMP(realloc_via_wrealloc);
	DUMP(realloc_via_xprealloc);
	DUMP64(realloc_via_copy);
	DUMP(realloc_via_vmm_shrink);
	DUMP(realloc_via_vmm_move_shrink);
	DUMP64(realloc_vmm_try_post_move);
	DUMP64(realloc_vmm_post_moved);
	DUMP(wasted_cumulative);
	DUMP(wasted_cumulative_walloc);
	DUMP(wasted_cumulative_xpmalloc);
	DUMP(wasted_cumulative_vmm);
	DUMV(wasted_average);
	DUMV(wasted_average_walloc);
	DUMV(wasted_average_xpmalloc);
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
