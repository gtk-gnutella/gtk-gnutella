/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
 * Copyright (c) 2006, 2009, Raphael Manfredi
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
 * Virtual memory management.
 *
 * @author Christian Biere
 * @date 2006
 * @author Raphael Manfredi
 * @date 2006, 2009
 */

#include "common.h"

RCSID("$Id$")

#include "vmm.h"

#include "cq.h"
#include "misc.h"
#include "tm.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * With VMM_INVALIDATE_FREE_PAGES freed pages are invalidated so that the
 * system can recycle them without ever paging them out as we don't care about
 * the data in them anymore.
 */
#define VMM_INVALIDATE_FREE_PAGES 1

/*
 * With VMM_PROTECT_FREE_PAGES freed pages are completely protected. This may
 * help to detect access-after-free bugs.
 */
/* #define VMM_PROTECT_FREE_PAGES 1 */

/**
 * Cached pages older than `page_cache_prune_timeout' seconds are released
 * to prevent that they are unnecessarily paged out to swap.
 */
static const time_delta_t page_cache_prune_timeout = 20; /* unit: seconds */

static size_t kernel_pagesize = 0;
static size_t kernel_pagemask = 0;
static unsigned kernel_pageshift = 0;

#define VMM_CACHE_SIZE	256		/* Amount of entries per cache line */
#define VMM_CACHE_LINES	32		/* Amount of cache lines */
#define VMM_CACHE_LIFE	60		/* At most 1 minute */

struct page_info {
	void *base;		/**< base address */
	time_t stamp;	/**< time at which the page was inserted */
};

struct page_cache {
	struct page_info info[VMM_CACHE_SIZE];	/**< sorted on base address */
	size_t current;		/**< amount of items in info[] */
	size_t pages;		/**< amount of consecutive pages for entries */
	size_t chunksize;	/**< size of each entry */
};

/**
 * The page cache.
 *
 * At index 0, we have pages whose size is the VMM page size.
 * Ad index n, we have areas made of n consecutive pages.
 */
static struct page_cache page_cache[VMM_CACHE_LINES];

static gboolean safe_to_malloc;		/**< True when malloc() was inited */
static guint32 vmm_debug;			/**< Debug level */

static inline gboolean
vmm_debugging(guint32 lvl)
{
	return safe_to_malloc && vmm_debug > lvl;
}

static void page_cache_insert_pages(void *base, size_t n);

static void
init_kernel_pagesize(void)
{
	kernel_pagesize = compat_pagesize();
	RUNTIME_ASSERT(is_pow2(kernel_pagesize));
	kernel_pagemask = kernel_pagesize - 1;
	kernel_pageshift = ffs(kernel_pagesize) - 1;
}

/**
 * Fast version of pagesize rounding (without the slow % operator).
 */
static inline size_t
round_pagesize_fast(size_t n)
{
	if (!kernel_pagesize)
		init_kernel_pagesize();

	return (n + kernel_pagemask) & ~kernel_pagemask;
}

/**
 * Fast version of page counting: how many pages does it take to store `n'?
 */
static inline size_t
pagecount_fast(size_t n)
{
	return round_pagesize_fast(n) >> kernel_pageshift;
}

/**
 * Rounds `n' up to so that it is aligned to the pagesize.
 */
size_t
round_pagesize(size_t n)
{
	return round_pagesize_fast(n);
}

static long
compat_pagesize_intern(void)
#if defined (_SC_PAGESIZE) || defined(_SC_PAGE_SIZE)
{
	long ret;

	errno = 0;
#if defined (_SC_PAGESIZE)
	ret = sysconf(_SC_PAGESIZE);
#else
	ret = sysconf(_SC_PAGE_SIZE);
#endif
	if (-1L == ret) {
		return_value_unless(0 == errno, 0);
	}
	return ret;
}
#else
{
	return getpagesize();
}
#endif /* _SC_PAGE_SIZE */

size_t
compat_pagesize(void)
{
	static int initialized;
	static size_t psize;

	if (!initialized) {
		long n;
		
		initialized = 1;
		n = compat_pagesize_intern();
		RUNTIME_ASSERT(n > 0);
		RUNTIME_ASSERT(n < INT_MAX);
		RUNTIME_ASSERT(is_pow2(n));
		psize = n;
		RUNTIME_ASSERT((size_t) psize == (size_t) n);
	}

	return psize;
}

/**
 * Allocate a new chunk of anonymous memory.
 */
static void *
vmm_mmap_anonymous(size_t size)
#if defined(HAS_MMAP)
{
	static int flags, failed, fd = -1;
	void *p;

	if (failed)
		return NULL;

#if defined(MAP_ANON)
	flags = MAP_PRIVATE | MAP_ANON;
#elif defined (MAP_ANONYMOUS)
	flags = MAP_PRIVATE | MAP_ANONYMOUS;
#else
	flags = MAP_PRIVATE;
	if (-1 == fd) {
		fd = get_non_stdio_fd(open("/dev/zero", O_RDWR, 0));
		return_value_unless(fd >= 0, NULL);
		set_close_on_exec(fd);
	}
#endif	/* MAP_ANON */

	p = mmap(0, size, PROT_READ | PROT_WRITE, flags, fd, 0);
	if (MAP_FAILED == p) {
		if (ENOMEM != errno) {
			failed = 1;
			return_value_unless(MAP_FAILED != p, NULL);
		}
		p = NULL;
	}
	return p;
}
#else	/* !HAS_MMAP */
{
	void *p;

	size = MIN(kernel_pagesize, size);
#if defined(HAS_POSIX_MEMALIGN)
	if (posix_memalign(&p, kernel_pagesize, size)) {
		p = NULL;
	}
#elif defined(HAS_MEMALIGN)
	p = memalign(kernel_pagesize, size);
#else
	(void) size;
	p = NULL;
	RUNTIME_UNREACHABLE();
#error "Neither mmap(), posix_memalign() nor memalign() available"
#endif	/* HAS_POSIX_MEMALIGN */
	return p;
}
#endif	/* HAS_MMAP */

/**
 * Allocates a page-aligned chunk of memory.
 *
 * @param size		the amount of bytes to allocate.
 *
 * @return On success a pointer to the allocated chunk is returned. On
 *		   failure NULL is returned.
 */
static void *
alloc_pages(size_t size)
{
	void *p;

	RUNTIME_ASSERT(kernel_pagesize > 0); /* Computed by round_pagesize_fast() */

	p = vmm_mmap_anonymous(size);
	return_value_unless(NULL != p, NULL);
	
	if (round_pagesize_fast((size_t) p) != (size_t) p) {
		RUNTIME_ASSERT(!"Aligned memory required");
	}

	if (vmm_debugging(5)) {
		g_message("VMM allocated %uKiB region at 0x%lx",
			(unsigned) size / 1024, (unsigned long) p);
	}

	return p;
}

/**
 * Free memory allocated by alloc_pages().
 */
static void
free_pages(void *p, size_t size)
{
	if (vmm_debugging(5)) {
		g_message("VMM freeing %uKiB region at 0x%lx",
			(unsigned) size / 1024, (unsigned long) p);
	}

#if defined(HAS_MMAP)
	{
		int ret;

		ret = munmap(p, size);
		return_unless(0 == ret);
	}
#elif defined(HAS_POSIX_MEMALIGN) || defined(HAS_MEMALIGN)
	(void) size;
	free(p);
#else
	(void) p;
	(void) size;
	RUNTIME_UNREACHABLE();
#error "Neither mmap(), posix_memalign() nor memalign() available"
#endif	/* HAS_POSIX_MEMALIGN || HAS_MEMALIGN */
}

/**
 * Lookup page within a cache line.  If ``match'' is TRUE, we're looking for
 * the exact entry.  Otherwise, we're looking for the place at which to insert
 * a new entry in the sorted array.
 *
 * @return index within the page cache info[] sorted array where "p" is stored,
 * -1 if not found.
 */
static size_t
vpc_lookup(const struct page_cache *pc, void *p, gboolean match)
{
	unsigned low = 0, high = pc->current - 1;

	/* Binary search */

	while (low <= high && uint_is_non_negative(high)) {
		unsigned mid = low + (high - low) / 2;
		void *item;

		g_assert(mid < pc->current);

		item = pc->info[mid].base;
		if (p > item)
			low = mid + 1;
		else if (p < item)
			high = mid - 1;
		else if (match)
			return mid;
		else
			g_error("memory chunk at 0x%lx already present in cache",
				(unsigned long) p);
	}

	return match ? (size_t) -1 : low;	/* Not found, or insert at ``low'' */
}

/**
 * Delete slot ``idx'' within cache line.
 */
static inline void
vpc_delete_slot(struct page_cache *pc, size_t idx)
{
	g_assert(size_is_non_negative(idx) && idx < pc->current);

	pc->current--;
	if (idx < pc->current) {
		memmove(&pc->info[idx], &pc->info[idx + 1],
			(pc->current - idx) * sizeof(pc->info[0]));
	}
}

/**
 * Remove entry within a cache line.
 */
static void
vpc_remove(struct page_cache *pc, void *p)
{
	size_t idx;

	idx = vpc_lookup(pc, p, TRUE);
	g_assert(idx != (size_t) -1);		/* Must have been found */
	vpc_delete_slot(pc, idx);
}

/**
 * Free page cached at given index in cache line.
 */
static void
vpc_free(struct page_cache *pc, size_t idx)
{
	void *p;

	g_assert(size_is_non_negative(idx) && idx < pc->current);

	p = pc->info[idx].base;
	free_pages(p, pc->chunksize);
	vpc_delete_slot(pc, idx);
}

/**
 * Insert entry within a cache line, coalescing consecutive entries in
 * higher-order cache lines, recursively.
 *
 * The base pointer MUST be pointing to a memory region corresponding to
 * the size of the chunks held in the cache.
 *
 * @param pc	page cache where entry is inserted
 * @param p		base pointer of the region to be added
 */
static void
vpc_insert(struct page_cache *pc, void *p)
{
	size_t idx;
	void *base = p;
	size_t pages = pc->pages;

	idx = vpc_lookup(pc, p, FALSE);

	g_assert(size_is_non_negative(idx) && idx <= pc->current);

	/*
	 * If we're inserting in the highest-order cache, there's no need
	 * to attempt to do any coalescing.
	 */

	if (VMM_CACHE_LINES == pages)
		goto insert;

	/*
	 * Look whether the page chunk before is also present in the cache line.
	 * If it is, it can be removed and coalesced with the current chunk.
	 */

	if (idx > 0) {
		void *before = pc->info[idx - 1].base;
		void *after = ptr_add_offset(before, pc->chunksize);

		if (after == p) {
			if (vmm_debugging(6)) {
				g_message("VMM page cache #%u: "
					"coalescing previous [0x%lx, 0x%lx] with [0x%lx, 0x%lx]",
					pc->pages - 1, (unsigned long) before,
					(unsigned long) ptr_add_offset(after, -1),
					(unsigned long) p,
					(unsigned long) ptr_add_offset(p, pc->chunksize - 1));
			}
			base = before;
			pages += pc->pages;
			vpc_remove(pc, before);
		}
	}

	/*
	 * Look whether the page chunk after is also present in the cache.
	 * If it is, it can be removed and coalesced with the current chunk.
	 */

	if (idx < pc->current) {
		void *end = ptr_add_offset(p, pc->chunksize);
		void *next = pc->info[idx].base;

		if (next == end) {
			if (vmm_debugging(6)) {
				g_message("VMM page cache #%u: "
					"coalescing [0x%lx, 0x%lx] with next [0x%lx, 0x%lx]",
					pc->pages - 1, (unsigned long) base,
					(unsigned long) ptr_add_offset(end, -1),
					(unsigned long) next,
					(unsigned long) ptr_add_offset(next, pc->chunksize - 1));
			}
			pages += pc->pages;
			vpc_remove(pc, next);
		}
	}

	/*
	 * If we coalesced the chunk, recurse to insert it in the proper cache.
	 * Otherwise, insertion is happening before ``idx''.
	 */

	if (pages != pc->pages)
		return page_cache_insert_pages(base, pages);

insert:

	/*
	 * Insert region in the local cache line.
	 */

	if (VMM_CACHE_SIZE == pc->current) {
		vpc_free(pc, VMM_CACHE_SIZE - 1);
		if (idx == VMM_CACHE_SIZE - 1) {
			idx--;
		}
	}

	if (idx < pc->current) {
		memmove(&pc->info[idx + 1], &pc->info[idx],
			(pc->current - idx) * sizeof(pc->info[0]));
	}

	pc->current++;
	pc->info[idx].base = base;
	pc->info[idx].stamp = tm_time();

	if (vmm_debugging(4)) {
		g_message("VMM page cache #%u: inserted [0x%lx, 0x%lx] %uKiB, "
			"now holds %u item%s",
			pc->pages - 1, (unsigned long) base,
			(unsigned long) ptr_add_offset(base, pc->chunksize - 1),
			(unsigned) pc->chunksize / 1024, pc->current,
			1 == pc->current ? "" : "s");
	}
}

/**
 * Find "n" consecutive pages in page cache and remove them from it.
 *
 * @return pointer to the base of the "n" pages if found, NULL otherwise.
 */
static void *
vpc_find_pages(struct page_cache *pc, size_t n)
{
	size_t i;
	size_t total = 0;
	size_t begin_idx = 0;
	void *base;
	void *end;
	char *p;

	if (0 == pc->current)
		return NULL;

	total = pc->pages;
	base = pc->info[0].base;
	end = ptr_add_offset(base, pc->chunksize);

	/*
	 * If we have not yet the amount of pages we want, iterate to find
	 * whether we have consecutive ranges in the cache.  This is only
	 * necessary if we are already in the highest-order cache line because
	 * lower-order caches are coalesced at insertion time.
	 */

	if (total < n) {
		for (i = 1; i < pc->current; i++) {
			void *start = pc->info[i].base;

			if (start == end) {
				total += pc->pages;
				end = ptr_add_offset(start, pc->chunksize);
				if (total >= n)
					goto found;
			} else {
				total = pc->pages;
				base = start;
				end = ptr_add_offset(base, pc->chunksize);
				begin_idx = i;
			}
		}

		return NULL;	/* Did not find enough consecutive pages */
	}

found:
	/*
	 * Remove the entries from the cache.
	 */

	 for (i = 0, p = base; i < total; i += pc->pages, p += pc->chunksize) {
		vpc_remove(pc, p);
	}
	 
	/*
	 * If we got more consecutive pages than the amount asked for, put
	 * the trailing pages back into the cache.
	 */

	if (total > n) {
		void *start = ptr_add_offset(base, n * compat_pagesize());
		page_cache_insert_pages(start, total - n);
	}

	return base;
}

/**
 * Find "n" consecutive pages in the page cache, and remove them if found.
 *
 * @return a pointer to the start of the memory region, NULL if we were
 * unable to find that amount of contiguous memory.
 */
static void *
page_cache_find_pages(size_t n)
{
	void *p;
	struct page_cache *pc = NULL;

	g_assert(size_is_positive(n));

	if (n >= VMM_CACHE_LINES) {
		pc = &page_cache[VMM_CACHE_LINES - 1];
		p = vpc_find_pages(pc, n);
	} else {
		pc = &page_cache[n - 1];
		p = vpc_find_pages(pc, n);

		/*
		 * Visit higher-order cache lines if we found nothing in the cache.
		 */

		if (NULL == p) {
			size_t i;

			for (i = n; i < VMM_CACHE_LINES && NULL == p; i++) {
				pc = &page_cache[i];
				p = vpc_find_pages(pc, n);
			}
		}
	}

	if (p != NULL && vmm_debugging(5)) {
		g_message("VMM found %uKiB region at 0x%lx in cache #%u%s",
			(unsigned) (n * compat_pagesize() / 1024),
			(unsigned long) p, pc->pages - 1,
			pc->pages == n ? "" : " (split)");
	}

	return p;
}

/**
 * Insert "n" consecutive pages starting at "base" in the page cache.
 *
 * If the cache is full, older memory is released and the new one is kept,
 * so that we minimize the risk of having cached memory swapped out.
 */
static void
page_cache_insert_pages(void *base, size_t n)
{
	size_t pages = n;
	void *p = base;

	/**
	 * If releasing more than what we can store in the largest cache line,
	 * break up the region into smaller chunks.
	 */

	while (pages > VMM_CACHE_LINES) {
		struct page_cache *pc = &page_cache[VMM_CACHE_LINES - 1];

		vpc_insert(pc, p);
		pages -= pc->pages;
		p = ptr_add_offset(p, pc->chunksize);
	}

	if (size_is_positive(pages)) {
		g_assert(pages <= VMM_CACHE_LINES);
		vpc_insert(&page_cache[pages - 1], p);
	}
}

/**
 * Attempting to coalesce the block with other entries in the cache.
 *
 * @return TRUE if coalescing occurred, with updated base and amount of pages.
 */
static gboolean
page_cache_coalesce_pages(void **base_ptr, size_t *pages_ptr)
{
	size_t i, j;
	void *base = *base_ptr;
	size_t pages = *pages_ptr;
	size_t old_pages = pages;
	void *end;

	/*
	 * Look in low-order caches whether we can find chunks before.
	 */

	for (i = 0; /* empty */; i++) {
		gboolean coalesced = FALSE;
		size_t first = old_pages - 1;

		for (j = MIN(first, VMM_CACHE_LINES - 1); j > 0; j--) {
			struct page_cache *lopc = &page_cache[j - 1];
			void *before = ptr_add_offset(base, -lopc->chunksize);
			size_t loidx;

			loidx = vpc_lookup(lopc, before, TRUE);
			if (loidx != (size_t) -1) {
				if (vmm_debugging(6)) {
					g_message("VMM iter #%u, coalescing previous [0x%lx, 0x%lx] "
						"from lower cache #%u with [0x%lx, 0x%lx]",
						(unsigned) i, (unsigned long) before,
						(unsigned long) ptr_add_offset(base, -1),
						lopc->pages - 1,
						(unsigned long) base,
						(unsigned long) ptr_add_offset(base,
							pages * compat_pagesize() - 1));
				}
				base = before;
				pages += lopc->pages;
				vpc_remove(lopc, before);
				coalesced = TRUE;
			}
		}

		if (!coalesced)
			break;
	}

	/**
	 * Look in higher-order caches whether we can find chunks before.
	 * Stop before the highest-order cache since regions there cannot be
	 * coalesced with any other (inserting them back to the cache would split
	 * the ranges again).
	 */

	for (j = old_pages + 1; j <= VMM_CACHE_LINES - 1; j++) {
		struct page_cache *hopc = &page_cache[j - 1];
		void *before = ptr_add_offset(base, -hopc->chunksize);
		size_t hoidx;

		hoidx = vpc_lookup(hopc, before, TRUE);
		if (hoidx != (size_t) -1) {
			if (vmm_debugging(6)) {
				g_message("VMM coalescing previous [0x%lx, 0x%lx] "
					"from higher cache #%u with [0x%lx, 0x%lx]",
					(unsigned long) before,
					(unsigned long) ptr_add_offset(base, -1), hopc->pages - 1,
					(unsigned long) base,
					(unsigned long) ptr_add_offset(base,
						pages * compat_pagesize() - 1));
			}
			base = before;
			pages += hopc->pages;
			vpc_remove(hopc, before);
		}
	}

	/*
	 * Look in low-order caches whether we can find chunks after.
	 */

	end = ptr_add_offset(base, pages * compat_pagesize());

	for (i = 0; /* empty */; i++) {
		gboolean coalesced = FALSE;
		size_t first = old_pages - 1;

		for (j = MIN(first, VMM_CACHE_LINES - 1); j > 0; j--) {
			struct page_cache *lopc = &page_cache[j - 1];
			size_t loidx;

			loidx = vpc_lookup(lopc, end, TRUE);
			if (loidx != (size_t) -1) {
				if (vmm_debugging(6)) {
					g_message("VMM iter #%u, coalescing next [0x%lx, 0x%lx] "
						"from lower cache #%u with [0x%lx, 0x%lx]",
						(unsigned) i, (unsigned long) end,
						(unsigned long) ptr_add_offset(end,
							lopc->chunksize - 1),
						lopc->pages - 1, (unsigned long) base,
						(unsigned long) ptr_add_offset(end, -1));
				}
				pages += lopc->pages;
				vpc_remove(lopc, end);
				end = ptr_add_offset(end, lopc->chunksize);
				coalesced = TRUE;
			}
		}

		if (!coalesced)
			break;
	}

	/**
	 * Look in higher-order caches whether we can find chunks after.
	 * Stop before the highest-order cache since regions there cannot be
	 * coalesced with any other (inserting them back to the cache would split
	 * the ranges again).
	 */

	for (j = old_pages + 1; j <= VMM_CACHE_LINES - 1; j++) {
		struct page_cache *hopc = &page_cache[j - 1];
		size_t hoidx;

		hoidx = vpc_lookup(hopc, end, TRUE);
		if (hoidx != (size_t) -1) {
			if (vmm_debugging(6)) {
				g_message("VMM coalescing next [0x%lx, 0x%lx] "
					"from higher cache #%u with [0x%lx, 0x%lx]",
					(unsigned long) end,
					(unsigned long) ptr_add_offset(end, hopc->chunksize - 1),
					hopc->pages - 1, (unsigned long) base,
					(unsigned long) ptr_add_offset(end, -1));
			}
			pages += hopc->pages;
			vpc_remove(hopc, end);
			end = ptr_add_offset(end, hopc->chunksize);
		}
	}

	if (pages != old_pages) {
		if (vmm_debugging(2)) {
			g_message("VMM coalesced %uKiB region [0x%lx, 0x%lx] into "
				"%uKiB region [0x%lx, 0x%lx]",
				(unsigned) (old_pages * compat_pagesize() / 1024),
				(unsigned long) *base_ptr,
				(unsigned long) ptr_add_offset(*base_ptr,
					old_pages * compat_pagesize() - 1),
				(unsigned) (pages * compat_pagesize() / 1024),
				(unsigned long) base,
				(unsigned long) ptr_add_offset(base,
					pages * compat_pagesize() - 1));
		}

		*base_ptr = base;
		*pages_ptr = pages;
		return TRUE;
	}

	return FALSE;
}

void
vmm_madvise_normal(void *p, size_t size)
{
	RUNTIME_ASSERT(p);
	RUNTIME_ASSERT(size > 0);
#if defined(HAS_MADVISE) && defined(MADV_NORMAL)
	madvise(p, size, MADV_NORMAL);
#endif	/* MADV_NORMAL */
}

void
vmm_madvise_sequential(void *p, size_t size)
{
	RUNTIME_ASSERT(p);
	RUNTIME_ASSERT(size > 0);
#if defined(HAS_MADVISE) && defined(MADV_SEQUENTIAL)
	madvise(p, size, MADV_SEQUENTIAL);
#endif	/* MADV_SEQUENTIAL */
}

void
vmm_madvise_free(void *p, size_t size)
{
	RUNTIME_ASSERT(p);
	RUNTIME_ASSERT(size > 0);
#if defined(HAS_MADVISE) && defined(MADV_FREE)
	madvise(p, size, MADV_FREE);
#elif defined(HAS_MADVISE) && defined(MADV_DONTNEED)
	madvise(p, size, MADV_DONTNEED);
#endif	/* MADV_FREE */
}

void
vmm_madvise_willneed(void *p, size_t size)
{
	RUNTIME_ASSERT(p);
	RUNTIME_ASSERT(size > 0);
#if defined(HAS_MADVISE) && defined(MADV_WILLNEED)
	madvise(p, size, MADV_WILLNEED);
#endif	/* MADV_WILLNEED */
}

static void
vmm_validate_pages(void *p, size_t size)
{
	RUNTIME_ASSERT(p);
	RUNTIME_ASSERT(size > 0);
#ifdef VMM_PROTECT_FREE_PAGES
	mprotect(p, size, PROT_READ | PROT_WRITE);
#endif	/* VMM_PROTECT_FREE_PAGES */
#ifdef VMM_INVALIDATE_FREE_PAGES 
	vmm_madvise_normal(p, size);
#endif	/* VMM_INVALIDATE_FREE_PAGES */
}

static void
vmm_invalidate_pages(void *p, size_t size)
{
	RUNTIME_ASSERT(p);
	RUNTIME_ASSERT(size > 0);
#ifdef VMM_PROTECT_FREE_PAGES
	mprotect(p, size, PROT_NONE);
#endif	/* VMM_PROTECT_FREE_PAGES */
#ifdef VMM_INVALIDATE_FREE_PAGES 
	vmm_madvise_free(p, size);
#endif	/* VMM_INVALIDATE_FREE_PAGES */
}

/**
 * Allocates a page-aligned memory chunk.
 *
 * @param size The size in bytes to allocate; will be rounded to the pagesize.
 */
void *
vmm_alloc(size_t size)
{
	size_t n;
	void *p;

	RUNTIME_ASSERT(size > 0);
	
	size = round_pagesize_fast(size);
	n = pagecount_fast(size);

	/*
	 * First look in the page cache to avoid requesting a new memory
	 * mapping from the kernel.
	 */

	p = page_cache_find_pages(n);

	if (p != NULL) {
		vmm_validate_pages(p, size);
		return p;
	}

	p = alloc_pages(size);

	if (NULL == p)
		g_error("cannot allocated %u bytes: out of virtual memmory",
			(unsigned) size);

	return p;
}

void *
vmm_alloc0(size_t size)
{
	size_t n;
	void *p;

	RUNTIME_ASSERT(size > 0);

	size = round_pagesize_fast(size);
	n = pagecount_fast(size);

	/*
	 * First look in the page cache to avoid requesting a new memory
	 * mapping from the kernel.
	 */

	p = page_cache_find_pages(n);

	if (p != NULL) {
		vmm_validate_pages(p, size);
		memset(p, 0, size);
		return p;
	}

	p = alloc_pages(size);

	if (NULL == p)
		g_error("cannot allocated %u bytes: out of virtual memmory",
			(unsigned) size);

	return p;		/* Memory allocated by kernel is already zero-ed */
}

/**
 * Free memory allocated via vmm_alloc().
 */
void
vmm_free(void *p, size_t size)
{
	RUNTIME_ASSERT(0 == size || p);

	if (p) {
		size_t n;

		RUNTIME_ASSERT(round_pagesize_fast((size_t) p) == (size_t) p);

		size = round_pagesize_fast(size);
		n = pagecount_fast(size);
		RUNTIME_ASSERT(n >= 1);

		vmm_invalidate_pages(p, size);
		page_cache_coalesce_pages(&p, &n);
		page_cache_insert_pages(p, n);
	}
}

/**
 * Scans the page cache for old pages and releases them if they have a certain
 * minimum age. We don't want to cache pages forever because they might never
 * be reused. Further, the OS would page them out anyway because they are
 * considered dirty even though we don't care about the content anymore. If we
 * recycled such old pages, the penalty from paging them in is unlikely lower
 * than the mmap()/munmap() overhead.
 */
static gboolean
page_cache_timer(gpointer unused_udata)
{
	time_t now = tm_time();
	static size_t line;
	struct page_cache *pc;
	size_t i;
	size_t expired = 0;

	(void) unused_udata;

	if (VMM_CACHE_LINES == line)
		line = 0;

	pc = &page_cache[line];

	if (vmm_debugging(pc->current > 0 ? 4 : 8)) {
		g_message("VMM scanning page cache #%u (%u item%s)",
			line, (unsigned) pc->current, 1 == pc->current ? "" : "s");
	}

	for (i = 0; i < pc->current; /* empty */) {
		time_delta_t d = delta_time(now, pc->info[i].stamp);
		if (d >= VMM_CACHE_LIFE) {
			vpc_free(pc, i);
			expired++;
		} else {
			i++;
		}
	}

	if (expired > 0 && vmm_debugging(1)) {
		g_message("VMM expired %u item%s (%uKiB total) from "
			"page cache #%u (%u item%s remaining)",
			(unsigned) expired, 1 == expired ? "" : "s",
			(unsigned) (expired * pc->chunksize / 1024),
			line, pc->current, 1 == pc->current ? "" : "s");
	}

	line++;			/* For next time */
	return TRUE;	/* Keep scheduling */
}

/**
 * Copies the given string to a read-only buffer. vmm_free() can be used
 * to free the memory.
 *
 * @param s A NUL-terminated string. If NULL, NULL is returned.
 * @return	On success, a copy of the string is returned. On failure, NULL
 *			is returned.
 */
const char *
prot_strdup(const char *s)
{
	size_t n;
	void *p;

	if (!s)
		return NULL;

	n = strlen(s) + 1;
	p = alloc_pages(round_pagesize_fast(n));
	if (p) {
		memcpy(p, s, n);
		mprotect(p, n, PROT_READ);
	}
	return p;
}

/**
 * @return	A page-sized and page-aligned chunk of memory which causes an
 *			exception to be raised if accessed.
 */
const void *
vmm_trap_page(void)
{
		static void *trap_page;

		if (!trap_page) {
			size_t size;
		   
			size = compat_pagesize();
			trap_page = alloc_pages(size);
			RUNTIME_ASSERT(trap_page);
			mprotect(trap_page, size, PROT_NONE);
		}
		return trap_page;
}

/**
 * Set VMM debug level.
 */
void
set_vmm_debug(guint32 level)
{
	vmm_debug = level;
}

/**
 * Called when memory allocator has been initialized and it is possible to
 * call routines that will allocate core memory and perform logging calls.
 */
void
vmm_malloc_inited(void)
{
	extern gboolean debugging(guint32 t);

	safe_to_malloc = TRUE;

	if (debugging(0) || vmm_debugging(0)) {
		g_message("VMM using %u bytes for the page cache",
			(unsigned) sizeof page_cache);
	}

	cq_periodic_add(callout_queue, 1000, page_cache_timer, NULL);
}

/**
 * Initialize the vitual memory manager.
 *
 * @attention
 * No memory allocation can be done in this routine, which is called very
 * early at startup.
 */
void
vmm_init(void)
{
	int i;
	size_t pagesize = compat_pagesize();

	for (i = 0; i < VMM_CACHE_LINES; i++) {
		struct page_cache *pc = &page_cache[i];
		size_t pages = i + 1;
		pc->pages = pages;
		pc->chunksize = pages * pagesize;
	}
}

/* vi: set ts=4 sw=4 cindent: */
