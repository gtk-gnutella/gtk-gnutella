/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
 * Copyright (c) 2006, Raphael Manfredi
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
 * @author Raphael Manfredi
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include "misc.h"
#include "tm.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * With VMM_GREEDY_PAGE_CACHE we always map memory for a complete slot. This
 * causes some over-allocation but reduces page-table fragmentation.
 */
/* #define VMM_GREEDY_PAGE_CACHE 1 */

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

/*
 * Cached pages older than `page_cache_prune_timeout' seconds are released
 * to prevent that they are unnecessarily paged out to swap.
 */
static const time_delta_t page_cache_prune_timeout = 20; /* unit: seconds */

static size_t kernel_pagesize = 0;
static size_t kernel_pagemask = 0;
static unsigned kernel_pageshift = 0;

struct page_stack {
	void *addr;		/**< base address */
	time_t stamp;	/**< time at which the page was inserted */
};

struct page_cache {
	size_t current;	/**< amount of currently used slots */
	struct page_stack stack[512];
};

static struct page_cache page_cache[16];

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
 * @param size The amount of bytes to allocate.
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
	return p;
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

	RUNTIME_ASSERT(size > 0);
	
	size = round_pagesize_fast(size);
	n = pagecount_fast(size) - 1;

	if (n < G_N_ELEMENTS(page_cache)) {
		if (page_cache[n].current > 0) {
			void *p = page_cache[n].stack[--page_cache[n].current].addr;
			vmm_validate_pages(p, size);
			return p;
		} else {
			unsigned m, max_cached;
			char *p, *base;

#ifdef VMM_GREEDY_PAGE_CACHE
		   	max_cached = G_N_ELEMENTS(page_cache[0].stack) / (n + 1);
#else
			max_cached = 1;
#endif	/* VMM_GREEDY_PAGE_CACHE */

			/*
			 * If alloc_pages() fails we are approaching our memory
			 * limit, so we retry with less pre-allocated pages.
			 */
			m = max_cached;
			do {
				base = alloc_pages(m * size);
				if (base) {
					max_cached = m;
					break;
				}
			} while (m-- > 1);

			/*
			 * If alloc_pages() failed completely, we retry with a
			 * a larger size to grab cached pages from the next level.
			 */

			if (!base && n < G_N_ELEMENTS(page_cache) - 1) {
				max_cached *= 2;	/* We will halve the pages */
				base = vmm_alloc(size * 2);
			}
			RUNTIME_ASSERT(NULL != base);	/* Out of memory */
	
			/*
			 * Split the big chunk into segments by freeing the pages from
			 * the end, filling the whole cache for this size.
			 */

			p = &base[(max_cached - 1) * size];
			while (p != base) {
				vmm_free(p, size);			/* Fills the cache entry */
				p -= size;
			}
			return p;
		}
	} else {
		void *p = alloc_pages(size);
		RUNTIME_ASSERT(NULL != p);	/* Out of memory */
		return p;
	}
}

void *
vmm_alloc0(size_t size)
{
	void *p;

	/* FIXME: If the pages are freshly mapped they are already clean */
	p = vmm_alloc(size);
	if (p) {
		memset(p, 0, size);
	}
	return p;	
}

static void
free_pages(void *p, size_t size)
{
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
 * Free memory allocated via vmm_alloc().
 */
void
vmm_free(void *p, size_t size)
{
	RUNTIME_ASSERT(0 == size || p);

	if (p) {
		size_t n, max_cached;

		RUNTIME_ASSERT(round_pagesize_fast((size_t) p) == (size_t) p);

		/*
		 * We cache 512 4KiB pages for instance, but only 256 8KiB pages,
		 * up to 32 64KiB pages, so that the amount of memory cached
		 * per "size bucket" is constant.
		 *		--RAM, 2006-09-16
		 */

		size = round_pagesize_fast(size);
		n = pagecount_fast(size);
		RUNTIME_ASSERT(n >= 1);
		max_cached = G_N_ELEMENTS(page_cache[0].stack) / n;
		n--;

		if (
			n < G_N_ELEMENTS(page_cache) &&
			page_cache[n].current < max_cached
		) {
			vmm_invalidate_pages(p, size);
			page_cache[n].stack[page_cache[n].current].addr = p;
			page_cache[n].stack[page_cache[n].current].stamp = tm_time();
			page_cache[n].current++;
		} else
			free_pages(p, size);
	}
}

/**
 * Scans the page cache for old pages and releases them if they have a certain
 * minimum age. We don't want to cache pages forever because they might never
 * be reused. Further, the OS would page them out anyway because they are
 * considered dirty even though we don't care about the content anymore. If we
 * recycled such old pages, the penalty from paging them in is unlikely lower
 * than the mmap()/munmap() overhead.
 *
 * @return The amount of memory in bytes that was unmapped.
 */
size_t
prune_page_cache(void)
{
	time_t now = tm_time();
	size_t size = 0, total = 0, n;

	for (n = 0; n < G_N_ELEMENTS(page_cache); n++) {
		size_t i, cur, pruned;

		pruned = 0;
		cur = page_cache[n].current;
		size += compat_pagesize();

		for (i = 0; i < cur; i++) {
			time_delta_t d = delta_time(now, page_cache[n].stack[i].stamp);
			if (d < page_cache_prune_timeout)
				break;
			RUNTIME_ASSERT(page_cache[n].stack[i].addr);
			free_pages(page_cache[n].stack[i].addr, size);
			page_cache[n].stack[i].addr = NULL;
			pruned++;
		}
		if (pruned > 0) {
			RUNTIME_ASSERT(page_cache[n].current >= pruned);
			page_cache[n].current -= pruned;
			total += pruned * size;

			memmove(&page_cache[n].stack[0], &page_cache[n].stack[pruned],
				(cur - pruned) * sizeof page_cache[n].stack[0]);
		}
	}
	return total;
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

/* vi: set ts=4 sw=4 cindent: */
