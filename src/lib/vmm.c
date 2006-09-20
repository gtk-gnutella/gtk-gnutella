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

static size_t kernel_pagesize = 0;
static size_t kernel_pagemask = 0;
static gint kernel_pageshift = 0;

static struct {
	struct {
		gpointer addr;
		time_t stamp;
	} stack[512];
	guint current;
} page_cache[16];

static const time_delta_t page_cache_prune_timeout = 20; /* unit: seconds */

static void
init_kernel_pagesize(void)
{
	kernel_pagesize = compat_pagesize();
	g_assert(is_pow2(kernel_pagesize));
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

static glong
compat_pagesize_intern(void)
#if defined (_SC_PAGE_SIZE)
{
	glong ret;

	errno = 0;
	ret = sysconf(_SC_PAGE_SIZE);
	if ((glong) -1 == ret && 0 != errno) {
		g_warning("sysconf(_SC_PAGE_SIZE) failed: %s", g_strerror(errno));
		return 0;
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
	static gboolean initialized;
	static size_t psize;

	if (!initialized) {
		glong n;
		
		initialized = TRUE;
		n = compat_pagesize_intern();
		g_assert(n > 0);
		g_assert(n < INT_MAX);
		g_assert(is_pow2(n));
		psize = n;
		g_assert((gulong) psize == (gulong) n);
	}

	return psize;
}

static gpointer
alloc_pages_intern(size_t size)
{
	void *p;

	g_assert(kernel_pagesize > 0);		/* Computed by round_pagesize_fast() */

#if defined(HAS_MMAP)
	{
		static gint fd = -1, flags = MAP_PRIVATE;
		
#if defined(MAP_ANON)
		flags |= MAP_ANON;
#elif defined (MAP_ANONYMOUS)
		flags |= MAP_ANONYMOUS;
#else
		if (-1 == fd)
			fd = open("/dev/zero", O_RDWR, 0);
		if (-1 == fd)
			g_error("alloc_pages(): open() failed for /dev/zero");
#endif	/* MAP_ANON */
		
		p = mmap(0, size, PROT_READ | PROT_WRITE, flags, fd, 0);
		if (MAP_FAILED == p)
			g_error("mmap(0, %lu, PROT_READ | PROT_WRITE, 0x%x, %d, 0) failed:"
				 " %s", (gulong) size, flags, fd, g_strerror(errno));
	}
#elif defined(HAS_POSIX_MEMALIGN)
	if (posix_memalign(&p, kernel_pagesize, size)) {
		g_error("posix_memalign() failed: %s", g_strerror(errno));
	}
#elif defined(HAS_MEMALIGN)
	p = memalign(kernel_pagesize, size);
	if (!p) {
		g_error("memalign() failed: %s", g_strerror(errno));
	}
#else
#error "Neither mmap(), posix_memalign() nor memalign() available"
	p = NULL;
	g_error("Neither mmap(), posix_memalign() nor memalign() available");
#endif	/* HAS_MMAP || HAS_POSIX_MEMALIGN || HAS_MEMALIGN */
	
	if (round_pagesize_fast((size_t) p) != (size_t) p)
		g_error("Aligned memory required");

	return p;
}

/**
 * Allocates a page-aligned memory chunk.
 *
 * @param size The size in bytes to allocate; will be rounded to the pagesize.
 */
gpointer
alloc_pages(size_t size)
{
	size_t n;

	g_assert(size > 0);
	
	size = round_pagesize_fast(size);
	n = pagecount_fast(size) - 1;

	if (n < G_N_ELEMENTS(page_cache)) {
		if (page_cache[n].current > 0) {
			void *p = page_cache[n].stack[--page_cache[n].current].addr;
			g_assert(p);
#ifdef INVALIDATE_FREE_PAGES 
			mprotect(p, size, PROT_READ | PROT_WRITE);
			madvise(p, size, MADV_NORMAL);
#endif	/* INVALIDATE_FREE_PAGES */
			return p;
		} else {
#ifdef GREEDY_PAGE_CACHE
			guint max_cached = G_N_ELEMENTS(page_cache[0].stack) / (n + 1);
			char *p, *base = alloc_pages_intern(max_cached * size);

			/*
			 * Split the big chunk into segments by freeing the pages from
			 * the end, filling the whole cache for this size.
			 */

			p = &base[(max_cached - 1) * size];
			while (p != base) {
				free_pages(p, size);		/* Fills the cache entry */
				p -= size;
			}
			return p;
#endif	/* GREEDY_PAGE_CACHE */
		}
	}
	return alloc_pages_intern(size);
}

static void
free_pages_intern(gpointer p, size_t size)
{
#if defined(HAS_MMAP)
	if (-1 == munmap(p, size))
		g_warning("munmap(0x%lx, %ld) failed: %s",
				(gulong) p, (gulong) size, g_strerror(errno));
#elif defined(HAS_POSIX_MEMALIGN) || defined(HAS_MEMALIGN)
	(void) size;
	free(p);
#else
	(void) p;
	(void) size;
	g_assert_not_reached();
#endif	/* HAS_POSIX_MEMALIGN || HAS_MEMALIGN */
}

/**
 * Free memory allocated via alloc_pages().
 */
void
free_pages(gpointer p, size_t size)
{
	g_assert(0 == size || p);

	if (p) {
		size_t n;
		guint max_cached;

		g_assert(round_pagesize_fast((size_t) p) == (size_t) p);

		/*
		 * We cache 512 4KiB pages for instance, but only 256 8KiB pages,
		 * up to 32 64KiB pages, so that the amount of memory cached
		 * per "size bucket" is constant.
		 *		--RAM, 2006-09-16
		 */

		size = round_pagesize_fast(size);
		n = pagecount_fast(size);
		g_assert(n >= 1);
		max_cached = G_N_ELEMENTS(page_cache[0].stack) / n ;
		n--;

		if (
			n < G_N_ELEMENTS(page_cache) &&
			page_cache[n].current < max_cached
		) {
#ifdef INVALIDATE_FREE_PAGES 
			mprotect(p, size, PROT_NONE);
#ifdef MADV_FREE
			madvise(p, size, MADV_FREE);
#else
			madvise(p, size, MADV_DONTNEED);
#endif	/* MADV_FREE */
#endif	/* INVALIDATE_FREE_PAGES */
			page_cache[n].stack[page_cache[n].current].addr = p;
			page_cache[n].stack[page_cache[n].current].stamp = tm_time();
			page_cache[n].current++;
		} else
			free_pages_intern(p, size);
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
	size_t size = 0, total = 0;
	guint n;

	for (n = 0; n < G_N_ELEMENTS(page_cache); n++) {
		guint i, cur, pruned;

		pruned = 0;
		cur = page_cache[n].current;
		size += compat_pagesize();

		for (i = 0; i < cur; i++) {
			time_delta_t d = delta_time(now, page_cache[n].stack[i].stamp);
			if (d < page_cache_prune_timeout)
				break;
			g_assert(page_cache[n].stack[i].addr);
			free_pages_intern(page_cache[n].stack[i].addr, size);
			page_cache[n].stack[i].addr = NULL;
			pruned++;
		}
		if (pruned > 0) {
			g_assert(page_cache[n].current >= pruned);
			page_cache[n].current -= pruned;
			total += pruned * size;

			memmove(&page_cache[n].stack[0], &page_cache[n].stack[pruned],
				(cur - pruned) * sizeof page_cache[n].stack[0]);
		}
	}
	return total;
}

/* vi: set ts=4 sw=4 cindent: */
