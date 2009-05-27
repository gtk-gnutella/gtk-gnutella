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
 * This is the lowest-level memory allocator, dealing with memory regions
 * at the granularity of a memory page.
 *
 * Although the application can use this layer directly, it should rely on
 * other memory allocators such as walloc(), a wrapping layer over zalloc(),
 * or halloc() when tracking the size of the allocated area is impractical
 * or just impossible.
 *
 * @author Christian Biere
 * @date 2006
 * @author Raphael Manfredi
 * @date 2006, 2009
 */

#include "common.h"

RCSID("$Id$")

#include "vmm.h"

#include "ascii.h"
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
static gboolean kernel_mapaddr_increasing;

#define VMM_CACHE_SIZE		256	/**< Amount of entries per cache line */
#define VMM_CACHE_LINES		32	/**< Amount of cache lines */
#define VMM_CACHE_LIFE		60	/**< At most 1 minute if not fragmenting */
#define VMM_CACHE_MAXLIFE	180	/**< At most 3 minutes if fragmenting */

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

/**
 * Structure used to represent a fragment in the virtual memory space.
 *
 * If the fragment is owned by the VMM layer, the end address is the first byte
 * beyond the end of the memory region (hence it is even).
 * If the fragment is a foreign one, then the end address is the last byte of
 * the memory region (hence it is odd).
 */
struct vm_fragment {
	const void *start;		/**< Start address */
	const void *end;		/**< End address (special, see comment above) */
};

/**
 * A process virtual memory map.
 *
 * The array holding the sorted fragments is allocated via alloc_pages().
 */
struct pmap {
	struct vm_fragment *array;		/**< Sorted array of vm_fragment structs */
	size_t count;					/**< Amount of entries in array */
	size_t size;					/**< Total amount of slots in array */
	size_t pages;					/**< Amount of pages for the array */
};

/**
 * The kernel version of the pmap and our own version.
 */
static struct pmap kernel_pmap;
static struct pmap local_pmap;

static gboolean safe_to_malloc;		/**< True when malloc() was inited */
static guint32 vmm_debug;			/**< Debug level */

static inline gboolean
vmm_debugging(guint32 lvl)
{
	return safe_to_malloc && vmm_debug > lvl;
}

static inline struct pmap *
vmm_pmap(void)
{
	return kernel_pmap.count ? &kernel_pmap : &local_pmap;
}

static void page_cache_insert_pages(void *base, size_t n);
static void pmap_remove(struct pmap *pm, void *p, size_t size);
static void pmap_load(struct pmap *pm);
static void pmap_insert_region(struct pmap *pm,
	const void *start, size_t size, gboolean foreign);

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
 * @return whether fragment is identified as foreign.
 */
static inline gboolean
vmf_is_foreign(const struct vm_fragment *vmf)
{
	return 0 != (pointer_to_ulong(vmf->end) & 0x1);
}

/**
 * Mark fragment as foreign.
 */
static void
vmf_mark_foreign(struct vm_fragment *vmf)
{
	if (!vmf_is_foreign(vmf)) {
		vmf->end = ptr_add_offset(deconstify_gpointer(vmf->end), -1);
	}
}

/**
 * @return first byte after the end of a fragment.
 */
static inline const void *
vmf_end(const struct vm_fragment *vmf)
{
	return vmf_is_foreign(vmf) ?
		ptr_add_offset(deconstify_gpointer(vmf->end), 1) : vmf->end;
}

/**
 * @return size of a memory fragment.
 */
static inline size_t
vmf_size(const struct vm_fragment *vmf)
{
	return ptr_diff(vmf_end(vmf), vmf->start);
}

/**
 * Dump current pmap.
 */
static void
vmm_dump_pmap(void)
{
	struct pmap *pm = vmm_pmap();
	size_t i;

	g_message("VMM current %s pmap (%lu region%s):",
		pm == &kernel_pmap ? "kernel" :
		pm == &local_pmap ? "local" : "unknown",
		(unsigned long) pm->count, 1 == pm->count ? "" : "s");

	for (i = 0; i < pm->count; i++) {
		struct vm_fragment *vmf = &pm->array[i];
		size_t hole = 0;

		if (i < pm->count - 1) {
			const void *next = pm->array[i+1].start;
			hole = ptr_diff(next, vmf_end(vmf));
		}

		g_message("VMM [0x%lx, 0x%lx] %luKiB%s%s%s%s",
			(unsigned long) vmf->start,
			(unsigned long) ptr_add_offset_const(vmf_end(vmf), -1),
			(unsigned long) (vmf_size(vmf) / 1024),
			vmf_is_foreign(vmf) ? " (foreign)" : "",
			hole ? " + " : "",
			hole ? size_t_to_string(hole / 1024) : "",
			hole ? "KiB hole" : "");
	}
}

#ifdef HAS_MMAP
/**
 * Find a hole in the virtual memory map where we could allocate "size" bytes.
 */
static const void *
vmm_find_hole(size_t size)
{
	struct pmap *pm = vmm_pmap();
	size_t i;

	if (pm == &local_pmap || 0 == pm->count)
		return NULL;

	if (kernel_mapaddr_increasing) {
		for (i = 0; i < pm->count; i++) {
			struct vm_fragment *vmf = &pm->array[i];
			const void *end = vmf_end(vmf);

			if (i == pm->count - 1) {
				return end;
			} else {
				struct vm_fragment *next = &pm->array[i + 1];

				if (ptr_diff(next->start, end) >= size)
					return end;
			}
		}
	} else {
		for (i = pm->count; i > 0; i--) {
			struct vm_fragment *vmf = &pm->array[i - 1];

			if (i == 1) {
				return ptr_add_offset_const(vmf->start, -size);
			} else {
				struct vm_fragment *prev = &pm->array[i - 2];

				if (ptr_diff(vmf->start, vmf_end(prev)) >= size)
					return ptr_add_offset_const(vmf->start, -size);
			}
		}
	}

	if (vmm_debugging(0)) {
		g_warning("VMM no %luKiB hole found in pmap",
			(unsigned long) (size / 1024));
	}

	return NULL;
}

/**
 * Insert foreign region in the pmap.
 */
static void
pmap_insert_foreign(struct pmap *pm, const void *start, size_t size)
{
	pmap_insert_region(pm, start, size, TRUE);
}
#endif	/* HAS_MMAP */

/**
 * Allocate a new chunk of anonymous memory.
 */
static void *
vmm_mmap_anonymous(size_t size)
#if defined(HAS_MMAP)
{
	static int flags, failed, fd = -1;
	void *p;
	void *hint;

	if (failed)
		return NULL;

	hint = deconstify_gpointer(vmm_find_hole(size));

	if (hint != NULL && vmm_debugging(7)) {
		g_message("VMM hinting 0x%lx for new %luKiB region",
			(unsigned long) hint, (unsigned long) (size / 1024));
	}

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

	p = mmap(hint, size, PROT_READ | PROT_WRITE, flags, fd, 0);
	if (MAP_FAILED == p) {
		if (ENOMEM != errno) {
			failed = 1;
			return_value_unless(MAP_FAILED != p, NULL);
		}
		p = NULL;
	} else if (hint != NULL && p != hint) {
		if (vmm_debugging(0)) {
			g_warning("VMM kernel did not follow hint 0x%lx for %luKiB region, "
				"picked 0x%lx",
				(unsigned long) hint, (unsigned long) (size / 1024),
				(unsigned long) p);
		}

		/*
		 * Kernel did not use our hint, maybe it was wrong because something
		 * got mapped at the place where we thought there was nothing...
		 *
		 * Reload the current kernel pmap if we're able to do so, otherwise
		 * mark the page at the selected hint as "foreign" so that we never
		 * attempt to select it again.
		 */

		if (vmm_pmap() == &kernel_pmap) {
			pmap_load(&kernel_pmap);
		} else {
			pmap_insert_foreign(vmm_pmap(), hint, kernel_pagesize);
		}
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
 * Insert region in the pmap, known to be native (i.e. non-foreign).
 */
static void
pmap_insert(struct pmap *pm, const void *start, size_t size)
{
	pmap_insert_region(pm, start, size, FALSE);
}

/**
 * Allocates a page-aligned chunk of memory.
 *
 * @param size			the amount of bytes to allocate.
 * @param update_pmap	whether our VMM pmap should be updated
 *
 * @return On success a pointer to the allocated chunk is returned. On
 *		   failure NULL is returned.
 */
static void *
alloc_pages(size_t size, gboolean update_pmap)
{
	void *p;

	RUNTIME_ASSERT(kernel_pagesize > 0);

	p = vmm_mmap_anonymous(size);
	return_value_unless(NULL != p, NULL);
	
	if (round_pagesize_fast((size_t) p) != (size_t) p) {
		RUNTIME_ASSERT(!"Aligned memory required");
	}

	if (vmm_debugging(5)) {
		g_message("VMM allocated %luKiB region at 0x%lx",
			(unsigned long) size / 1024, (unsigned long) p);
	}

	if (update_pmap)
		pmap_insert(vmm_pmap(), p, size);

	return p;
}

/**
 * Release pages allocated by alloc_pages().
 * Must not be called directly other than through free_pages*() routines.
 */
static void
free_pages_intern(void *p, size_t size, gboolean update_pmap)
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

	if (update_pmap)
		pmap_remove(vmm_pmap(), p, size);
}

/**
 * Free memory allocated by alloc_pages().
 */
static void
free_pages(void *p, size_t size, gboolean update_pmap)
{
	if (vmm_debugging(5)) {
		g_message("VMM freeing %luKiB region at 0x%lx",
			(unsigned long) size / 1024, (unsigned long) p);
	}

	free_pages_intern(p, size, update_pmap);
}

/**
 * Allocate a new pmap.
 */
static void
pmap_allocate(struct pmap *pm)
{
	g_assert(NULL == pm->array);
	g_assert(0 == pm->pages);

	pm->array = alloc_pages(kernel_pagesize, FALSE);
	pm->pages = 1;
	pm->count = 0;
	pm->size = kernel_pagesize / sizeof pm->array[0];

	if (NULL == pm->array)
		g_error("cannot initialize the VMM layer: out of memory already?");

	pmap_insert(vmm_pmap(), pm->array, kernel_pagesize);
}

/**
 * Extend the pmap by allocating one more page.
 */
static void
pmap_extend(struct pmap *pm)
{
	struct vm_fragment *narray;
	size_t nsize;
	size_t osize;
	void *oarray;

	osize = kernel_pagesize * pm->pages;
	nsize = osize + kernel_pagesize;

	/*
	 * It is possible to recursively enter here through alloc_pages() when
	 * mmap() is used to allocate virtual memory, in case we reload the
	 * kernel map or insert a foreign region.
	 *
	 * To protect against that, we start by allocating the new pages and
	 * remember the amount of pages in the map.  If upon return from the
	 * alloc_pages() call we see the number is different, it means the
	 * allocation was done and we can free up the pages we already allocated
	 * and return.
	 */

	{
		size_t old_pages = pm->pages;

		narray = alloc_pages(nsize, FALSE);

		if (pm->pages != old_pages) {
			if (vmm_debugging(0))
				g_warning("VMM already recursed to pmap_extend(), ignoring");
			if (narray != NULL)
				free_pages(narray, nsize, FALSE);
			return;
		}

		if (NULL == narray)
			g_error("cannot extend pmap: out of virtual memory");
	}

	oarray = pm->array;
	pm->pages++;
	pm->size = nsize / sizeof pm->array[0];
	memcpy(narray, oarray, osize);
	pm->array = narray;

	/*
	 * Freeing could update the pmap we've been extending.
	 *
	 * The structure must therefore be in a consistent state before the old
	 * array can be freed, so this must come last.
	 */

	free_pages(oarray, osize, TRUE);
	pmap_insert(vmm_pmap(), narray, nsize);
}

/**
 * Lookup address within the pmap.
 *
 * If ``low_ptr'' is non-NULL, it is written with the index where insertion
 * of a new item should happen (in which case the returned value must be NULL).
 *
 * @return found fragment if address lies within the fragment, NULL if
 * no fragment containing the address was found.
 */
static struct vm_fragment *
pmap_lookup(const struct pmap *pm, const void *p, size_t *low_ptr)
{
	size_t low = 0, high = pm->count - 1;
	struct vm_fragment *item;

	/* Binary search */

	for (;;) {
		size_t mid;

		if (low > high || high > SIZE_MAX / 2) {
			item = NULL;		/* Not found */
			break;
		}

		mid = low + (high - low) / 2;

		g_assert(mid < pm->count);

		item = &pm->array[mid];
		if (p >= vmf_end(item))
			low = mid + 1;
		else if (p < item->start)
			high = mid - 1;
		else
			break;	/* Found */
	}

	if (low_ptr != NULL)
		*low_ptr = low;

	return item;
}

/**
 * Add a new fragment at the tail of pmap (must be added in order).
 */
static void
pmap_add(struct pmap *pm, const void *start, const void *end, gboolean foreign)
{
	struct vm_fragment *vmf;

	g_assert(pm->array != NULL);
	g_assert(pm->count <= pm->size);
	g_assert(start < end);

	if (pm->count == pm->size)
		pmap_extend(pm);

	g_assert(pm->count < pm->size);

	/*
	 * Ensure that entries are inserted in order.
	 */

	if (pm->count > 0) {
		vmf = &pm->array[pm->count - 1];
		g_assert(start >= vmf->end);
	}

	/*
	 * For foreign fragments (not allocated by VMM), the end pointer is not
	 * the first byte after the end of the region but the last valid pointer
	 * of the region.
	 */

	vmf = &pm->array[pm->count++];
	vmf->start = start;
	vmf->end = foreign ? ptr_add_offset(deconstify_gpointer(end), -1) : end;
}

/**
 * Insert region in the pmap.
 */
static void
pmap_insert_region(struct pmap *pm,
	const void *start, size_t size, gboolean foreign)
{
	const void *end = ptr_add_offset_const(start, size);
	struct vm_fragment *vmf;
	size_t idx;

	g_assert(pm->array != NULL);
	g_assert(pm->count <= pm->size);
	g_assert(start < end);

	if (pm->count == pm->size)
		pmap_extend(pm);

	if (pmap_lookup(pm, start, &idx))
		g_error("pmap already contains the new region");

	g_assert(pm->count < pm->size);
	g_assert(idx <= pm->count);

	/*
	 * See whether we can coalesce the new region with the existing ones.
	 * We can't coalesce a native region with a foreign one.
	 */

	if (idx > 0) {
		struct vm_fragment *prev = &pm->array[idx - 1];

		if (!foreign == !vmf_is_foreign(prev) && prev->end == start) {
			prev->end = end;
			if (foreign)
				vmf_mark_foreign(prev);

			/*
			 * If we're now bumping into the next chunk, we need to coalesce
			 * it with the previous one and get rid of its entry.
			 */
			
			if (idx < pm->count) {
				struct vm_fragment *next = &pm->array[idx];

				if (!foreign == !vmf_is_foreign(next) && next->start == end) {
					prev->end = next->end;
					pm->count--;
					if (idx < pm->count) {
						memmove(&pm->array[idx], &pm->array[idx+1],
							sizeof(pm->array[0]) * (pm->count - idx));
					}
				}
			}
			return;
		}
	}

	if (idx < pm->count) {
		struct vm_fragment *next = &pm->array[idx];

		if (!foreign == !vmf_is_foreign(next) && next->start == end) {
			next->start = start;
			return;
		}

		/*
		 * Make room before ``idx'', the insertion point.
		 */

		memmove(&pm->array[idx+1], &pm->array[idx],
			sizeof(pm->array[0]) * (pm->count - idx));
	}

	pm->count++;
	vmf = &pm->array[idx];
	vmf->start = start;
	vmf->end = end;

	if (foreign)
		vmf_mark_foreign(vmf);
}

/**
 * Parse a line read from /proc/self/maps and add it to the map.
 * @return TRUE if we managed to parse the line correctly
 */
static gboolean
pmap_parse_and_add(struct pmap *pm, char *line)
{
	int error;
	const char *ep;
	const char *p = line;
	const void *start, *end;
	gboolean foreign = FALSE;

	if (vmm_debugging(9))
		g_message("VMM parsing \"%s\"", line);

	/*
	 * Typical format of lines on linux:
	 *
	 *                                 device
	 *  start  -  end    perm offset   mj:mn
	 *
	 * 08048000-0804f000 r-xp 00000000 09:00 1585       /bin/cat
	 * 08050000-08071000 rw-p 08050000 00:00 0          [heap]
	 * b7f9a000-b7f9d000 rw-p b7f9a000 00:00 0
	 * bfdba000-bfdcf000 rw-p bffeb000 00:00 0          [stack]
	 */

	start = parse_pointer(p, &ep, &error);
	if (error || NULL == start) {
		if (vmm_debugging(0))
			g_warning("VMM cannot parse start address");
		return FALSE;
	}

	if (*ep != '-')
		return FALSE;

	p = ++ep;
	end = parse_pointer(p, &ep, &error);
	if (error || NULL == end) {
		if (vmm_debugging(0))
			g_warning("VMM cannot parse end address");
		return FALSE;
	}

	if (end <= start) {
		if (vmm_debugging(0))
			g_warning("VMM invalid start/end address pair");
		return FALSE;
	}

	p = skip_ascii_blanks(ep);

	{
		char perms[4];
		int i;
		int c;

		for (i = 0; i < 4; i++) {
			c = *p++;
			if ('0' == c) {
				if (vmm_debugging(0))
					g_warning("VMM short permission string");
				return FALSE;
			}
			perms[i] = c;
		}

		if ('x' == perms[2] || 'w' != perms[1] || 'p' != perms[3])
			foreign = TRUE;		/* This region was not allocated by VMM */
	}

	pmap_add(pm, start, end, foreign);

	return TRUE;
}

/**
 * Load the process's memory map from /proc/self/maps into the supplied map.
 */
static void
pmap_load(struct pmap *pm)
{
	static int failed;
	int fd;
	char buf[4096];
	int rw;
	int pos;
	int size;

	if (failed)
		return;

	if (vmm_debugging(8))
		g_message("VMM loading kernel memory map");

	/*
	 * This is a low-level routine, do not use stdio at all as it could
	 * allocate memory and re-enter the VMM layer.  Likewise, do not
	 * allocate any memory, excepted for the pmap where entries are stored.
	 */

	fd = open("/proc/self/maps", O_RDONLY);
	if (-1 == fd) {
		failed = TRUE;
		if (vmm_debugging(0))
			g_warning("VMM cannot open /proc/self/maps: %s", g_strerror(errno));
		return;
	}

	pm->count = 0;
	rw = pos = size = 0;

	for (;;) {
		char *p;
		int c;

		g_assert(size >= 0);

		if (pos == size) {
			g_assert(UNSIGNED(size) < sizeof buf);
			rw = read(fd, &buf[size], sizeof buf - size);
			if (0 == rw)
				break;				/* Done, EOF reached */
			else if (-1 == rw) {
				if (vmm_debugging(0)) {
					g_warning("VMM error reading /proc/self/maps: %s",
						g_strerror(errno));
				}
				break;
			}
			size += rw;
		}

		g_assert(UNSIGNED(size) <= sizeof buf);
		g_assert(pos < size);

		p = &buf[pos];
		while (pos < size && (c = *p)) {
			if ('\n' == c) {
				*p = '\0';
				goto eol_found;
			}
			pos++;
			p++;
		}

		if ('\0' == c) {
			if (vmm_debugging(0)) {
				g_warning("VMM unexpected NUL in /proc/self/maps output");
			}
			failed = TRUE;
			goto done;
		}

		if (pos == size && UNSIGNED(size) < sizeof buf)
			continue;

		if (vmm_debugging(0)) {
			g_warning("VMM too long a line in /proc/self/maps output");
		}
		failed = TRUE;
		goto done;

	eol_found:
		/*
		 * Found a line, contained from buf[0] to buf[pos] (trailing NUL).
		 */

		if (!pmap_parse_and_add(pm, buf)) {
			if (vmm_debugging(0)) {
				g_warning("VMM error parsing \"%s\"", buf);
			}
			failed = TRUE;
			goto done;
		}

		if (pos < size - 1) {
			memmove(&buf[0], &buf[pos+1], size - pos - 1);
		}
		size -= pos + 1;
		pos = 0;
	}

done:
	close(fd);

	if (vmm_debugging(1)) {
		g_message("VMM kernel memory map holds %lu region%s",
			(unsigned long) pm->count, 1 == pm->count ? "" : "s");
	}
}

/**
 * Log missing region.
 */
static void
pmap_log_missing(const struct pmap *pm, const void *p, size_t size)
{
	if (vmm_debugging(0)) {
		g_warning("VMM %luKiB region at 0x%lx missing from %s pmap",
			(unsigned long) (size / 1024), (unsigned long) p,
			pm == &kernel_pmap ? "kernel" :
			pm == &local_pmap ? "local" : "unknown");
	}
}

/**
 * Is block within an identified region, and not at the beginning or tail?
 */
static gboolean
pmap_is_within_region(const struct pmap *pm, const void *p, size_t size)
{
	struct vm_fragment *vmf;

	vmf = pmap_lookup(pm, p, NULL);

	if (NULL == vmf) {
		pmap_log_missing(pm, p, size);
		return FALSE;
	}

	return p != vmf->start && vmf_end(vmf) != ptr_add_offset_const(p, size);
}

/**
 * Is block an identified fragment?
 */
static gboolean
pmap_is_fragment(const struct pmap *pm, const void *p, size_t npages)
{
	struct vm_fragment *vmf;

	vmf = pmap_lookup(pm, p, NULL);

	if (NULL == vmf) {
		pmap_log_missing(pm, p, npages * kernel_pagesize);
		return FALSE;
	}

	return p == vmf->start && npages == pagecount_fast(vmf_size(vmf));
}

/**
 * Remove whole region from the list of identified fragments.
 */
static void
pmap_remove_whole_region(struct pmap *pm, const void *p, size_t size)
{
	struct vm_fragment *vmf;
	size_t idx;

	vmf = pmap_lookup(pm, p, NULL);

	g_assert(vmf != NULL);				/* Must be found */
	g_assert(vmf_size(vmf) == size);	/* And with the proper size */

	idx = vmf - pm->array;
	g_assert(size_is_non_negative(idx) && idx < pm->count);

	if (idx != pm->count - 1) {
		memmove(&pm->array[idx], &pm->array[idx + 1],
			(pm->count - idx - 1) * sizeof pm->array[0]);
	}

	pm->count--;
}

/**
 * Remove region from the pmap, which can create a new fragment.
 */
static void
pmap_remove(struct pmap *pm, void *p, size_t size)
{
	struct vm_fragment *vmf = pmap_lookup(pm, p, NULL);

	if (vmf != NULL) {
		const void *end = ptr_add_offset_const(p, size);

		g_assert(!vmf_is_foreign(vmf));	/* Cannot remove foreign entries */

		if (p == vmf->start) {

			if (vmm_debugging(2)) {
				g_message("VMM %luKiB region at 0x%lx was %s fragment",
					(unsigned long) size / 1024, (unsigned long) p,
					end == vmf->end ? "a whole" : "start of a");
			}

			if (end == vmf->end) {
				pmap_remove_whole_region(pm, p, size);
			} else {
				vmf->start = end;			/* Known fragment reduced */
				g_assert(vmf->start < vmf->end);
			}
		} else {
			const void *vend = vmf->end;

			g_assert(vmf->start < p);
			g_assert(end <= vend);

			vmf->end = p;

			if (end != vend) {
				if (vmm_debugging(1)) {
					g_message("VMM freeing %luKiB region at 0x%lx "
						"fragments VM space",
						(unsigned long) size / 1024, (unsigned long) p);
				}
				pmap_insert(pm, end, ptr_diff(vend, end));
			}
		}
	} else {
		if (vmm_debugging(0)) {
			g_warning("VMM %luKiB region at 0x%lx missing from pmap",
				(unsigned long) size / 1024, (unsigned long) p);
		}
	}
}

/**
 * Like free_pages() but for freeing of a cached/cacheable page and
 * update our pmap.
 */
static void
free_pages_forced(void *p, size_t size, gboolean fragment)
{
	if (vmm_debugging(fragment ? 2 : 5)) {
		g_message("VMM freeing %luKiB region at 0x%lx%s",
			(unsigned long) size / 1024, (unsigned long) p,
			fragment ? " (fragment)" : "");
	}

	/*
	 * Do not let free_pages_intern() update our pmap, as we are about to
	 * do it ourselves.
	 */

	free_pages_intern(p, size, FALSE);

	/*
	 * If we're freeing a fragment, we can remove it from the list of known
	 * regions, since we already know it is a standalone region.
	 */

	if (fragment) {
		pmap_remove_whole_region(vmm_pmap(), p, size);
	} else {
		pmap_remove(vmm_pmap(), p, size);
	}
}

/**
 * Lookup page within a cache line.
 *
 * If ``low_ptr'' is non-NULL, it is written with the index where insertion
 * of a new item should happen (in which case the returned value must be NULL).
 *
 * @return index within the page cache info[] sorted array where "p" is stored,
 * -1 if not found.
 */
static size_t
vpc_lookup(const struct page_cache *pc, const char *p, size_t *low_ptr)
{
	size_t low = 0, high = pc->current - 1;
	size_t mid;

	/* Binary search */

	for (;;) {
		const char *item;

		if (low > high || high > SIZE_MAX / 2) {
			mid = -1;		/* Not found */
			break;
		}

		mid = low + (high - low) / 2;

		g_assert(mid < pc->current);

		item = pc->info[mid].base;
		if (p > item)
			low = mid + 1;
		else if (p < item)
			high = mid - 1;
		else
			break;				/* Found */
	}

	if (low_ptr != NULL)
		*low_ptr = low;

	return mid;
}

/**
 * Delete slot ``idx'' within cache line.
 */
static inline void
vpc_delete_slot(struct page_cache *pc, size_t idx)
{
	g_assert(size_is_positive(pc->current));
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

	idx = vpc_lookup(pc, p, NULL);
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

	g_assert(size_is_positive(pc->current));
	g_assert(size_is_non_negative(idx) && idx < pc->current);

	p = pc->info[idx].base;
	free_pages_forced(p, pc->chunksize, FALSE);
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

	g_assert(size_is_non_negative(pc->current) &&
		pc->current <= VMM_CACHE_SIZE);

	if ((size_t ) -1 != vpc_lookup(pc, p, &idx)) {
		g_error("memory chunk at 0x%lx already present in cache",
			(unsigned long) p);
	}

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
				g_message("VMM page cache #%lu: "
					"coalescing previous [0x%lx, 0x%lx] with [0x%lx, 0x%lx]",
					(unsigned long) pc->pages - 1, (unsigned long) before,
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
				g_message("VMM page cache #%lu: "
					"coalescing [0x%lx, 0x%lx] with next [0x%lx, 0x%lx]",
					(unsigned long) pc->pages - 1, (unsigned long) base,
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

	if (pages != pc->pages) {
		if (vmm_debugging(2)) {
			g_message("VMM coalesced %luKiB region [0x%lx, 0x%lx] into "
				"%luKiB region [0x%lx, 0x%lx] (recursing)",
				(unsigned long) (pc->chunksize / 1024),
				(unsigned long) p,
				(unsigned long) ptr_add_offset(p, pc->chunksize - 1),
				(unsigned long) (pages * kernel_pagesize / 1024),
				(unsigned long) base,
				(unsigned long) ptr_add_offset(base,
					pages * kernel_pagesize - 1));
		}
		page_cache_insert_pages(base, pages);
		return;
	}

insert:

	/*
	 * Insert region in the local cache line.
	 */

	if (VMM_CACHE_SIZE == pc->current) {
		size_t kidx = kernel_mapaddr_increasing ? VMM_CACHE_SIZE - 1 : 0;
		if (vmm_debugging(4)) {
			void *lbase = pc->info[kidx].base;
			g_message("VMM page cache #%lu: kicking out [0x%lx, 0x%lx] %luKiB",
				(unsigned long) pc->pages - 1, (unsigned long) lbase,
				(unsigned long) ptr_add_offset(lbase, pc->chunksize - 1),
				(unsigned long) pc->chunksize / 1024);
		}
		vpc_free(pc, kidx);
		if (idx > kidx)
			idx--;
	}

	g_assert(size_is_non_negative(pc->current) && pc->current < VMM_CACHE_SIZE);
	g_assert(size_is_non_negative(idx) && idx < VMM_CACHE_SIZE);

	if (idx < pc->current) {
		memmove(&pc->info[idx + 1], &pc->info[idx],
			(pc->current - idx) * sizeof(pc->info[0]));
	}

	pc->current++;
	pc->info[idx].base = base;
	pc->info[idx].stamp = tm_time();

	if (vmm_debugging(4)) {
		g_message("VMM page cache #%lu: inserted [0x%lx, 0x%lx] %luKiB, "
			"now holds %lu item%s",
			(unsigned long) pc->pages - 1, (unsigned long) base,
			(unsigned long) ptr_add_offset(base, pc->chunksize - 1),
			(unsigned long) pc->chunksize / 1024,
			(unsigned long) pc->current, 1 == pc->current ? "" : "s");
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
	size_t total = 0;
	void *base, *end;

	if (0 == pc->current)
		return NULL;

	/*
	 * If we're looking for less pages than what this cache line stores, it
	 * means we'll have to split the pages.  To limit fragmentation of the VM
	 * space, we avoid splitting regions at the beginning or at the tail of a
	 * VM region (since these can be released without fragmenting further).
	 */

	if (n > pc->pages) {
		size_t i;

		for (i = 0; i < pc->current; i++) {
			base = kernel_mapaddr_increasing ?
				pc->info[i].base : pc->info[pc->current - 1 - i].base;
			if (pmap_is_within_region(vmm_pmap(), base, pc->chunksize))
				goto selected;
		}

		return NULL;
	} else {
		base = kernel_mapaddr_increasing ?
			pc->info[0].base : pc->info[pc->current - 1].base;
	}

selected:
	end = ptr_add_offset(base, pc->chunksize);
	total = pc->pages;

	/*
	 * If we have not yet the amount of pages we want, iterate to find
	 * whether we have consecutive ranges in the cache.  This is only
	 * necessary if we are already in the highest-order cache line because
	 * lower-order caches are coalesced at insertion time.
	 */

	if (total < n) {
		size_t i;

		if (1 == pc->current)
			return NULL;

		if (kernel_mapaddr_increasing) {
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
				}
			}
		} else {
			for (i = pc->current - 1; i > 0; i--) {
				void *prev_base = pc->info[i - 1].base;
				void *last = ptr_add_offset(prev_base, pc->chunksize);

				if (last == base) {
					total += pc->pages;
					base = prev_base;
					if (total >= n)
						goto found;
				} else {
					total = pc->pages;
					base = prev_base;
					end = last;
				}
			}
		}

		return NULL;	/* Did not find enough consecutive pages */
	}

found:
	/*
	 * Remove the entries from the cache.
	 */
	{
		char *p = base;
		size_t i;

		for (i = 0; i < total; i += pc->pages) {
			vpc_remove(pc, p);
			p += pc->chunksize;
		}

		g_assert(cast_to_char_ptr(end) == p);
	}
	 
	/*
	 * If we got more consecutive pages than the amount asked for, put
	 * the leading / trailing pages back into the cache.
	 */

	if (total > n) {
		if (kernel_mapaddr_increasing) {
			void *start = ptr_add_offset(base, n * kernel_pagesize);
			page_cache_insert_pages(start, total - n);	/* Strip trailing */
		} else {
			void *start = ptr_add_offset(end, -n * kernel_pagesize);
			page_cache_insert_pages(base, total - n);	/* Strip leading */
			base = start;
		}
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
		if (vmm_debugging(3)) {
			g_message("VMM lookup for large area (%lu pages) returned 0x%lx",
				(unsigned long) n, (unsigned long) p);
		}
	} else {
		pc = &page_cache[n - 1];
		p = vpc_find_pages(pc, n);

		/*
		 * Visit higher-order cache lines if we found nothing in the cache.
		 *
		 * To avoid VM space fragmentation, we never split a larger region
		 * to allocate just one page.  This policy allows us to fill the holes
		 * that can be created and avoid undoing the coalescing we may have
		 * achieved so far in higher-order caches.
		 */

		if (NULL == p && n > 1) {
			size_t i;

			for (i = n; i < VMM_CACHE_LINES && NULL == p; i++) {
				pc = &page_cache[i];
				p = vpc_find_pages(pc, n);
			}
		}
	}

	if (p != NULL && vmm_debugging(5)) {
		g_message("VMM found %luKiB region at 0x%lx in cache #%lu%s",
			(unsigned long) (n * kernel_pagesize / 1024),
			(unsigned long) p,
			(unsigned long) pc->pages - 1,
			pc->pages == n ? "" :
			n > VMM_CACHE_LINES ? " (merged)" : " (split)");
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

	/*
	 * Identified memory fragments are immediately freed and not put
	 * back into the cache, in order to reduce fragmentation of the
	 * memory space.
	 */

	if (pmap_is_fragment(vmm_pmap(), base, n)) {
		free_pages_forced(base, n * kernel_pagesize, TRUE);
		return;
	}

	/*
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
	const size_t old_pages = pages;
	void *end;

	if (pages >= VMM_CACHE_LINES)
		return FALSE;

	/*
	 * Look in low-order caches whether we can find chunks before.
	 */

	for (i = 0; /* empty */; i++) {
		gboolean coalesced = FALSE;

		j = MIN(old_pages, VMM_CACHE_LINES) - 1;
		while (j-- > 0) {
			struct page_cache *lopc = &page_cache[j];
			void *before;
			size_t loidx;

			if (0 == lopc->current)
				continue;

			before = ptr_add_offset(base, -lopc->chunksize);
			loidx = vpc_lookup(lopc, before, NULL);

			if (loidx != (size_t) -1) {
				if (vmm_debugging(6)) {
					g_message("VMM iter #%lu, coalescing previous "
						"[0x%lx, 0x%lx] from lower cache #%lu "
						"with [0x%lx, 0x%lx]",
						(unsigned long) i, (unsigned long) before,
						(unsigned long) ptr_add_offset(base, -1),
						(unsigned long) lopc->pages - 1,
						(unsigned long) base,
						(unsigned long) ptr_add_offset(base,
							pages * kernel_pagesize - 1));
				}
				base = before;
				pages += lopc->pages;
				vpc_remove(lopc, before);
				coalesced = TRUE;
				if (pages >= VMM_CACHE_LINES)
					goto done;
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

	for (j = old_pages; j < VMM_CACHE_LINES - 1; j++) {
		struct page_cache *hopc = &page_cache[j];
		void *before;
		size_t hoidx;

		if (0 == hopc->current)
			continue;

		before = ptr_add_offset(base, -hopc->chunksize);
		hoidx = vpc_lookup(hopc, before, NULL);

		if (hoidx != (size_t) -1) {
			if (vmm_debugging(6)) {
				g_message("VMM coalescing previous [0x%lx, 0x%lx] "
					"from higher cache #%lu with [0x%lx, 0x%lx]",
					(unsigned long) before,
					(unsigned long) ptr_add_offset(base, -1),
					(unsigned long) hopc->pages - 1,
					(unsigned long) base,
					(unsigned long) ptr_add_offset(base,
						pages * kernel_pagesize - 1));
			}
			base = before;
			pages += hopc->pages;
			vpc_remove(hopc, before);
			if (pages >= VMM_CACHE_LINES)
				goto done;
		}
	}

	/*
	 * Look in low-order caches whether we can find chunks after.
	 */

	end = ptr_add_offset(base, pages * kernel_pagesize);

	for (i = 0; /* empty */; i++) {
		gboolean coalesced = FALSE;

		j = MIN(old_pages, VMM_CACHE_LINES) - 1;
		while (j-- > 0) {
			struct page_cache *lopc = &page_cache[j];
			size_t loidx;

			if (0 == lopc->current)
				continue;

			loidx = vpc_lookup(lopc, end, NULL);
			if (loidx != (size_t) -1) {
				if (vmm_debugging(6)) {
					g_message("VMM iter #%lu, coalescing next [0x%lx, 0x%lx] "
						"from lower cache #%lu with [0x%lx, 0x%lx]",
						(unsigned long) i, (unsigned long) end,
						(unsigned long) ptr_add_offset(end,
							lopc->chunksize - 1),
						(unsigned long) lopc->pages - 1, (unsigned long) base,
						(unsigned long) ptr_add_offset(end, -1));
				}
				pages += lopc->pages;
				vpc_remove(lopc, end);
				end = ptr_add_offset(end, lopc->chunksize);
				coalesced = TRUE;
				if (pages >= VMM_CACHE_LINES)
					goto done;
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

	for (j = old_pages; j < VMM_CACHE_LINES - 1; j++) {
		struct page_cache *hopc = &page_cache[j];
		size_t hoidx;

		if (0 == hopc->current)
			continue;

		hoidx = vpc_lookup(hopc, end, NULL);
		if (hoidx != (size_t) -1) {
			if (vmm_debugging(6)) {
				g_message("VMM coalescing next [0x%lx, 0x%lx] "
					"from higher cache #%lu with [0x%lx, 0x%lx]",
					(unsigned long) end,
					(unsigned long) ptr_add_offset(end, hopc->chunksize - 1),
					(unsigned long) hopc->pages - 1,
					(unsigned long) base,
					(unsigned long) ptr_add_offset(end, -1));
			}
			pages += hopc->pages;
			vpc_remove(hopc, end);
			end = ptr_add_offset(end, hopc->chunksize);
			if (pages >= VMM_CACHE_LINES)
				goto done;
		}
	}

done:
	if (pages != old_pages) {
		if (vmm_debugging(2)) {
			g_message("VMM coalesced %luKiB region [0x%lx, 0x%lx] into "
				"%luKiB region [0x%lx, 0x%lx]",
				(unsigned long) (old_pages * kernel_pagesize / 1024),
				(unsigned long) *base_ptr,
				(unsigned long) ptr_add_offset(*base_ptr,
					old_pages * compat_pagesize() - 1),
				(unsigned long) (pages * kernel_pagesize / 1024),
				(unsigned long) base,
				(unsigned long) ptr_add_offset(base,
					pages * kernel_pagesize - 1));
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
 * Allocates a page-aligned memory chunk, possibly returning a cached region
 * and only allocating a new region when necessary.
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

	p = alloc_pages(size, TRUE);
	if (NULL == p)
		g_error("cannot allocate %lu bytes: out of virtual memmory",
			(unsigned long) size);

	return p;
}

/**
 * Same a vmm_alloc() but zeroes the allocated region.
 */
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

	p = alloc_pages(size, TRUE);
	if (NULL == p)
		g_error("cannot allocate %lu bytes: out of virtual memmory",
			(unsigned long) size);

	return p;		/* Memory allocated by the kernel is already zero-ed */
}

/**
 * Free memory allocated via vmm_alloc(), possibly returning it to the cache.
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

		/*
		 * Memory regions that are larger than our highest-order cache
		 * are allocated and freed as-is, and never broken into smaller
		 * pages.  The purpose is to avoid excessive virtual memory space
		 * fragmentation, leading at some point to the unability for the
		 * kernel to find a large consecutive virtual memory region.
		 */

		if (n <= VMM_CACHE_LINES) {
			vmm_invalidate_pages(p, size);
			page_cache_coalesce_pages(&p, &n);
			page_cache_insert_pages(p, n);
		} else {
			free_pages(p, size, TRUE);
		}
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
	static size_t line;
	time_t now = tm_time();
	struct page_cache *pc;
	size_t i;
	size_t expired = 0;
	size_t old_regions = vmm_pmap()->count;

	(void) unused_udata;

	if (VMM_CACHE_LINES == line)
		line = 0;

	pc = &page_cache[line];

	if (vmm_debugging(pc->current > 0 ? 4 : 8)) {
		g_message("VMM scanning page cache #%lu (%lu item%s)",
			(unsigned long) line,
			(unsigned long) pc->current, 1 == pc->current ? "" : "s");
	}

	for (i = 0; i < pc->current; /* empty */) {
		time_delta_t d = delta_time(now, pc->info[i].stamp);

		/*
		 * To avoid undue fragmentation of the memory space, do not free
		 * a block that lies within an already identified region too soon.
		 * Wait longer, for it to be further coalesced hopefully.
		 */

		if (
			d >= VMM_CACHE_MAXLIFE ||
			(
				d >= VMM_CACHE_LIFE && !pmap_is_within_region(vmm_pmap(),
					pc->info[i].base, pc->chunksize)
			)
		) {
			vpc_free(pc, i);
			expired++;
		} else {
			i++;
		}
	}

	if (expired > 0 && vmm_debugging(1)) {
		size_t regions = vmm_pmap()->count;
		g_message("VMM expired %lu item%s (%luKiB total) from "
			"page cache #%lu (%lu item%s remaining), "
			"process has %lu VM regions%s",
			(unsigned long) expired, 1 == expired ? "" : "s",
			(unsigned long) (expired * pc->chunksize / 1024),
			(unsigned long) line,
			(unsigned long) pc->current, 1 == pc->current ? "" : "s",
			(unsigned long) regions,
			old_regions < regions ? " (fragmented further)" : "");

		if (vmm_debugging(5)) {
			vmm_dump_pmap();
		}
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
	p = alloc_pages(round_pagesize_fast(n), TRUE);
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
			trap_page = alloc_pages(size, TRUE);
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
		g_message("VMM using %lu bytes for the page cache",
			(unsigned long) sizeof page_cache);
		g_message("VMM kernel grows virtual memory by %s addresses",
			kernel_mapaddr_increasing ? "increasing" : "decreasing");
	}

	pmap_load(&kernel_pmap);
	cq_periodic_add(callout_queue, 1000, page_cache_timer, NULL);
}

/**
 * Initialize the vitual memory manager.
 *
 * @attention
 * No external memory allocation (malloc() and friends) can be done in this
 * routine, which is called very early at startup.
 */
void
vmm_init(void)
{
	int i;

	init_kernel_pagesize();

	for (i = 0; i < VMM_CACHE_LINES; i++) {
		struct page_cache *pc = &page_cache[i];
		size_t pages = i + 1;
		pc->pages = pages;
		pc->chunksize = pages * kernel_pagesize;
	}

	/*
	 * Allocate the pmaps.
	 */

	pmap_allocate(&local_pmap);
	pmap_allocate(&kernel_pmap);

	/*
	 * Determine how the kernel is growing the virtual memory region.
	 */

	{
		void *p = alloc_pages(kernel_pagesize, FALSE);
		void *q = alloc_pages(kernel_pagesize, FALSE);

		kernel_mapaddr_increasing = q > p;

		free_pages(q, kernel_pagesize, FALSE);
		free_pages(p, kernel_pagesize, FALSE);
	}
}

/* vi: set ts=4 sw=4 cindent: */
