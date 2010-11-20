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

#define VMM_SOURCE
#include "vmm.h"

#include "ascii.h"
#include "cq.h"
#include "fd.h"
#include "parse.h"
#include "pow2.h"
#include "stringify.h"
#include "tm.h"
#include "unsigned.h"
#include "omalloc.h"
#include "glib-missing.h"

#ifdef TRACK_VMM
#include "hashtable.h"
#include "stacktrace.h"
#endif

#ifdef MINGW32
#include <windows.h>
#endif

#include "lib/override.h"		/* Must be the last header included */

/*
 * With VMM_INVALIDATE_FREE_PAGES freed pages are invalidated so that the
 * system can recycle them without ever paging them out as we don't care about
 * the data in them anymore.
 *
 * This may cause the kernel to re-initialize a page with zeroes when the
 * page is un-cached, and causes an extra system call each time the page is
 * put in the cache or removed from it, which is a non negligeable penalty,
 * not even counting the work the kernel has to do.  This partly defeats the
 * advantage of having a cache to quickly recycle pages.
 *
 * Therefore, by default it is not enabled.
 */
#if 0
#define VMM_INVALIDATE_FREE_PAGES
#endif

/*
 * With VMM_PROTECT_FREE_PAGES freed pages are completely protected. This may
 * help to detect access-after-free bugs.
 */
#if 0
#define VMM_PROTECT_FREE_PAGES
#endif

static size_t kernel_pagesize = 0;
static size_t kernel_pagemask = 0;
static unsigned kernel_pageshift = 0;
static gboolean kernel_mapaddr_increasing;

#define VMM_CACHE_SIZE		256	/**< Amount of entries per cache line */
#define VMM_CACHE_LINES		32	/**< Amount of cache lines */
#define VMM_CACHE_LIFE		60	/**< At most 1 minute if not fragmenting */
#define VMM_CACHE_MAXLIFE	180	/**< At most 3 minutes if fragmenting */
#define VMM_STACK_MINSIZE	(64 * 1024)		/**< Minimum stack size */

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
	size_t generation;				/**< Reloading generation number */
	unsigned loading:1;				/**< Pmap being loaded */
	unsigned resized:1;				/**< Pmap has been resized */
	unsigned extending:1;			/**< Pmap being extended */
};

/**
 * The kernel version of the pmap and our own version.
 */
static struct pmap kernel_pmap;
static struct pmap local_pmap;

static gboolean safe_to_malloc;		/**< True when malloc() was inited */
static gboolean stop_freeing;		/**< No longer release memory */
static guint32 vmm_debug;			/**< Debug level */
static const void *initial_brk;		/**< Startup position of the heap */
static const void *initial_sp;		/**< Initial "bottom" of the stack */
static gboolean sp_increasing;		/**< Growing direction of the stack */
static const void *vmm_base;		/**< Where we'll start allocating */

#ifdef TRACK_VMM
static void vmm_track_init(void);
static void vmm_track_malloc_inited(void);
static void vmm_track_post_init(void);
static void vmm_track_close(void);
#endif

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
static void pmap_remove(struct pmap *pm, const void *p, size_t size);
static void pmap_load(struct pmap *pm);
static void pmap_insert_region(struct pmap *pm,
	const void *start, size_t size, gboolean foreign);
static void pmap_overrule(struct pmap *pm, const void *p, size_t size);
static void vmm_reserve_stack(size_t amount);

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

/**
 * Rounds pointer down so that it is aligned to the start of the page.
 */
static inline const void *
page_start(const void *p)
{
	unsigned long addr = pointer_to_ulong(p);

	addr &= ~kernel_pagemask;
	return ulong_to_pointer(addr);
}

static long
compat_pagesize_intern(void)
{
#ifdef MINGW32
	SYSTEM_INFO system_info;

	GetSystemInfo(&system_info);
	return system_info.dwPageSize;
#elif defined (_SC_PAGESIZE) || defined(_SC_PAGE_SIZE)
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
#else /* !_SC_PAGESIZE && !_SC_PAGE_SIZE */
	return getpagesize();
#endif /* MINGW32 */
}

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
	return booleanize((pointer_to_ulong(vmf->end) & 0x1));
}

static inline void
vmf_set_end(struct vm_fragment *vmf, const void *end, gboolean foreign)
{
	g_assert(0 == (pointer_to_ulong(end) & 0x1));
	vmf->end = const_ptr_add_offset(end, -booleanize(foreign));
}

/**
 * @return first byte after the end of a fragment.
 */
static inline const void *
vmf_end(const struct vm_fragment *vmf)
{
	return vmf_is_foreign(vmf) ? const_ptr_add_offset(vmf->end, 1) : vmf->end;
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

	g_debug("VMM current %s pmap (%lu region%s):",
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

		g_debug("VMM [0x%lx, 0x%lx] %luKiB%s%s%s%s",
			(unsigned long) vmf->start,
			(unsigned long) const_ptr_add_offset(vmf_end(vmf), -1),
			(unsigned long) (vmf_size(vmf) / 1024),
			vmf_is_foreign(vmf) ? " (foreign)" : "",
			hole ? " + " : "",
			hole ? size_t_to_string(hole / 1024) : "",
			hole ? "KiB hole" : "");
	}
}

#if defined(HAS_MMAP) || defined(MINGW32)
/**
 * Find a hole in the virtual memory map where we could allocate "size" bytes.
 */
static const void *
vmm_find_hole(size_t size)
{
	struct pmap *pm = vmm_pmap();
	size_t i;

	if (0 == pm->count || pm->loading)
		return NULL;

	if (kernel_mapaddr_increasing) {
		for (i = 0; i < pm->count; i++) {
			struct vm_fragment *vmf = &pm->array[i];
			const void *end = vmf_end(vmf);

			if (ptr_cmp(end, vmm_base) < 0)
				continue;

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

			if (ptr_cmp(vmf->start, vmm_base) > 0)
				continue;

			if (i == 1) {
				return page_start(const_ptr_add_offset(vmf->start, -size));
			} else {
				struct vm_fragment *prev = &pm->array[i - 2];

				if (ptr_diff(vmf->start, vmf_end(prev)) >= size)
					return page_start(const_ptr_add_offset(vmf->start, -size));
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
 * Compute the size of the first hole at the base of the VM space and return
 * its location in ``hole_ptr'', if we find one with a non-zero length.
 */
static size_t
vmm_first_hole(const void **hole_ptr)
{
	struct pmap *pm = vmm_pmap();
	size_t i;

	if (0 == pm->count)
		return 0;

	if (kernel_mapaddr_increasing) {
		for (i = 0; i < pm->count; i++) {
			struct vm_fragment *vmf = &pm->array[i];
			const void *end = vmf_end(vmf);

			if (ptr_cmp(end, vmm_base) < 0)
				continue;

			if (i == pm->count - 1) {
				*hole_ptr = end;
				return SIZE_MAX;
			} else {
				struct vm_fragment *next = &pm->array[i + 1];
				if (next->start == end)
					continue;		/* Foreign and native do not coalesce */
				*hole_ptr = end;
				return ptr_diff(next->start, end);
			}
		}
	} else {
		for (i = pm->count; i > 0; i--) {
			struct vm_fragment *vmf = &pm->array[i - 1];

			if (ptr_cmp(vmf->start, vmm_base) > 0)
				continue;

			if (i == 1) {
				*hole_ptr = ulong_to_pointer(kernel_pagesize);	/* Not NULL */
				return SIZE_MAX;
			} else {
				struct vm_fragment *prev = &pm->array[i - 2];
				const void *end = vmf_end(prev);
				if (vmf->start == end)
					continue;		/* Foreign and native do not coalesce */
				*hole_ptr = vmf->start;
				return ptr_diff(vmf->start, end);
			}
		}
	}

	return 0;
}

/**
 * Wrapper on mmap() and munmap() to allocate/free anonymous memory.
 */
#ifdef MINGW32
static inline void *
vmm_valloc(void *hint, size_t size)
{
	return mingw_valloc(hint, size);
}

static inline int
vmm_vfree(void *addr, size_t size)
{
	return mingw_vfree(addr, size);
}

static inline int
vmm_vfree_fragment(void *addr, size_t size)
{
	return mingw_vfree_fragment(addr, size);
}
#else	/* !MINGW32 */
static void *
vmm_valloc(void *hint, size_t size)
{
	static int fd = -1;
	int flags;

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

	return mmap(hint, size, PROT_READ | PROT_WRITE, flags, fd, 0);
}

static inline int
vmm_vfree(void *addr, size_t size)
{
	return munmap(addr, size);
}

static inline int
vmm_vfree_fragment(void *addr, size_t size)
{
	return munmap(addr, size);
}
#endif	/* MINGW32 */

#else	/* !HAS_MMAP && !MINGW32 */
static inline size_t
vmm_first_hole(const void **unused)
{
	(void) unused;
	return 0;
}
#endif	/* HAS_MMAP || MINGW32 */

/**
 * Insert foreign region in the pmap.
 */
static void
pmap_insert_foreign(struct pmap *pm, const void *start, size_t size)
{
	pmap_insert_region(pm, start, size, TRUE);
}

/**
 * Allocate a new chunk of anonymous memory.
 *
 * @param size		amount of bytes we want
 * @param hole		if non-NULL, identified VM hole of at least size bytes.
 */
static void *
vmm_mmap_anonymous(size_t size, const void *hole)
#if defined(HAS_MMAP) || defined(MINGW32)
{
	static int failed;
	void *hint, *p;
	static guint64 hint_followed;

	if (failed)
		return NULL;

	if (G_UNLIKELY(stop_freeing)) {
		hint = NULL;
	} else {
		hint = deconstify_gpointer(NULL == hole ? vmm_find_hole(size) : hole);
	}

	if (hint != NULL && vmm_debugging(8)) {
		g_debug("VMM hinting %s0x%lx for new %luKiB region",
			NULL == hole ? "" : "supplied ",
			(unsigned long) hint, (unsigned long) (size / 1024));
	}

	p = vmm_valloc(hint, size);

	if (MAP_FAILED == p) {
		if (ENOMEM != errno) {
			failed = 1;
			return_value_unless(MAP_FAILED != p, NULL);
		}
		p = NULL;
	} else if (p != hint) {
		if (hint != NULL && vmm_debugging(0)) {
			g_warning("VMM kernel did not follow hint 0x%lx for %luKiB region, "
				"picked 0x%lx (after %lu followed hint%s)",
				(unsigned long) hint, (unsigned long) (size / 1024),
				(unsigned long) p, (unsigned long) hint_followed,
				hint_followed == 1 ? "" : "s");
		}

		/*
		 * Because the hint was not followed and we're not dealing with
		 * "foreign" memory here, we have to over-rule any chunk of the map
		 * space that we could have declared as "foreign" and which would
		 * overlap the space we just mapped.
		 *
		 * This can happen when we declared "foreign" some pages because
		 * our past allocations at these hinted spots failed, but for some
		 * reason the memory was released and we could not notice it.
		 */

		pmap_overrule(vmm_pmap(), p, size);

		if (NULL == hint)
			goto done;

		/*
		 * Kernel did not use our hint, maybe it was wrong because something
		 * got mapped at the place where we thought there was nothing...
		 *
		 * Reload the current kernel pmap if we're able to do so, otherwise
		 * see whether we can mark something as "foreign" in the VM space so
		 * that we avoid further attempts at the same location for blocks
		 * of similar sizes.
		 */

		hint_followed = 0;

		if (vmm_pmap() == &kernel_pmap) {
			if (vmm_debugging(0)) {
				g_debug("VMM current kernel pmap before reloading attempt:");
				vmm_dump_pmap();
			}
			pmap_load(&kernel_pmap);
			vmm_reserve_stack(0);
		} else if (!local_pmap.extending) {
			if (size <= kernel_pagesize) {
				pmap_insert_foreign(&local_pmap, hint, kernel_pagesize);
				if (vmm_debugging(0)) {
					g_debug("VMM marked hint 0x%lx as foreign",
						(unsigned long) hint);
				}
			} else if (
				ptr_cmp(hint, ptr_add_offset(p, size)) >= 0 ||
				ptr_cmp(hint, p) < 0
			) {
				void *try;

				/*
				 * The hint address is not included in the allocted segment.
				 *
				 * Try allocating a single page at the hint location, and
				 * if we don't succeed, we can mark it as foreign.  If
				 * we succeed and we were previously trying to allocate
				 * exactly two pages, then we know the next page is foreign.
				 */

				try = vmm_valloc(hint, kernel_pagesize);

				if (try != MAP_FAILED) {
					if (try != hint) {
						pmap_insert_foreign(&local_pmap, hint, kernel_pagesize);
						if (vmm_debugging(0)) {
							g_debug("VMM marked hint 0x%lx as foreign",
								(unsigned long) hint);
						}
					} else if (2 == pagecount_fast(size)) {
						void *next = ptr_add_offset(hint, kernel_pagesize);
						if (next != p) {
							pmap_insert_foreign(&local_pmap, next,
								kernel_pagesize);
							if (vmm_debugging(0)) {
								g_debug("VMM marked 0x%lx (page after 0x%lx) "
									"as foreign",
									(unsigned long) next, (unsigned long) hint);
							}
						} else {
							if (vmm_debugging(0)) {
								g_debug("VMM funny kernel ignored hint 0x%lx "
									"and allocated 8 KiB at 0x%lx whereas hint "
									"was free",
									(unsigned long) hint, (unsigned long) p);
							}
						}
					} else {
						if (vmm_debugging(1)) {
							g_debug("VMM hinted 0x%lx is not a foreign page",
								(unsigned long) hint);
						}
					}
					if (0 != vmm_vfree(try, kernel_pagesize)) {
						g_warning("VMM cannot free single page at 0x%lx: %s",
							(unsigned long) try, g_strerror(errno));
					}

				} else {
					if (vmm_debugging(0)) {
						g_warning("VMM cannot allocate one page at 0x%lx: %s",
							(unsigned long) hint, g_strerror(errno));
					}
				}
			} else {
				if (vmm_debugging(0)) {
					g_debug("VMM hint 0x%lx fell within allocated "
						"[0x%lx, 0x%lx]",
						(unsigned long) hint, (unsigned long) p,
						(unsigned long) ptr_add_offset(p, size - 1));
				}
			}
		}
	} else if (hint != NULL) {
		hint_followed++;
	}
done:
	return p;
}
#else	/* !HAS_MMAP */
{
	void *p;

	(void) hole;
	size = round_pagesize_fast(size);
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
	if (p) {
		memset(p, 0, size);
	}
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
 * @param hole			if non-NULL, identified VM hole of size bytes at least
 *
 * @return On success a pointer to the allocated chunk is returned. On
 *		   failure NULL is returned.
 */
static void *
alloc_pages(size_t size, gboolean update_pmap, const void *hole)
{
	void *p;
	size_t generation = kernel_pmap.generation;

	RUNTIME_ASSERT(kernel_pagesize > 0);

	p = vmm_mmap_anonymous(size, hole);
	return_value_unless(NULL != p, NULL);
	
	if (page_start(p) != p) {
		RUNTIME_ASSERT(!"Aligned memory required");
	}

	if (vmm_debugging(5)) {
		g_debug("VMM allocated %luKiB region at 0x%lx",
			(unsigned long) size / 1024, (unsigned long) p);
	}

	/*
	 * Since the kernel pmap can be reloaded by vmm_mmap_anonymous(), we
	 * need to be careful and not insert something that will be listed there.
	 *
	 * NB: we check the kernel_pmap object only but we use vmm_pmap() for
	 * inserting in case we do not use the kernel pmap.
	 */

	if (update_pmap && kernel_pmap.generation == generation)
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
	/*
	 * If ``stop_freeing'' was set, well be only updating the pmap so that
	 * we can spot "leaks" at vmm_close() time.
	 */

	if (G_UNLIKELY(stop_freeing))
		goto pmap_update;

#if defined(HAS_MMAP) || defined(MINGW32)
	{
		int ret = 0;

		ret = vmm_vfree_fragment(p, size);
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

pmap_update:
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
		g_debug("VMM freeing %luKiB region at 0x%lx",
			(unsigned long) size / 1024, (unsigned long) p);
	}

	free_pages_intern(p, size, update_pmap);
}

/**
 * Lookup address within the pmap.
 *
 * If ``low_ptr'' is non-NULL, it is written with the index where insertion
 * of a new item should happen (in which case the returned value must be NULL)
 * or with the index of the found fragment within the pmap.
 *
 * @return found fragment if address lies within the fragment, NULL if
 * no fragment containing the address was found.
 */
static struct vm_fragment *
pmap_lookup(const struct pmap *pm, const void *p, size_t *low_ptr)
{
	size_t low = 0, high = pm->count - 1;
	struct vm_fragment *item;
	size_t mid = 0;

	/* Binary search */

	for (;;) {
		if (low > high || high > SIZE_MAX / 2) {
			item = NULL;		/* Not found */
			break;
		}

		mid = low + (high - low) / 2;

		g_assert(mid < pm->count);

		item = &pm->array[mid];
		if (ptr_cmp(p, vmf_end(item)) >= 0)
			low = mid + 1;
		else if (ptr_cmp(p, item->start) < 0)
			high = mid - 1;
		else
			break;	/* Found */
	}

	if (low_ptr != NULL)
		*low_ptr = (item == NULL) ? low : mid;

	return item;
}

/**
 * Allocate a new pmap.
 */
static void
pmap_allocate(struct pmap *pm)
{
	g_assert(NULL == pm->array);
	g_assert(0 == pm->pages);

	pm->array = alloc_pages(kernel_pagesize, FALSE, NULL);
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
	size_t old_generation;
	gboolean was_extending = pm->extending;

retry:

	osize = kernel_pagesize * pm->pages;
	nsize = osize + kernel_pagesize;
	old_generation = vmm_pmap()->generation;

	if (vmm_debugging(0)) {
		g_debug("VMM extending %s%s%s pmap from %lu KiB to %lu KiB",
			pm->extending ? "(recursively) " : "",
			pm->loading ? "loading " : "",
			pm == &kernel_pmap ? "kernel" : "local",
			(unsigned long) osize / 1024, (unsigned long) nsize / 1024);
	}

	pm->extending = TRUE;

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

		narray = alloc_pages(nsize, FALSE, NULL);	/* May recurse here */

		if (pm->pages != old_pages) {
			if (vmm_debugging(0)) {
				g_warning("VMM already recursed to pmap_extend(), "
					"pmap is now %lu KiB",
					(unsigned long) (kernel_pagesize * pm->pages) / 1024);
			}
			g_assert(kernel_pagesize * pm->pages >= nsize);
			if (narray != NULL)
				free_pages(narray, nsize, FALSE);

			/*
			 * If after recursion we're left with a full pmap. we need to
			 * retry another extension.
			 */

			if (pm->count != pm->size)
				return;

			if (vmm_debugging(0))
				g_warning("VMM however pmap is still full, extending again...");
			
			goto retry;
		}

		if (NULL == narray)
			g_error("cannot extend pmap: out of virtual memory");
	}

	oarray = pm->array;
	pm->pages++;
	pm->size = nsize / sizeof pm->array[0];
	memcpy(narray, oarray, osize);
	pm->array = narray;
	if (!was_extending) {
		pm->extending = FALSE;
	}

	/*
	 * Freeing could update the pmap we've been extending.
	 *
	 * The structure must therefore be in a consistent state before the old
	 * array can be freed, so this must come last.
	 */

	free_pages(oarray, osize, TRUE);

	/*
	 * Watch out for extending the kernel pmap whilst we're reloading it.
	 * This means our data structures were too small, and we'll need to
	 * reload it again.
	 */

	{
		struct pmap *vpm = vmm_pmap();

		if (!vpm->loading) {
			if (vpm->generation == old_generation) {
				pmap_insert(vpm, narray, nsize);
			} else {
				if (vmm_debugging(0)) {
					g_debug("VMM kernel pmap reloaded during extension");
				}
				/* New pages must be there! */
				g_assert(NULL != pmap_lookup(vpm, narray, NULL));
			}
		} else {
			vpm->resized = TRUE;
		}
	}
}

/**
 * Add a new fragment at the tail of pmap (must be added in order), coalescing
 * fragments of the same foreign type.
 */
static void
pmap_add(struct pmap *pm, const void *start, const void *end, gboolean foreign)
{
	struct vm_fragment *vmf;

	g_assert(pm->array != NULL);
	g_assert(pm->count <= pm->size);
	g_assert(ptr_cmp(start, end) < 0);

	if (pm->count == pm->size)
		pmap_extend(pm);

	g_assert(pm->count < pm->size);

	/*
	 * Ensure that entries are inserted in order.
	 */

	if (pm->count > 0) {
		vmf = &pm->array[pm->count - 1];
		g_assert(ptr_cmp(start, vmf_end(vmf)) >= 0);
	}

	/*
	 * Attempt coalescing.
	 */

	if (pm->count > 0) {
		vmf = &pm->array[pm->count - 1];
		if (vmf_is_foreign(vmf) == foreign && vmf_end(vmf) == start) {
			vmf_set_end(vmf, end, foreign);
			return;
		}
	}

	/*
	 * For foreign fragments (not allocated by VMM), the end pointer is not
	 * the first byte after the end of the region but the last valid pointer
	 * of the region.
	 */

	vmf = &pm->array[pm->count++];
	vmf->start = start;
	vmf_set_end(vmf, end, foreign);
}

/**
 * Insert region in the pmap.
 */
static void
pmap_insert_region(struct pmap *pm,
	const void *start, size_t size, gboolean foreign)
{
	const void *end = const_ptr_add_offset(start, size);
	struct vm_fragment *vmf;
	size_t idx;
	gboolean reloaded = FALSE;

	g_assert(pm->array != NULL);
	g_assert(pm->count <= pm->size);
	g_assert(ptr_cmp(start, end) < 0);
	foreign = booleanize(foreign);

	/*
	 * Watch out for the kernel pmap being reloaded because the kernel did not
	 * follow our hint when the pmap pages were allocated.
	 */

	if (pm->count == pm->size) {
		size_t generation = kernel_pmap.generation;

		pmap_extend(pm);

		if (kernel_pmap.generation != generation) {
			if (vmm_debugging(1)) {
				g_debug("VMM kernel pmap reloaded before inserting "
					"%s[0x%lx, 0x%lx]",
					foreign ? "foreign " : "",
					(unsigned long) start,
					(unsigned long) const_ptr_add_offset(end, -1));
			}
			reloaded = TRUE;
		}
	}

	vmf = pmap_lookup(pm, start, &idx);

	if (vmf != NULL) {
		if (reloaded) {
			if (vmm_debugging(2)) {
				g_debug("VMM good, reloaded kernel pmap contains region");
			}
		} else {
			if (vmm_debugging(0)) {
				g_warning("pmap already contains the new region [0x%lx, 0x%lx]",
					(unsigned long) start,
					(unsigned long) const_ptr_add_offset(start, size - 1));
				vmm_dump_pmap();
			}
			g_assert(foreign);
			g_assert(vmf_is_foreign(vmf));
			g_assert(ptr_cmp(end, vmf_end(vmf)) <= 0);
		}
		return;
	} else if (reloaded) {
		if (vmm_debugging(0)) {
			g_warning("VMM reloaded kernel pmap does not contain "
				"%s[0x%lx, 0x%lx], will add now",
				foreign ? "foreign " : "",
				(unsigned long) start,
				(unsigned long) const_ptr_add_offset(end, -1));
		}
		/* FALL THROUGH */
	}

	g_assert(pm->count < pm->size);
	g_assert(idx <= pm->count);

	/*
	 * See whether we can coalesce the new region with the existing ones.
	 * We can't coalesce a native region with a foreign one.
	 */

	if (idx > 0) {
		struct vm_fragment *prev = &pm->array[idx - 1];

		g_assert(ptr_cmp(vmf_end(prev), start) <= 0); /* No overlap with prev */

		if (vmf_is_foreign(prev) == foreign && vmf_end(prev) == start) {
			vmf_set_end(prev, end, foreign);

			/*
			 * If we're now bumping into the next chunk, we need to coalesce
			 * it with the previous one and get rid of that "next" entry.
			 */
			
			if (idx < pm->count) {
				struct vm_fragment *next = &pm->array[idx];

				if (vmf_is_foreign(next) == foreign && next->start == end) {
					vmf_set_end(prev, vmf_end(next), foreign);

					/*
					 * Get rid of the entry at ``idx'' in the array.
					 * We need to shift data back by one slot unless we remove
					 * the last entry.
					 */

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

		g_assert(ptr_cmp(end, next->start) <= 0);	/* No overlap with next */

		if (vmf_is_foreign(next) == foreign && next->start == end) {
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
	vmf_set_end(vmf, end, foreign);
}

/**
 * Parse a line read from /proc/self/maps and add it to the map.
 * @return TRUE if we managed to parse the line correctly
 */
static gboolean
pmap_parse_and_add(struct pmap *pm, const char *line)
{
	int error;
	const char *ep;
	const char *p = line;
	const void *start, *end;
	gboolean foreign = FALSE;

	if (vmm_debugging(9))
		g_debug("VMM parsing \"%s\"", line);

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

	if (ptr_cmp(end, start) <= 0) {
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

struct iobuffer {
	char *buf;
	size_t size;
	char *rptr;
	size_t fill;
	unsigned int eof:1;
	unsigned int error:1;
	unsigned int toobig:1;
};

static void
iobuffer_init(struct iobuffer *iob, char *dst, size_t size)
{
	iob->buf = dst;
	iob->size = size;
	iob->rptr = dst;
	iob->fill = 0;
	iob->eof = 0;
	iob->error = 0;
	iob->toobig = 0;
}

/**
 * Reads a line from an open file descriptor whereas each successive call
 * clears the previous line. Lines are separated by '\n' which is replaced
 * by a NUL when returned. The maximum acceptable line length is bound to
 * the buffer size. iob->error is set on I/O errors, iob->toobig is set
 * once the buffer is full without any newline character.
 *
 * @param iob	An initialized, valid 'struct iobuffer'.
 * @param fd	An open file descriptor.
 *
 * @return NULL on failure or EOF, pointer to the current line on success.
 */
static const char *
iobuffer_readline(struct iobuffer *iob, int fd)
{
	g_assert(iob);
	g_assert(iob->buf);
	g_assert(iob->rptr);
	g_assert(iob->fill <= iob->size);

	/* Clear previous line and shift following chars */
	if (iob->rptr != iob->buf) {
		size_t n = iob->rptr - iob->buf;

		g_assert(iob->fill >= n);
		iob->fill -= n;
		memmove(iob->buf, iob->rptr, iob->fill);
		iob->rptr = iob->buf;
	}

	do {
		/* Refill buffer if not EOF and not full */
		if (!iob->eof && iob->fill < iob->size) {
			size_t n = iob->size - iob->fill;
			ssize_t ret;

			ret = read(fd, &iob->buf[iob->fill], n);
			if ((ssize_t) -1 == ret) {
				iob->error = TRUE;
				iob->eof = TRUE;
				break;
			} else if (0 == ret) {
				iob->eof = TRUE;
			} else {
				iob->fill += ret;
			}
		}
		if (iob->fill > 0) {
			char *p = memchr(iob->buf, '\n', iob->fill);
			if (p) {
				*p = '\0';
				iob->rptr = &p[1];
				return iob->buf;
			}
		}
		if (iob->fill >= iob->size) {
			iob->toobig = TRUE;
			break;
		}
	} while (!iob->eof);

	return NULL;
}

/**
 * @return	A negative value on failure. If zero is returned, check pm->resize
 *			and try again.
 */
static inline int
pmap_load_data(struct pmap *pm)
{
	struct iobuffer iob;
	char buf[4096];
	int fd, ret = -1;

	/*
	 * This is a low-level routine, do not use stdio at all as it could
	 * allocate memory and re-enter the VMM layer.  Likewise, do not
	 * allocate any memory, excepted for the pmap where entries are stored.
	 */

	fd = open("/proc/self/maps", O_RDONLY);
	if (fd < 0) {
		if (vmm_debugging(0)) {
			g_warning("VMM cannot open /proc/self/maps: %s", g_strerror(errno));
		}
		goto failure;
	}

	/*
	 * Dirty the pages associated with buf to avoid that the kernel has to
	 * extend the stack, which may modify mappings while reading from /proc.
	 */

	memset(buf, 0, sizeof buf);

	pm->count = 0;
	iobuffer_init(&iob, buf, sizeof buf);

	while (!pm->resized) {
		const char *line;

		line = iobuffer_readline(&iob, fd);
		if (NULL == line) {
			if (iob.error) {
				if (vmm_debugging(0)) {
					g_warning("VMM error reading /proc/self/maps: %s",
							g_strerror(errno));
				}
				goto failure;
			}
			if (iob.toobig) {
				if (vmm_debugging(0)) {
					g_warning("VMM too long a line in /proc/self/maps output");
				}
				goto failure;
			}
			break;
		}
		if (!pmap_parse_and_add(pm, line)) {
			if (vmm_debugging(0)) {
				g_warning("VMM error parsing \"%s\"", buf);
			}
			goto failure;
		}
	}
	ret = 0;

failure:
	fd_close(&fd, FALSE);
	return ret;
}

/**
 * Load the process's memory map from /proc/self/maps into the supplied map.
 */
static void
pmap_load(struct pmap *pm)
{
	/*
	 * FIXME
	 *
	 * Before the 0.96.7 release, I'm disabling kernel pmap loading.
	 *
	 * This is because upon kernel map loading, we do not know currently
	 * how to propagate the regions we have allocated already to o prevent
	 * them from being coalesced by the loading into a "foreign" area (despite
	 * them being truly owned by us already).
	 *
	 * This would then trigger undue assertion failures because suddenly
	 * we would think we're releasing memory allocated via vmm_mmap() (as
	 * it would be wrongly be part of a fragment tagged foreign) when in
	 * reality we're releasing memory allocated through vmm_alloc().
	 *
	 * 		--RAM, 2010-03-05
	 */
	(void) pm;

#if 0
	static int failed;
	unsigned attempt = 0;

	if (failed)
		return;

	g_assert(&kernel_pmap == pm);

	if (vmm_debugging(8)) {
		g_debug("VMM loading kernel memory map (for generation #%lu)",
			(unsigned long) pm->generation + 1);
	}

	for (;;) {
		int ret;

		pm->loading = TRUE;
		pm->resized = FALSE;

		ret = pmap_load_data(pm);
		if (ret < 0) {
			failed = TRUE;
			break;
		}
		if (!pm->resized)
			break;

		if (++attempt > 10) {
			/* Unconditional warning -- something may break afterwards */
			g_warning("VMM unable to reload kernel pmap after %u attempts",
					attempt);
			break;
		}

		if (vmm_debugging(0)) {
			g_warning("VMM kernel pmap resized during loading attempt #%u"
				", retrying", attempt);
		}
	}

	pm->loading = FALSE;

	if (!failed)
		pm->generation++;

	if (vmm_debugging(1)) {
		g_debug("VMM kernel memory map (generation #%lu) holds %lu region%s",
			(unsigned long) pm->generation,
			(unsigned long) pm->count, 1 == pm->count ? "" : "s");
	}
#endif
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

	return p != vmf->start && vmf_end(vmf) != const_ptr_add_offset(p, size);
}

/**
 * Given a known-to-be-mapped block (base address and size), compute the
 * distance of its middle point to the border of the region holding it:
 * the smallest distance between the middle point and the start and end of the
 * region.
 *
 * @return the distance to the border of the enclosing region.
 */
static size_t
pmap_nesting_within_region(const struct pmap *pm, const void *p, size_t size)
{
	struct vm_fragment *vmf;
	const void *middle;
	size_t distance_to_start;
	size_t distance_to_end;

	vmf = pmap_lookup(pm, p, NULL);

	if (NULL == vmf) {
		pmap_log_missing(pm, p, size);
		return 0;
	}

	middle = const_ptr_add_offset(p, size / 2);
	distance_to_start = ptr_diff(middle, vmf->start);
	distance_to_end = ptr_diff(vmf_end(vmf), middle);

	return MIN(distance_to_start, distance_to_end);
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
 * Is range available (hole) within the VM space?
 */
static gboolean
pmap_is_available(const struct pmap *pm, const void *p, size_t size)
{
	size_t idx;

	if (pmap_lookup(pm, p, &idx))
		return FALSE;

	g_assert(size_is_non_negative(idx));

	if (idx < pm->count) {
		struct vm_fragment *vmf = &pm->array[idx];
		const void *end = const_ptr_add_offset(p, size);

		return ptr_cmp(end, vmf->start) <= 0;
	}

	return TRUE;
}

/**
 * Assert range is within one single (coalesced) region of the VM space.
 */
void
assert_vmm_is_allocated(const void *base, size_t size)
{
	struct vm_fragment *vmf;
	const void *end;
	const void *vend;

	g_assert(base != NULL);
	g_assert(size_is_positive(size));

	vmf = pmap_lookup(vmm_pmap(), base, NULL);

	g_assert(vmf != NULL);
	g_assert(vmf_size(vmf) >= size);

	end = const_ptr_add_offset(base, size);
	vend = vmf_end(vmf);

	g_assert(ptr_cmp(base, vmf->start) >= 0);
	g_assert(ptr_cmp(end, vend) <= 0);
}

/**
 * Assert that pointer is not belonging to a foreign VM space.
 */
void
assert_vmm_is_not_foreign(const void *p)
{
	struct vm_fragment *vmf;

	g_assert(p != NULL);
	vmf = pmap_lookup(vmm_pmap(), p, NULL);

	g_assert(vmf != NULL);
	g_assert(!vmf_is_foreign(vmf));
}

/**
 * Assert that pointer is belonging to a foreign VM space.
 */
void
assert_vmm_is_foreign(const void *p)
{
	struct vm_fragment *vmf;

	g_assert(p != NULL);
	vmf = pmap_lookup(vmm_pmap(), p, NULL);

	g_assert(vmf != NULL);
	g_assert(vmf_is_foreign(vmf));
}

/**
 * Is region starting at ``base'' and of ``size'' bytes a virtual memory
 * fragment, i.e. a standalone mapping in the middle of the VM space?
 */
gboolean
vmm_is_fragment(const void *base, size_t size)
{
	g_assert(base != NULL);
	g_assert(size_is_positive(size));

	return pmap_is_fragment(vmm_pmap(), base, pagecount_fast(size));
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
pmap_remove(struct pmap *pm, const void *p, size_t size)
{
	struct vm_fragment *vmf = pmap_lookup(pm, p, NULL);

	if (vmf != NULL) {
		const void *end = const_ptr_add_offset(p, size);
		const void *vend = vmf_end(vmf);
		gboolean foreign = vmf_is_foreign(vmf);

		g_assert(vmf_size(vmf) >= size);

		if (p == vmf->start) {

			if (vmm_debugging(2)) {
				g_debug("VMM %s%luKiB region at 0x%lx was %s fragment",
					foreign ? "foreign " : "",
					(unsigned long) size / 1024, (unsigned long) p,
					end == vend ? "a whole" : "start of a");
			}

			if (end == vend) {
				pmap_remove_whole_region(pm, p, size);
			} else {
				vmf->start = end;			/* Known fragment reduced */
				g_assert(ptr_cmp(vmf->start, vend) < 0);
			}
		} else {
			g_assert(ptr_cmp(vmf->start, p) < 0);
			g_assert(ptr_cmp(end, vend) <= 0);

			vmf_set_end(vmf, p, foreign);

			if (end != vend) {
				if (vmm_debugging(1)) {
					g_debug("VMM freeing %s%luKiB region at 0x%lx "
						"fragments VM space",
						foreign ? "foreign " : "",
						(unsigned long) size / 1024, (unsigned long) p);
				}
				pmap_insert_region(pm, end, ptr_diff(vend, end), foreign);
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
 * Forcefully remove a foreign region from the pmap (``size'' bytes starting
 * at ``p''), belonging to a given foreign fragment.
 */
static void
pmap_remove_foreign(struct pmap *pm, struct vm_fragment *vmf,
	const void *p, size_t size)
{
	const void *end = const_ptr_add_offset(p, size);
	const void *vend;

	g_assert(vmf != NULL);
	g_assert(vmf_is_foreign(vmf));
	g_assert(size_is_positive(size));

	vend = vmf_end(vmf);

	g_assert(ptr_cmp(vmf->start, p) <= 0);
	g_assert(ptr_cmp(p, vend) < 0);
	g_assert(ptr_cmp(vmf->start, end) <= 0);
	g_assert(ptr_cmp(end, vend) <= 0);

	if (vmm_debugging(0)) {
		g_warning("VMM forgetting foreign %luKiB region at 0x%lx in pmap",
			(unsigned long) size / 1024, (unsigned long) p);
	}

	if (p == vmf->start) {
		if (end == vend) {
			pmap_remove_whole_region(pm, p, size);
		} else {
			vmf->start = end;			/* Known fragment reduced */
		}
	} else {
		vmf_set_end(vmf, p, TRUE);

		if (end != vend) {
			/* Insert trailing part back as a foreign region */
			pmap_insert_foreign(pm, end, ptr_diff(vend, end));
		}
	}
}

/**
 * Kernel may have overruled our foreign region accounting by allocating
 * ``size'' bytes starting at ``p''.  Make sure we remove all foreign pages
 * in this space.
 */
static void
pmap_overrule(struct pmap *pm, const void *p, size_t size)
{
	const void *base = p;
	size_t remain = size;

	while (size_is_positive(remain)) {
		size_t idx;
		struct vm_fragment *vmf = pmap_lookup(pm, base, &idx);
		size_t len;

		g_assert(size_is_non_negative(idx));

		if (NULL == vmf) {
			const void *end = const_ptr_add_offset(base, remain);
			const void *vend;
			size_t gap;

			/* ``base'' does not belong to any known region, ``idx'' is next */

			if (idx >= pm->count)
				break;

			vmf = &pm->array[idx];
			vend = vmf_end(vmf);

			if (ptr_cmp(end, vmf->start) <= 0)
				return;		/* Next region starts after our target */

			/* We have an overlap with region in ``vmf'' */

			g_assert(vmf_is_foreign(vmf));

			gap = ptr_diff(vmf->start, base);
			g_assert(size_is_positive(gap));
			g_assert(gap <= remain);

			remain -= gap;
			base = vmf->start;

			/* FALL THROUGH */
		}

		/*
		 * We have to remove ``remain'' bytes starting at ``base''.
		 */

		len = ptr_diff(vmf_end(vmf), base);		/* From base to end of region */

		g_assert(vmf_is_foreign(vmf));
		g_assert(size_is_positive(len));

		if (len <= remain) {
			pmap_remove_foreign(pm, vmf, base, len);
			base = const_ptr_add_offset(base, len);
			remain -= len;
		} else {
			pmap_remove_foreign(pm, vmf, base, remain);
			break;
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
		g_debug("VMM freeing %luKiB region at 0x%lx%s",
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
	assert_vmm_is_allocated(p, pc->chunksize);
	assert_vmm_is_not_foreign(p);
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
	assert_vmm_is_allocated(p, pc->chunksize);
	assert_vmm_is_not_foreign(p);
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
	assert_vmm_is_allocated(p, pc->chunksize);
	assert_vmm_is_not_foreign(p);

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
				g_debug("VMM page cache #%lu: "
					"coalescing previous [0x%lx, 0x%lx] with [0x%lx, 0x%lx]",
					(unsigned long) pc->pages - 1, (unsigned long) before,
					(unsigned long) ptr_add_offset(after, -1),
					(unsigned long) p,
					(unsigned long) ptr_add_offset(p, pc->chunksize - 1));
			}
			base = before;
			pages += pc->pages;
			vpc_remove(pc, before);
			idx--;		/* Removed entry before insertion point */
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
				g_debug("VMM page cache #%lu: "
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
			g_debug("VMM coalesced %luKiB region [0x%lx, 0x%lx] into "
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
			g_debug("VMM page cache #%lu: kicking out [0x%lx, 0x%lx] %luKiB",
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
		g_debug("VMM page cache #%lu: inserted [0x%lx, 0x%lx] %luKiB, "
			"now holds %lu item%s",
			(unsigned long) pc->pages - 1, (unsigned long) base,
			(unsigned long) ptr_add_offset(base, pc->chunksize - 1),
			(unsigned long) pc->chunksize / 1024,
			(unsigned long) pc->current, 1 == pc->current ? "" : "s");
	}
}

/**
 * Compare two pointers according to the growing direction of the VM space.
 * A pointer is larger than another if it is further away from the base.
 */
static inline int
vmm_ptr_cmp(const void *a, const void *b)
{
	if (a == b)
		return 0;

	return (kernel_mapaddr_increasing ? +1 : -1) * ptr_cmp(a, b);
}

/**
 * Find "n" consecutive pages in page cache and remove them from it.
 *
 * @param pc		the page cache line to search
 * @param n			amount of pages wanted
 * @param hole		if non-NULL, first known hole (uncached) that would fit
 *
 * @return pointer to the base of the "n" pages if found, NULL otherwise.
 */
static void *
vpc_find_pages(struct page_cache *pc, size_t n, const void *hole)
{
	size_t total = 0;
	void *base, *end;

	if (0 == pc->current)
		return NULL;

	if (n > pc->pages) {
		size_t i;

		/*
		 * Since we're looking for less pages than what this cache line stores,
		 * we'll have to split the page.
		 */

		for (i = 0; i < pc->current; i++) {
			base = kernel_mapaddr_increasing ?
				pc->info[i].base : pc->info[pc->current - 1 - i].base;

			/*
			 * We stop considering pages that are further away than the
			 * identified hole.  Since we traverse the cache line in the
			 * proper order, from "lower" addresses to "upper" ones, we can
			 * abort as soon as we've gone beyond the hole.
			 */

			if (hole != NULL && vmm_ptr_cmp(base, hole) > 0) {
				if (vmm_debugging(7)) {
					g_debug("VMM page cache #%lu: stopping split attempt "
						"at 0x%lx (upper than hole 0x%lx)",
						(unsigned long) pc->pages - 1,
						(unsigned long) base, (unsigned long) hole);
				}
				break;
			}

			goto selected;
		}

		return NULL;
	} else {
		size_t i;
		size_t max_distance = 0;
		base = NULL;

		/*
		 * Allocate the innermost pages within the region, so that pages at
		 * the beginning or end of the region remain unused and can be
		 * released if they're not needed.
		 */

		for (i = 0; i < pc->current; i++) {
			size_t d;
			const void *p;

			p = kernel_mapaddr_increasing ?
				pc->info[i].base : pc->info[pc->current - 1 - i].base;

			/*
			 * Stop considering pages that are further away from the
			 * identified hole.
			 */

			if (hole != NULL && vmm_ptr_cmp(p, hole) > 0) {
				if (vmm_debugging(7)) {
					g_debug("VMM page cache #%lu: stopping lookup at 0x%lx "
						"(upper than hole 0x%lx)",
						(unsigned long) pc->pages - 1,
						(unsigned long) p, (unsigned long) hole);
				}
				break;
			}

			d = pmap_nesting_within_region(vmm_pmap(), p, pc->chunksize);
			if (d > max_distance) {
				max_distance = d;
				base = deconstify_gpointer(p);
			}
		}

		if (NULL == base)
			return NULL;

		/* FALL THROUGH */
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
					if (hole != NULL && vmm_ptr_cmp(start, hole) > 0) {
						if (vmm_debugging(7)) {
							g_debug("VMM cache #%lu: stopping merge at "
								"0x%lx (upper than hole 0x%lx)",
								(unsigned long) pc->pages - 1,
								(unsigned long) start, (unsigned long) hole);
						}
						break;
					}

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
					if (hole != NULL && vmm_ptr_cmp(prev_base, hole) > 0) {
						if (vmm_debugging(7)) {
							g_debug("VMM cache #%lu: stopping merge at "
								"0x%lx (upper than hole 0x%lx)",
								(unsigned long) pc->pages - 1,
								(unsigned long) prev_base,
								(unsigned long) hole);
						}
						break;
					}

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
 * @param n			number of pages we want
 * @param hole_ptr	variable where first hole we found is written to
 *
 * @return a pointer to the start of the memory region, NULL if we were
 * unable to find that amount of contiguous memory.  In any case, ``hole_ptr''
 * is written with the first suitable hole we identified in the VM space.
 */
static void *
page_cache_find_pages(size_t n, const void **hole_ptr)
{
	void *p;
	size_t len;
	const void *hole;
	struct page_cache *pc = NULL;

	g_assert(size_is_positive(n));
	g_assert(hole_ptr != NULL);

	/*
	 * Before using pages from the cache, look where the first hole is
	 * at the start of the virtual memory space.  If we find one that can
	 * suit this allocation, then do not use cached pages that would
	 * lie after the hole.
	 */

	hole = NULL;
	len = vmm_first_hole(&hole);

	if (pagecount_fast(len) < n) {
		hole = NULL;
	} else if (!kernel_mapaddr_increasing) {
		size_t length = size_saturate_mult(n, kernel_pagesize);

		g_assert((size_t) -1 != length);
		g_assert(ptr_diff(hole, NULL) > length);

		hole = const_ptr_add_offset(hole, -length);
	}

	if (hole != NULL && vmm_debugging(8)) {
		g_debug("VMM lowest hole of %lu page%s at 0x%lx",
			(unsigned long) n, n == 1 ? "" : "s", (unsigned long) hole);
	}

	*hole_ptr = hole;

	if (n >= VMM_CACHE_LINES) {
		/*
		 * Our only hope to find suitable pages in the cache is to have
		 * consecutive ranges in the largest cache line.
		 */

		pc = &page_cache[VMM_CACHE_LINES - 1];
		p = vpc_find_pages(pc, n, hole);

		if (vmm_debugging(3)) {
			g_debug("VMM lookup for large area (%lu pages) returned 0x%lx",
				(unsigned long) n, (unsigned long) p);
		}
	} else {
		/*
		 * Start looking for a suitable page in the page cache matching
		 * the size we want.
		 */

		pc = &page_cache[n - 1];
		p = vpc_find_pages(pc, n, hole);

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
				p = vpc_find_pages(pc, n, hole);
			}
		}
	}

	if (p != NULL && vmm_debugging(5)) {
		g_debug("VMM found %luKiB region at 0x%lx in cache #%lu%s",
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

	assert_vmm_is_allocated(base, n * kernel_pagesize);
	assert_vmm_is_not_foreign(base);

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

	assert_vmm_is_allocated(base, pages * kernel_pagesize);

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
					g_debug("VMM iter #%lu, coalescing previous "
						"[0x%lx, 0x%lx] from lower cache #%lu "
						"with [0x%lx, 0x%lx]",
						(unsigned long) i, (unsigned long) before,
						(unsigned long) ptr_add_offset(base, -1),
						(unsigned long) lopc->pages - 1,
						(unsigned long) base,
						(unsigned long) ptr_add_offset(base,
							pages * kernel_pagesize - 1));
				}
				assert_vmm_is_allocated(before,
					(pages + lopc->pages) * kernel_pagesize);
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
				g_debug("VMM coalescing previous [0x%lx, 0x%lx] "
					"from higher cache #%lu with [0x%lx, 0x%lx]",
					(unsigned long) before,
					(unsigned long) ptr_add_offset(base, -1),
					(unsigned long) hopc->pages - 1,
					(unsigned long) base,
					(unsigned long) ptr_add_offset(base,
						pages * kernel_pagesize - 1));
			}
			assert_vmm_is_allocated(before,
				(pages + hopc->pages) * kernel_pagesize);
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
					g_debug("VMM iter #%lu, coalescing next [0x%lx, 0x%lx] "
						"from lower cache #%lu with [0x%lx, 0x%lx]",
						(unsigned long) i, (unsigned long) end,
						(unsigned long) ptr_add_offset(end,
							lopc->chunksize - 1),
						(unsigned long) lopc->pages - 1, (unsigned long) base,
						(unsigned long) ptr_add_offset(end, -1));
				}
				assert_vmm_is_allocated(base,
					(pages + lopc->pages) * kernel_pagesize);
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
				g_debug("VMM coalescing next [0x%lx, 0x%lx] "
					"from higher cache #%lu with [0x%lx, 0x%lx]",
					(unsigned long) end,
					(unsigned long) ptr_add_offset(end, hopc->chunksize - 1),
					(unsigned long) hopc->pages - 1,
					(unsigned long) base,
					(unsigned long) ptr_add_offset(end, -1));
			}
			assert_vmm_is_allocated(base,
				(pages + hopc->pages) * kernel_pagesize);
			pages += hopc->pages;
			vpc_remove(hopc, end);
			end = ptr_add_offset(end, hopc->chunksize);
			if (pages >= VMM_CACHE_LINES)
				goto done;
		}
	}

done:
	assert_vmm_is_allocated(base, pages * kernel_pagesize);

	if (pages != old_pages) {
		if (vmm_debugging(2)) {
			g_debug("VMM coalesced %luKiB region [0x%lx, 0x%lx] into "
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
	RUNTIME_ASSERT(size_is_positive(size));
#if defined(HAS_MADVISE) && defined(MADV_NORMAL)
	madvise(p, size, MADV_NORMAL);
#endif	/* MADV_NORMAL */
}

void
vmm_madvise_sequential(void *p, size_t size)
{
	RUNTIME_ASSERT(p);
	RUNTIME_ASSERT(size_is_positive(size));
#if defined(HAS_MADVISE) && defined(MADV_SEQUENTIAL)
	madvise(p, size, MADV_SEQUENTIAL);
#endif	/* MADV_SEQUENTIAL */
}

void
vmm_madvise_free(void *p, size_t size)
{
	RUNTIME_ASSERT(p);
	RUNTIME_ASSERT(size_is_positive(size));
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
	RUNTIME_ASSERT(size_is_positive(size));
#if defined(HAS_MADVISE) && defined(MADV_WILLNEED)
	madvise(p, size, MADV_WILLNEED);
#endif	/* MADV_WILLNEED */
}

static void
vmm_validate_pages(void *p, size_t size)
{
	RUNTIME_ASSERT(p);
	RUNTIME_ASSERT(size_is_positive(size));
#ifdef VMM_PROTECT_FREE_PAGES
	mprotect(p, size, PROT_READ | PROT_WRITE);
#endif	/* VMM_PROTECT_FREE_PAGES */
#ifdef VMM_INVALIDATE_FREE_PAGES 
	/*  This should be unnecessary */
	/*  vmm_madvise_normal(p, size); */
#endif	/* VMM_INVALIDATE_FREE_PAGES */
}

static void
vmm_invalidate_pages(void *p, size_t size)
{
	RUNTIME_ASSERT(p);
	RUNTIME_ASSERT(size_is_positive(size));

	if (G_UNLIKELY(stop_freeing))
		return;

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
	const void *hole;

	RUNTIME_ASSERT(size_is_positive(size));
	
	size = round_pagesize_fast(size);
	n = pagecount_fast(size);

	/*
	 * First look in the page cache to avoid requesting a new memory
	 * mapping from the kernel.
	 */

	p = page_cache_find_pages(n, &hole);
	if (p != NULL) {
		vmm_validate_pages(p, size);
		assert_vmm_is_allocated(p, size);
		assert_vmm_is_not_foreign(p);
		return p;
	}

	p = alloc_pages(size, TRUE, hole);
	if (NULL == p)
		g_error("cannot allocate %lu bytes: out of virtual memory",
			(unsigned long) size);

	assert_vmm_is_allocated(p, size);
	assert_vmm_is_not_foreign(p);
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
	const void *hole;

	RUNTIME_ASSERT(size_is_positive(size));

	size = round_pagesize_fast(size);
	n = pagecount_fast(size);

	/*
	 * First look in the page cache to avoid requesting a new memory
	 * mapping from the kernel.
	 */

	p = page_cache_find_pages(n, &hole);
	if (p != NULL) {
		vmm_validate_pages(p, size);
		memset(p, 0, size);
		assert_vmm_is_allocated(p, size);
		assert_vmm_is_not_foreign(p);
		return p;
	}

	p = alloc_pages(size, TRUE, hole);
	if (NULL == p)
		g_error("cannot allocate %lu bytes: out of virtual memory",
			(unsigned long) size);

	assert_vmm_is_allocated(p, size);
	assert_vmm_is_not_foreign(p);
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

		assert_vmm_is_allocated(p, size);
		assert_vmm_is_not_foreign(p);

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
		g_debug("VMM scanning page cache #%lu (%lu item%s)",
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
		g_debug("VMM expired %lu item%s (%luKiB total) from "
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
 * Copies the given string to a read-only buffer.
 *
 * @param s A NUL-terminated string. If NULL, NULL is returned.
 * @return	On success, a copy of the string is returned. On failure, NULL
 *			is returned.
 */
const char *
prot_strdup(const char *s)
{
	size_t n, size;
	void *p;

	if (!s)
		return NULL;

	n = strlen(s) + 1;
	size = round_pagesize_fast(n);
	p = alloc_pages(size, FALSE, NULL);
	if (p) {
		memcpy(p, s, n);
		mprotect(p, size, PROT_READ);
		pmap_insert_foreign(vmm_pmap(), p, size);
	}
	return p;
}

/**
 * Get a protected region bearing a non-NULL address.
 *
 * This is used as the address of sentinel objects for which we can do
 * pointer comparisons but which we shall never try to access directly as
 * they are "fake" object addresses.
 *
 * @return	A page-sized and page-aligned chunk of memory which causes an
 *			exception to be raised if accessed.
 */
const void *
vmm_trap_page(void)
{
	static const void *trap_page;

	if (NULL == trap_page) {
		void *p = alloc_pages(kernel_pagesize, FALSE, NULL);
		RUNTIME_ASSERT(p);
		mprotect(p, kernel_pagesize, PROT_NONE);
		trap_page = p;
	}
	return trap_page;
}

/**
 * @return whether the virtual memory segment grows with increasing addresses.
 */
gboolean
vmm_grows_upwards(void)
{
	return kernel_mapaddr_increasing;
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
	safe_to_malloc = TRUE;
#ifdef TRACK_VMM
	vmm_track_malloc_inited();
#endif
}

/**
 * Mark "amount" bytes as foreign in the local pmap, reserved for the stack.
 *
 * When the kernel pmap is loaded, simply make sure we find the stack
 * region and reserve an extra VMM_STACK_MINSIZE bytes for it to grow
 * further.
 */
static void
vmm_reserve_stack(size_t amount)
{
	const void *stack_base, *stack_end, *stack_low;

	/*
	 * If we could read the kernel pmap, reserve an extra VMM_STACK_MINSIZE
	 * after the stack, as a precaution.
	 */

	if (vmm_pmap() == &kernel_pmap) {
		struct vm_fragment *vmf = pmap_lookup(&kernel_pmap, initial_sp, NULL);
		gboolean first_time = NULL == vmm_base;

		if (NULL == vmf) {
			if (vmm_debugging(0)) {
				g_warning("VMM no stack region found in the kernel pmap");
			}
			if (NULL == vmm_base)
				vmm_base = vmm_trap_page();
		} else {
			const void *reserve_start;

			if (vmm_debugging(1)) {
				g_debug("VMM stack region found in the kernel pmap (%lu KiB)",
					(unsigned long) (vmf_size(vmf) / 1024));
			}

			stack_end = deconstify_gpointer(
				sp_increasing ? vmf_end(vmf) : vmf->start);
			reserve_start = const_ptr_add_offset(stack_end,
				(kernel_mapaddr_increasing ? +1 : -1) * VMM_STACK_MINSIZE);

			if (
				!pmap_is_available(&kernel_pmap,
					reserve_start, VMM_STACK_MINSIZE)
			) {
				if (vmm_debugging(0)) {
					g_warning("VMM cannot reserve extra %uKiB %s stack",
						VMM_STACK_MINSIZE / 1024,
						sp_increasing ? "after" : "before");
				}
			} else {
				pmap_insert_foreign(&kernel_pmap,
					reserve_start, VMM_STACK_MINSIZE);
				if (vmm_debugging(1)) {
					g_debug("VMM reserved [0x%lx, 0x%lx] "
						"%s stack for possible growing",
						(unsigned long) reserve_start,
						(unsigned long) const_ptr_add_offset(reserve_start,
							VMM_STACK_MINSIZE - 1),
						sp_increasing ? "after" : "before");
					vmm_dump_pmap();
				}
			}

			if (NULL == vmm_base)
				vmm_base = reserve_start;
		}
		if (first_time)
			goto vm_setup;
		return;
	}

	RUNTIME_ASSERT(amount != 0);

	/*
	 * If stack and VM region grow in opposite directions, there is ample
	 * room for the stack provided their relative position is correct.
	 */

	if ((size_t) -1 == amount) {
		vmm_base = vmm_trap_page();
		goto vm_setup;
	}

	stack_base = page_start(initial_sp);
	if (!sp_increasing)
		stack_base = const_ptr_add_offset(stack_base, kernel_pagesize);

	stack_end = const_ptr_add_offset(stack_base,
		(sp_increasing ? +1 : -1) * amount);
	stack_low = sp_increasing ? stack_base : stack_end;

	if (pmap_is_available(&local_pmap, stack_low, amount)) {
		pmap_insert_foreign(&local_pmap, stack_low, amount);
		if (vmm_debugging(1)) {
			g_debug("VMM reserved %luKiB [0x%lx, 0x%lx] for the stack",
				(unsigned long) amount / 1024,
				(unsigned long) stack_low,
				(unsigned long) const_ptr_add_offset(stack_low, amount - 1));
		}
		if (kernel_mapaddr_increasing) {
			const void *after_stack = const_ptr_add_offset(stack_low, amount);
			vmm_base = vmm_trap_page();
			if (ptr_cmp(vmm_base, after_stack) > 0)
				vmm_base = after_stack;
		} else {
			vmm_base = vmm_trap_page();
			if (ptr_cmp(vmm_base, stack_low) < 0)
				vmm_base = stack_low;
		}
	} else {
		if (vmm_debugging(0)) {
			g_warning("VMM cannot reserve %luKiB [0x%lx, 0x%lx] for the stack",
				(unsigned long) amount / 1024,
				(unsigned long) stack_low,
				(unsigned long) const_ptr_add_offset(stack_low, amount - 1));
			vmm_dump_pmap();
		}
		vmm_base = vmm_trap_page();
	}

vm_setup:
	if (vmm_debugging(0)) {
		g_debug("VMM will allocate pages from 0x%lx %swards",
			(unsigned long) vmm_base,
			kernel_mapaddr_increasing ? "up" : "down");
	}
}

/**
 * Called later in the initialization chain once the callout queue has been
 * initialized and the properties loaded.
 */
void
vmm_post_init(void)
{
	struct {
		unsigned non_default:1;
		unsigned vmm_invalidate_free_pages:1;
		unsigned vmm_protect_free_pages:1;
	} settings = { FALSE, FALSE, FALSE };

	/*
	 * Log VMM configuration.
	 */

#ifdef VMM_INVALIDATE_FREE_PAGES
	settings.non_default = TRUE;
	settings.vmm_invalidate_free_pages = TRUE;
#endif
#ifdef VMM_PROTECT_FREE_PAGES
	settings.non_default = TRUE;
	settings.vmm_protect_free_pages = TRUE;
#endif

	if (settings.non_default) {
		g_message("VMM settings: %s%s",
			settings.vmm_invalidate_free_pages ?
				"VMM_INVALIDATE_FREE_PAGES" : "",
			settings.vmm_protect_free_pages ?
				"VMM_PROTECT_FREE_PAGES" : "");
	}

	if (vmm_debugging(0)) {
		g_debug("VMM using %lu bytes for the page cache",
			(unsigned long) sizeof page_cache);
		g_debug("VMM kernel grows virtual memory by %s addresses",
			kernel_mapaddr_increasing ? "increasing" : "decreasing");
		g_debug("VMM stack grows by %s addresses",
			sp_increasing ? "increasing" : "decreasing");
	}

	if (vmm_debugging(1)) {
		g_debug("VMM initial break at 0x%lx", (unsigned long) initial_brk);
		g_debug("VMM stack bottom at 0x%lx", (unsigned long) initial_sp);
	}

	pmap_load(&kernel_pmap);
	cq_periodic_add(callout_queue, 1000, page_cache_timer, NULL);

	/*
	 * Check whether we have enough room for the stack to grow.
	 */

	{
		const void *vmbase = vmm_trap_page();	/* First page allocated */
		const void *end = const_ptr_add_offset(vmbase, kernel_pagesize);
		size_t room;

		if (ptr_cmp(initial_sp, vmbase) > 0) {
			if (!sp_increasing) {
				/*
				 * Stack is after the VM region and is decreasing, it can
				 * grow at most to the end of the allocated region.
				 */

				room = round_pagesize(ptr_diff(initial_sp, end));
			} else {
				/*
				 * Stack is after the VM region and is increasing.
				 * The kernel should be able to extend it.
				 */

				room = (size_t) -1;
			}
		} else {
			if (sp_increasing) {

				/*
				 * Stack is before the VM region and is increasing, it can
				 * grow at most to the start of the allocated region.
				 */

				room = round_pagesize(ptr_diff(vmbase, initial_sp));
			} else {
				/*
				 * Stack is before the VM region and is decreasing.
				 * The kernel should be able to extend it.
				 */

				room = (size_t) -1;
			}
		}

		if ((size_t) -1 == room) {
			if (vmm_debugging(0)) {
				g_debug("VMM kernel can grow the stack as needed");
			}
		} else if (room < VMM_STACK_MINSIZE) {
			g_warning("VMM stack has only %luKiB to grow!",
				(unsigned long) room / 1024);
		} else if (vmm_debugging(0)) {
			g_debug("VMM stack has at most %luKiB to grow",
				(unsigned long) room / 1024);
		}

		/*
		 * Reserve mappings for the stack so that we do not attempt
		 * to hint an allocation within that range.
		 */

		vmm_reserve_stack(room);
	}

#ifdef TRACK_VMM
	vmm_track_post_init();
#endif
}

/**
 * Early initialization of the vitual memory manager.
 *
 * @attention
 * No external memory allocation (malloc() and friends) can be done in this
 * routine, which is called very early at startup.
 */
void
vmm_init(const void *sp)
{
	int i;

	RUNTIME_ASSERT(sp != &i);

#ifndef MINGW32
	initial_brk = sbrk(0);
#endif
	initial_sp = sp;
	sp_increasing = ptr_cmp(&i, sp) > 0;

	init_kernel_pagesize();

	for (i = 0; i < VMM_CACHE_LINES; i++) {
		struct page_cache *pc = &page_cache[i];
		size_t pages = i + 1;
		pc->pages = pages;
		pc->chunksize = pages * kernel_pagesize;
	}

	/*
	 * Allocate the trap page early so that it is at the bottom of the
	 * memory space, hopefully (not really true on Linux, but close enough).
	 */
	(void) vmm_trap_page();

	/*
	 * Allocate the pmaps.
	 */

	pmap_allocate(&local_pmap);
	pmap_allocate(&kernel_pmap);

	pmap_insert_foreign(vmm_pmap(), vmm_trap_page(), kernel_pagesize);

	/*
	 * Determine how the kernel is growing the virtual memory region.
	 */

	{
		void *p = alloc_pages(kernel_pagesize, FALSE, NULL);
		void *q = alloc_pages(kernel_pagesize, FALSE, NULL);

		kernel_mapaddr_increasing = ptr_cmp(q, p) > 0;

		free_pages(q, kernel_pagesize, FALSE);
		free_pages(p, kernel_pagesize, FALSE);
	}

#ifdef TRACK_VMM
	vmm_track_init();
#endif
}

/**
 * Signal that we're about to close down all activity.
 */
void
vmm_pre_close(void)
{
	/*
	 * It's still safe to log, however it's going to get messy with all
	 * the memory freeing activity.  Better avoid such clutter.
	 */

	safe_to_malloc = FALSE;		/* Turn logging off */
}

/**
 * Signal that we should stop freeing memory pages.
 *
 * This is mostly useful during final cleanup when halloc() replaces malloc()
 * because some parts of the cleanup code in glib or libc expect to be able
 * to access memory that has been freed and do not like us invalidating the
 * addresses.
 */
void
vmm_stop_freeing(void)
{
	stop_freeing = TRUE;

	if (vmm_debugging(0))
		g_debug("VMM will no longer release freed pages");
}

/**
 * Final shutdown.
 */
void
vmm_close(void)
{
	struct pmap *pm = vmm_pmap();
	size_t pages = 0;
	size_t memory = 0;
	size_t i;

	/*
	 * Clear all cached pages.
	 */

	for (i = 0; i < VMM_CACHE_LINES; i++) {
		struct page_cache *pc = &page_cache[i];
		size_t j;

		for (j = 0; j < pc->current; j++) {
			vpc_free(pc, j);
		}
	}

#ifdef TRACK_VMM
	vmm_track_close();
#endif

	/*
	 * Look at remaining regions (leaked pages?).
	 */

	for (i = 0; i < pm->count; i++) {
		struct vm_fragment *vmf = &pm->array[i];

		if (vmf_is_foreign(vmf))
			continue;

		/*
		 * Found an allocated region, still.
		 */

		memory += vmf_size(vmf) / 1024;
		pages += pagecount_fast(vmf_size(vmf));
	}

	/*
	 * Substract "once" memory.
	 */

	{
		size_t opages = omalloc_page_count();

		if (opages > pages) {
			g_warning("VMM omalloc() claims using %lu page%s, we have %lu left",
				(unsigned long) opages, 1 == opages ? "" : "s",
				(unsigned long) pages);
		} else {
			pages -= opages;
			memory -= opages * (compat_pagesize() / 1024);
		}
	}

	if (pages != 0) {
		g_warning("VMM still holds %lu page%s totaling %s KiB",
			(unsigned long) pages, 1 == pages ? "" : "s",
			size_t_to_string(memory));
	}
}

/***
 *** mmap() and munmap() wrappers: the application should not call these
 *** system calls directly but go through the wrappers so that the VMM layer
 *** can keep an accurate view of the process's virtul memory map.
 ***/

/**
 * Wrapper of the mmap() system call.
 */
void *
vmm_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
#if defined(HAS_MMAP)
	void *p = mmap(addr, length, prot, flags, fd, offset);

	if (p != MAP_FAILED) {
		pmap_insert_foreign(vmm_pmap(), p, round_pagesize_fast(length));
		assert_vmm_is_allocated(p, length);

		if (vmm_debugging(5)) {
			g_debug("VMM mapped %luKiB region at 0x%lx "
				"(fd #%d, offset 0x%lx)",
				(unsigned long) length / 1024, (unsigned long) p,
				fd, (unsigned long) offset);
		}
	} else if (vmm_debugging(0)) {
		g_warning("VMM FAILED maping of %luKiB region "
			"(fd #%d, offset 0x%lx)",
			(unsigned long) length / 1024, fd, (unsigned long) offset);
	}

	return p;
#else	/* !HAS_MMAP */
	(void) addr;
	(void) length;
	(void) prot;
	(void) flags;
	(void) offset;
	g_assert_not_reached();

	return MAP_FAILED;
#endif	/* HAS_MMAP */
}

/**
 * Wrappper of the munmap() system call.
 */
int
vmm_munmap(void *addr, size_t length)
{
#if defined(HAS_MMAP)
	int ret;

	assert_vmm_is_allocated(addr, length);
	assert_vmm_is_foreign(addr);

	ret = munmap(addr, length);

	if (0 == ret) {
		pmap_remove(vmm_pmap(), addr, round_pagesize_fast(length));

		if (vmm_debugging(5)) {
			g_debug("VMM unmapped %luKiB region at 0x%lx",
				(unsigned long) length / 1024, (unsigned long) addr);
		}
	} else {
		g_warning("munmap() failed: %s", g_strerror(errno));
	}

	return ret;
#else	/* !HAS_MMAP */
	(void) addr;
	(void) length;
	g_assert_not_reached();

	return -1;
#endif	/* HAS_MMAP */
}

/***
 *** Allocation tracking -- enabled by compiling with -DTRACK_VMM.
 ***/

#ifdef TRACK_VMM
/**
 * This table assotiates an allocate pointer with a page_track structure.
 */
static hash_table_t *tracked;		/**< Allocations tracked */
static hash_table_t *not_leaking;	/**< Known non-leaks */

/**
 * Describes an allocated group of pages.
 */
struct page_track {
	size_t size;					/**< Length of consecutive pages */
	const char *file;				/**< File where allocation was made */
	int line;						/**< Line number within file */
#ifdef MALLOC_FRAMES
	const struct stackatom *ast;	/**< Allocation stack trace (atom) */
#endif
#ifdef MALLOC_TIME
	time_t atime;					/**< Allocation time */
#endif
};

/**
 * Because we're going to use hash_table_t to keep track of the allocated
 * pages, and due to the fact that this data structure internally relies on
 * the VMM layer, we may recurse to the tracking code at any time.
 *
 * This flag keeps track of recursions so that we avoid exercising any
 * tracking when recursion is detected.
 */
static gboolean vmm_recursed;

/**
 * This buffer allows us to queue allocations or deletions whenever a
 * tracking activity occurs and we've detected recursion.
 */
#define VMM_BUFFER	16

enum track_operation {
	VMM_ALLOC = 0,
	VMM_FREE
};

struct track_buffer {
	enum track_operation op;
	const void *addr;
	struct page_track pt;
#ifdef MALLOC_FRAMES
	struct stacktrace where;
#endif
};

struct buffering {
	size_t idx;				/**< Next available slot (0 = empty) */
	size_t missed;			/**< "could not buffer" events */
	size_t max;				/**< Max buffer index, for logging */
};

static struct track_buffer vmm_buffered[VMM_BUFFER];
static struct buffering vmm_buffer;

/**
 * Buffering of non-leaking events that happen before we're fully initialized
 */

static const void *vmm_nl_buffered[VMM_BUFFER];
static struct buffering vmm_nl_buffer;

/**
 * Human version of operations.
 */
static const char *
track_operation_to_string(enum track_operation op)
{
	switch (op) {
	case VMM_ALLOC:	return "alloc";
	case VMM_FREE:	return "free";
	}

	return "unknown operation";
}

static void unbuffer_operations(void);
static void vmm_free_record(const void *p, size_t size,
	const char *file, int line);

/**
 * Buffer operation for deferred processing (up to next alloc/free).
 * We're buffering the fact that the operation took place, not deferring the
 * actual allocation / free that is described.
 */
static void
buffer_operation(enum track_operation op,
	const void *p, size_t size, const char *file, int line)
{
	if (vmm_buffer.idx >= G_N_ELEMENTS(vmm_buffered)) {
		vmm_buffer.missed++;
		if (vmm_debugging(0)) {
			g_warning("VMM unable to defer tracking of "
				"%s (%lu bytes starting 0x%lx) at \"%s:%d\" (issue #%lu)",
				track_operation_to_string(op),
				(unsigned long) size, (unsigned long) p, file, line,
				(unsigned long) vmm_buffer.missed);
			stacktrace_where_print(stderr);
		}
	} else {
		size_t i = vmm_buffer.idx++;
		struct track_buffer *tb = &vmm_buffered[i];

		if (vmm_buffer.idx > vmm_buffer.max) {
			vmm_buffer.max = vmm_buffer.idx;
		}

		if (vmm_debugging(5)) {
			g_warning("VMM deferring tracking of "
				"%s (%lu bytes starting 0x%lx) at \"%s:%d\" (item #%lu)",
				track_operation_to_string(op),
				(unsigned long) size, (unsigned long) p, file, line,
				(unsigned long) vmm_buffer.idx);
		}

		tb->op = op;
		tb->addr = p;
		tb->pt.size = size;
		tb->pt.file = file;
		tb->pt.line = line;
#ifdef MALLOC_FRAMES
		stacktrace_get_offset(&tb->where, 2);
#endif
#ifdef MALLOC_TIME
		tb->pt.atime = tm_time();
#endif
	}
}

/*
 * In case TRACK_MALLOC is activated, we want the raw malloc() and free()
 * from here on...
 *
 * For that reason, the following code should stay at the bottom of the file.
 */
#undef malloc
#undef free

/**
 * Handle freeing of page, as described by the supplied page_track structure.
 */
static void
vmm_free_record_desc(const void *p, const struct page_track *pt)
{
	struct page_track *xpt;

	g_assert(pt != NULL);

	xpt = hash_table_lookup(tracked, p);

	if (NULL == xpt) {
		if (vmm_debugging(0)) {
			g_warning("VMM (%s:%d) attempt to free page at 0x%lx twice?",
				pt->file, pt->line, (unsigned long) p);
			stacktrace_where_print(stderr);
			if (0 == vmm_buffer.missed) {
				g_error("VMM vmm_free() of unknown address 0x%lx",
					(unsigned long) p);
			}
		}
		return;
	}

	if (xpt->size != pt->size) {
		if (vmm_debugging(0)) {
			g_warning("VMM (%s:%d) freeing page at 0x%lx (%lu bytes) "
				"from \"%s:%d\" with wrong size %lu [%lu missed event%s]",
				pt->file, pt->line, (unsigned long) p,
				(unsigned long) xpt->size, xpt->file, xpt->line,
				(unsigned long) pt->size, (unsigned long) vmm_buffer.missed,
				1 == vmm_buffer.missed ? "" : "s");
			stacktrace_where_print(stderr);
		}
	}

	hash_table_remove(tracked, p);
	free(xpt);						/* raw free() */
}

/**
 * Handle allocation as described in the supplied page_track structure.
 */
static void
vmm_alloc_record_desc(const void *p, const struct page_track *pt)
{
	struct page_track *xpt;

	g_assert(pt != NULL);

	if (NULL != (xpt = hash_table_lookup(tracked, p))) {
		g_warning("VMM (%s:%d) reusing page start 0x%lx (%lu bytes) "
			"from %s:%d, missed its freeing",
			pt->file, pt->line, (unsigned long) p, (unsigned long) xpt->size,
			xpt->file, xpt->line);
#ifdef MALLOC_FRAMES
		g_warning("VMM page 0x%lx was allocated from:", (unsigned long) p);
		stacktrace_atom_print(stderr, xpt->ast);
#endif
		g_warning("VMM current stack:");
		stacktrace_where_print(stderr);

		vmm_free_record_desc(p, pt);
	}

	xpt = malloc(sizeof *xpt);		/* raw malloc() */
	*xpt = *pt;						/* struct copy */

	if (!hash_table_insert(tracked, p, xpt))
		g_error("cannot record page allocation");
}

/**
 * Record that ``p'' is ``size'' bytes long and was allocated from "file:line".
 *
 * @return its argument ``p''
 */
static void *
vmm_alloc_record(void *p, size_t size, const char *file, int line)
{
	struct page_track pt;

	if (NULL == tracked)
		return p;					/* Tracking not initialized yet */

	if (vmm_recursed) {
		buffer_operation(VMM_ALLOC, p, size, file, line);
		return p;
	}

	if (vmm_buffer.idx != 0) {
		unbuffer_operations();
	}

	/*
	 * Critical section protected against recursion.
	 */

	g_assert(!vmm_recursed);

	vmm_recursed = TRUE;
	pt.size = size;
	pt.file = file;
	pt.line = line;
#ifdef MALLOC_FRAMES
	{
		struct stacktrace st;

		stacktrace_get_offset(&st, 1);
		pt.ast = stacktrace_get_atom(&st);
	}
#endif
#ifdef MALLOC_TIME
	pt.atime = tm_time();
#endif

	vmm_alloc_record_desc(p, &pt);
	vmm_recursed = FALSE;

	return p;
}

/**
 * Record that ``p'' (pointing to ``size'' bytes is now free.
 */
static void
vmm_free_record(const void *p, size_t size, const char *file, int line)
{
	struct page_track pt;

	if (vmm_recursed) {
		buffer_operation(VMM_FREE, p, size, file, line);
		return;
	}

	if (vmm_buffer.idx != 0) {
		unbuffer_operations();
	}

	/*
	 * Critical section protected against recursion.
	 */

	g_assert(!vmm_recursed);

	vmm_recursed = TRUE;
	pt.size = size;
	pt.file = file;
	pt.line = line;
	vmm_free_record_desc(p, &pt);
	vmm_recursed = FALSE;
}

/**
 * Shift out the first entry in the buffer, copying the value into the
 * supplied structure.
 */
static void
unbuffer_first(struct track_buffer *dest)
{
	g_assert(dest != NULL);
	g_assert(size_is_positive(vmm_buffer.idx));
	g_assert(vmm_buffer.idx <= G_N_ELEMENTS(vmm_buffered));

	*dest = vmm_buffered[0];		/* Struct copy */

	/* Shift everything down one position */
	memmove(&vmm_buffered[0], &vmm_buffered[1],
		(vmm_buffer.idx - 1) * sizeof vmm_buffered[0]);

	vmm_buffer.idx--;			/* One more slot available */
}

/**
 * Unbuffer operations in the order they were issued.
 */
static void unbuffer_operations(void)
{
	g_assert(size_is_positive(vmm_buffer.idx));

	while (vmm_buffer.idx != 0) {
		struct track_buffer tb;

		/*
		 * Shift the oldest operation before attempting to pocess it,
		 * making at least space for one more bufferable operation.
		 */

		unbuffer_first(&tb);		/* Decreases vmm_buffer.idx */

		g_assert(!vmm_recursed);
		vmm_recursed = TRUE;

		/*
		 * Process buffered operation.
		 */

		if (vmm_debugging(2)) {
			g_warning("VMM processing deferred "
				"%s (%lu bytes starting 0x%lx) at \"%s:%d\" "
				"(%lu other record%s pending)",
				track_operation_to_string(tb.op),
				(unsigned long) tb.pt.size, (unsigned long) tb.addr,
				tb.pt.file, tb.pt.line,
				(unsigned long) vmm_buffer.idx, 1 == vmm_buffer.idx ? "" : "s");
		}

		switch (tb.op) {
		case VMM_ALLOC:
#ifdef MALLOC_FRAMES
			tb.pt.ast = stacktrace_get_atom(&tb.where);
#endif
			vmm_alloc_record_desc(tb.addr, &tb.pt);
			break;
		case VMM_FREE:
#ifdef MALLOC_FRAMES
			tb.pt.ast = NULL;
#endif
			vmm_free_record_desc(tb.addr, &tb.pt);
			break;
		}

		vmm_recursed = FALSE;
	}
}

/**
 * Record a non-leaking address.
 */
static void *
vmm_not_leaking(const void *o)
{
	if (not_leaking != NULL) {
		hash_table_insert(not_leaking, o, GINT_TO_POINTER(1));
	} else {
		/*
		 * Buffer the event until we're initialized.
		 */

		if (vmm_nl_buffer.idx >= G_N_ELEMENTS(vmm_nl_buffered)) {
			vmm_nl_buffer.missed++;
		} else {
			size_t i = vmm_nl_buffer.idx++;

			if (vmm_nl_buffer.idx > vmm_nl_buffer.max) {
				vmm_nl_buffer.max = vmm_nl_buffer.idx;
			}
			vmm_nl_buffered[i] = o;
		}
	}

	return deconstify_gpointer(o);
}

/**
 * Tracking version of vmm_alloc().
 */
void *
vmm_alloc_track(size_t size, const char *file, int line)
{
	void *p;

	p = vmm_alloc(size);
	return vmm_alloc_record(p, size, file, line);
}

/**
 * Tracking version of vmm_alloc() for memory flagged as non-leaking.
 */
void *
vmm_alloc_track_not_leaking(size_t size, const char *file, int line)
{
	void *p;

	p = vmm_alloc_track(size, file, line);
	return vmm_not_leaking(p);
}

/**
 * Tracking version of vmm_alloc0().
 */
void *
vmm_alloc0_track(size_t size, const char *file, int line)
{
	void *p;

	p = vmm_alloc0(size);
	return vmm_alloc_record(p, size, file, line);
}

/**
 * Tracking version of vmm_free().
 */
void
vmm_free_track(void *p, size_t size, const char *file, int line)
{
	if (not_leaking != NULL) {
		hash_table_remove(not_leaking, p);
	}

	vmm_free_record(p, size, file, line);
	vmm_free(p, size);
}

/**
 * Initialization of the VMM tracking.
 */
static void
vmm_track_init(void)
{
	tracked = hash_table_new_real();
	not_leaking = hash_table_new_real();

	/*
	 * Handle buffered non-leaking events.
	 */

	if (vmm_nl_buffer.idx != 0) {
		size_t i;
		for (i = 0; i < vmm_nl_buffer.idx; i++) {
			vmm_not_leaking(vmm_nl_buffered[i]);
		}
	}
}

/**
 * Malloc was initialized, we can log.
 * Display warning if we overflowed our buffering.
 */
static void
vmm_track_malloc_inited(void)
{
	if (vmm_buffer.missed != 0) {
		g_warning("VMM missed %lu initial tracking event%s",
			(unsigned long) vmm_buffer.missed,
			1 == vmm_buffer.missed ? "" : "s");
	}
}

/**
 * Called when properties have been loaded, so we can use vmm_debugging().
 */
static void
vmm_track_post_init(void)
{
	if (vmm_buffer.max > 0 && vmm_debugging(0)) {
		g_debug("VMM required %lu bufferred event%s",
			(unsigned long) vmm_buffer.max,
			1 == vmm_buffer.max ? "" : "s");
	}
	if (vmm_nl_buffer.max > 0 && vmm_debugging(0)) {
		g_debug("VMM required %lu bufferred non-leaking event%s",
			(unsigned long) vmm_nl_buffer.max,
			1 == vmm_nl_buffer.max ? "" : "s");
	}
}

/**
 * vmm_log_pages		-- hash table iterator callback
 *
 * Log used pages, and record them among the `leaksort' set for future summary.
 */
static void
vmm_log_pages(const void *k, void *v, gpointer leaksort)
{
	const struct page_track *pt = v;
	char ago[32];

	if (hash_table_lookup(not_leaking, k))
		return;

#ifdef MALLOC_TIME
	gm_snprintf(ago, sizeof ago, " [%s]",
		short_time(delta_time(tm_time(), pt->atime)));
#else
	ago[0] = '\0';
#endif	/* MALLOC_TIME */

	g_warning("leaked page%s 0x%lx (%lu bytes) from \"%s:%d\"%s",
		pt->size > kernel_pagesize ? "s" : "",
		(unsigned long) k, (unsigned long) pt->size,
		pt->file, pt->line, ago);

	leak_add(leaksort, pt->size, pt->file, pt->line);

#ifdef MALLOC_FRAMES
	g_message("block 0x%lx allocated from: ", (unsigned long) k);
	stacktrace_atom_print(stderr, pt->ast);
#endif
}

/**
 * Report leaks.
 */
static void
vmm_track_close(void)
{
	void *leaksort;

	leaksort = leak_init();
	hash_table_foreach(tracked, vmm_log_pages, leaksort);
	leak_dump(leaksort);
	leak_close(leaksort);

	/*
	 * Do not destroy ``tracked'', in case the final messages we emit cause
	 * a memory allocation and the VMM layer is called again.
	 */
}

/**
 * The raw vmm_alloc().
 */
void *
vmm_alloc_notrack(size_t size)
{
	return vmm_alloc(size);
}

/**
 * The raw vmm_free().
 */
void
vmm_free_notrack(void *p, size_t size)
{
	vmm_free(p, size);
}
#endif	/* TRACK_VMM */

/* vi: set ts=4 sw=4 cindent: */
