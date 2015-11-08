/*
 * Copyright (c) 2006, Christian Biere
 * Copyright (c) 2006, 2011, 2013-2015, Raphael Manfredi
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
 * Virtual Memory Management (VMM).
 *
 * This is the lowest-level memory allocator, dealing with memory regions
 * at the granularity of a memory page (usually 4 KiB).
 *
 * Although the application can use this layer directly, it should rely on
 * other memory allocators such as walloc(), a wrapping layer over zalloc(),
 * or halloc() when tracking the size of the allocated area is impractical
 * or just impossible.  These allocators are in turn built on top of VMM.
 *
 * The VMM layer maintains a map of the virtual address space in order to
 * reduce memory fragmentation: we're making every attempt to avoid creating
 * fragments, which would be harmful in a 32-bit virtual address space as it
 * would end-up preventing the creation of large chunks of virtual memory.
 *
 * At the same time, in order to avoid exercising the kernel virtual memory
 * management code too often, we're maintaining a cache of small pages,
 * possibly coalescing them into bigger areas before releasing them or recycling
 * them because the process needs to allocate more memory.  Coalesced areas
 * can be split to fulfill smaller allocations, if necessary.
 *
 * Because we're not the kernel, we cannot get an accurate vision on the
 * usage of the virtual memory space.  Sometimes allocation at a given place
 * will fail, because for instance the kernel mapped a shared library there.
 * Such spots are marked as "foreign" memory zones, i.e. areas of the memory
 * that we did not allocate.
 *
 * The usage of UNIX mmap() and munmap() system calls should be avoided in
 * the application, preferring the wrappers vmm_mmap() and vmm_munmap() because
 * this lets us "see" the memory-mapped zones as "foreign" zones, without
 * having to discover them: since these zones are transient, most of the time,
 * it would cause a permanent waste of the memory virtual space: a region is
 * marked "foreign" once and is never forgotten, unless it was created via
 * vmm_mmap() and is now released through vmm_munmap().
 *
 * Virtual memory is allocated through vmm_alloc() or vmm_alloc0() and is
 * released through vmm_free().  The application should always strive to
 * give back memory through vmm_free() as soon as it no longer needs it.
 * It must carefully give back as much as was allocated though, so it must
 * keep track of the size of the allocated zone.  Because we're tracking
 * the allocated areas in memory, assertions can detect blatant misuses, but
 * cannot trap all the errors.
 *
 * When compiled with TRACK_VMM, a record of allocated virtual memory is kept
 * to allow leak detection (block of page allocated and never freed) or bad
 * freeing attempts (trying to free an address that was never allocated).
 * The tracking code also supports general MALLOC_FRAMES and MALLOC_TIME
 * compile options, to record allocation frames for an address and the time
 * at which the allocation took place.
 *
 * @attention
 * The initialization of the various memory allocators in the application
 * is tricky.  Although vmm_init() will necessarily be the first call made,
 * other allocators may need to be initialized, and the initialization order
 * is important.
 *
 * We distinguish two different type of memory regions here: "user" and "core".
 *
 * A "user" region is one allocated explicitly by user code to use as a
 * storage area. It is allocated by vmm_alloc() and needs to be released by
 * calling vmm_free().
 *
 * A "core" region is one allocated by other memory allocators and which will
 * be broken up into pieces possibly before being distributed to users.
 *
 * Portions of "core" regions may be freed at any time, whereas "user" regions
 * are allocated and freed atomically.  No "user" region should leak, but "core"
 * regions can and will leak due to possible memory fragmentation at the memory
 * allocator level.
 *
 * @author Christian Biere
 * @date 2006
 * @author Raphael Manfredi
 * @date 2006, 2009, 2011, 2013-2015
 */

#include "common.h"

#define VMM_SOURCE
#include "vmm.h"

#include "alloca.h"			/* For alloca_stack_direction() */
#include "array_util.h"
#include "ascii.h"
#include "atomic.h"
#include "cq.h"
#include "crash.h"			/* For crash_hook_add(), crash_oom() */
#include "dump_options.h"
#include "evq.h"
#include "fd.h"
#include "log.h"
#include "memusage.h"
#include "mutex.h"
#include "omalloc.h"
#include "once.h"
#include "parse.h"
#include "pow2.h"
#include "rwlock.h"
#include "sha1.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"			/* For str_bprintf() */
#include "stringify.h"
#include "thread.h"			/* For thread_small_id() */
#include "tm.h"
#include "tmalloc.h"
#include "unsigned.h"
#include "xmalloc.h"
#include "zalloc.h"

#ifdef TRACK_VMM
#include "hashtable.h"
#endif

#ifdef MINGW32
#include <windows.h>
#endif

#include "override.h"		/* Must be the last header included */

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
static bool kernel_mapaddr_increasing;
static once_flag_t vmm_early_inited;
static once_flag_t vmm_inited;
static bool vmm_fully_inited;
static bool vmm_crashing;

#define VMM_CACHE_SIZE		256	/**< Amount of entries per cache line */
#define VMM_CACHE_LINES		32	/**< Amount of cache lines */
#define VMM_CACHE_LIFE		60	/**< At most 1 minute on short-term strategy */
#define VMM_CACHE_MAXLIFE	900	/**< At most 15 minutes on long-term strategy */
#define VMM_STACK_MINSIZE	(64 * 1024)		/**< Minimum stack size */
#define VMM_FOREIGN_LIFE	(60 * 60)		/**< 60 minutes */
#define VMM_FOREIGN_MAXLEN	(512 * 1024)	/**< 512 KiB */
#define VMM_WARN_THRESH		512	/**< Pages, 2 MiB with 4K pages */

struct page_info {
	void *base;		/**< base address */
	time_t stamp;	/**< time at which the page was inserted */
};

struct page_cache {
	struct page_info info[VMM_CACHE_SIZE];	/**< sorted on base address */
	spinlock_t lock;	/**< thread-safe protection */
	size_t current;		/**< amount of items in info[] */
	size_t pages;		/**< amount of consecutive pages for entries */
	size_t chunksize;	/**< size of each entry */
	/* Statistics */
	uint64 targeted;	/**< allocations targeting this cache line */
	uint64 allocated;	/**< allocations done from this cache line */
	uint64 denied;		/**< allocations denied despite line being non-empty */
	uint64 split;		/**< splits done from this cache line */
	uint64 evicted;		/**< amount of pages evicted */
	uint64 expired;		/**< amount of pages expired */
};

/**
 * The page cache.
 *
 * At index 0, we have pages whose size is the VMM page size.
 * Ad index n, we have areas made of n+1 consecutive pages.
 */
static struct page_cache page_cache[VMM_CACHE_LINES];
static size_t page_cache_line;	/**< Next cache line to expire */

/**
 * Fragment types
 */
typedef enum {
	VMF_NATIVE	= 0,		/**< Allocated by this layer */
	VMF_MAPPED	= 1,		/**< Memory-mapped by this layer */
	VMF_FOREIGN	= 2			/**< Foreign region */
} vmf_type_t;

/**
 * Structure used to represent a fragment in the virtual memory space.
 */
struct vm_fragment {
	const void *start;		/**< Start address */
	const void *end;		/**< First byte beyond end of region */
	time_t mtime;			/**< Last time we updated fragment */
	vmf_type_t type;		/**< Fragment type */
};

/**
 * A process virtual memory map.
 *
 * The array holding the sorted fragments is allocated via alloc_pages().
 */
struct pmap {
	struct vm_fragment *array;		/**< Sorted array of vm_fragment structs */
	rwlock_t lock;					/**< Thread-safe locking */
	size_t count;					/**< Amount of entries in array */
	size_t size;					/**< Total amount of slots in array */
	size_t pages;					/**< Amount of pages for the array */
	unsigned extending:1;			/**< Pmap being extended */
};

/**
 * Internal statistics collected.
 *
 * The AU64() fields are atomically updated (without taking the VMM stats lock).
 */
static struct vmm_stats {
	uint64 allocations;				/**< Total number of allocations */
	uint64 allocations_zeroed;		/**< Total number of zeroing in allocs */
	uint64 allocations_core;		/**< Core memory allocations */
	uint64 allocations_user;		/**< User memory allocations */
	uint64 freeings;				/**< Total number of freeings */
	uint64 freeings_core;			/**< Core memory freeings */
	uint64 freeings_user;			/**< User memory freeings */
	uint64 shrinkings;				/**< Total number of shrinks */
	uint64 shrinkings_core;			/**< Core memory shrinkings */
	uint64 shrinkings_user;			/**< User memory shrinkings */
	AU64(resizings);				/**< Total amount of vmm_resize() calls */
	AU64(mmaps);					/**< Total number of mmap() calls */
	AU64(munmaps);					/**< Total number of munmap() calls */
	uint64 magazine_allocations;	/**< Allocations through thread magazine */
	uint64 magazine_freeings;		/**< Freeings through thread magazine */
	uint64 magazine_freeings_frag;	/**< Magazine regions that were fragments */
	uint64 hints_followed;			/**< Allocations following hints */
	uint64 hints_ignored;			/**< Allocations ignoring non-NULL hints */
	uint64 alloc_from_cache;		/**< Allocation from cache */
	uint64 alloc_from_cache_pages;	/**< Pages allocated from cache */
	uint64 alloc_direct_core;		/**< Allocation done through core */
	uint64 alloc_direct_core_pages;/**< Pages allocated from core */
	uint64 free_to_cache;			/**< Freeings directed to cache */
	uint64 free_to_cache_pages;		/**< Amount of pages directed to cache */
	uint64 free_to_system;			/**< Freeings returned to kernel */
	uint64 free_to_system_pages;	/**< Amount of pages returned to kernel */
	uint64 free_to_system_extra_pages;	/**< Cached paged coalesced in free */
	uint64 forced_freed;			/**< Amount of forceful freeings */
	uint64 forced_freed_pages;		/**< Amount of pages forcefully freed */
	AU64(cache_evictions);			/**< Evictions due to cache being full */
	AU64(cache_coalescing);			/**< Amount of coalescing from cache */
	AU64(cache_line_coalescing);	/**< Amount of coalescing in cache line */
	uint64 cache_expired;			/**< Amount of entries expired from cache */
	uint64 cache_expired_pages;		/**< Expired pages from cache */
	uint64 cache_kept;				/**< Cached entries that we do not expire */
	AU64(cache_ignored);			/**< Ignored cache lines during lookups */
	AU64(cache_exact_match);		/**< Found entry in the right cache line */
	AU64(cache_splits);				/**< Split cached entries in allocations */
	AU64(cache_high_coalescing);	/**< Large regions successfully coalesced */
	AU64(cache_too_large);			/**< Allocation too large for cache */
	uint64 pmap_foreign_discards;	/**< Foreign regions discarded */
	uint64 pmap_foreign_discarded_pages;	/**< Foreign pages discarded */
	AU64(pmap_overruled);			/**< Regions overruled by kernel */
	AU64(pmap_dropped);				/**< Dropped regions while extending pmap */
	uint64 hole_reused;				/**< Amount of times we use cached hole */
	uint64 hole_invalidated;		/**< Times we invalidate cached hole */
	uint64 hole_updated;			/**< Times we updated the cached hole */
	uint64 hole_unchanged;			/**< Times we left the cached hole as-is */
	size_t user_memory;				/**< Amount of "user" memory allocated */
	size_t user_pages;				/**< Amount of "user" memory pages used */
	size_t user_blocks;				/**< Amount of "user" memory blocks */
	size_t core_memory;				/**< Amount of "core" memory allocated */
	size_t core_pages;				/**< Amount of "core" memory pages used */
	/* Tracking core blocks doesn't make sense: "core" can be fragmented */
	memusage_t *user_mem;			/**< User memory usage statistics */
	memusage_t *core_mem;			/**< Core usage statistics */
	/* Counter to prevent digest from being the same twice in a row */
	AU64(vmm_stats_digest);
} vmm_stats;
static spinlock_t vmm_stats_slk = SPINLOCK_INIT;

#define VMM_STATS_LOCK		spinlock_hidden(&vmm_stats_slk)
#define VMM_STATS_UNLOCK	spinunlock_hidden(&vmm_stats_slk)

#define VMM_STATS_INCX(x)	AU64_INC(&vmm_stats.x)

/**
 * The local version of the process memory map.
 */
static struct pmap local_pmap;

/**
 * The maintained value of the "first hole" in the VM space.
 *
 * This is the lowest hole in the VM space, which lies at the bottom of
 * the memory space if the VM grows upwards or near the end when the VM grows
 * downwards.
 *
 * Caching this value and maintaining it through allocations and frees lets
 * us improve performance during concurrent allocations because vmm_first_hole()
 * does not need to take the pmap's read-lock if the hole is valid.
 */
static struct vmm_hole {
	const void *start;		/**< Start address */
	const void *end;		/**< First byte beyond end of region */
} vmm_hole;
static spinlock_t vmm_hole_slk = SPINLOCK_INIT;

#define VMM_HOLE_LOCK		spinlock_hidden(&vmm_hole_slk)
#define VMM_HOLE_UNLOCK		spinunlock_hidden(&vmm_hole_slk)

/**
 * The "upper hole" in the VM space is an estimated upper bound of the
 * address where the next allocation could take place for regions smaller
 * than the estimated free space.
 *
 * The "upper hole" is a conservative estimate of the first free region
 * further away from the last allocation point.
 */
static struct vm_upper_hole {
	const void *p;			/**< Start address of region */
	size_t len;				/**< Length of the identified hole there */
} vmm_upper_hole;
static spinlock_t vmm_upper_hole_slk = SPINLOCK_INIT;

#define VMM_UPPER_HOLE_LOCK		spinlock_hidden(&vmm_upper_hole_slk)
#define VMM_UPPER_HOLE_UNLOCK	spinunlock_hidden(&vmm_upper_hole_slk)

/**
 * The memory allocation strategy.
 */
static enum vmm_strategy vmm_strategy = VMM_STRATEGY_SHORT_TERM;
static spinlock_t vmm_strategy_slk = SPINLOCK_INIT;
static cperiodic_t *vmm_periodic;

#define VMM_STRATEGY_LOCK		spinlock_hidden(&vmm_strategy_slk)
#define VMM_STRATEGY_UNLOCK		spinunlock_hidden(&vmm_strategy_slk)

/*
 * The VMM allocation layer is used by other memory allocators to get more
 * core, but can also be used by the application to allocate known-to-be-large
 * areas or memory (e.g. hash table arenas, or RX buffers).
 *
 * Unfortunately, as a user-level memory allocator, the VMM layer is very
 * slow, and more so on freeing because it attempts to coalesce pages.
 *
 * It is fair to say it is about 10 times slower than walloc() for 4K blocks,
 * when single-threaded.  If we add concurrency, the VMM layer does not scale
 * well, and throughput with 8 threads allocating 4K blocks concurrently is
 * about 100 times worse than the throughput obtained with 1 thread, which is
 * not already spectacular...
 *
 * To increase throughput of VMM as a user-level allocator, we add support
 * for distribution through thread magazines, for blocks up to 5 system pages.
 * These are small enough to not waste too much memory in the unused magazines.
 * This is ONLY for user memory, not core allocations.
 *
 * Thread magazines will not be created until the event queue is up.
 */

#define VMM_MAGAZINE_PAGEMAX	5	/**< Up to 5 pages */
static tmalloc_t *vmm_magazine[VMM_MAGAZINE_PAGEMAX];

static bool safe_to_log;			/**< True when we can log */
static bool stop_freeing;			/**< No longer release memory */
static uint32 vmm_debug;			/**< Debug level */
static int sp_direction;			/**< Growing direction of the stack */
static const void *vmm_base;		/**< Where we'll start allocating */
static const void *stack_base;		/**< Where stack starts (its "bottom") */
#ifdef HAS_SBRK
static const void *initial_brk;		/**< Startup position of the heap */
#endif

#ifdef TRACK_VMM
static void vmm_track_init(void);
static void vmm_track_malloc_inited(void);
static void vmm_track_post_init(void);
static void vmm_track_close(void);
#endif

#define vmm_debugging(lvl)	G_UNLIKELY(vmm_debug > (lvl) && safe_to_log)

bool
vmm_is_debugging(uint32 level) 
{ 
	return vmm_debugging(level);
}

bool
vmm_is_inited(void)
{
	return vmm_fully_inited;
}

static inline struct pmap *
vmm_pmap(void)
{
	return &local_pmap;
}

static bool page_cache_insert_pages(void *base, size_t n);
static void pmap_remove(struct pmap *pm, const void *p, size_t size);
static size_t pmap_insert_region(struct pmap *pm,
	const void *start, size_t size, vmf_type_t type);
static void pmap_overrule(struct pmap *pm,
	const void *p, size_t size, vmf_type_t type);
static struct vm_fragment *pmap_lookup(const struct pmap *pm,
	const void *p, size_t *low_ptr);
static void vmm_reserve_stack(size_t amount);
static void *page_cache_find_pages(size_t n, bool user_mem, bool emergency);
static void page_cache_free_all(bool locked);

/**
 * @return whether VMM is in crash mode.
 */
bool
vmm_is_crashing(void)
{
	return vmm_crashing;
}

/**
 * Put the VMM layer in crashing mode.
 *
 * This is activated on assertion failures and other fatal conditions, and
 * is an irreversible operation.  Its purpose is to prevent any usage of
 * internal data structures that could be corrupted, yet allow basic memory
 * allocation during crashing.
 *
 * In crashing mode, allocations are done without any pmap updating and
 * no shrinking nor freeing occurs.
 */
G_GNUC_COLD void
vmm_crash_mode(void)
{
	vmm_crashing = TRUE;
	ZERO(&vmm_magazine);
	atomic_mb();
}

/**
 * Initialize constants for the computation of kernel page roundings.
 */
static G_GNUC_COLD void
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
static inline ALWAYS_INLINE size_t G_GNUC_PURE
round_pagesize_fast(size_t n)
{
	return (n + kernel_pagemask) & ~kernel_pagemask;
}

/**
 * Fast version of page counting: how many pages does it take to store `n'?
 */
static inline ALWAYS_INLINE size_t G_GNUC_PURE
pagecount_fast(size_t n)
{
	return round_pagesize_fast(n) >> kernel_pageshift;
}

/**
 * Fast version for converting amount of pages into a size.
 */
static inline ALWAYS_INLINE size_t G_GNUC_PURE
nsize_fast(size_t n)
{
	return n << kernel_pageshift;
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
static inline G_GNUC_PURE ALWAYS_INLINE const void *
page_start(const void *p)
{
	unsigned long addr = pointer_to_ulong(p);

	addr &= ~kernel_pagemask;
	return ulong_to_pointer(addr);
}

/**
 * Rounds pointer down so that it is aligned to the start of its page.
 *
 * @return the base address of the page where ``p'' lies.
 */
const void *
vmm_page_start(const void *p)
{
	return page_start(p);
}

/**
 * @return the base address of the page following the one where ``p'' lies.
 */
const void *
vmm_page_next(const void *p)
{
	return page_start(const_ptr_add_offset(p, kernel_pagesize));
}

/**
 * Count amount of pages required to hold given size.
 */
size_t
vmm_page_count(size_t size)
{
	return pagecount_fast(size);
}

/**
 * Loudly warn with a possible stack trace.
 */
static void G_GNUC_PRINTF(1, 2)
vmm_warn_once(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_minilogv(G_LOG_LEVEL_WARNING, TRUE, format, args);
	va_end(args);

	if (!stacktrace_caller_known(2))		/* Caller of our caller */
		s_stacktrace(TRUE, 2);
}

/**
 * Initialize the stack shape: direction, bottom (base) address.
 */
static G_GNUC_COLD void
init_stack_shape(void)
{
	int sp;

	sp_direction = alloca_stack_direction();
	stack_base = page_start(&sp);
	if (sp_direction < 0)
		stack_base = const_ptr_add_offset(stack_base, kernel_pagesize);
}

#define VMM_PAGESIZE_DFLT		4096		/* If we don't know better */

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
	if (ret < 0) {
		return_value_unless(0 == errno, VMM_PAGESIZE_DFLT);
		return VMM_PAGESIZE_DFLT;
	}
	return ret;
}
#else /* !_SC_PAGESIZE && !_SC_PAGE_SIZE */
{
	return getpagesize();
}
#endif /* _SC_PAGESIZE || _SC_PAGE_SIZE */

size_t
compat_pagesize(void)
{
	static bool initialized;
	static size_t psize;

	if G_UNLIKELY(!initialized) {
		long n;
		
		initialized = TRUE;
		n = compat_pagesize_intern();
		g_assert(n > 0);
		g_assert(n < INT_MAX);
		g_assert(is_pow2(n));
		psize = n;
		g_assert((size_t) psize == (size_t) n);
	}

	return psize;
}

/**
 * @return whether fragment is identified as foreign.
 */
static inline ALWAYS_INLINE bool
vmf_is_foreign(const struct vm_fragment *vmf)
{
	return VMF_FOREIGN == vmf->type;
}

/**
 * @return whether fragment is identified as being memory-mapped.
 */
static inline ALWAYS_INLINE bool
vmf_is_mapped(const struct vm_fragment *vmf)
{
	return VMF_MAPPED == vmf->type;
}

/**
 * @return whether fragment is identified as being native.
 */
static inline ALWAYS_INLINE bool
vmf_is_native(const struct vm_fragment *vmf)
{
	return VMF_NATIVE == vmf->type;
}

/**
 * @return size of a memory fragment.
 */
static inline ALWAYS_INLINE size_t
vmf_size(const struct vm_fragment *vmf)
{
	return ptr_diff(vmf->end, vmf->start);
}

/**
 * @return whether memory fragment is an "old" foreign region thatwe may
 * discard.
 */
static inline ALWAYS_INLINE bool
vmf_is_old_foreign(const struct vm_fragment *vmf)
{
	/*
	 * We only discard "foreign" regions that are not too large, because we
	 * don't want to spend too much time attempting to use addresses from
	 * that range as allocation hints, in case it is a truly "foreign" region.
	 */

	return vmf_is_foreign(vmf) &&
		vmf_size(vmf) <= VMM_FOREIGN_MAXLEN &&
		delta_time(tm_time(), vmf->mtime) > VMM_FOREIGN_LIFE;
}

/**
 * @return textual description of memory fragment type.
 */
static const char *
vmf_type_str(const vmf_type_t type)
{
	switch (type) {
	case VMF_NATIVE:	return "native";
	case VMF_MAPPED:	return "mapped";
	case VMF_FOREIGN:	return "foreign";
	}

	g_error("corrupted VM fragment type: %d", type);
	return NULL;
}

/**
 * @return textual description of a memory fragment type in static buffer.
 */
static const char *
vmf_to_string(const struct vm_fragment *vmf)
{
	static char buf[THREAD_MAX][80];
	char *b = &buf[thread_small_id()][0];
	size_t n = pagecount_fast(vmf_size(vmf));

	str_bprintf(b, sizeof buf[0], "%s [%p, %p[ (%zu page%s)",
		vmf_type_str(vmf->type), vmf->start, vmf->end, n, plural(n));

	return b;
}

/**
 * Dump current pmap to specified logagent.
 */
G_GNUC_COLD void
vmm_dump_pmap_log(logagent_t *la)
{
	struct pmap *pm = vmm_pmap();
	size_t i, count, size, length;
	time_t now = tm_time();
	struct vm_fragment *array;

	/*
	 * We use a write-lock and not a read-lock here, which can seem surprising
	 * at first since we're in essence reading the pmap.  However, we are
	 * allocating memory and re-enter the VMM layer, attempting to then grab
	 * the write-lock.  It is not allowed to request a write-lock when the
	 * read-lock is already owned (one needs to upgrade it or release the read
	 * lock and request the write lock).
	 *
	 * Therefore we need to take the write-lock to be fully protected, since
	 * we can then take it again or request read-locks whilst we own the
	 * write-lock.
	 */

	rwlock_wlock(&pm->lock);

	count = pm->count;
	size = pm->size;
	length = count * sizeof array[0];
	array = vmm_alloc(length);			/* Why we need a write-lock on pmap */
	memcpy(array, pm->array, length);

	rwlock_wunlock(&pm->lock);

	/*
	 * Remaining code running without any lock, using the data we just copied.
	 */

	log_debug(la, "VMM local pmap (%zu/%zu region%s):",
		count, size, plural(count));

	for (i = 0; i < count; i++) {
		struct vm_fragment *vmf = &array[i];
		size_t hole = 0;

		if (i < count - 1) {
			const void *next = array[i+1].start;
			hole = ptr_diff(next, vmf->end);
		}

		/*
		 * Because log_debug() can allocate memory, which could then recurse
		 * and update the pmap, we MUST NOT access ``vmf'' afterwards.
		 *
		 * Since all the arguments will be evaluated and pushed on the stack
		 * before we can recurse, there is no need to copy the content of
		 * ``vmf'' before making the call though.
		 */

		log_debug(la, "VMM [%p, %p] %zuKiB %s%s%s%s (%s)%s",
			vmf->start, const_ptr_add_offset(vmf->end, -1),
			vmf_size(vmf) / 1024, vmf_type_str(vmf->type),
			hole ? " + " : "",
			hole ? size_t_to_string(hole / 1024) : "",
			hole ? "KiB hole" : "",
			compact_time(delta_time(now, vmf->mtime)),
			size_is_non_negative(hole) ? "" : " *UNSORTED*");
	}

	vmm_free(array, length);
}

/**
 * Dump current pmap.
 */
G_GNUC_COLD void
vmm_dump_pmap(void)
{
	vmm_dump_pmap_log(log_agent_stderr_get());
}

#if defined(HAS_MMAP) || defined(MINGW32)
/**
 * Find a hole in the virtual memory map where we could allocate "size" bytes.
 *
 * This routine must be called with the pmap write-locked.
 */
static const void *
vmm_find_hole(size_t size)
{
	struct pmap *pm = vmm_pmap();
	size_t i;

	assert_rwlock_is_owned(&pm->lock);

	if G_UNLIKELY(!vmm_fully_inited)
		return NULL;

	if G_UNLIKELY(0 == pm->count)
		return NULL;

	if (kernel_mapaddr_increasing) {
		for (i = 0; i < pm->count; i++) {
			struct vm_fragment *vmf = &pm->array[i];
			const void *end = vmf->end;

			if G_UNLIKELY(ptr_cmp(end, vmm_base) < 0)
				continue;

			if G_UNLIKELY(i == pm->count - 1) {
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
			const void *start = vmf->start;

			if G_UNLIKELY(ptr_cmp(start, vmm_base) > 0)
				continue;

			if G_UNLIKELY(1 == i) {
				return page_start(const_ptr_add_offset(start, -size));
			} else {
				struct vm_fragment *prev = &pm->array[i - 2];

				if (ptr_diff(start, prev->end) >= size)
					return page_start(const_ptr_add_offset(start, -size));
			}
		}
	}

	if (vmm_debugging(0)) {
		s_miniwarn("VMM no %zuKiB hole found in pmap", size / 1024);
	}

	return NULL;
}

/**
 * Discard region at specified index within the pmap.
 */
static inline void
pmap_drop(struct pmap *pm, size_t idx)
{
	ARRAY_REMOVE_DEC(pm->array, idx, pm->count);
}

/**
 * Discard foreign region at specified index within the pmap.
 */
static void
pmap_discard_index(struct pmap *pm, size_t idx)
{
	struct vm_fragment *vmf;

	g_assert(pm != NULL);
	g_assert(size_is_non_negative(idx) && idx < pm->count);
	assert_rwlock_is_owned(&pm->lock);

	vmf = &pm->array[idx];

	g_assert_log(vmf_is_foreign(vmf), "vmf={%s}", vmf_to_string(vmf));

	if (vmm_debugging(0)) {
		s_minidbg("VMM discarding %s region at %p (%zuKiB) updated %us ago",
			vmf_type_str(vmf->type), vmf->start,
			vmf_size(vmf) / 1024, (unsigned) delta_time(tm_time(), vmf->mtime));
	}

	VMM_STATS_LOCK;
	vmm_stats.pmap_foreign_discards++;
	vmm_stats.pmap_foreign_discarded_pages += pagecount_fast(vmf_size(vmf));
	VMM_STATS_UNLOCK;

	pmap_drop(pm, idx);
}

/**
 * Compute the size of the first hole at the base of the VM space and return
 * its location in ``hole_ptr'', if we find one with a non-zero length.
 *
 * @param hole_ptr		where first hole address is written to
 * @param discard		whether we can discard foreign regions during lookup
 *
 * @return size of the first hole we found, 0 if none found.
 *
 * @attention
 * When kernel_mapaddr_increasing is FALSE, the value in hole_ptr is the end
 * of the memory region.  To get the starting address of the hole (i.e. the
 * memory pointer that would get allocated to cover the hole), one has to
 * substract the size of the region from the returned pointer.
 */
static G_GNUC_HOT size_t
vmm_first_hole(const void **hole_ptr, bool discard)
{
	struct pmap *pm = vmm_pmap();
	size_t i, result = 0;
	bool wlock = FALSE;

	/*
	 * Check with the cached version of the hole first.
	 *
	 * Each time we can return the cached hole, we improve concurrency because
	 * we do not need to request the pmap's read-lock at all.
	 *
	 * When we are allocating from the page cache, we can achieve efficient
	 * allocations because we do not need to lock the pmap at all.
	 */

	VMM_HOLE_LOCK;

	if (NULL != vmm_hole.start) {
		result = ptr_diff(vmm_hole.end, vmm_hole.start);
		*hole_ptr = kernel_mapaddr_increasing ? vmm_hole.start : vmm_hole.end;

		/*
		 * Normally we should have the VMM stats lock to update the stats,
		 * but here we always update this counter when we have the hole lock,
		 * and this is sufficient to prevent concurrent updates.
		 */

		vmm_stats.hole_reused++;
		VMM_HOLE_UNLOCK;

		return result;
	}

	VMM_HOLE_UNLOCK;

	/*
	 * Hole has been invalidated, recompute it.
	 */

	rwlock_rlock(&pm->lock);

	if G_UNLIKELY(0 == pm->count) {
		rwlock_runlock(&pm->lock);
		return 0;
	}

retry:

	if (kernel_mapaddr_increasing) {
		for (i = 0; i < pm->count; i++) {
			struct vm_fragment *vmf = &pm->array[i];
			const void *end = vmf->end;

			if G_UNLIKELY(ptr_cmp(end, vmm_base) < 0)
				continue;

			if G_UNLIKELY(i == pm->count - 1) {
				*hole_ptr = end;
				result = SIZE_MAX;
				goto done;
			} else {
				struct vm_fragment *next = &pm->array[i + 1];

				/*
				 * If we are at a foreign region that has not been updated
				 * for some time, discard it and try to reuse that region.
				 */

				if G_UNLIKELY(discard && vmf_is_old_foreign(vmf)) {
					const void *start = vmf->start;

					/* Upgrade from read to write lock if needed */

					if G_UNLIKELY(!wlock) {
						if (rwlock_upgrade(&pm->lock)) {
							wlock = TRUE;
						} else {
							rwlock_runlock(&pm->lock);
							rwlock_wlock(&pm->lock);
							wlock = TRUE;
							goto retry;
						}
					}

					pmap_discard_index(pm, i);
					*hole_ptr = start;
					result = ptr_diff(next->start, start);
					goto done;
				}

				if (next->start == end)
					continue;		/* Different types do not coalesce */
				*hole_ptr = end;
				result = ptr_diff(next->start, end);
				goto done;
			}
		}
	} else {
		for (i = pm->count; i > 0; i--) {
			struct vm_fragment *vmf = &pm->array[i - 1];
			const void *start = vmf->start;

			if G_UNLIKELY(ptr_cmp(start, vmm_base) > 0)
				continue;

			if G_UNLIKELY(1 == i) {
				*hole_ptr = start;
				result = SIZE_MAX;
				goto done;
			} else {
				struct vm_fragment *prev = &pm->array[i - 2];

				/*
				 * If we are at a foreign region that has not been updated
				 * for some time, discard it and try to reuse that region.
				 */

				if G_UNLIKELY(discard && vmf_is_old_foreign(vmf)) {
					const void *end = vmf->end;

					/* Upgrade from read to write lock if needed */

					if G_UNLIKELY(!wlock) {
						if (rwlock_upgrade(&pm->lock)) {
							wlock = TRUE;
						} else {
							rwlock_runlock(&pm->lock);
							rwlock_wlock(&pm->lock);
							wlock = TRUE;
							goto retry;
						}
					}

					pmap_discard_index(pm, i - 1);
					*hole_ptr = end;
					result = ptr_diff(end, prev->end);
					goto done;
				}

				if (start == prev->end)
					continue;		/* Foreign and native do not coalesce */
				*hole_ptr = start;
				result = ptr_diff(start, prev->end);
				goto done;
			}
		}
	}

done:
	if (wlock)
		rwlock_wunlock(&pm->lock);
	else
		rwlock_runlock(&pm->lock);

	/*
	 * This is just a hint, it's OK if, by the time we fill it in, it's been
	 * obsoleted by concurrent allocation in the VM space.
	 */

	if (result != 0) {
		VMM_HOLE_LOCK;
		if (kernel_mapaddr_increasing) {
			vmm_hole.start = *hole_ptr;
			vmm_hole.end = const_ptr_add_offset(vmm_hole.start, result);
		} else {
			vmm_hole.end = *hole_ptr;
			vmm_hole.start = const_ptr_add_offset(vmm_hole.end, -result);
		}
		VMM_HOLE_UNLOCK;
	}

	return result;
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
vmm_first_hole(const void **unused, bool discard)
{
	(void) unused;
	(void) discard;
	return 0;
}
#endif	/* HAS_MMAP || MINGW32 */

static inline void
vmm_set_stop_freeing(bool val)
{
	stop_freeing = val;
#ifdef MINGW32
	mingw_set_stop_vfree(val);
#endif
}

/**
 * Dump current VMM hole to specified logagent.
 */
G_GNUC_COLD void
vmm_dump_hole_log(logagent_t *la)
{
	struct vmm_hole h;
	struct vm_upper_hole u;
	const void *hole;
	size_t len;

	VMM_HOLE_LOCK;
	h = vmm_hole;		/* struct copy */
	VMM_HOLE_UNLOCK;
	VMM_UPPER_HOLE_LOCK;
	u = vmm_upper_hole;	/* struct copy */
	VMM_UPPER_HOLE_UNLOCK;

	if (!kernel_mapaddr_increasing)
		u.p = const_ptr_add_offset(u.p, -u.len);

	log_debug(la, "VMM upper hole [%p, %p] %zuKiB",
		u.p, const_ptr_add_offset(u.p, u.len), u.len / 1024);

	if (h.start != NULL) {
		log_debug(la, "VMM cached first hole [%p, %p] %zuKiB",
			h.start, h.end, ptr_diff(h.end, h.start) / 1024);
	} else {
		log_debug(la, "VMM cached first hole was stale");
	}

	VMM_HOLE_LOCK;
	vmm_hole.start = NULL;		/* Invalidate cached hole */
	VMM_HOLE_UNLOCK;

	len = vmm_first_hole(&hole, FALSE);
	if (0 == len) {
		log_debug(la, "VMM no hole found");
	} else {
		if (!kernel_mapaddr_increasing)
			hole = const_ptr_add_offset(hole, -len);

		log_debug(la, "VMM newest first hole [%p, %p] %zuKiB",
			hole, const_ptr_add_offset(hole, len), len / 1024);
	}
}

/**
 * Update cached hole if the region falls within or encompasses it.
 *
 * @param p		start of the region (allocated, marked foreign, memory-mapped)
 * @param size	length of the region
 * @param alloc	whether region was allocated
 */
static void
vmm_hole_update(const void *p, size_t size, bool alloc)
{
	/*
	 * NOTE: we update the hole statistics with the hole lock held: we do
	 * not grab the VMM stats lock instead, since this is sufficient to
	 * guarantee atomic updates: thes counters are only updated whilst
	 * holding that hole lock.
	 */

	VMM_HOLE_LOCK;
	if (vmm_hole.start != NULL) {
		const void *end = const_ptr_add_offset(p, size);

		if (
			alloc && kernel_mapaddr_increasing &&
			ptr_cmp(end, vmm_hole.start) <= 0
		) {
			/* Allocated before hole, hole was stale */
			vmm_hole.start = NULL;		/* Invalidate hole */
			vmm_stats.hole_invalidated++;
		}
		else if (alloc && !kernel_mapaddr_increasing &&
			ptr_cmp(p, vmm_hole.end) >= 0
		) {
			/* Allocated after hole, hole was stale */
			vmm_hole.start = NULL;		/* Invalidate hole */
			vmm_stats.hole_invalidated++;
		}
		else if (
			ptr_cmp(p, vmm_hole.start) <= 0 &&
			ptr_cmp(end, vmm_hole.end) >= 0
		) {
			/* Hole in the middle of the region */
			vmm_hole.start = NULL;		/* Invalidate hole */
			vmm_stats.hole_invalidated++;
		}
		else if (
			ptr_cmp(p, vmm_hole.start) >= 0 &&
			ptr_cmp(end, vmm_hole.end) <= 0
		) {
			/* Region falls within hole but does not cover it all */
			if (0 == ptr_cmp(p, vmm_hole.start)) {
				vmm_hole.start = end;
				vmm_stats.hole_updated++;
			} else if (0 == ptr_cmp(end, vmm_hole.end)) {
				vmm_hole.end = p;
				vmm_stats.hole_updated++;
			} else if (kernel_mapaddr_increasing) {
				vmm_hole.end = p;
				vmm_stats.hole_updated++;
			} else {
				vmm_hole.start = end;
				vmm_stats.hole_updated++;
			}
		}
		else if (
			ptr_cmp(end, vmm_hole.start) >= 0 &&
			ptr_cmp(end, vmm_hole.end) < 0
		) {
			vmm_hole.start = end;
			vmm_stats.hole_updated++;
		}
		else if (
			ptr_cmp(p, vmm_hole.start) >= 0 &&
			ptr_cmp(p, vmm_hole.end) < 0
		) {
			vmm_hole.end = p;
			vmm_stats.hole_updated++;
		} else {
			vmm_stats.hole_unchanged++;
		}

		if (0 == ptr_cmp(vmm_hole.start, vmm_hole.end)) {
			vmm_hole.start = NULL;		/* Invalidate "empty" hole */
			vmm_stats.hole_invalidated++;
		}
	}
	VMM_HOLE_UNLOCK;
}

/**
 * Update the "upper hole" address for VMM allocation tuning.
 *
 * @param pm		the pmap updated after the allocation
 * @param idx		the region in the pmap where allocation was done.
 */
static void
vmm_upper_hole_update(struct pmap *pm, size_t idx)
{
	struct vm_fragment *vmf;
	struct vm_upper_hole upper;

	assert_rwlock_is_owned(&pm->lock);
	g_assert(idx < pm->count);

	vmf = &pm->array[idx];
	g_assert(vmf_is_native(vmf));	/* Was just allocated */

	/*
	 * Look at how much room we have with the next region, when moving
	 * away from the VM base.  If the region where the allocation took
	 * place is the last, then the upper bound is known and the available
	 * length is unbound.
	 *
	 * If the next region is adjacent (e.g. we're bumping into a foreign
	 * region) then we could move further up in the pmap to find a hole,
	 * but we want a quick estimate, not a true hole.
	 */

	if (kernel_mapaddr_increasing) {
		if G_UNLIKELY(pm->count - 1 == idx) {
			upper.p = vmf->end;
			upper.len = SIZE_MAX;
		} else {
			struct vm_fragment *next = &pm->array[idx + 1];
			upper.p = next->start;
			upper.len = ptr_diff(next->start, vmf->end);	/* Can be 0 */
		}
	} else {
		if G_UNLIKELY(0 == idx) {
			upper.p = vmf->start;
			upper.len = SIZE_MAX;
		} else {
			struct vm_fragment *prev = &pm->array[idx - 1];
			upper.p = prev->end;
			upper.len = ptr_diff(vmf->start, prev->end);	/* Can be 0 */
		}
	}

	VMM_UPPER_HOLE_LOCK;
	vmm_upper_hole = upper;		/* struct copy */
	VMM_UPPER_HOLE_UNLOCK;
}

/**
 * Insert foreign region in the pmap.
 */
static inline void
pmap_insert_foreign(struct pmap *pm, const void *start, size_t size)
{
	pmap_insert_region(pm, start, size, VMF_FOREIGN);
	vmm_hole_update(start, size, FALSE);
}

#ifdef HAS_MMAP
/**
 * Insert memory-mapped region in the pmap.
 */
static inline void
pmap_insert_mapped(struct pmap *pm, const void *start, size_t size)
{
	pmap_insert_region(pm, start, size, VMF_MAPPED);
	vmm_hole_update(start, size, FALSE);
}
#endif	/* HAS_MMAP */

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
	void *p;
	void *hint = deconstify_pointer(hole);
	static uint64 hint_followed;

	if G_UNLIKELY(failed)
		return NULL;

	if G_UNLIKELY(hint != NULL) {
		if (vmm_debugging(8)) {
			s_minidbg("VMM hinting %p for new %zuKiB region",
				hint, size / 1024);
		}
	}

	p = vmm_valloc(hint, size);

	if G_UNLIKELY(MAP_FAILED == p) {
		if (ENOMEM != errno) {
			failed = 1;
			return_value_unless(MAP_FAILED != p, NULL);
		}
		p = NULL;
	} else if G_UNLIKELY(p != hint) {
		struct pmap *pm = vmm_pmap();

		/*
		 * Allocation hint was not followed.
		 */

		if G_UNLIKELY(hint != NULL) {
			if (vmm_debugging(0)) {
				s_miniwarn("VMM kernel did not follow hint %p for %zuKiB "
					"region, picked %p (after %zu followed hint%s)",
					hint, size / 1024, p, (size_t) hint_followed,
					plural(hint_followed));
			}
			VMM_STATS_LOCK;
			vmm_stats.hints_ignored++;
			hint_followed = 0;		/* Always updated with stats lock taken */
			VMM_STATS_UNLOCK;
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

		rwlock_wlock(&pm->lock);		/* Begin critical section */

		pmap_overrule(pm, p, size, VMF_NATIVE);

		if (NULL == hint) {
			rwlock_wunlock(&pm->lock);
			goto done;
		}

		/*
		 * Kernel did not use our hint, maybe it was wrong because something
		 * got mapped at the place where we thought there was nothing...
		 *
		 * See whether we can mark something as "foreign" in the VM space so
		 * that we avoid further attempts at the same location for blocks
		 * of similar sizes.
		 *
		 * On Windows, we reserve a large chunk of VM space at startup and
		 * allocate from there, until it is exhausted, at which time we use
		 * emergency allocations with NULL hints.  When that happens, we near
		 * a process restart so it is useless to start identifying regions in
		 * the VM space where things have been mapped by the kernel.
		 *		--RAM, 2015-04-07
		 */

		if (!pm->extending && !is_running_on_mingw()) {
			if (size <= kernel_pagesize) {
				pmap_insert_foreign(pm, hint, kernel_pagesize);
				if (vmm_debugging(0)) {
					s_minidbg("VMM marked hint %p as foreign", hint);
				}
			} else if (
				ptr_cmp(hint, ptr_add_offset(p, size)) >= 0 ||
				ptr_cmp(hint, p) < 0
			) {
				void *try;

				/*
				 * The hint address is not included in the allocated segment.
				 *
				 * Try allocating a single page at the hint location, and
				 * if we don't succeed, we can mark it as foreign.  If
				 * we succeed and we were previously trying to allocate
				 * exactly two pages, then we know the next page is foreign.
				 */

				try = vmm_valloc(hint, kernel_pagesize);

				if G_LIKELY(try != MAP_FAILED) {
					if (try != hint) {
						pmap_insert_foreign(pm, hint, kernel_pagesize);
						if (vmm_debugging(0)) {
							s_minidbg("VMM marked hint %p as foreign", hint);
						}
					} else if (2 == pagecount_fast(size)) {
						void *next = ptr_add_offset(hint, kernel_pagesize);
						if (next != p) {
							pmap_insert_foreign(pm, next, kernel_pagesize);
							if (vmm_debugging(0)) {
								s_minidbg("VMM marked %p (page after %p) "
									"as foreign", next, hint);
							}
						} else {
							if (vmm_debugging(0)) {
								s_minidbg("VMM funny kernel ignored hint %p "
									"and allocated 8 KiB at %p whereas hint "
									"was free", hint, p);
							}
						}
					} else {
						if (vmm_debugging(1)) {
							s_minidbg("VMM hinted %p is not a foreign page",
								hint);
						}
					}
					if (0 != vmm_vfree(try, kernel_pagesize)) {
						s_miniwarn("VMM cannot free one page at %p: %m", try);
					}

				} else {
					if (vmm_debugging(0)) {
						s_miniwarn("VMM cannot allocate one page at %p: %m",
							hint);
					}
				}
			} else {
				if (vmm_debugging(0)) {
					s_minidbg("VMM hint %p fell within allocated [%p, %p]",
						hint, p, ptr_add_offset(p, size - 1));
				}
			}
		}
		rwlock_wunlock(&pm->lock);		/* End critical section */
	} else if (hint != NULL) {
		/*
		 * Allocation took place at the hinted address.
		 */

		if G_UNLIKELY(0 == (hint_followed & 0xff)) {
			if (vmm_debugging(0)) {
				s_minidbg("VMM hint %p followed for %zuKiB (%zu consecutive)",
					hint, size / 1024, (size_t) hint_followed);
			}
		}
		VMM_STATS_LOCK;
		hint_followed++;
		vmm_stats.hints_followed++;
		VMM_STATS_UNLOCK;
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
	g_assert_not_reached();
#error "Neither mmap(), posix_memalign() nor memalign() available"
#endif	/* HAS_POSIX_MEMALIGN */
	if (p != NULL) {
		memset(p, 0, size);
	}
	return p;
}
#endif	/* HAS_MMAP */

static void
vmm_validate_pages(void *p, size_t size)
{
	g_assert(p);
	g_assert(size_is_positive(size));
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
	g_assert(p);
	g_assert(size_is_positive(size));

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
 * Insert region in the pmap, known to be native.
 */
static size_t
pmap_insert(struct pmap *pm, const void *start, size_t size)
{
	return pmap_insert_region(pm, start, size, VMF_NATIVE);
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
alloc_pages(size_t size, bool update_pmap)
{
	void *p;
	const void *hole = NULL;
	struct pmap *pm = vmm_pmap();

	g_assert(kernel_pagesize > 0);

	if (update_pmap) {
		/*
		 * We only compute a hole when we're going to update the pmap.
		 * Because we hold the pmap's write lock, only one thread at a time
		 * will be able to perform the allocation with that selected hole.
		 */

		rwlock_wlock(&pm->lock);
		if (G_UNLIKELY(stop_freeing)) {
			hole = NULL;
		} else {
			hole = vmm_find_hole(size);
		}
	}

	p = vmm_mmap_anonymous(size, hole);

	if G_UNLIKELY(NULL == p) {
		size_t n = pagecount_fast(size);

		/*
		 * Emergency situation: we're out of memory, we're going to request
		 * that this process be restarted.  If we return NULL from here, this
		 * is going to be a burtal restart, and we can maybe perform a clean
		 * one: all we have to do is be able to allocate from the page cache,
		 * even though this would not be an optimal allocation.
		 *		--RAM, 2015-04-02
		 *
		 * We request "user memory" from the page cache to ensure we're going
		 * to be served if there is memory available there.
		 */

		p = page_cache_find_pages(n, TRUE, TRUE);
		if (p != NULL) {
			vmm_validate_pages(p, size);
			memset(p, 0, size);				/* Kernel memory always zeroed */

			/* We're going to crash and restart, don't update statistics */

			crash_restart("%s(): emergency allocation of %'zu bytes from "
				"the page cache, requesting restart",
				G_STRFUNC, size);

			/* Allocation from page cache: region is already in the pmap */
			goto done;
		}

		/*
		 * Critical situation: free all the pages from the page cache and
		 * retry allocation.
		 */

		page_cache_free_all(TRUE);

		if (update_pmap) {
			if (G_UNLIKELY(stop_freeing)) {
				hole = NULL;
			} else {
				hole = vmm_find_hole(size);
			}
		}

		p = vmm_mmap_anonymous(size, hole);

		if (p != NULL) {
			/* We're going to crash and restart, don't update statistics */

			crash_restart("%s(): emergency allocation of %'zu bytes after "
				"clearing the page cache, requesting restart",
				G_STRFUNC, size);

			goto allocated;
		}

	done:
		if (update_pmap)
			rwlock_wunlock(&pm->lock);

		return p;
	}

allocated:
	g_assert_log(page_start(p) == p, "aligned memory required: %p", p);

	if (vmm_debugging(5)) {
		s_minidbg("VMM allocated %zuKiB region at %p", size / 1024, p);
	}

	vmm_hole_update(p, size, TRUE);

	if (update_pmap) {
		size_t idx;

		idx = pmap_insert(pm, p, size);
		vmm_upper_hole_update(pm, idx);
		rwlock_wunlock(&pm->lock);
	}

	return p;
}

/**
 * Release pages allocated by alloc_pages().
 * Must not be called directly other than through free_pages*() routines.
 */
static void
free_pages_intern(void *p, size_t size, bool update_pmap)
{
	/*
	 * The critical region is required when we're going to update the
	 * pmap since another thread could concurrently allocate memory that
	 * was already freed at the kernel level but which could be still
	 * accounted for as "busy" in the pmap -- a situation likely to break
	 * assertions.
	 */

	if (update_pmap)
		rwlock_wlock(&vmm_pmap()->lock);

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

		if G_UNLIKELY(ret != 0) {
			s_minierror("%s(): release of %'zu bytes at %p failed: %s",
				G_STRFUNC, size, p, symbolic_errno(errno));
		}
	}
#elif defined(HAS_POSIX_MEMALIGN) || defined(HAS_MEMALIGN)
	(void) size;
	free(p);
#else
	(void) p;
	(void) size;
	g_assert_not_reached();
#error "Neither mmap(), posix_memalign() nor memalign() available"
#endif	/* HAS_POSIX_MEMALIGN || HAS_MEMALIGN */

	/*
	 * Update the cached first hole if freed region touches it.
	 *
	 * NOTE: we update the hole statistics with the hole lock held: we do
	 * not grab the VMM stats lock instead, since this is sufficient to
	 * guarantee atomic updates: thes counters are only updated whilst
	 * holding that hole lock.
	 */

	VMM_HOLE_LOCK;
	if (vmm_hole.start != NULL) {
		const void *end = ptr_add_offset(p, size);

		if (kernel_mapaddr_increasing && ptr_cmp(end, vmm_hole.start) <= 0) {
			if (0 == ptr_cmp(end, vmm_hole.start)) {
				vmm_hole.start = p;
				vmm_stats.hole_updated++;
			} else {
				vmm_hole.start = NULL;	/* Invalidate, our hole was stale */
				vmm_stats.hole_invalidated++;
			}
		}
		else if (!kernel_mapaddr_increasing && ptr_cmp(p, vmm_hole.end) >= 0) {
			if (0 == ptr_cmp(p, vmm_hole.end)) {
				vmm_hole.end = end;
				vmm_stats.hole_updated++;
			} else {
				vmm_hole.start = NULL;	/* Invalidate, our hole was stale */
				vmm_stats.hole_invalidated++;
			}
		}
		else if (
			ptr_cmp(p, vmm_hole.start) <= 0 &&
			ptr_cmp(end, vmm_hole.end) >= 0
		) {
			/* Hole in the middle of the freed region */
			vmm_hole.start = p;
			vmm_hole.end = end;
			vmm_stats.hole_updated++;
		}
		else if (
			ptr_cmp(p, vmm_hole.start) >= 0 &&
			ptr_cmp(end, vmm_hole.end) <= 0
		) {
			/* Freed region falls within hole but does not cover it all */
			vmm_hole.start = NULL;		/* Invalidate, our hole was stale */
			vmm_stats.hole_invalidated++;
		}
		else if (
			ptr_cmp(p, vmm_hole.start) <= 0 &&
			ptr_cmp(end, vmm_hole.start) >= 0
		) {
			vmm_hole.start = p;
			if (ptr_cmp(end, vmm_hole.end) > 0)
				vmm_hole.end = end;
			vmm_stats.hole_updated++;
		}
		else if (
			ptr_cmp(p, vmm_hole.end) <= 0 &&
			ptr_cmp(end, vmm_hole.end) >= 0
		) {
			vmm_hole.end = end;
			if (ptr_cmp(p, vmm_hole.start) < 0)
				vmm_hole.start = p;
			vmm_stats.hole_updated++;
		} else {
			vmm_stats.hole_unchanged++;
		}
	}
	VMM_HOLE_UNLOCK;

pmap_update:
	if (update_pmap) {
		struct pmap *pm = vmm_pmap();

		pmap_remove(pm, p, size);
		rwlock_wunlock(&pm->lock);
	}
}

/**
 * Free memory allocated by alloc_pages().
 */
static void
free_pages(void *p, size_t size, bool update_pmap)
{
	if (vmm_debugging(5)) {
		s_minidbg("VMM freeing %zuKiB region at %p", size / 1024, p);
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
static G_GNUC_HOT struct vm_fragment *
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
		if (ptr_cmp(p, item->end) >= 0)
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

	rwlock_init(&pm->lock);
	pm->array = alloc_pages(kernel_pagesize, FALSE);
	pm->pages = 1;
	pm->count = 0;
	pm->size = kernel_pagesize / sizeof pm->array[0];

	if (NULL == pm->array)
		s_minierror("cannot initialize the VMM layer: out of memory already?");

	rwlock_wlock(&vmm_pmap()->lock);
	pmap_insert(vmm_pmap(), pm->array, kernel_pagesize);
	rwlock_wunlock(&vmm_pmap()->lock);
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
	bool was_extending = pm->extending;

	assert_rwlock_is_owned(&pm->lock);

retry:

	osize = kernel_pagesize * pm->pages;
	nsize = osize + kernel_pagesize;

	if (vmm_debugging(0)) {
		s_minidbg("VMM extending %spmap from %zu KiB to %zu KiB",
			pm->extending ? "(recursively) " : "",
			osize / 1024, nsize / 1024);
	}

	pm->extending = TRUE;

	/*
	 * It is possible to recursively enter here through alloc_pages() when
	 * mmap() is used to allocate virtual memory, in case we insert a foreign
	 * region.
	 *
	 * To protect against that, we start by allocating the new pages and
	 * remember the amount of pages in the map.  If upon return from the
	 * alloc_pages() call we see the number is different, it means the
	 * allocation was done and we can free up the pages we already allocated
	 * and return.
	 */

	{
		size_t old_pages = pm->pages;

		narray = alloc_pages(nsize, FALSE);	/* May recurse here */

		if (NULL == narray) {
			crash_oom("%s(): cannot extend pmap to %'zu bytes: "
				"out of virtual memory", G_STRFUNC, nsize);
		}

		if (pm->pages != old_pages) {
			if (vmm_debugging(0)) {
				s_miniwarn("VMM already recursed to %s(), pmap is now %zu KiB",
					G_STRFUNC, (kernel_pagesize * pm->pages) / 1024);
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
				s_miniwarn("VMM however pmap is still full, extending again!");
			
			goto retry;
		} else {
			if (vmm_debugging(0)) {
				s_minidbg("VMM allocated new %zu KiB pmap at %p",
					nsize / 1024, narray);
			}
		}
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

	pmap_insert(pm, narray, nsize);
	free_pages(oarray, osize, TRUE);
}

/**
 * Insert region in the pmap.
 *
 * @return index where region was inserted / coalesced to.
 */
static size_t
pmap_insert_region(struct pmap *pm,
	const void *start, size_t size, vmf_type_t type)
{
	const void *end = const_ptr_add_offset(start, size);
	struct vm_fragment *vmf;
	size_t idx;

	assert_rwlock_is_owned(&pm->lock);

	g_assert(pm->array != NULL);
	g_assert(pm->count < pm->size);
	g_assert(round_pagesize_fast(size) == size);

	vmf = pmap_lookup(pm, start, &idx);

	if G_UNLIKELY(vmf != NULL) {
		if (vmm_debugging(0)) {
			s_miniwarn("pmap already contains new %s region [%p, %p]",
				vmf_type_str(vmf->type),
				start, const_ptr_add_offset(start, size - 1));
			vmm_dump_pmap();
		}
		g_assert(VMF_FOREIGN == type);
		g_assert_log(vmf_is_foreign(vmf),
			"vmf={%s}, start=%p, size=%zu",
			vmf_to_string(vmf), start, size);
		g_assert(ptr_cmp(end, vmf->end) <= 0);
		goto done;
	}

	g_assert(idx <= pm->count);

	/*
	 * See whether we can coalesce the new region with the existing ones.
	 * We can't coalesce regions of different types.
	 */

	if (idx > 0) {
		struct vm_fragment *prev = &pm->array[idx - 1];

		g_assert_log(
			ptr_cmp(prev->end, start) <= 0, /* No overlap with prev */
			"idx=%zu, start=%p, size=%zu, prev={%s}",
			idx, start, size, vmf_to_string(prev));

		if (prev->type == type && prev->end == start) {
			prev->end = end;
			prev->mtime = tm_time();

			/*
			 * If we're now bumping into the next chunk, we need to coalesce
			 * it with the previous one and get rid of that "next" entry.
			 */
			
			if G_LIKELY(idx < pm->count) {
				struct vm_fragment *next = &pm->array[idx];

				g_assert_log(ptr_cmp(next->start, end) >= 0, /* No overlap */
					"idx=%zu, end=%p, size=%zu, next={%s}",
					idx, end, size, vmf_to_string(next));

				if (next->type == type && next->start == end) {
					prev->end = next->end;	/* prev->mtime updated above */

					/*
					 * Get rid of the entry at ``idx'' in the array.
					 */

					pmap_drop(pm, idx);
				}
			}
			idx--;
			goto done;
		}
	}

	if G_LIKELY(idx < pm->count) {
		struct vm_fragment *next = &pm->array[idx];

		g_assert_log(ptr_cmp(end, next->start) <= 0, /* No overlap with next */
			"idx=%zu, end=%p, size=%zu, next={%s}",
			idx, end, size, vmf_to_string(next));

		if (next->type == type && next->start == end) {
			next->start = start;
			next->mtime = tm_time();
			goto done;
		}

		/*
		 * Make room at ``idx'', the insertion point.
		 */

		ARRAY_MAKEROOM(pm->array, idx, pm->count, pm->size);
	}

	pm->count++;
	vmf = &pm->array[idx];
	vmf->start = start;
	vmf->end = end;
	vmf->type = type;
	vmf->mtime = tm_time();

done:
	/*
	 * After each insertion we need to monitor whether the pmap is full and
	 * extend it before the next insertion happens. If we were to extend
	 * the pmap upon entry in this routine, we could allocate a new pmap
	 * overlapping with the region we are going to insert, resulting in
	 * corrupted structures leading to crashes.
	 *
	 * Therefore, always ensure we have room for at least one more slot.
	 */

	if G_UNLIKELY(pm->count == pm->size) {
		pmap_extend(pm);

		/*
		 * After an extension of the pmap, we need to recompute the index in
		 * the array where the region we had to insert initially has been
		 * placed.  Indeed, the pages holding the pmap are also inserted in
		 * the pmap array, and therefore the previous insertion index may now
		 * be invalid (if e.g. we inserted the new pmap before, or the old pmap
		 * which has now been freed was a fragment before the insertion point).
		 *		--RAM, 2015-03-02
		 */

		vmf = pmap_lookup(pm, start, &idx);
		g_assert(vmf != NULL);		/* Must be found, we just inserted it */
	}

	return idx;
}

/**
 * Log missing region.
 */
static inline void
pmap_log_missing(const struct pmap *pm, const void *p, size_t size)
{
	(void) pm;

	if (vmm_debugging(0)) {
		s_miniwarn("VMM %zuKiB region at %p missing from pmap", size / 1024, p);
	}
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
	struct pmap *wpm = deconstify_pointer(pm);

	rwlock_rlock(&wpm->lock);

	vmf = pmap_lookup(pm, p, NULL);

	if (NULL == vmf) {
		pmap_log_missing(pm, p, size);
		rwlock_runlock(&wpm->lock);
		return 0;
	}

	middle = const_ptr_add_offset(p, size / 2);
	distance_to_start = ptr_diff(middle, vmf->start);
	distance_to_end = ptr_diff(vmf->end, middle);

	rwlock_runlock(&wpm->lock);
	return MIN(distance_to_start, distance_to_end);
}

/**
 * Is block at a region extremity?
 */
static bool
pmap_is_extremity(const struct pmap *pm, const void *p, size_t npages)
{
	struct vm_fragment *vmf;
	size_t idx;

	g_assert(rwlock_is_taken(&pm->lock));	/* needs at least the read lock */

	vmf = pmap_lookup(pm, p, &idx);

	if (NULL == vmf) {
		pmap_log_missing(pm, p, nsize_fast(npages));
		return FALSE;
	}

	/*
	 * The ``npages'' pages starting at ``p'' are an extremity if they lie
	 * at the beginning or end of the region.
	 *
	 * Since regions are not adjacent in the pmap (or they would have been
	 * merged), identifying an extremity is useful at free time: it increases
	 * the amount of consecutive free space in the VM space.
	 *
	 * Note that a whole region is considered an extremity, and it's a memory
	 * fragment in the sense of pmap_is_fragment().
	 */

	if (0 == ptr_cmp(p, vmf->start))
		return TRUE;			/* Extremity at the beginning of region */

	if (0 == ptr_cmp(const_ptr_add_offset(p, nsize_fast(npages)), vmf->end))
		return TRUE;			/* Extremity at the end of region */

	return FALSE;		/* Region is held within the memory fragment */
}

/**
 * Is block an identified fragment?
 */
static bool
pmap_is_fragment(const struct pmap *pm, const void *p, size_t npages)
{
	struct vm_fragment *vmf;
	size_t idx;

	g_assert(rwlock_is_taken(&pm->lock));	/* needs at least the read lock */

	vmf = pmap_lookup(pm, p, &idx);

	if (NULL == vmf) {
		pmap_log_missing(pm, p, nsize_fast(npages));
		return FALSE;
	}

	/*
	 * If block lies within a VM fragment, it's not a fragment.
	 */

	if (p != vmf->start || npages != pagecount_fast(vmf_size(vmf)))
		return FALSE;

	/*
	 * If the block is next to a foreign/mapped region, then it's not a
	 * fragment, regardless of whether the other region is in the direction
	 * of the VM growing range or not.
	 */

	if (idx != 0) {
		struct vm_fragment *prev = &pm->array[idx - 1];
		if (prev->end == vmf->start)
			return FALSE;
	}

	if (idx != pm->count - 1) {
		struct vm_fragment *next = &pm->array[idx + 1];
		if (next->start == vmf->end)
			return FALSE;
	}

	return TRUE;
}

/**
 * Is range available (hole) within the VM space?
 */
static bool
pmap_is_available(const struct pmap *pm, const void *p, size_t size)
{
	size_t idx;
	struct pmap *wpm = deconstify_pointer(pm);
	bool result = FALSE;

	rwlock_rlock(&wpm->lock);

	if (pmap_lookup(pm, p, &idx))
		goto done;

	g_assert(size_is_non_negative(idx));

	if (idx < pm->count) {
		struct vm_fragment *vmf = &pm->array[idx];
		const void *end = const_ptr_add_offset(p, size);

		result = ptr_cmp(end, vmf->start) <= 0;
	}

done:
	rwlock_runlock(&wpm->lock);
	return result;
}

/**
 * Assert range is within one single (coalesced) region of the VM space
 * of the specified type.
 */
static void
assert_vmm_is_allocated(const void *base, size_t size, vmf_type_t type,
	bool locked)
{
	struct vm_fragment *vmf;
	const void *end;
	const void *vend;
	struct pmap *pm = vmm_pmap();

	g_assert(base != NULL);
	g_assert(size_is_positive(size));

	if (locked) {
		/*
		 * Must prevent deadlocks if we are called with a spinlock held.
		 * Since this is only used for assertions, it's OK to not always
		 * be able to run it.
		 */

		if (!rwlock_rlock_try(&pm->lock))
			return;
	} else {
		rwlock_rlock(&pm->lock);
	}

	vmf = pmap_lookup(vmm_pmap(), base, NULL);

	g_assert(vmf != NULL);
	g_assert(vmf_size(vmf) >= size);

	end = const_ptr_add_offset(base, size);
	vend = vmf->end;

	g_assert(ptr_cmp(base, vmf->start) >= 0);
	g_assert(ptr_cmp(end, vend) <= 0);

	/*
	 * Range was part of a single fragment, now check it is of proper type.
	 */

	g_assert(vmf->type == type);

	rwlock_runlock(&pm->lock);
}

/**
 * Is pointer within the stack?
 *
 * If the ``top'' parameter is NULL, then the current stack pointer will be
 * used as the "upper" bound.
 *
 * @param p		the pointer we wish to check
 * @param top	"top" stack pointer, or NULL if unknown
 *
 * @return whether the pointer is within the bottom and the top of the stack.
 */
bool
vmm_is_stack_pointer(const void *p, const void *top)
{
	int sp;

	if G_UNLIKELY(0 == sp_direction)
		init_stack_shape();

	if (!thread_is_single())
		return thread_is_stack_pointer(p, top, NULL);

	if (NULL == top)
		top = &sp;

	if (sp_direction < 0) {
		/* Stack growing down, stack_base is its highest address */
		g_assert(ptr_cmp(stack_base, &sp) > 0);
		return ptr_cmp(p, top) >= 0 && ptr_cmp(p, stack_base) < 0;
	} else {
		/* Stack growing up, stack_base is its lowest address */
		g_assert(ptr_cmp(stack_base, &sp) < 0);
		return ptr_cmp(p, top) <= 0 && ptr_cmp(p, stack_base) >= 0;
	}
}

/**
 * Is pointer a valid native VMM one?
 */
bool
vmm_is_native_pointer(const void *p)
{
	struct vm_fragment *vmf;
	bool native;
	struct pmap *pm = vmm_pmap();

	rwlock_rlock(&pm->lock);

	vmf = pmap_lookup(pm, page_start(p), NULL);

	native = vmf != NULL && VMF_NATIVE == vmf->type;

	rwlock_runlock(&pm->lock);
	return native;
}

/**
 * Is region starting at ``p'' and of ``n'' pages a virtual memory
 * extremity, i.e. at the beginning or end of an allocated region?
 */
static bool
vmm_is_extremity(const void *p, size_t n)
{
	struct pmap *pm = vmm_pmap();
	bool is_extremity;

	g_assert(p != NULL);
	g_assert(size_is_positive(n));

	rwlock_rlock(&pm->lock);
	is_extremity = pmap_is_extremity(pm, p, n);
	rwlock_runlock(&pm->lock);

	return is_extremity;
}

/**
 * Is region starting at ``base'' and of ``size'' bytes a virtual memory
 * fragment, i.e. a standalone mapping in the middle of the VM space?
 */
bool
vmm_is_fragment(const void *base, size_t size)
{
	struct pmap *pm = vmm_pmap();
	bool is_fragment;

	g_assert(base != NULL);
	g_assert(size_is_positive(size));

	rwlock_rlock(&pm->lock);
	is_fragment = pmap_is_fragment(pm, base, pagecount_fast(size));
	rwlock_runlock(&pm->lock);

	return is_fragment;
}

/**
 * Is region starting at ``base'' and of ``size'' bytes a relocatable memory
 * region moveable at a better VM address?
 */
bool
vmm_is_relocatable(const void *base, size_t size)
{
	const void *hole;
	size_t len;

	g_assert(base != NULL);
	g_assert(size_is_positive(size));

	/*
	 * Look for a hole better placed in the VM space.
	 */
	
	hole = NULL;
	len = vmm_first_hole(&hole, FALSE);

	if (len < size)
		return FALSE;

	g_assert(hole != NULL);

	/*
	 * Don't use vmm_ptr_cmp() here since we need to correct the starting
	 * address returned by vmm_first_hole() when kernel_mapaddr_increasing
	 * is FALSE.
	 */

	if (kernel_mapaddr_increasing) {
		return ptr_cmp(hole, base) < 0;
	} else {
		hole = const_ptr_add_offset(hole, -round_pagesize_fast(size));
		return ptr_cmp(hole, base) > 0;
	}
}

/**
 * Remove whole region from the list of identified fragments.
 */
static void
pmap_remove_whole_region(struct pmap *pm, const void *p, size_t size)
{
	struct vm_fragment *vmf;
	size_t idx;

	assert_rwlock_is_owned(&pm->lock);
	g_assert(round_pagesize_fast(size) == size);

	vmf = pmap_lookup(pm, p, NULL);

	g_assert(vmf != NULL);				/* Must be found */
	g_assert(vmf_size(vmf) == size);	/* And with the proper size */

	idx = vmf - pm->array;
	g_assert(size_is_non_negative(idx) && idx < pm->count);

	pmap_drop(pm, idx);
}

/**
 * Remove region from the pmap, which can create a new fragment.
 */
static void
pmap_remove(struct pmap *pm, const void *p, size_t size)
{
	struct vm_fragment *vmf;

	assert_rwlock_is_owned(&pm->lock);

	g_assert(round_pagesize_fast(size) == size);

	vmf = pmap_lookup(pm, p, NULL);

	if (vmf != NULL) {
		const void *end = const_ptr_add_offset(p, size);
		const void *vend = vmf->end;

		g_assert_log(vmf_size(vmf) >= size,
			"vmf={%s} vmf_size=%zu size=%zu",
			vmf_to_string(vmf), vmf_size(vmf), size);

		if (p == vmf->start) {

			if (vmm_debugging(2)) {
				s_minidbg("VMM %s %zuKiB region at %p was %s fragment",
					vmf_type_str(vmf->type), size / 1024, p,
					end == vend ? "a whole" : "start of a");
			}

			if (end == vend) {
				pmap_remove_whole_region(pm, p, size);
			} else {
				vmf->start = end;			/* Known fragment reduced */
				vmf->mtime = tm_time();
				g_assert(ptr_cmp(vmf->start, vend) < 0);
			}
		} else {
			g_assert(ptr_cmp(vmf->start, p) < 0);
			g_assert(ptr_cmp(end, vend) <= 0);

			vmf->end = p;
			vmf->mtime = tm_time();

			if (end != vend) {
				if (vmm_debugging(1)) {
					s_minidbg("VMM freeing %s %zuKiB region at %p "
						"fragments VM space",
						vmf_type_str(vmf->type), size / 1024, p);
				}
				pmap_insert_region(pm, end, ptr_diff(vend, end), vmf->type);
			}
		}
	} else {
		if (vmm_debugging(0)) {
			s_minicarp("VMM %zuKiB region at %p missing from pmap",
				size / 1024, p);
		}
	}
}

/**
 * Forcefully remove a region from the pmap (``size'' bytes starting
 * at ``p''), belonging to a given fragment.
 */
static void
pmap_remove_from(struct pmap *pm, struct vm_fragment *vmf,
	const void *p, size_t size)
{
	const void *end = const_ptr_add_offset(p, size);
	const void *vend;

	assert_rwlock_is_owned(&pm->lock);

	g_assert(vmf != NULL);
	g_assert(size_is_positive(size));
	g_assert(round_pagesize_fast(size) == size);

	vend = vmf->end;

	g_assert(ptr_cmp(vmf->start, p) <= 0);
	g_assert(ptr_cmp(p, vend) < 0);
	g_assert(ptr_cmp(vmf->start, end) <= 0);
	g_assert(ptr_cmp(end, vend) <= 0);

	if (vmm_debugging(0)) {
		s_miniwarn("VMM forgetting %s %zuKiB region at %p in pmap",
			vmf_type_str(vmf->type), size / 1024, p);
	}

	if (p == vmf->start) {
		if (end == vend) {
			pmap_remove_whole_region(pm, p, size);
		} else {
			vmf->start = end;			/* Known fragment reduced */
			vmf->mtime = tm_time();
		}
	} else {
		vmf->end = p;
		vmf->mtime = tm_time();

		if (end != vend) {
			/*
			 * Insert trailing part back as a region of the same type.
			 *
			 * CAUTION:
			 * We may be in a situation where we are extending the pmap
			 * from pmap_extend() and, while allocating the new pages for
			 * the new pmap, we have to call pmap_overrule(), and here we
			 * come, attempting to remove a foreign maping, partially.
			 *
			 * If the pmap is being extended, it means it is full and we
			 * do not want to insert a new region: we can't anyway.
			 * When that region is a foreign mapping, we can simply drop it,
			 * as this information is intuited and could be stale.
			 *		--RAM, 2015-09-27
			 */

			if G_LIKELY(!pm->extending) {
				/* Normal case */
				pmap_insert_region(pm, end, ptr_diff(vend, end), vmf->type);
			} else if (vmf_is_foreign(vmf)) {
				/* Exceptional: pamp is full, dropping foreign region */
				if (vmm_debugging(0)) {
					s_message("VMM forgetting %s: pmap is full and extending",
						vmf_to_string(vmf));
				}
				VMM_STATS_INCX(pmap_dropped);
			} else {
				/* Error case, MUST NOT happen, but if it does... */
				s_warning("cannot remove from %s VM fragment while "
					"pmap is extending (count=%zu, size=%zu)",
					vmf_type_str(vmf->type), pm->count, pm->size);
				s_error_from(_WHERE_, "extending pmap and attempting to "
					"remove %zu bytes at %p from %s",
					size, p, vmf_to_string(vmf));
			}
		}
	}
}

/**
 * Kernel may have overruled our foreign region accounting by allocating
 * ``size'' bytes starting at ``p''.  Make sure we remove all foreign pages
 * in this space.
 */
static void
pmap_overrule(struct pmap *pm, const void *p, size_t size, vmf_type_t type)
{
	const void *base = p;
	size_t remain = size;

	assert_rwlock_is_owned(&pm->lock);

	while (size_is_positive(remain)) {
		size_t idx;
		struct vm_fragment *vmf = pmap_lookup(pm, base, &idx);
		size_t len;

		g_assert(size_is_non_negative(idx));

		if (NULL == vmf) {
			const void *end = const_ptr_add_offset(base, remain);
			size_t gap;

			/* ``base'' does not belong to any known region, ``idx'' is next */

			if (idx >= pm->count)
				break;

			vmf = &pm->array[idx];

			if (ptr_cmp(end, vmf->start) <= 0)
				return;		/* Next region starts after our target */

			/* We have an overlap with region in ``vmf'' */

			g_assert_log(vmf_is_foreign(vmf),
				"vmf={%s}, base=%p, remain=%zu",
				vmf_to_string(vmf), base, remain);

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

		VMM_STATS_INCX(pmap_overruled);
		len = ptr_diff(vmf->end, base);		/* From base to end of region */

		g_assert_log(size_is_positive(len), "len = %zu", len);

		/*
		 * When attempting an mmap() operation, we can safely overlap
		 * an existing memory-mapped region since one can mmap() a different
		 * portion of a file at the same address for instance.
		 */

		g_assert_log(VMF_MAPPED == type || vmf_is_foreign(vmf),
			"vmf={%s}, base=%p, len=%zu, remain=%zu",
			vmf_to_string(vmf), base, len, remain);

		g_assert(!vmf_is_native(vmf));	/* Never overrule allocated memory */

		if (len < remain) {
			pmap_remove_from(pm, vmf, base, len);
			base = const_ptr_add_offset(base, len);
			remain -= len;
		} else {
			pmap_remove_from(pm, vmf, base, remain);
			break;
		}
	}
}

/**
 * Like free_pages() but for freeing of a cached/cacheable page and
 * update our pmap.
 */
static void
free_pages_forced(void *p, size_t size)
{
	struct pmap *pm = vmm_pmap();

	if (vmm_debugging(5)) {
		s_minidbg("VMM freeing %zuKiB region at %p", size / 1024, p);
	}

	rwlock_wlock(&pm->lock);
	pmap_remove(pm, p, size);
	rwlock_wunlock(&pm->lock);

	/*
	 * Because the pmap has already been updated, we can release the page
	 * without holding any lock.
	 */

	free_pages_intern(p, size, FALSE);
}

/**
 * Free array of pages, each entry being a region of the given size,
 * updating our pmap as we go.
 *
 * @param vec		the vector of pages to free
 * @param vnct		the amount of pages in the vector
 * @param size		size of regions in the vector (same size for all entries)
 */
static void
free_pages_vector(void *vec[], size_t vcnt, size_t size)
{
	struct pmap *pm = vmm_pmap();
	size_t i;

	if (vmm_debugging(5)) {
		for (i = 0; i < vcnt; i++) {
			s_minidbg("VMM freeing %zuKiB region at %p", size / 1024, vec[i]);
		}
	}

	rwlock_wlock(&pm->lock);

	for (i = 0; i < vcnt; i++) {
		pmap_remove(pm, vec[i], size);
	}

	/*
	 * Because the pmap has already been updated, we can release all the
	 * pages without holding the write lock.
	 *
	 * We downgrade to a read lock though to prevent another allocator for
	 * trying to allocate from the regions we removed in the pmap, when the
	 * corresponding pages are still held in the process.
	 *		--RAM, 2015-04-06
	 */

	rwlock_downgrade(&pm->lock);

	for (i = 0; i < vcnt; i++) {
		free_pages_intern(vec[i], size, FALSE);
	}

	rwlock_runlock(&pm->lock);
}

/**
 * Lookup page within a cache line.
 *
 * If ``low_ptr'' is non-NULL, it is written with the index where insertion
 * of a new item should happen (in which case the returned value must be -1).
 *
 * @return index within the page cache info[] sorted array where "p" is stored,
 * -1 if not found.
 */
static size_t
vpc_lookup(const struct page_cache *pc, const char *p, size_t *low_ptr)
{
	size_t low = 0, high = pc->current - 1;
	size_t mid;

	if G_UNLIKELY(0 == pc->current) {
		if (low_ptr != NULL)
			*low_ptr = 0;
		return -1;
	}

	/* Optimize if have more than 4 items */

	if G_LIKELY(high >= 4) {
		const char *q = pc->info[0].base;

		if G_UNLIKELY(q == p)
			return 0;
		if (p < q) {
			if (low_ptr != NULL)
				*low_ptr = 0;
			return -1;
		}
		low++;		/* We already checked item 0 */

		q = pc->info[high].base;
		if G_UNLIKELY(q == p)
			return high;
		if (p > q) {
			if (low_ptr != NULL)
				*low_ptr = high + 1;
			return -1;
		}
		high--;		/* We already checked last item */
	}

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
 * Remove entry within a cache line at specified index.
 * The associated pages are not released to the system.
 */
static void
vpc_remove_at(struct page_cache *pc, const void *p, size_t idx)
{
	g_assert(size_is_non_negative(idx) && idx < pc->current);
	g_assert(p == pc->info[idx].base);
	assert_vmm_is_allocated(p, pc->chunksize, VMF_NATIVE, TRUE);
	g_assert(size_is_positive(pc->current));
	g_assert(spinlock_is_held(&pc->lock));

	/*
	 * Delete the slot entry, moving back items by one position unless the
	 * last item was removed.
	 */

	ARRAY_REMOVE_DEC(pc->info, idx, pc->current);
}

/**
 * Remove entry within a cache line, keeping the associated pages mapped.
 */
static void
vpc_remove(struct page_cache *pc, const void *p)
{
	size_t idx;

	g_assert(spinlock_is_held(&pc->lock));

	idx = vpc_lookup(pc, p, NULL);
	g_assert(idx != (size_t) -1);		/* Must have been found */
	vpc_remove_at(pc, p, idx);
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
	void *evicted = NULL;

	g_assert(size_is_non_negative(pc->current) &&
		pc->current <= VMM_CACHE_SIZE);
	assert_vmm_is_allocated(p, pc->chunksize, VMF_NATIVE, FALSE);

	spinlock(&pc->lock);

	if G_UNLIKELY((size_t ) -1 != vpc_lookup(pc, p, &idx)) {
		s_error_from(_WHERE_,
			"memory chunk at %p already present in %zu page-long VMM cache",
			p, pc->pages);
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
		void *bend = ptr_add_offset(before, pc->chunksize);

		if G_UNLIKELY(bend == p) {
			if (vmm_debugging(6)) {
				s_minidbg("VMM page cache #%zu: "
					"coalescing previous [%p, %p] with [%p, %p]",
					pc->pages - 1, before, ptr_add_offset(bend, -1), p,
					ptr_add_offset(p, pc->chunksize - 1));
			}
			base = before;
			pages += pc->pages;
			vpc_remove_at(pc, before, idx - 1);
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

		if G_UNLIKELY(next == end) {
			if (vmm_debugging(6)) {
				s_minidbg("VMM page cache #%zu: "
					"coalescing [%p, %p] with next [%p, %p]",
					pc->pages - 1, base, ptr_add_offset(end, -1), next,
					ptr_add_offset(next, pc->chunksize - 1));
			}
			pages += pc->pages;
			vpc_remove_at(pc, next, idx);
		}
	}

	/*
	 * If we coalesced the chunk, recurse to insert it in the proper cache.
	 * Otherwise, insertion is happening before ``idx''.
	 */

	if G_UNLIKELY(pages != pc->pages) {
		if (vmm_debugging(2)) {
			s_minidbg("VMM coalesced %zuKiB region [%p, %p] into "
				"%zuKiB region [%p, %p] (recursing)",
				pc->chunksize / 1024,
				p, ptr_add_offset(p, pc->chunksize - 1),
				pages * kernel_pagesize / 1024,
				base, ptr_add_offset(base, pages * kernel_pagesize - 1));
		}
		spinunlock(&pc->lock);
		page_cache_insert_pages(base, pages);
		VMM_STATS_INCX(cache_line_coalescing);
		return;
	}

insert:

	/*
	 * Insert region in the local cache line.
	 */

	if G_UNLIKELY(VMM_CACHE_SIZE == pc->current) {
		size_t kidx = kernel_mapaddr_increasing ? VMM_CACHE_SIZE - 1 : 0;

		evicted = pc->info[kidx].base;

		if (vmm_debugging(4)) {
			s_minidbg("VMM page cache #%zu: kicking out [%p, %p] %zuKiB",
				pc->pages - 1, evicted,
				ptr_add_offset(evicted, pc->chunksize - 1),
				pc->chunksize / 1024);
		}

		/*
		 * Can't call vpc_free() here because we already hold the spinlock
		 * and vpc_free() will need to call free_pages_forced() which will
		 * then grab a mutex.  This is a recipe for deadlocks.
		 *
		 * Hence we memorize the address to free and will do that at the
		 * end when we have released the spinlock.
		 */

		vpc_remove_at(pc, evicted, kidx);

		if (idx > kidx)
			idx--;

		VMM_STATS_INCX(cache_evictions);
		pc->evicted++;
	}

	g_assert(size_is_non_negative(pc->current) && pc->current < VMM_CACHE_SIZE);
	g_assert(size_is_non_negative(idx) && idx < VMM_CACHE_SIZE);

	/*
	 * Shift items up if we're not inserting at the last position in the array.
	 */

	ARRAY_FIXED_MAKEROOM(pc->info, idx, pc->current);

	pc->current++;
	pc->info[idx].base = base;
	pc->info[idx].stamp = tm_time();

	if (vmm_debugging(4)) {
		s_minidbg("VMM page cache #%zu: inserted [%p, %p] %zuKiB, "
			"now holds %zu item%s",
			pc->pages - 1, base, ptr_add_offset(base, pc->chunksize - 1),
			pc->chunksize / 1024, pc->current, plural(pc->current));
	}

	spinunlock(&pc->lock);

	/*
	 * Free the page we evicted now that we have released the spinlock.
	 */

	if G_UNLIKELY(evicted != NULL) {
		free_pages_forced(evicted, pc->chunksize);
	}
}

/**
 * Compare two pointers according to the growing direction of the VM space.
 * A pointer is larger than another if it is further away from the base.
 */
static inline int
vmm_ptr_cmp(const void *a, const void *b)
{
	if G_UNLIKELY(a == b)
		return 0;

	return kernel_mapaddr_increasing ? ptr_cmp(a, b) : ptr_cmp(b, a);
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

	spinlock(&pc->lock);

	if G_UNLIKELY(0 == pc->current)	/* Tested by caller (without the lock) */
		goto not_found;

	if (n > pc->pages) {
		/*
		 * Since we're looking for more pages than what this cache line stores,
		 * we'll have to coalesce the page with neighbouring chunks, which
		 * only makes sense when looking for pages in the highest order page
		 * cache.
		 */

		g_assert(VMM_CACHE_LINES == pc->pages);		/* Highest-order line */

		base = kernel_mapaddr_increasing ?
			pc->info[0].base : pc->info[pc->current - 1].base;

		goto selected;
	} else {
		size_t i;
		size_t max_distance = 0;

		base = NULL;

		if (n == pc->pages)
			pc->targeted++;

		/*
		 * When we're looking for less consecutive pages than what this cache
		 * line holds, it will require splitting of the entry.
		 *
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
			 * We stop considering pages that are further away than the
			 * identified hole.  Since we traverse the cache line in the
			 * proper order, from "lower" addresses to "upper" ones, we can
			 * abort as soon as we've gone beyond the hole.
			 */

			if (hole != NULL && vmm_ptr_cmp(p, hole) > 0) {
				if (vmm_debugging(7)) {
					s_minidbg("VMM page cache #%zu: "
						"%s lookup for %zu page%s at %p "
						"(upper than hole %p, ignoring %zu cached entr%s)",
						pc->pages - 1, i == 0 ? "ignoring" : "stopping",
						n, plural(n), p, hole,
						pc->current - i, plural(pc->current - i));
				}
				if (0 == i) {
					/* Did not consider any of the pages in that line */
					VMM_STATS_INCX(cache_ignored);
					pc->denied++;
				}
				break;
			}

			d = 1 + pmap_nesting_within_region(vmm_pmap(), p, pc->chunksize);
			if (d > max_distance) {
				max_distance = d;
				base = deconstify_pointer(p);
			}
		}

		if (NULL == base)
			goto not_found;		/* Cache line was empty */

		if (n == pc->pages)
			VMM_STATS_INCX(cache_exact_match);

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

		if (VMM_CACHE_LINES != pc->pages)
			goto not_found;		/* Not at highest-order cache line */

		if (1 == pc->current)
			goto not_found;		/* No other entries to coalesce with */

		/*
		 * Coalescing in the highest-order cache line does not take into
		 * account the first VM hole: we give priority to coalescing these
		 * large ranges, since it is more useful than attempting to allocate
		 * from the hole: the pages are already allocated, the range is large,
		 * we avoid letting the kernel re-install all these mappings for us if
		 * we can satisfy the allocation via coalescing.
		 */

		if (kernel_mapaddr_increasing) {
			for (i = 1; i < pc->current; i++) {
				void *start = pc->info[i].base;

				if (start == end) {
					total += pc->pages;
					end = ptr_add_offset(start, pc->chunksize);
					if (total >= n)
						goto found;
				} else {
					/*
					 * No luck coalescing what we had so far with the next
					 * entry.  Restart the coalescing process from this
					 * cached entry then.
					 */

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
					/*
					 * No luck coalescing what we had so far with the next
					 * entry.  Restart the coalescing process from this
					 * cached entry then.
					 */

					total = pc->pages;
					base = prev_base;
					end = last;
				}
			}
		}

		goto not_found;		/* Did not find enough consecutive pages */
	}

found:
	g_assert(total >= n);

	/*
	 * Remove the entries from the cache.
	 */

	{
		void *p = base;
		size_t i;

		for (i = 0; i < total; i += pc->pages) {
			vpc_remove(pc, p);
			p = ptr_add_offset(p, pc->chunksize);
		}

		g_assert(end == p);
	}

	spinunlock(&pc->lock);

	/*
	 * If we got more consecutive pages than the amount asked for, put
	 * the leading / trailing pages back into the cache.
	 */

	if (total > n) {
		if (kernel_mapaddr_increasing) {
			void *start = ptr_add_offset(base, nsize_fast(n));
			page_cache_insert_pages(start, total - n);	/* Strip trailing */
		} else {
			void *start = ptr_add_offset(end, nsize_fast(-n));
			page_cache_insert_pages(base, total - n);	/* Strip leading */
			base = start;
		}
	}

	return base;

not_found:
	spinunlock(&pc->lock);
	return NULL;
}

/**
 * Find "n" consecutive pages in the page cache, and remove them if found.
 *
 * @param n			number of pages we want
 * @param user_mem	whether we're allocating user memory (as opposed to core)
 * @param emergency	whether we need to find pages from the cache at all costs
 *
 * @return a pointer to the start of the memory region, NULL if we were
 * unable to find that amount of contiguous memory.
 */
static void *
page_cache_find_pages(size_t n, bool user_mem, bool emergency)
{
	void *p;
	size_t len;
	const void *hole = NULL;
	struct vm_upper_hole upper;
	struct page_cache *pc = NULL;
	enum vmm_strategy strategy = vmm_strategy;

	g_assert(size_is_positive(n));

	/*
	 * In emergency situations, we're going to act as if we were allocating
	 * under a short-term strategy, to be able to locate a region from the
	 * cache, knowing that we're going to end this process soon anyway due
	 * to memory shortage.
	 */

	if G_UNLIKELY(emergency)
		strategy = VMM_STRATEGY_SHORT_TERM;

	/*
	 * When allocating with a short-term strategy, we attempt to reuse the
	 * cached memory as much as possible.
	 *
	 * Likewise for user memory: as opposed to core memory which will likely
	 * be further fragmented into smaller pieces and therefore less prone to
	 * ever beeing freed soon, user memory is typically allocated, used and
	 * freed as a whole.  So it's more important to be careful when allocating
	 * core memory under a long-term strategy: it will most probably be a
	 * memory region we will not free before a long time, if ever.
	 */

	if (user_mem || VMM_STRATEGY_SHORT_TERM == strategy)
		goto short_term_strategy;

	/*
	 * Long-term strategy:
	 *
	 * Before using pages from the cache, look where the first hole is
	 * at the start of the virtual memory space.  If we find one that can
	 * suit this allocation, then do not use cached pages that would
	 * lie after the hole.
	 */

	len = vmm_first_hole(&hole, TRUE);

	/*
	 * If we know an "upper hole", adjust the first hole address to be that
	 * one, as it will be more representative of where we are more likely
	 * to be able to allocate new core.
	 */

	VMM_UPPER_HOLE_LOCK;
	upper = vmm_upper_hole;		/* struct copy */
	VMM_UPPER_HOLE_UNLOCK;

	if (pagecount_fast(upper.len) >= n) {
		hole = upper.p;
		len = upper.len;
	}

	if (pagecount_fast(len) < n) {
		hole = NULL;
	} else if (!kernel_mapaddr_increasing) {
		size_t length = nsize_fast(n);

		g_assert((size_t) -1 != length);
		g_assert(ptr_diff(hole, NULL) > length);

		hole = const_ptr_add_offset(hole, -length);
	}

	if G_UNLIKELY(hole != NULL) {
		if (vmm_debugging(8)) {
			size_t np = pagecount_fast(len);
			s_minidbg("VMM %s hole of %zu page%s at %p (%zu page%s)",
				hole == upper.p ? "upper" : "lowest",
				n, plural(n), hole, np, plural(np));
		}
	}

	/* FALL THROUGH */

short_term_strategy:

	if (n >= VMM_CACHE_LINES) {
		/*
		 * Our only hope to find suitable pages in the cache is to have
		 * consecutive ranges in the largest cache line.
		 */

		pc = &page_cache[VMM_CACHE_LINES - 1];
		p = pc->current != 0 ? vpc_find_pages(pc, n, hole) : NULL;

		if (n > VMM_CACHE_LINES) {
			if (p != NULL) {
				/* Coalesced large blocks from the higher cache line */
				VMM_STATS_INCX(cache_high_coalescing);
			} else {
				/* Request was too large for the cache */
				VMM_STATS_INCX(cache_too_large);
			}
		}

		if (vmm_debugging(3)) {
			s_minidbg("VMM lookup for large area (%zu pages) returned %p", n, p);
		}
	} else {
		bool single_page = user_mem || VMM_STRATEGY_SHORT_TERM == strategy;

		/*
		 * Start looking for a suitable page in the page cache matching
		 * the size we want.
		 */

		pc = &page_cache[n - 1];
		p = pc->current != 0 ? vpc_find_pages(pc, n, hole) : NULL;

		/*
		 * Visit higher-order cache lines if we found nothing in the cache.
		 *
		 * Short-term strategy or user memory:
		 * If we have data in our cache, reuse it, even for a single page.
		 *
		 * Long-term strategy:
		 * To avoid VM space fragmentation, we never split a larger region
		 * to allocate just one page.  This policy allows us to fill the holes
		 * that can be created and avoids undoing the coalescing we may have
		 * achieved so far in higher-order caches.
		 */

		if (NULL == p && (single_page || n > 1)) {
			size_t i;
			bool aggressive = FALSE;

		try_harder:
			for (i = n; i < VMM_CACHE_LINES && NULL == p; i++) {
				pc = &page_cache[i];

				if (0 == pc->current)
					continue;

				/*
				 * If splitting the page would put the remaining pages into
				 * a full cache line, then avoid allocation from the current
				 * cache line unless we're being aggressive.
				 */

				{
					size_t r = i - n + 1;		/* pc->pages == i + 1 */
					struct page_cache *rpc = &page_cache[r - 1];

					if G_UNLIKELY(VMM_CACHE_SIZE == rpc->current && !aggressive)
						continue;	/* Remaining pages going to full cache */
				}

				p = vpc_find_pages(pc, n, hole);
			}

			if G_LIKELY(p != NULL) {
				VMM_STATS_INCX(cache_splits);
			} else {
				/*
				 * In emergency situations, we need to retry the above lookups,
				 * accepting to split regions even if they end-up falling into
				 * a full cache line.
				 */

				if (emergency && !aggressive) {
					aggressive = TRUE;
					goto try_harder;
				}
			}
		}

		if (p != NULL) {
			spinlock_hidden(&pc->lock);
			pc->allocated++;
			if (n != pc->pages)
				pc->split++;
			spinunlock_hidden(&pc->lock);
		}
	}

	if (vmm_debugging(5) && p != NULL) {
		s_minidbg("VMM found %zuKiB region at %p in cache #%zu%s",
			n * kernel_pagesize / 1024, p, pc->pages - 1,
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
 *
 * @return TRUE if pages were cached, FALSE if they were forcefully freed.
 */
static bool
page_cache_insert_pages(void *base, size_t n)
{
	size_t pages = n;
	void *p = base;
	struct pmap *pm = vmm_pmap();
	bool wlock = FALSE;

	assert_vmm_is_allocated(base, nsize_fast(n), VMF_NATIVE, FALSE);

	if G_UNLIKELY(stop_freeing)
		return FALSE;

	/*
	 * With a short-term allocation strategy, keep allocated memory around
	 * by always caching the pages, as long as we have room in our cache.
	 */

	if (VMM_STRATEGY_SHORT_TERM == vmm_strategy)
		goto short_term_strategy;

	/*
	 * Identified region extremities (which includes standalone fragments)
	 * are immediately freed and not put back into the cache, in order to
	 * reduce fragmentation of the memory space and maximize the size of
	 * free space.
	 *
	 * Start with a read lock on the pmap, which only needs to be upgraded
	 * to a write lock if the area ends up being an extremity.
	 */

	rwlock_rlock(&pm->lock);

retry:
	if G_UNLIKELY(pmap_is_extremity(pm, base, n)) {
		/*
		 * Upgrade to write lock.
		 *
		 * If we cannot atomically upgrade, we need to release the read lock
		 * and re-acquire the write lock, after which we need to retry the
		 * evaluation to see whether the pages are still an extremity.
		 */

		if (!wlock) {
			if (rwlock_upgrade(&pm->lock)) {
				wlock = TRUE;
			} else {
				rwlock_runlock(&pm->lock);
				rwlock_wlock(&pm->lock);
				wlock = TRUE;
				goto retry;
			}
		}

		/*
		 * We have the write lock.
		 */

		pmap_remove(pm, base, nsize_fast(n));

		/*
		 * We do not need a write lock to free the pages, and it's best to
		 * not keep it since we're about to issue a system call, most likely.
		 */

		rwlock_wunlock(&pm->lock);

		if (vmm_debugging(2)) {
			s_minidbg("VMM freeing %zuKiB fragment at %p",
				n << (kernel_pageshift - 10), base);
		}

		free_pages_intern(base, nsize_fast(n), FALSE);

		VMM_STATS_LOCK;
		vmm_stats.forced_freed++;
		vmm_stats.forced_freed_pages += n;
		VMM_STATS_UNLOCK;

		return FALSE;
	}

	if G_UNLIKELY(wlock)
		rwlock_wunlock(&pm->lock);
	else
		rwlock_runlock(&pm->lock);

	/* FALL THROUGH */

short_term_strategy:

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

	return TRUE;
}

/**
 * Attempting to coalesce the block with other entries in the cache.
 *
 * Cached pages being coalesced with the block are removed from the cache
 * and the resulting block is not part of the cache.
 *
 * @return TRUE if coalescing occurred, with updated base and amount of pages.
 */
static G_GNUC_HOT bool
page_cache_coalesce_pages(void **base_ptr, size_t *pages_ptr)
{
	size_t i, j;
	void *base = *base_ptr;
	size_t pages = *pages_ptr;
	const size_t old_pages = pages;
	void *end;

	assert_vmm_is_allocated(base, nsize_fast(pages), VMF_NATIVE, FALSE);

	if G_UNLIKELY(stop_freeing)
		return FALSE;

	end = ptr_add_offset(base, nsize_fast(pages));

	/*
	 * Look in low-order caches whether we can find chunks before.
	 */

	for (i = 0; /* empty */; i++) {
		bool coalesced = FALSE;

		j = MIN(old_pages, VMM_CACHE_LINES) - 1;
		while (j-- > 0) {
			struct page_cache *lopc = &page_cache[j];
			void *before;
			size_t loidx;

			if (0 == lopc->current)
				continue;

			spinlock(&lopc->lock);

			if G_UNLIKELY(0 == lopc->current) {
				spinunlock(&lopc->lock);
				continue;
			}

			before = ptr_add_offset(base, -lopc->chunksize);
			loidx = vpc_lookup(lopc, before, NULL);

			if G_UNLIKELY(loidx != (size_t) -1) {
				if (vmm_debugging(6)) {
					s_minidbg("VMM iter #%zu, coalescing previous "
						"[%p, %p] from lower cache #%zu with [%p, %p]",
						i, before, ptr_add_offset(base, -1),
						lopc->pages - 1, base,
						ptr_add_offset(base, pages * kernel_pagesize - 1));
				}
				vpc_remove_at(lopc, before, loidx);
				spinunlock(&lopc->lock);
				base = before;
				pages += lopc->pages;

				assert_vmm_is_allocated(before,
					nsize_fast(pages), VMF_NATIVE, FALSE);

				coalesced = TRUE;
			} else {
				spinunlock(&lopc->lock);
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

		spinlock(&hopc->lock);

		if G_UNLIKELY(0 == hopc->current) {
			spinunlock(&hopc->lock);
			continue;
		}

		before = ptr_add_offset(base, -hopc->chunksize);
		hoidx = vpc_lookup(hopc, before, NULL);

		if G_UNLIKELY(hoidx != (size_t) -1) {
			if (vmm_debugging(6)) {
				s_minidbg("VMM coalescing previous [%p, %p] "
					"from higher cache #%zu with [%p, %p]",
					before, ptr_add_offset(base, -1), hopc->pages - 1,
					base, ptr_add_offset(base, pages * kernel_pagesize - 1));
			}
			vpc_remove_at(hopc, before, hoidx);
			spinunlock(&hopc->lock);
			base = before;
			pages += hopc->pages;

			assert_vmm_is_allocated(before,
				nsize_fast(pages), VMF_NATIVE, FALSE);
		} else {
			spinunlock(&hopc->lock);
		}
	}

	/*
	 * Look in low-order caches whether we can find chunks after.
	 */

	g_assert(ptr_add_offset(base, nsize_fast(pages)) == end);

	for (i = 0; /* empty */; i++) {
		bool coalesced = FALSE;

		j = MIN(old_pages, VMM_CACHE_LINES) - 1;
		while (j-- > 0) {
			struct page_cache *lopc = &page_cache[j];
			size_t loidx;

			if (0 == lopc->current)
				continue;

			spinlock(&lopc->lock);

			if G_UNLIKELY(0 == lopc->current) {
				spinunlock(&lopc->lock);
				continue;
			}

			loidx = vpc_lookup(lopc, end, NULL);

			if G_UNLIKELY(loidx != (size_t) -1) {
				if (vmm_debugging(6)) {
					s_minidbg("VMM iter #%zu, coalescing next [%p, %p] "
						"from lower cache #%zu with [%p, %p]",
						i, end, ptr_add_offset(end, lopc->chunksize - 1),
						lopc->pages - 1, base, ptr_add_offset(end, -1));
				}
				vpc_remove_at(lopc, end, loidx);
				spinunlock(&lopc->lock);
				pages += lopc->pages;
				end = ptr_add_offset(end, lopc->chunksize);

				assert_vmm_is_allocated(base,
					nsize_fast(pages), VMF_NATIVE, FALSE);

				coalesced = TRUE;
			} else {
				spinunlock(&lopc->lock);
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

		spinlock(&hopc->lock);

		if G_UNLIKELY(0 == hopc->current) {
			spinunlock(&hopc->lock);
			continue;
		}

		hoidx = vpc_lookup(hopc, end, NULL);

		if G_UNLIKELY(hoidx != (size_t) -1) {
			if (vmm_debugging(6)) {
				s_minidbg("VMM coalescing next [%p, %p] "
					"from higher cache #%zu with [%p, %p]",
					end, ptr_add_offset(end, hopc->chunksize - 1),
					hopc->pages - 1, base, ptr_add_offset(end, -1));
			}
			vpc_remove_at(hopc, end, hoidx);
			spinunlock(&hopc->lock);
			pages += hopc->pages;
			end = ptr_add_offset(end, hopc->chunksize);

			assert_vmm_is_allocated(base,
				nsize_fast(pages), VMF_NATIVE, FALSE);
		} else {
			spinunlock(&hopc->lock);
		}
	}

	assert_vmm_is_allocated(base, nsize_fast(pages), VMF_NATIVE, FALSE);
	g_assert(ptr_add_offset(base, nsize_fast(pages)) == end);

	if G_UNLIKELY(pages != old_pages) {
		if (vmm_debugging(2)) {
			s_minidbg("VMM coalesced %zuKiB region [%p, %p] into "
				"%zuKiB region [%p, %p]",
				old_pages * kernel_pagesize / 1024, *base_ptr,
				ptr_add_offset(*base_ptr, old_pages * compat_pagesize() - 1),
				pages * kernel_pagesize / 1024,
				base, ptr_add_offset(base, pages * kernel_pagesize - 1));
		}

		*base_ptr = base;
		*pages_ptr = pages;
		VMM_STATS_INCX(cache_coalescing);

		return TRUE;
	}

	return FALSE;
}

void
vmm_madvise_normal(void *p, size_t size)
{
	g_assert(p);
	g_assert(size_is_positive(size));
#if defined(HAS_MADVISE) && defined(MADV_NORMAL)
	madvise(p, size, MADV_NORMAL);
#endif	/* MADV_NORMAL */
}

void
vmm_madvise_sequential(void *p, size_t size)
{
	g_assert(p);
	g_assert(size_is_positive(size));
#if defined(HAS_MADVISE) && defined(MADV_SEQUENTIAL)
	madvise(p, size, MADV_SEQUENTIAL);
#endif	/* MADV_SEQUENTIAL */
}

void
vmm_madvise_free(void *p, size_t size)
{
	g_assert(p);
	g_assert(size_is_positive(size));
#if defined(HAS_MADVISE) && defined(MADV_FREE)
	madvise(p, size, MADV_FREE);
#elif defined(HAS_MADVISE) && defined(MADV_DONTNEED)
	madvise(p, size, MADV_DONTNEED);
#endif	/* MADV_FREE */
}

void
vmm_madvise_willneed(void *p, size_t size)
{
	g_assert(p);
	g_assert(size_is_positive(size));
#if defined(HAS_MADVISE) && defined(MADV_WILLNEED)
	madvise(p, size, MADV_WILLNEED);
#endif	/* MADV_WILLNEED */
}

/**
 * Allocates a page-aligned memory chunk, possibly returning a cached region
 * and only allocating a new region when necessary.
 *
 * When ``user_mem'' is FALSE, it means we're allocating memory that will be
 * used by other memory allocators, not by "users": that memory will be
 * accounted for when it is in turn allocated for user consumption, which is
 * why we must not account for it here as being user memory.
 *
 * @param size 		size in bytes to allocate; will be rounded to the pagesize.
 * @param user_mem	whether this memory is meant for "user" consumption
 * @param zero_mem	whether memory needs to be zeroed
 *
 * @return pointer to allocated memory region
 */
static void *
vmm_alloc_internal(size_t size, bool user_mem, bool zero_mem)
{
	size_t n;
	void *p;

	g_assert(size_is_positive(size));

	if G_UNLIKELY(0 == kernel_pagesize)
		vmm_init();

	size = round_pagesize_fast(size);

	if G_UNLIKELY(vmm_crashing)
		return vmm_valloc(NULL, size);	/* Memory always zeroed by kernel */

	n = pagecount_fast(size);

	/*
	 * First look in the page cache to avoid requesting a new memory
	 * mapping from the kernel.
	 */

	p = page_cache_find_pages(n, user_mem, FALSE);
	if (p != NULL) {
		vmm_validate_pages(p, size);
		if G_UNLIKELY(zero_mem)
			memset(p, 0, size);

		assert_vmm_is_allocated(p, size, VMF_NATIVE, FALSE);

		VMM_STATS_LOCK;
		vmm_stats.alloc_from_cache++;
		vmm_stats.alloc_from_cache_pages += n;
		goto update_stats;
	}

	/*
	 * When debugging, spot areas of the code that perform large allocations.
	 * Each spot is only traced once, the first time we go over the allocation
	 * threshold.
	 */

	if (n > VMM_WARN_THRESH && vmm_debugging(1)) {
		vmm_warn_once("%s(): large allocation of %'zu bytes",
			G_STRFUNC, size);
	}

	/*
	 * Could not find suitable page in cache, need to allocate more memory.
	 */

	p = alloc_pages(size, TRUE);
	if (NULL == p) {
		crash_oom("%s(): cannot allocate %'zu bytes: out of virtual memory",
			G_STRFUNC, size);
	}

	/* Memory allocated by the kernel is already zero-ed */

	assert_vmm_is_allocated(p, size, VMF_NATIVE, FALSE);
	VMM_STATS_LOCK;
	vmm_stats.alloc_direct_core++;
	vmm_stats.alloc_direct_core_pages += n;

	/* FALL THROUGH */

update_stats:
	vmm_stats.allocations++;
	if G_UNLIKELY(zero_mem)
		vmm_stats.allocations_zeroed++;

	if (user_mem) {
		vmm_stats.allocations_user++;
		vmm_stats.user_memory += size;
		vmm_stats.user_pages += n;
		vmm_stats.user_blocks++;
		memusage_add(vmm_stats.user_mem, size);
	} else {
		vmm_stats.allocations_core++;
		vmm_stats.core_memory += size;
		vmm_stats.core_pages += n;
		memusage_add(vmm_stats.core_mem, size);
	}
	VMM_STATS_UNLOCK;

	return p;
}

/**
 * Should we cache ``n'' pages starting at ``p''?
 */
static inline bool
vmm_should_cache(const void *p, size_t n)
{
	/*
	 * Long-term strategy:
	 *
	 * Memory regions that are larger than our highest-order cache are
	 * allocated and freed as-is, and almost never broken into smaller
	 * pages.  The purpose is to avoid excessive virtual memory space
	 * fragmentation, leading at some point to the unability for the
	 * kernel to find a large consecutive virtual memory region.
	 *
	 * Short-term strategy:
	 *
	 * Cache everything, breaking up larger regions.  When the largest
	 * line is full, we'll start evicting memory of course.
	 */

	if (VMM_STRATEGY_SHORT_TERM == vmm_strategy) {
		return TRUE;
	} else {
		size_t len;
		const void *hole;

		/*
		 * In long-term strategy, attempt to cache memory that lies before
		 * the first hole, because this is where we want to keep memory
		 * allocated.
		 */

		len = vmm_first_hole(&hole, FALSE);
		if (len != 0 && vmm_ptr_cmp(p, hole) < 0)
			return TRUE;

		/*
		 * If region is small-enough to fit our cache, check whether it is
		 * an extremity: we want to release extremities as soon as possible
		 * to maximize free space.
		 */

		if (n <= VMM_CACHE_LINES && !vmm_is_extremity(p, n))
			return TRUE;
	}

	return FALSE;
}

/**
 * Free memory allocated via vmm_alloc() or vmm_core_alloc(), possibly
 * returning it to the cache.
 *
 * When ``user_mem'' is FALSE, it means we're freeing memory that was being
 * used by other memory allocators, not by "users": that memory was not
 * accounted for as being used by this layer but rather as "core" memory,
 * i.e. resource for other memory allocators.
 */
static void
vmm_free_internal(void *p, size_t size, bool user_mem)
{
	g_assert(0 == size || p);
	g_assert(size_is_non_negative(size));

	if G_UNLIKELY(vmm_crashing)
		return;

	if (p != NULL) {
		size_t n;

		g_assert(page_start(p) == p);

		size = round_pagesize_fast(size);
		n = pagecount_fast(size);

		g_assert(n >= 1);			/* Asserts that size != 0 */

		assert_vmm_is_allocated(p, size, VMF_NATIVE, FALSE);

		if (vmm_should_cache(p, n)) {
			size_t m = n;
			vmm_invalidate_pages(p, size);
			page_cache_coalesce_pages(&p, &m);
			if (page_cache_insert_pages(p, m)) {
				VMM_STATS_LOCK;
				vmm_stats.free_to_cache++;
				vmm_stats.free_to_cache_pages += n;
			} else {
				VMM_STATS_LOCK;		/* For later below */
			}
		} else {
			size_t m = n;
			page_cache_coalesce_pages(&p, &m);
			free_pages(p, nsize_fast(m), TRUE);
			VMM_STATS_LOCK;
			vmm_stats.free_to_system++;
			vmm_stats.free_to_system_pages += m;
			vmm_stats.free_to_system_extra_pages += m - n;
		}

		/* Stats are already locked */

		vmm_stats.freeings++;

		if (user_mem) {
			vmm_stats.freeings_user++;
			vmm_stats.user_memory -= size;
			vmm_stats.user_pages -= n;
			g_assert(size_is_non_negative(vmm_stats.user_pages));
			g_assert(size_is_non_negative(vmm_stats.user_memory));
			vmm_stats.user_blocks--;
			VMM_STATS_UNLOCK;
			memusage_remove(vmm_stats.user_mem, size);
		} else {
			vmm_stats.freeings_core++;
			vmm_stats.core_memory -= size;
			vmm_stats.core_pages -= n;
			g_assert(size_is_non_negative(vmm_stats.core_pages));
			g_assert(size_is_non_negative(vmm_stats.core_memory));
			VMM_STATS_UNLOCK;
			memusage_remove(vmm_stats.core_mem, size);
		}
	}
}

/**
 * Internal general-purpose memory allocator given to the thread magazine
 * depot in order to either allocate objects or the magazines themselves.
 *
 * If the amount requested is not exactly an even amount of pages, then
 * the memory allocation is actually performed by xmalloc(), because we
 * know the allocation cannot be for a magazine round.
 *
 * Note that if the memory allocated is a magazine round, it will be freed
 * via vmm_free() first, which will put it back to the appropriate magazine,
 * and only when the magazine depot needs to release the allocated rounds
 * will it invoke vmm_free_raw().
 *
 * @param size The size in bytes to allocate; will be rounded to the pagesize.
 *
 * @return a memory region that can be freed via vmm_free_raw().
 */
static void *
vmm_alloc_raw(size_t size)
{
	if G_LIKELY(round_pagesize_fast(size) == size)
		return vmm_alloc_internal(size, TRUE, FALSE);

	return xmalloc(size);
}

/**
 * Free memory allocated via vmm_alloc_raw().
 */
static void
vmm_free_raw(void *p, size_t size)
{
	if G_LIKELY(round_pagesize_fast(size) == size)
		vmm_free_internal(p, size, TRUE);
	else
		xfree(p);
}

/**
 * Get a magazine depot for the given amount of pages.
 *
 * @param npages	amount of pages we want to allocate
 *
 * @return the magazine depot corresponding to the requested size, NULL if
 * we cannot get any suitable depot at this time.
 */
static tmalloc_t *
vmm_get_magazine(size_t npages)
{
	tmalloc_t *depot;

	g_assert(npages <= G_N_ELEMENTS(vmm_magazine));
	g_assert(npages != 0);

	if G_UNLIKELY(NULL == (depot = vmm_magazine[npages - 1])) {
		static mutex_t vmm_magazine_mtx = MUTEX_INIT;
		static uint8 maginit[VMM_MAGAZINE_PAGEMAX];
		size_t idx = npages - 1;

		/*
		 * If the virtual memory layer is not fully initalized, don't use
		 * magazines to prevent deadlocks during auto-initialization.
		 */

		if G_UNLIKELY(!atomic_bool_get(&vmm_fully_inited))
			return NULL;

		/*
		 * The thread-magazine allocator needs the event queue, so if we're
		 * called too soon in the initialization process, we cannot enable
		 * VMM page distribution through magazines.
		 */

		if (!evq_is_inited())
			return NULL;			/* Too soon */

		if G_UNLIKELY(vmm_crashing)
			return NULL;			/* In crash mode, don't use magazines */

		/*
		 * The mutex and the maginit[] protection help us prevent any possible
		 * recursion during auto-initialization.
		 */

		mutex_lock(&vmm_magazine_mtx);

		if (NULL == (depot = vmm_magazine[idx]) && !maginit[idx]) {
			char name[STR_CONST_LEN("vmm-") + SIZE_T_DEC_BUFLEN + 1];

			maginit[idx] = TRUE;
			str_bprintf(name, sizeof name, "vmm-%zu", nsize_fast(npages));
			depot = vmm_magazine[idx] =
				tmalloc_create(name, nsize_fast(npages),
					vmm_alloc_raw, vmm_free_raw);
		}

		mutex_unlock(&vmm_magazine_mtx);
	}

	return depot;
}

/**
 *  Allocate pages through magazine, if possible.
 *
 * @param npages		amount of pages to allocate
 * @param zero			whether to zero the allocated region
 *
 * @return pointer to start of allocated region, NULL if we did not allocate.
 */
static void *
vmm_magazine_alloc(size_t npages, bool zero)
{
	tmalloc_t *depot = vmm_get_magazine(npages);

	if G_UNLIKELY(NULL == depot)
		return NULL;

	VMM_STATS_LOCK;
	vmm_stats.allocations++;
	vmm_stats.allocations_user++;
	vmm_stats.magazine_allocations++;
	if (zero)
		vmm_stats.allocations_zeroed++;
	VMM_STATS_UNLOCK;

	return zero ? tmalloc0(depot) : tmalloc(depot);
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
	size_t npages = pagecount_fast(size);

	if G_LIKELY(npages <= VMM_MAGAZINE_PAGEMAX) {
		void *p = vmm_magazine_alloc(npages, FALSE);

		if G_LIKELY(p != NULL)
			return p;
	}

	return vmm_alloc_internal(size, TRUE, FALSE);
}

/**
 * Same a vmm_alloc() but zeroes the allocated region.
 */
void *
vmm_alloc0(size_t size)
{
	size_t npages = pagecount_fast(size);

	if G_LIKELY(npages <= VMM_MAGAZINE_PAGEMAX) {
		void *p = vmm_magazine_alloc(npages, TRUE);

		if G_LIKELY(p != NULL)
			return p;
	}

	return vmm_alloc_internal(size, TRUE, TRUE);
}

/**
 * Allocates a page-aligned memory chunk, meant to be use as core for other
 * memory allocator built on top of this layer.
 *
 * This means memory allocated here will NOT be accounted for as "user memory"
 * and it MUST be freed with vmm_core_free() for sound accounting.
 *
 * @param size The size in bytes to allocate; will be rounded to the pagesize.
 */
void *
vmm_core_alloc(size_t size)
{
	return vmm_alloc_internal(size, FALSE, FALSE);
}

/**
 * Free memory allocated via vmm_alloc(), possibly returning it to the cache
 * or to the thread magazine if the amount of pages is less than largest amount
 * we serve through magazines.
 */
void
vmm_free(void *p, size_t size)
{
	size_t npages = pagecount_fast(size);

	if G_LIKELY(npages <= VMM_MAGAZINE_PAGEMAX) {
		tmalloc_t *depot;

		/*
		 * If we're running under a long-term VMM allocation strategy,
		 * check whether the region we're releasing is a VMM extremity.
		 * If it is, it should be released.
		 */

		if G_UNLIKELY(
			VMM_STRATEGY_LONG_TERM == vmm_strategy &&
			vmm_is_extremity(p, npages)
		) {
			VMM_STATS_LOCK;
			vmm_stats.magazine_freeings++;
			vmm_stats.magazine_freeings_frag++;
			VMM_STATS_UNLOCK;
			goto user_free;
		}

		depot = vmm_get_magazine(npages);

		if G_LIKELY(depot != NULL) {
			VMM_STATS_LOCK;
			vmm_stats.freeings++;
			vmm_stats.freeings_user++;
			vmm_stats.magazine_freeings++;
			VMM_STATS_UNLOCK;

			tmfree(depot, p);
			return;
		}

		/* FALL THROUGH -- if no depot yet for that amount of pages */
	}

user_free:
	vmm_free_internal(p, size, TRUE);
}

/**
 * Free core allocated via vmm_core_alloc(), possibly returning it to the cache.
 */
void
vmm_core_free(void *p, size_t size)
{
	vmm_free_internal(p, size, FALSE);
}

/**
 * Shrink allocated space via vmm_alloc() or vmm_core_alloc() down to
 * specified size.
 *
 * @param p			the memory region base
 * @param size		current size of the memory region
 * @param new_size	new requested size of the memory region (smaller)
 * @param user_mem	whether this was memory used directly by callers
 *
 * Calling with a NULL pointer is OK when the size is 0.
 * Otherwise calling with a new_size of 0 actually frees the memory region.
 */
static void
vmm_shrink_internal(void *p, size_t size, size_t new_size, bool user_mem)
{
	g_assert(0 == size || p != NULL);
	g_assert(new_size <= size);
	g_assert(page_start(p) == p);

	if G_UNLIKELY(vmm_crashing)
		return;

	if (0 == new_size) {
		vmm_free_internal(p, size, user_mem);
	} else if (p != NULL) {
		size_t osize, nsize;

		assert_vmm_is_allocated(p, size, VMF_NATIVE, FALSE);

		osize = round_pagesize_fast(size);
		nsize = round_pagesize_fast(new_size);

		g_assert(nsize <= osize);

		if (osize != nsize) {
			size_t delta = osize - nsize;
			size_t n = pagecount_fast(delta);
			void *q = ptr_add_offset(p, nsize);

			g_assert(n >= 1);

			if (vmm_should_cache(q, n)) {
				size_t m = n;
				vmm_invalidate_pages(q, delta);
				page_cache_coalesce_pages(&q, &m);
				if (page_cache_insert_pages(q, m)) {
					VMM_STATS_LOCK;
					vmm_stats.free_to_cache++;
					vmm_stats.free_to_cache_pages += n;
				} else {
					VMM_STATS_LOCK;		/* For later below */
				}
			} else {
				size_t m = n;
				page_cache_coalesce_pages(&q, &m);
				free_pages(q, nsize_fast(m), TRUE);
				VMM_STATS_LOCK;
				vmm_stats.free_to_system++;
				vmm_stats.free_to_system_pages += n;
				vmm_stats.free_to_system_extra_pages += m - n;
			}

			/* Stats are already locked */

			vmm_stats.shrinkings++;

			if (user_mem) {
				vmm_stats.shrinkings_user++;
				vmm_stats.user_memory -= delta;
				vmm_stats.user_pages -= n;
				g_assert(size_is_non_negative(vmm_stats.user_pages));
				g_assert(size_is_non_negative(vmm_stats.user_memory));
				VMM_STATS_UNLOCK;
				memusage_remove(vmm_stats.user_mem, delta);
			} else {
				vmm_stats.shrinkings_core++;
				vmm_stats.core_memory -= delta;
				vmm_stats.core_pages -= n;
				g_assert(size_is_non_negative(vmm_stats.core_pages));
				g_assert(size_is_non_negative(vmm_stats.core_memory));
				VMM_STATS_UNLOCK;
				memusage_remove(vmm_stats.core_mem, delta);
			}
		}
	}
}

/**
 * Shrink allocated user space via vmm_alloc() down to specified size.
 *
 * Calling with a NULL pointer is OK when the size is 0.
 * Otherwise calling with a new_size of 0 actually performs a vmm_free().
 */
void
vmm_shrink(void *p, size_t size, size_t new_size)
{
	vmm_shrink_internal(p, size, new_size, TRUE);
}

/**
 * Shrink allocated core space via vmm_core_alloc() down to specified size.
 *
 * Calling with a NULL pointer is OK when the size is 0.
 * Otherwise calling with a new_size of 0 actually performs a vmm_core_free().
 */
void
vmm_core_shrink(void *p, size_t size, size_t new_size)
{
	vmm_shrink_internal(p, size, new_size, FALSE);
}

/**
 * Resize VMM region to be able to hold the specified amount of bytes.
 *
 * When the size is reduced, the region is shrinked.  Otherwise, a new region
 * is allocated and the data are moved, then the old region is freed.
 *
 * @return pointer to the new start of the region.
 */
void *
vmm_resize(void *p, size_t size, size_t new_size)
{
	size_t asize, anew;
	void *np;

	VMM_STATS_INCX(resizings);

	asize = round_pagesize(size);		/* Allocated size */
	anew = round_pagesize(new_size);

	if (asize == anew)
		return p;

	if G_UNLIKELY(vmm_crashing) {
		if (anew < asize)
			return p;
		np = vmm_valloc(NULL, anew);
		memcpy(np, p, size);
		return np;
	}

	if (anew < asize) {
		vmm_shrink_internal(p, size, new_size, TRUE);
		return p;
	}

	/*
	 * Have to allocate a new region and move data around.
	 */

	np = vmm_alloc_internal(new_size, TRUE, FALSE);
	memcpy(np, p, size);
	vmm_free_internal(p, size, TRUE);

	return np;
}

/*
 * Is ``i'' the highest (in the VM growing direction) entry of the cache line?
 */
static inline bool
vpc_is_highest(const struct page_cache *pc, size_t i, bool looped)
{
	return kernel_mapaddr_increasing ?
		pc->current - 1 == i : (0 == i && !looped);
}

/**
 * Scans the page cache for old pages and releases them if they have a certain
 * minimum age. We don't want to cache pages forever because they might never
 * be reused. Further, the OS would page them out anyway because they are
 * considered dirty even though we don't care about the content anymore. If we
 * recycled such old pages, the penalty from paging them in is unlikely lower
 * than the mmap()/munmap() overhead.
 */
static bool
page_cache_timer(void *unused_udata)
{
	time_t now = tm_time();
	struct page_cache *pc;
	size_t i, expired = 0, kept = 0, old_regions = vmm_pmap()->count;
	const void *hole;
	struct vm_upper_hole upper;
	size_t len;
	void *freed[VMM_CACHE_SIZE];
	bool looped, populated;

	(void) unused_udata;

	pc = &page_cache[page_cache_line];

	/*
	 * Compute the first hole capable of holding a region of the same size as
	 * the one used by this cache line.  This allows us to avoid freeing
	 * pages that lie "before" that hole in the VM space, since we always
	 * want to allocate memory in the "lowest" addresses.
	 */

	len = vmm_first_hole(&hole, FALSE);

	/*
	 * If we know an "upper hole", adjust the first hole address to be that
	 * one, as it will be more representative of where we are more likely
	 * to be able to allocate new core.
	 */

	VMM_UPPER_HOLE_LOCK;
	upper = vmm_upper_hole;		/* struct copy */
	VMM_UPPER_HOLE_UNLOCK;

	if (upper.len >= pc->chunksize) {
		len = upper.len;
		hole = upper.p;
	}

	if (len >= pc->chunksize) {
		if (!kernel_mapaddr_increasing)
			hole = const_ptr_add_offset(hole, -len);
	} else {
		hole = NULL;
	}

	spinlock(&pc->lock);

	if (vmm_debugging(pc->current > 0 ? 4 : 8)) {
		s_minidbg("VMM scanning page cache #%zu (%zu item%s)",
			page_cache_line, pc->current, plural(pc->current));
	}

	/*
	 * Because the array storing the cache line is updated in-place, we need
	 * to compute whether it has more than one item before starting our loops.
	 *
	 * Likewise, we need to remember whether we looped at all to be able to
	 * determine that we are at the "highest position" in the array: when
	 * the VM space is decreasing, that position is at index 0, but only
	 * the first time we go through the loop.
	 */

	populated = pc->current > 1;
	looped = FALSE;						/* Needed by vpc_is_highest() */

	for (i = 0; i < pc->current; /* empty */) {
		time_delta_t d = delta_time(now, pc->info[i].stamp);
		void *base = pc->info[i].base;

		/*
		 * Cached regions falling before the identified hole are always kept.
		 *
		 * The rationale is that this is a good place to allocate from, so we
		 * want to reuse the space.  And releasing that space would invalidate
		 * the computed hole, making it likely that we would then again request
		 * allocation at that freed spot later on.
		 *
		 * The only exception is the last (or first when the VM grows down)
		 * entry of a cache line when there is more than one item, to make
		 * sure we never keep a region forever needlessly.
		 */

		if (
			hole != NULL && vmm_ptr_cmp(base, hole) <= 0 &&
			!(populated && vpc_is_highest(pc ,i, looped))
		) {
			if (d >= VMM_CACHE_MAXLIFE)
				kept++;
			i++;				/* i > 0 now, no need to set "looped" here */
			continue;
		}

		/*
		 * To avoid undue fragmentation of the memory space, do not free
		 * a block that lies within an already identified region too soon.
		 * Wait longer, for it to be further coalesced hopefully.
		 *
		 * Under a long-term strategy, extremities above the hole are always
		 * freed, regardless of their age in the cache.
		 */

		if (
			d >= VMM_CACHE_MAXLIFE ||
			(vmm_is_extremity(base, pc->chunksize) &&
				(VMM_STRATEGY_LONG_TERM == vmm_strategy || d >= VMM_CACHE_LIFE)
			)
		) {

			/*
			 * Do not call vpc_free() here, as it will issue a system call
			 * and we are still holding the lock on the page cache line
			 * Stack the address, delaying freeing after we released the lock.
			 */

			vpc_remove_at(pc, base, i);
			freed[expired++] = base;
			looped = TRUE;
		} else {
			i++;				/* i > 0 now, no need to set "looped" here */
		}
	}

	pc->expired += expired;
	spinunlock(&pc->lock);

	g_assert(expired <= G_N_ELEMENTS(freed));

	if G_UNLIKELY(expired > 0) {
		/*
		 * Free the pages we removed from the cache.
		 */

		free_pages_vector(freed, expired, pc->chunksize);

		VMM_STATS_LOCK;
		vmm_stats.cache_expired += expired;
		vmm_stats.cache_expired_pages +=
			expired * pagecount_fast(pc->chunksize);
		VMM_STATS_UNLOCK;

		if (vmm_debugging(1)) {
			size_t regions = vmm_pmap()->count;
			s_minidbg("VMM expired %zu item%s (%zuKiB total) from "
				"page cache #%zu (%zu item%s remaining), "
				"process has %zu VM regions%s",
				expired, plural(expired),
				expired * pc->chunksize / 1024, page_cache_line,
				pc->current, plural(pc->current), regions,
				old_regions < regions ? " (fragmented further)" : "");
		}
		if (vmm_debugging(5)) {
			vmm_dump_pmap();
		}
	}

	if G_UNLIKELY(kept > 0) {
		VMM_STATS_LOCK;
		vmm_stats.cache_kept += kept;
		VMM_STATS_UNLOCK;
	}

	/*
	 * For next time, compute cache line number to scan.
	 */

	if G_UNLIKELY(VMM_CACHE_LINES -1 == page_cache_line)
		page_cache_line = 0;
	else
		page_cache_line++;

	return TRUE;	/* Keep scheduling */
}

/**
 * Free all the pages in the page cache.
 *
 * @param locked	whether the pmap is already write-locked
 */
static void
page_cache_free_all(bool locked)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(page_cache); i++) {
		struct page_cache *pc = &page_cache[i];
		size_t j;
		void *freed[VMM_CACHE_SIZE];

		/*
		 * When the pmap is already write-locked, we cannot lock the page
		 * cache or we risk a deadlock with page_cache_timer() which first
		 * locks the cache lines and then attempts to write-lock the pmap.
		 */

		if (locked) {
			if (!spinlock_try(&pc->lock)) {
				size_t pages = pc->current;
				s_miniwarn("%s(): skipping locked cache line #%zu "
					"(%'zu bytes) with %zu page%s",
					G_STRFUNC, i, pc->chunksize, pages, plural(pages));
				continue;
			}
		} else {
			spinlock(&pc->lock);
		}

		for (j = 0; j < pc->current; j++) {
			freed[j] = pc->info[j].base;
		}

		free_pages_vector(freed, pc->current, pc->chunksize);
		pc->expired += pc->current;
		pc->current = 0;

		spinunlock(&pc->lock);
	}
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
	static spinlock_t trap_slk = SPINLOCK_INIT;

	if G_LIKELY(trap_page != NULL)
		return trap_page;

	spinlock(&trap_slk);

	if (NULL == trap_page) {
		void *p;

		if G_UNLIKELY(0 == kernel_pagesize)
			vmm_init();

		p = alloc_pages(kernel_pagesize, FALSE);
		g_assert(p);
		mprotect(p, kernel_pagesize, PROT_NONE);
		trap_page = p;

		/* The trap page is accounted as user memory */
		VMM_STATS_LOCK;
		vmm_stats.user_memory += kernel_pagesize;
		vmm_stats.user_pages++;
		vmm_stats.user_blocks++;
		VMM_STATS_UNLOCK;
		memusage_add(vmm_stats.user_mem, kernel_pagesize);
	}

	spinunlock(&trap_slk);

	return trap_page;
}

/**
 * @return whether the virtual memory segment grows with increasing addresses.
 */
bool
vmm_grows_upwards(void)
{
	return kernel_mapaddr_increasing;
}

/**
 * Set VMM debug level.
 */
void
set_vmm_debug(uint32 level)
{
	vmm_debug = level;
}

/**
 * Set the VMM allocation strategy.
 *
 * The default strategy is VMM_STRATEGY_SHORT_TERM, which is suitable for
 * short-lived programs: memory is allocated and is not released to the system
 * until we can no longer cache the pages.
 *
 * For long-lived programs, it is best to use VMM_STRATEGY_LONG_TERM which
 * will periodically release unused memeory and which will, over time and
 * gradually, compact memory and limit the amount of VM regions that the
 * kernel needs to manage.
 *
 * @param strategy		desired VM allocation strategy
 */
void
vmm_set_strategy(enum vmm_strategy strategy)
{
	VMM_STRATEGY_LOCK;

	switch (strategy) {
	case VMM_STRATEGY_SHORT_TERM:
		cq_periodic_remove(&vmm_periodic);
		break;
	case VMM_STRATEGY_LONG_TERM:
		if (NULL == vmm_periodic)
			vmm_periodic = evq_raw_periodic_add(1000, page_cache_timer, NULL);
		break;
	}

	vmm_strategy = strategy;

	VMM_STRATEGY_UNLOCK;
}

/**
 * Called when memory allocator has been initialized and it is possible to
 * call routines that will allocate core memory and perform logging calls.
 */
void
vmm_malloc_inited(void)
{
	safe_to_log = TRUE;
#ifdef TRACK_VMM
	vmm_track_malloc_inited();
#endif
}

/**
 * Generate a SHA1 digest of the current VMM statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
vmm_stats_digest(sha1_t *digest)
{
	/*
	 * Don't take locks to read the statistics, to enhance unpredictability.
	 */

	VMM_STATS_INCX(vmm_stats_digest);
	SHA1_COMPUTE(vmm_stats, digest);
}

/**
 * Dump page cache statistics to specified logging agent.
 */
G_GNUC_COLD void
vmm_dump_pcache_log(logagent_t *la)
{
	size_t i;

	for (i = 0; i < VMM_CACHE_LINES; i++) {
		struct page_cache *pc = &page_cache[i];
		size_t count;
		uint64 targeted, allocated, denied, split, evicted, expired;

#define COPY(x)	x = pc->x

		spinlock(&pc->lock);
		count = pc->current;
		COPY(targeted);
		COPY(allocated);
		COPY(denied);
		COPY(split);
		COPY(evicted);
		COPY(expired);
		spinunlock(&pc->lock);

#undef COPY
		log_info(la, "VMM cache #%zu: cnt=%zu, req=%s, ok=%s, deny=%s, "
			"split=%zu, evict=%zu, exp=%zu",
			i, count, uint64_to_string(targeted), uint64_to_string2(allocated),
			uint64_to_string3(denied), (size_t) split, (size_t) evicted,
			(size_t) expired);
	}
}

/**
 * Dump VMM statistics to specified logging agent.
 */
G_GNUC_COLD void
vmm_dump_stats_log(logagent_t *la, unsigned options)
{
	struct pmap *pm = vmm_pmap();
	size_t cached_pages = 0, mapped_pages = 0, native_pages = 0;
	size_t i;
	struct vmm_stats stats;

	VMM_STATS_LOCK;
	stats = vmm_stats;		/* struct copy under lock protection */
	VMM_STATS_UNLOCK;

#define DUMP(x)	log_info(la, "VMM %s = %s", #x,		\
	(options & DUMP_OPT_PRETTY) ?					\
		uint64_to_gstring(stats.x) : uint64_to_string(stats.x))

#define DUMP64(x) G_STMT_START {							\
	uint64 v = AU64_VALUE(&vmm_stats.x);					\
	log_info(la, "VMM %s = %s", #x,							\
		(options & DUMP_OPT_PRETTY) ?						\
			uint64_to_gstring(v) : uint64_to_string(v));	\
} G_STMT_END

	DUMP(allocations);
	DUMP(allocations_zeroed);
	DUMP(freeings);
	DUMP(shrinkings);
	DUMP64(resizings);
	DUMP(allocations_core);
	DUMP(freeings_core);
	DUMP(shrinkings_core);
	DUMP(allocations_user);
	DUMP(freeings_user);
	DUMP(shrinkings_user);
	DUMP64(mmaps);
	DUMP64(munmaps);
	DUMP(magazine_allocations);
	DUMP(magazine_freeings);
	DUMP(magazine_freeings_frag);
	DUMP(hints_followed);
	DUMP(hints_ignored);
	DUMP(alloc_from_cache);
	DUMP(alloc_from_cache_pages);
	DUMP(alloc_direct_core);
	DUMP(alloc_direct_core_pages);
	DUMP(free_to_cache);
	DUMP(free_to_cache_pages);
	DUMP(free_to_system);
	DUMP(free_to_system_pages);
	DUMP(free_to_system_extra_pages);
	DUMP(forced_freed);
	DUMP(forced_freed_pages);
	DUMP64(cache_evictions);
	DUMP64(cache_coalescing);
	DUMP64(cache_line_coalescing);
	DUMP(cache_expired);
	DUMP(cache_expired_pages);
	DUMP(cache_kept);
	DUMP64(cache_ignored);
	DUMP64(cache_exact_match);
	DUMP64(cache_splits);
	DUMP64(cache_high_coalescing);
	DUMP64(cache_too_large);

	/*
	 * Count cached entries -- this is a transient value, so no need to
	 * lock each cache line anyway, we do not care about the exact figures.
	 */

	for (i = 0; i < VMM_CACHE_LINES; i++) {
		struct page_cache *pc = &page_cache[i];

		log_info(la, "VMM cache_entries_%zu = %zu", i, pc->current);
	}

	log_info(la, "VMM cache_entries_next_expire = %zu", page_cache_line);

	DUMP(pmap_foreign_discards);
	DUMP(pmap_foreign_discarded_pages);
	DUMP64(pmap_overruled);
	DUMP64(pmap_dropped);

	/*
	 * These variables are not updated with the VMM stats lock but whith
	 * the VMM hole lock.  This means we did not take a full consistent
	 * view since we copied the statistics with the stats lock held only.
	 */

#define HOLE_COPY(x)	stats.x = vmm_stats.x

	VMM_HOLE_LOCK;
	HOLE_COPY(hole_reused);
	HOLE_COPY(hole_invalidated);
	HOLE_COPY(hole_updated);
	HOLE_COPY(hole_unchanged);
	VMM_HOLE_UNLOCK;

#undef HOLE_COPY

	DUMP(hole_reused);
	DUMP(hole_invalidated);
	DUMP(hole_updated);
	DUMP(hole_unchanged);

#undef DUMP
#define DUMP(x) log_info(la, "VMM pmap_%s = %s", #x,	\
	(options & DUMP_OPT_PRETTY) ?						\
		size_t_to_gstring(x) : size_t_to_string(x))

	{
		size_t count, size, pages;

		rwlock_rlock(&pm->lock);
		count = pm->count;
		size = pm->size;
		pages = pm->pages;
		rwlock_runlock(&pm->lock);

		DUMP(count);
		DUMP(size);
		DUMP(pages);
	}

#undef DUMP
#define DUMP(x)	log_info(la, "VMM %s = %s", #x,		\
	(options & DUMP_OPT_PRETTY) ?					\
		size_t_to_gstring(stats.x) : size_t_to_string(stats.x))

	DUMP(user_memory);
	DUMP(user_pages);
	DUMP(user_blocks);
	DUMP(core_memory);
	DUMP(core_pages);

#undef DUMP

	/*
	 * Compute amount of cached pages.
	 */

	for (i = 0; i < VMM_CACHE_LINES; i++) {
		struct page_cache *pc = &page_cache[i];

		/* Don't spinlock, it's OK to have dirty reads here */

		cached_pages += pc->current * pc->pages;
	}

	/*
	 * Compute the amount of known native / mapped pages.
	 */

	rwlock_rlock(&pm->lock);

	for (i = 0; i < pm->count; i++) {
		struct vm_fragment *vmf = &pm->array[i];

		if (vmf_is_native(vmf)) {
			native_pages += pagecount_fast(vmf_size(vmf));
		} else if (vmf_is_mapped(vmf)) {
			mapped_pages += pagecount_fast(vmf_size(vmf));
		}
	}

	rwlock_runlock(&pm->lock);

#define DUMP(v,x)	log_info(la, "VMM %s = %s", (v),	\
	(options & DUMP_OPT_PRETTY) ?						\
		size_t_to_gstring(x) : size_t_to_string(x))

	DUMP("cached_pages", cached_pages);
	DUMP("mapped_pages", mapped_pages);
	DUMP("native_pages", native_pages);

	/*
	 * "computed_native_pages" MUST be equal to "native_pages" or it means
	 * we're not accounting the allocated pages correctly, either in the
	 * statistics or in the pmap regions.
	 */

	DUMP("computed_native_pages",
		cached_pages + stats.user_pages + stats.core_pages + local_pmap.pages);

	DUMP64(vmm_stats_digest);

#undef DUMP64
#undef DUMP
}

/**
 * Dump VMM statistics at exit time, along with the current pmap.
 */
G_GNUC_COLD void
vmm_dump_stats(void)
{
	s_info("VMM running statistics:");
	vmm_dump_stats_log(log_agent_stderr_get(), 0);
	vmm_dump_pmap();
}

/**
 * Dump VMM usage statistics to specified logging agent.
 */
G_GNUC_COLD void
vmm_dump_usage_log(logagent_t *la, unsigned options)
{
	if (NULL == vmm_stats.user_mem) {
		log_warning(la, "VMM user memory usage stats not configured");
	} else {
		memusage_summary_dump_log(vmm_stats.user_mem, la, options);
	}
	if (NULL == vmm_stats.core_mem) {
		log_warning(la, "VMM core memory usage stats not configured");
	} else {
		memusage_summary_dump_log(vmm_stats.core_mem, la, options);
	}
}

/**
 * In case an assertion failure occurs in this file, dump statistics
 * and the pmap.
 */
static G_GNUC_COLD void
vmm_crash_hook(void)
{
	int sp;

	s_minidbg("VMM pagesize=%zu bytes, virtual addresses are %s",
		kernel_pagesize,
		kernel_mapaddr_increasing ? "increasing" : "decreasing");

	s_minidbg("VMM base=%p, base_sp=%p, current_sp=%p (stack growing %s)",
		vmm_base, stack_base, (void *) &sp,
		ptr_cmp(stack_base, &sp) < 0 ? "up" : "down");

	vmm_dump_stats();
}

/**
 * Mark "amount" bytes as foreign in the local pmap, reserved for the stack.
 *
 * When the kernel pmap is loaded, simply make sure we find the stack
 * region and reserve an extra VMM_STACK_MINSIZE bytes for it to grow
 * further.
 */
static G_GNUC_COLD void
vmm_reserve_stack(size_t amount)
{
	const void *stack_end, *stack_low;
	bool sp_increasing = sp_direction > 0;
	struct pmap *pm = vmm_pmap();

	g_assert(amount != 0);

	/*
	 * If stack and VM region grow in opposite directions, there is ample
	 * room for the stack provided their relative position is correct.
	 */

	if ((size_t) -1 == amount) {
		vmm_base = vmm_trap_page();
		goto vm_setup;
	}

	stack_end = const_ptr_add_offset(stack_base,
		(sp_increasing ? +1 : -1) * amount);
	stack_low = sp_increasing ? stack_base : stack_end;

	rwlock_wlock(&pm->lock);

	if (pmap_is_available(pm, stack_low, amount)) {
		pmap_insert_foreign(pm, stack_low, amount);
		if (vmm_debugging(1)) {
			s_minidbg("VMM reserved %zuKiB [%p, %p] for the stack",
				amount / 1024, stack_low,
				const_ptr_add_offset(stack_low, amount - 1));
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
			s_warning("VMM cannot reserve %zuKiB [%p, %p] for the stack",
				amount / 1024, stack_low,
				const_ptr_add_offset(stack_low, amount - 1));
			vmm_dump_pmap();
		}
		vmm_base = vmm_trap_page();
	}

	rwlock_wunlock(&pm->lock);

vm_setup:
	if (vmm_debugging(0)) {
		s_minidbg("VMM will allocate pages from %p %swards",
			vmm_base, kernel_mapaddr_increasing ? "up" : "down");
	}
}

/**
 * Turn on memory usage statistics.
 */
static G_GNUC_COLD void
vmm_memusage_init_once(void)
{
	g_assert(NULL == vmm_stats.user_mem);
	g_assert(NULL == vmm_stats.core_mem);

	vmm_stats.user_mem = memusage_alloc("VMM user", 0);
	vmm_stats.core_mem = memusage_alloc("VMM core", 0);
}

/**
 * Enable memory usage statistics collection.
 */
G_GNUC_COLD void
vmm_memusage_init(void)
{
	static once_flag_t memusage_inited;

	ONCE_FLAG_RUN(memusage_inited, vmm_memusage_init_once);
}

/**
 * Called later in the initialization chain once the callout queue has been
 * initialized and the properties loaded.
 */
G_GNUC_COLD void
vmm_post_init(void)
{
	struct {
		unsigned non_default:1;
		unsigned vmm_invalidate_free_pages:1;
		unsigned vmm_protect_free_pages:1;
	} settings = { FALSE, FALSE, FALSE };

	crash_hook_add(_WHERE_, vmm_crash_hook);

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
		s_message("VMM settings: %s%s",
			settings.vmm_invalidate_free_pages ?
				"VMM_INVALIDATE_FREE_PAGES" : "",
			settings.vmm_protect_free_pages ?
				"VMM_PROTECT_FREE_PAGES" : "");
	}

	if (vmm_debugging(0)) {
		s_minidbg("VMM using %zu bytes for the page cache", sizeof page_cache);
		s_minidbg("VMM kernel grows virtual memory by %s addresses",
			kernel_mapaddr_increasing ? "increasing" : "decreasing");
		s_minidbg("VMM stack grows by %s addresses",
			sp_direction > 0 ? "increasing" : "decreasing");
		s_minidbg("VMM running in thread #%u", thread_small_id());
	}

	if (vmm_debugging(1)) {
#ifdef HAS_SBRK
		s_minidbg("VMM initial break at %p", initial_brk);
#endif
		s_minidbg("VMM %screasing stack bottom at %p",
			sp_direction > 0 ? "in" : "de", stack_base);
	}

	/*
	 * Check whether we have enough room for the stack to grow.
	 */

	{
		const void *vmbase = vmm_trap_page();	/* First page allocated */
		const void *end = const_ptr_add_offset(vmbase, kernel_pagesize);
		size_t room;

		if (ptr_cmp(stack_base, vmbase) > 0) {
			if (sp_direction < 0) {
				/*
				 * Stack is after the VM region and is decreasing, it can
				 * grow at most to the end of the allocated region.
				 */

				room = round_pagesize(ptr_diff(stack_base, end));
			} else {
				/*
				 * Stack is after the VM region and is increasing.
				 * The kernel should be able to extend it.
				 */

				room = (size_t) -1;
			}
		} else {
			if (sp_direction > 0) {

				/*
				 * Stack is before the VM region and is increasing, it can
				 * grow at most to the start of the allocated region.
				 */

				room = round_pagesize(ptr_diff(vmbase, stack_base));
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
				s_minidbg("VMM kernel can grow the stack as needed");
			}
		} else if (room < VMM_STACK_MINSIZE) {
			s_warning("VMM stack has only %zuKiB to grow!", room / 1024);
		} else if (vmm_debugging(0)) {
			s_minidbg("VMM stack has at most %zuKiB to grow", room / 1024);
		}

		/*
		 * Reserve mappings for the stack so that we do not attempt
		 * to hint an allocation within that range.
		 */

		vmm_reserve_stack(room);
	}

	mingw_vmm_post_init();

#ifdef TRACK_VMM
	vmm_track_post_init();
#endif
}

/**
 * Initialize the VMM layer, once.
 */
static G_GNUC_COLD void
vmm_early_init_once(void)
{
	int i;

#ifdef HAS_SBRK
	initial_brk = sbrk(0);
#endif
	init_kernel_pagesize();
	init_stack_shape();

	for (i = 0; i < VMM_CACHE_LINES; i++) {
		struct page_cache *pc = &page_cache[i];
		size_t pages = i + 1;
		pc->pages = pages;
		pc->chunksize = nsize_fast(pages);
		spinlock_init(&pc->lock);
	}

	/*
	 * Allocate the pmaps.
	 */

	pmap_allocate(&local_pmap);

	g_assert_log(1 == local_pmap.pages,
		"local_pmap.pages = %zu", local_pmap.pages);

	/*
	 * Allocate the trap page early so that it is at the bottom of the
	 * memory space, hopefully (not really true on Linux, but close enough).
	 */

	vmm_base = vmm_trap_page();

	/*
	 * The VMM trap page was allocated earlier, before we have the pmap
	 * structure to record it.
	 *
	 * Insert it now, as a native region since we have allocated it.
	 */

	rwlock_wlock(&local_pmap.lock);
	pmap_insert(&local_pmap, vmm_trap_page(), kernel_pagesize);
	rwlock_wunlock(&local_pmap.lock);

	/*
	 * Determine how the kernel is growing the virtual memory region.
	 */
#ifdef MINGW32
	kernel_mapaddr_increasing = 1;
#else
	{
		void *p = alloc_pages(kernel_pagesize, FALSE);
		void *q = alloc_pages(kernel_pagesize, FALSE);

		kernel_mapaddr_increasing = ptr_cmp(q, p) > 0;

		free_pages(q, kernel_pagesize, FALSE);
		free_pages(p, kernel_pagesize, FALSE);
	}
#endif
#ifdef TRACK_VMM
	vmm_track_init();
#endif
}

/**
 * Mark the VMM layer as initialized, once.
 */
static G_GNUC_COLD void
vmm_init_once(void)
{
	/*
	 * We can now use the VMM layer to allocate memory via xmalloc().
	 */

	xmalloc_vmm_inited();
	zalloc_vmm_inited();

	atomic_bool_set(&vmm_fully_inited, TRUE);
}

/**
 * Emergency initialization of the VMM layer very early in the process, when
 * it's too soon to be able to call xmalloc_vmm_inited().
 *
 * This is only visible from the xmalloc() layer to be able to perform
 * posix_memalign() calls very early in the process startup.
 */
G_GNUC_COLD void
vmm_early_init(void)
{
	once_flag_run(&vmm_early_inited, vmm_early_init_once);
}

/**
 * Early initialization of the vitual memory manager.
 *
 * @attention
 * No external memory allocation (malloc() and friends) can be done in this
 * routine, which is called very early at startup.
 */
G_GNUC_COLD void
vmm_init(void)
{
	vmm_early_init();
	once_flag_run(&vmm_inited, vmm_init_once);
}

/**
 * Reset all VMM magazines.
 */
static void
vmm_magazine_reset(void)
{
	int i;

	for (i = 0; i < VMM_MAGAZINE_PAGEMAX; i++) {
		tmalloc_t *d = vmm_magazine[i];
		if (d != NULL) {
			tmalloc_reset(d);
		}
	}
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

	vmm_magazine_reset();
	safe_to_log = FALSE;		/* Turn logging off */
	cq_periodic_remove(&vmm_periodic);
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
	memusage_free_null(&vmm_stats.user_mem);
	memusage_free_null(&vmm_stats.core_mem);

	vmm_set_stop_freeing(TRUE);

	if (vmm_debugging(0))
		s_minidbg("VMM will no longer release freed pages");
}

/**
 * Final shutdown.
 */
G_GNUC_COLD void
vmm_close(void)
{
	struct pmap *pm = vmm_pmap();
	size_t mapped_pages = 0;
	size_t mapped_memory = 0;
	size_t pages = 0;
	size_t native_pages = 0;
	size_t memory = 0;
	size_t i;

	vmm_magazine_reset();

	/*
	 * Clear all cached pages.
	 */

	page_cache_free_all(FALSE);

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

		if (vmf_is_native(vmf)) {
			size_t n = pagecount_fast(vmf_size(vmf));
			memory += vmf_size(vmf) / 1024;
			pages += n;
			native_pages += n;
		} else if (vmf_is_mapped(vmf)) {
			mapped_memory += vmf_size(vmf) / 1024;
			mapped_pages += pagecount_fast(vmf_size(vmf));
		} else {
			s_warning("VMM invalid memory fragment type (%d)", vmf->type);
		}
	}

	/*
	 * Substract "once" memory.
	 */

	{
		size_t opages = omalloc_page_count();
		size_t smem = stacktrace_memory_used();
		size_t spages = pagecount_fast(smem);
		size_t mmem = malloc_memory_used();
		size_t mpages = pagecount_fast(mmem);

		if (opages > pages) {
			s_warning("VMM omalloc() claims using %zu page%s, have %zu left",
				opages, plural(opages), pages);
		} else {
			pages -= opages;
			memory -= opages * (compat_pagesize() / 1024);
		}

		if (mpages > pages) {
			s_warning("VMM malloc() claims using %zu page%s, have %zu left",
				mpages, plural(mpages), pages);
		} else {
			pages -= mpages;
			memory -= mpages * (compat_pagesize() / 1024);
		}

		if (spages > pages) {
			s_warning("VMM stacktrace claims using %zu page%s, have %zu left",
				spages, plural(spages), pages);
		} else {
			pages -= spages;
			memory -= spages * (compat_pagesize() / 1024);
		}
	}

	if (pages != 0) {
		s_warning("VMM still holds %zu non-attributed page%s totaling %s KiB",
			pages, plural(pages), size_t_to_string(memory));
		if (vmm_stats.user_pages != 0) {
			s_warning("VMM holds %zu user page%s (%zu block%s) totaling %s KiB",
				vmm_stats.user_pages, plural(vmm_stats.user_pages),
				vmm_stats.user_blocks, plural(vmm_stats.user_blocks),
				size_t_to_string(vmm_stats.user_memory / 1024));
		}
		if (vmm_stats.core_pages != 0) {
			s_message("VMM holds %zu core page%s totaling %s KiB",
				vmm_stats.core_pages, plural(vmm_stats.core_pages),
				size_t_to_string(vmm_stats.core_memory / 1024));
		}
	}
	if (native_pages != vmm_stats.user_pages + vmm_stats.core_pages) {
		s_warning("VMM holds %zu native pages, but %zu user + %zu core = %zu",
			native_pages, vmm_stats.user_pages,
			vmm_stats.core_pages, vmm_stats.user_pages + vmm_stats.core_pages);
	}
	if (mapped_pages != 0) {
		s_warning("VMM still holds %zu memory-mapped page%s totaling %s KiB",
			mapped_pages, plural(mapped_pages),
			size_t_to_string(mapped_memory));
	}
}

/***
 *** mmap() and munmap() wrappers: the application should not call these
 *** system calls directly but go through the wrappers so that the VMM layer
 *** can keep an accurate view of the process's virtual memory map.
 ***/

#ifdef HAS_MMAP
/**
 * Record memory-mapped region in the pmap.
 */
static void
pmap_mmap(struct pmap *pm, void *p, size_t size)
{
	/*
	 * The mapped memory region is "foreign" memory as far as we are
	 * concerned and may overlap with previously allocated "foreign"
	 * chunks in whole or in part.
	 *
	 * Invoke pmap_overrule() before pmap_insert_mapped() to make
	 * sure we clean up our memory map before attempting to insert
	 * a new chunk since the insertion code is not prepared to handle
	 * all the overlapping cases we can encounter.
	 */

	rwlock_wlock(&pm->lock);
	pmap_overrule(pm, p, size, VMF_MAPPED);
	pmap_insert_mapped(pm, p, size);
	rwlock_wunlock(&pm->lock);
}
#endif	/* HAS_MMAP */

/**
 * Wrapper of the mmap() system call.
 */
void *
vmm_mmap(void *addr, size_t length, int prot, int flags,
	int fd, fileoffset_t offset)
{
#ifdef HAS_MMAP
	void *p = mmap(addr, length, prot, flags, fd, offset);

	if G_LIKELY(p != MAP_FAILED) {
		VMM_STATS_INCX(mmaps);
		pmap_mmap(vmm_pmap(), p, round_pagesize_fast(length));

		assert_vmm_is_allocated(p, length, VMF_MAPPED, FALSE);

		if (vmm_debugging(5)) {
			s_minidbg("VMM mapped %zuKiB region at %p (fd #%d, offset 0x%lx)",
				length / 1024, p, fd, (unsigned long) offset);
		}
	} else if (vmm_debugging(0)) {
		s_warning("VMM FAILED maping of %zuKiB region (fd #%d, offset 0x%lx)",
			length / 1024, fd, (unsigned long) offset);
	}

	return p;
#else	/* !HAS_MMAP */
	(void) addr;
	(void) length;
	(void) prot;
	(void) flags;
	(void) fd;
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
	struct pmap *pm = vmm_pmap();

	assert_vmm_is_allocated(addr, length, VMF_MAPPED, FALSE);

	/*
	 * We need to clear the region in the pmap BEFORE attempting to
	 * unmap the region.  Failure to do that would mean we can have
	 * another thread map to the cleared region whilst our pmap says
	 * the region is already busy, leading to pmap_overrule() assertion
	 * failures later, possibly.
	 *
	 * Of course, this means re-establishing the mapping later on if
	 * the munmap() call fails.  But given the assert above, we know
	 * our pmap correctly accounts that region as mapped, so the system
	 * call should not fail!
	 *
	 *		--RAM, 2015-10-03
	 */

	rwlock_wlock(&pm->lock);
	pmap_remove(pm, addr, round_pagesize_fast(length));
	rwlock_wunlock(&pm->lock);

	VMM_STATS_INCX(munmaps);

	ret = munmap(addr, length);

	if G_LIKELY(0 == ret) {
		if (vmm_debugging(5)) {
			s_minidbg("VMM unmapped %zuKiB region at %p", length / 1024, addr);
		}
	} else {
		/*
		 * This is so unexpected that it deserves a loud warning with a full
		 * stacktrace so that we can later assess the damage if we get a
		 * weird behaviour.
		 */

		s_carp("munmap(%p, %zu) failed: %m", addr, length);

		/* Re-establish mapping in pmap since we could not unmap the region */
		pmap_mmap(pm, addr, round_pagesize_fast(length));
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

/* FIXME -- the TRACK_VMM code is not thread-safe yet -- RAM, 2011-12-29 */

#ifdef TRACK_VMM
/**
 * This table assotiates an allocated pointer with a page_track structure.
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
	unsigned user:1;				/**< User memory or core? */
};

/**
 * Because we're going to use hash_table_t to keep track of the allocated
 * pages, and due to the fact that this data structure internally relies on
 * the VMM layer, we may recurse to the tracking code at any time.
 *
 * This flag keeps track of recursions so that we avoid exercising any
 * tracking when recursion is detected.
 */
static bool vmm_recursed;

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
static void vmm_free_record(const void *p, size_t size, bool user_mem,
	const char *file, int line);

/**
 * User or core memory?
 */
static const char *
track_mem(bool user_mem)
{
	return user_mem ? "user" : "core";
}

/**
 * Buffer operation for deferred processing (up to next alloc/free).
 * We're buffering the fact that the operation took place, not deferring the
 * actual allocation / free that is described.
 */
static void
buffer_operation(enum track_operation op,
	const void *p, size_t size, bool user_mem, const char *file, int line)
{
	if (vmm_buffer.idx >= G_N_ELEMENTS(vmm_buffered)) {
		vmm_buffer.missed++;
		if (vmm_debugging(0)) {
			s_warning("VMM unable to defer tracking of "
				"%s (%zu %s bytes starting %p) at \"%s:%d\" (issue #%zu)",
				track_operation_to_string(op),
				track_mem(user_mem), p, file, line, vmm_buffer.missed);
			stacktrace_where_print(stderr);
		}
	} else {
		size_t i = vmm_buffer.idx++;
		struct track_buffer *tb = &vmm_buffered[i];

		if (vmm_buffer.idx > vmm_buffer.max) {
			vmm_buffer.max = vmm_buffer.idx;
		}

		if (vmm_debugging(5)) {
			s_warning("VMM deferring tracking of "
				"%s (%zu %s bytes starting %p) at \"%s:%d\" (item #%zu)",
				track_operation_to_string(op),
				size, track_mem(user_mem), p, file, line, vmm_buffer.idx);
		}

		tb->op = op;
		tb->addr = p;
		tb->pt.size = size;
		tb->pt.file = file;
		tb->pt.line = line;
		tb->pt.user = booleanize(user_mem);
#ifdef MALLOC_FRAMES
		stacktrace_get_offset(&tb->where, 2);
#endif
#ifdef MALLOC_TIME
		tb->pt.atime = tm_time();
#endif
	}
}

/*
 * In case TRACK_MALLOC is activated, we want the raw xhmalloc() and xfree()
 * from here on...
 *
 * For that reason, the following code should stay at the bottom of the file.
 */
#undef xhmalloc
#undef xfree

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
		/*
		 * If we're dealing with a "core" region, we can free any sub-part
		 * of the initially allocated region, not just the start of the
		 * region.
		 *
		 * Therefore, our tracking of "core" regions is imperfect and we
		 * must not emit any warning when the base address is not found.
		 */

		if (!pt->user)
			return;			/* Freeing middle of "core" region */

		if (vmm_debugging(0)) {
			s_carp("VMM (%s:%d) attempt to free %s page at %p twice?",
				pt->file, pt->line, track_mem(pt->user), p);
			if (0 == vmm_buffer.missed) {
				s_error_from(_WHERE_,
					"VMM vmm_free() of unknown address %p", p);
			}
		}
		return;
	}

	/*
	 * Again, since we can free any part of a core region before freeing
	 * the beginning, we may end up with a much smaller region to free when
	 * the base pointer (which is the only thing we track) is finally freed.
	 *
	 * Only warn for "user" regions.
	 */

	if (pt->user && xpt->size != pt->size) {
		if (vmm_debugging(0)) {
			s_carp("VMM (%s:%d) freeing %s page at %p (%zu bytes) "
				"from \"%s:%d\" with wrong size %zu [%zu missed event%s]",
				pt->file, pt->line, track_mem(xpt->user), p,
				xpt->size, xpt->file, xpt->line, pt->size,
				vmm_buffer.missed, plural(vmm_buffer.missed));
		}
	}

	if (xpt->user != pt->user) {
		if (vmm_debugging(0)) {
			s_carp("VMM (%s:%d) freeing %s page at %p (%zu bytes) "
				"from \"%s:%d\" as wrong type \"%s\" [%zu missed event%s]",
				pt->file, pt->line, track_mem(xpt->user), p,
				xpt->size, xpt->file, xpt->line, track_mem(pt->user),
				vmm_buffer.missed, plural(vmm_buffer.missed));
		}
	}

	hash_table_remove(tracked, p);
	xfree(xpt);						/* raw free() */

	if (not_leaking != NULL)
		hash_table_remove(not_leaking, p);
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
		s_warning("VMM (%s:%d) reusing page start %p (%zu %s bytes) "
			"from %s:%d, missed its freeing",
			pt->file, pt->line, p, xpt->size,
			track_mem(xpt->user), xpt->file, xpt->line);
#ifdef MALLOC_FRAMES
		s_warning("VMM %s page %p was allocated from:",
			track_mem(xpt->user), p);
		stacktrace_atom_print(stderr, xpt->ast);
#endif
		s_warning("VMM current stack:");
		stacktrace_where_print(stderr);

		vmm_free_record_desc(p, pt);
	}

	xpt = xhmalloc(sizeof *xpt);	/* raw malloc() */
	*xpt = *pt;						/* struct copy */

	if (!hash_table_insert(tracked, p, xpt))
		s_error("cannot record page allocation");
}

/**
 * Record that ``p'' is ``size'' bytes long and was allocated from "file:line".
 *
 * @return its argument ``p''
 */
static void *
vmm_alloc_record(void *p, size_t size, bool user_mem,
	const char *file, int line)
{
	struct page_track pt;

	if (NULL == tracked)
		return p;					/* Tracking not initialized yet */

	if (vmm_recursed) {
		buffer_operation(VMM_ALLOC, p, size, user_mem, file, line);
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
	pt.user = booleanize(user_mem);
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
 * Record that ``p'' (pointing to ``size'') bytes is now free.
 */
static void
vmm_free_record(const void *p, size_t size, bool user_mem,
	const char *file, int line)
{
	struct page_track pt;

	if (vmm_recursed) {
		buffer_operation(VMM_FREE, p, size, user_mem, file, line);
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
	pt.user = booleanize(user_mem);
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

	ARRAY_REMOVE_DEC(vmm_buffered, 0, vmm_buffer.idx);
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
			s_warning("VMM processing deferred "
				"%s (%zu %s bytes starting %p) at \"%s:%d\" "
				"(%zu other record%s pending)",
				track_operation_to_string(tb.op), tb.pt.size,
				track_mem(tb.pt.user), tb.addr, tb.pt.file, tb.pt.line,
				vmm_buffer.idx, plural(vmm_buffer.idx));
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

	return deconstify_pointer(o);
}

/**
 * Tracking version of vmm_alloc().
 */
void *
vmm_alloc_track(size_t size, bool user_mem, const char *file, int line)
{
	void *p;

	p = vmm_alloc_internal(size, user_mem, FALSE);
	return vmm_alloc_record(p, size, user_mem, file, line);
}

/**
 * Tracking version of vmm_alloc() for memory flagged as non-leaking.
 */
void *
vmm_alloc_track_not_leaking(size_t size, const char *file, int line)
{
	void *p;

	p = vmm_alloc_track(size, TRUE, file, line);
	return vmm_not_leaking(p);
}

/**
 * Tracking version of vmm_core_alloc() for memory flagged as non-leaking.
 */
void *
vmm_core_alloc_track_not_leaking(size_t size, const char *file, int line)
{
	void *p;

	p = vmm_alloc_track(size, FALSE, file, line);
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
	return vmm_alloc_record(p, size, TRUE, file, line);
}

/**
 * Tracking version of vmm_free().
 */
void
vmm_free_track(void *p, size_t size, bool user_mem,
	const char *file, int line)
{
	if (not_leaking != NULL) {
		hash_table_remove(not_leaking, p);
	}

	vmm_free_record(p, size, user_mem, file, line);
	vmm_free_internal(p, size, user_mem);
}

/**
 * Tracking version of vmm_shrink().
 */
void
vmm_shrink_track(void *p, size_t size, size_t new_size, bool user_mem,
	const char *file, int line)
{
	/* The shrinking point becomes the new allocation point (file, line) */
	vmm_free_record(p, size, user_mem, file, line);
	vmm_alloc_record(p, new_size, user_mem, file, line);
	vmm_shrink_internal(p, size, new_size, user_mem);
}

/**
 * Tracking version of vmm_resize().
 */
void *
vmm_resize_track(void *p, size_t osize, size_t nsize,
	const char *file, int line)
{
	void *np;

	/* The resize point becomes the new allocation point (file, line) */
	vmm_free_record(p, osize, TRUE, file, line);

	np = vmm_resize(p, osize, nsize);
	vmm_alloc_record(np, nsize, TRUE, file, line);

	return np;
}

/**
 * Tracking version of vmm_resize() for memory flagged as non-leaking.
 */
void *
vmm_resize_track_not_leaking(void *p, size_t osize, size_t nsize,
	const char *file, int line)
{
	void *np;

	np = vmm_resize_track(p, osize, nsize, file, line);
	return vmm_not_leaking(np);
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
		s_warning("VMM missed %zu initial tracking event%s",
			vmm_buffer.missed, plural(vmm_buffer.missed));
	}
}

/**
 * Called when properties have been loaded, so we can use vmm_debugging().
 */
static void
vmm_track_post_init(void)
{
	if (vmm_buffer.max > 0 && vmm_debugging(0)) {
		s_minidbg("VMM required %zu bufferred event%s",
			vmm_buffer.max, plural(vmm_buffer.max));
	}
	if (vmm_nl_buffer.max > 0 && vmm_debugging(0)) {
		s_minidbg("VMM required %zu bufferred non-leaking event%s",
			vmm_nl_buffer.max, plural(vmm_nl_buffer.max));
	}
}

/**
 * vmm_log_pages		-- hash table iterator callback
 *
 * Log used pages, and record them among the `leaksort' set for future summary.
 */
static void
vmm_log_pages(const void *k, void *v, void *leaksort)
{
	const struct page_track *pt = v;
	char ago[32];

	if (hash_table_lookup(not_leaking, k))
		return;

	/*
	 * If page is a "core" page, then it was allocated by a memory allocator
	 * for its own supply of memory to manage and distribute to users, not
	 * for direct "user" consumption.  Therefore, we're not interested by
	 * its leaking.
	 */

	if (!pt->user)
		return;

#ifdef MALLOC_TIME
	str_bprintf(ago, sizeof ago, " [%s]",
		short_time(delta_time(tm_time(), pt->atime)));
#else
	ago[0] = '\0';
#endif	/* MALLOC_TIME */

	s_warning("leaked %s page%s %p (%zu bytes) from \"%s:%d\"%s",
		track_mem(pt->user), pt->size > kernel_pagesize ? "s" : "",
		k, pt->size, pt->file, pt->line, ago);

	leak_add(leaksort, pt->size, pt->file, pt->line);

#ifdef MALLOC_FRAMES
	s_message("%s block %p allocated from: ", track_mem(pt->user), k);
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
