/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Memory allocator for replacing libc's malloc() and friends.
 *
 * This allocator is based on the VMM layer and is meant to be a drop-in
 * malloc() replacement.  Contrary to the allocators found in most libc, this
 * version does not rely on sbrk() and attempts to reduce memory fragmentation.
 *
 * However, for bootstrapping reasons (to be able to handle very early memory
 * allocation before the VMM layer has been initialized), we include an
 * allocator based on sbrk().
 *
 * Routines here are called xmalloc(), xfree(), xrealloc() and xcalloc()
 * to make it possible to unplug the malloc replacement easily.
 *
 * Although xmalloc() is not tailored for multi-threading allocation, it has
 * been made thread-safe because the GTK library can create multiple threads
 * on some platforms, unbeknown to us!
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#define XMALLOC_SOURCE

#include "xmalloc.h"
#include "bit_array.h"
#include "cq.h"
#include "crash.h"			/* For crash_hook_add() */
#include "dump_options.h"
#include "elist.h"
#include "erbtree.h"
#include "log.h"
#include "mem.h"			/* For mem_is_valid_ptr() */
#include "mempcpy.h"
#include "memusage.h"
#include "misc.h"			/* For short_size() and clamp_strlen() */
#include "mutex.h"
#include "once.h"
#include "pow2.h"
#include "spinlock.h"
#include "str.h"			/* For str_vbprintf() */
#include "stringify.h"
#include "thread.h"
#include "tm.h"
#include "unsigned.h"
#include "vmm.h"
#include "walloc.h"
#include "xsort.h"

#include "override.h"		/* Must be the last header included */

#ifdef USE_MY_MALLOC			/* metaconfig symbol */
#define XMALLOC_IS_MALLOC		/* xmalloc() becomes malloc() */
#endif

#if 0
#define XMALLOC_SORT_SAFETY		/* Adds expensive sort checking assertions */
#endif

/*
 * When XMALLOC_ALLOW_WALLOC is defined, small blocks are allocated via walloc()
 * when there are no available blocks in the freelist for that size. This was
 * the default until xgc() was introduced, in an attempt to fight fragmentation.
 *
 * However, with the freelist global coalescing now performed by xgc() in the
 * background, this no longer seems a good approach as it limits the potential
 * of coalescing: walloc()-ed blocks are unreacheable, and long-lived blocks
 * allocated by walloc() prevent garbage collecting of zones.
 *
 * Therefore, as of 2012-04-01, we disable walloc() remapping, but keep the
 * necessary code in place just in case we have to reinstate it.
 */
#if 0
#define XMALLOC_ALLOW_WALLOC	/* Small blocks can use walloc() */
#endif

/*
 * The VMM layer is based on mmap() and falls back to posix_memalign()
 * or memalign().
 *
 * However, when trapping malloc() we also have to define posix_memalign(),
 * memalign() and valign() because glib 2.x can use these routines in its
 * slice allocator and the pointers returned by these functions must be
 * free()able.
 *
 * It follows that when mmap() is not available, we cannot trap malloc().
 */
#if defined(HAS_MMAP) || defined(MINGW32)
#define CAN_TRAP_MALLOC
#endif
#if defined(XMALLOC_IS_MALLOC) && !defined(CAN_TRAP_MALLOC)
#undef XMALLOC_IS_MALLOC
#endif

/**
 * Memory alignment constraints.
 *
 * Glib-2.30.2 does masking on pointer values with 0x7, relying on the
 * assumption that the system's malloc() will return pointers aligned on
 * 8 bytes.
 *
 * To be able to work successfully on systems with such a glib, we have no
 * other option but to remain speachless... and comply with that assumption.
 */
#define XMALLOC_ALIGNBYTES	MAX(8, MEM_ALIGNBYTES)	/* Forced thanks to glib */
#define XMALLOC_MASK		(XMALLOC_ALIGNBYTES - 1)
#define xmalloc_round(s) \
	((size_t) (((unsigned long) (s) + XMALLOC_MASK) & ~XMALLOC_MASK))

/**
 * Header prepended to all allocated objects.
 */
struct xheader {
	size_t length;			/**< Length of the allocated block */
};

#define XHEADER_SIZE	xmalloc_round(sizeof(struct xheader))

/**
 * Allocated block size controls.
 *
 * We have two block sizing strategies: one for smaller blocks and one for
 * bigger blocks.  In each case, the block sizes are multiples of a constant
 * value, and as the bucket index increases the size increases by this
 * constant multiplication factor.  The difference is that the multiplication
 * factor is smaller for small-sized blocks.
 *
 * This size architecture helps limit the amount of buckets we have to handle
 * but creates a discrete set of allowed block sizes, which requires careful
 * handling when splitting or coalescing blocks to avoid reaching an invalid
 * size which we would then never be able to insert in the freelist buckets.
 *
 * Up to XMALLOC_FACTOR_MAXSIZE bytes we use buckets that are a multiple
 * of XMALLOC_BUCKET_FACTOR.  With that factor being 8 for instance,
 * the first bucket holds 8-byte blocks, the second bucket holds 2*8 = 16=byte
 * blocks, and so on.
 *
 * Above XMALLOC_FACTOR_MAXSIZE and until XMALLOC_MAXSIZE, buckets are
 * increasing by XMALLOC_BLOCK_SIZE bytes.  For a block size of
 * 1024, the first bucket would be XMALLOC_FACTOR_MAXSIZE + 0 * 1024,
 * the second XMALLOC_FACTOR_MAXSIZE + 1 * 1024, etc...
 *
 * The index in the bucket array where the switch between the first and second
 * sizing strategy operates is called the "cut-over" index.
 */
#define XMALLOC_FACTOR_MAXSIZE	1024
#define XMALLOC_BUCKET_FACTOR	MAX(XMALLOC_ALIGNBYTES, XHEADER_SIZE)
#define XMALLOC_BLOCK_SIZE		256
#define XMALLOC_MAXSIZE			32768	/**< Largest block size in free list */

/**
 * Minimum size for a block split: the size of blocks in bucket #0.
 */
#define XMALLOC_SPLIT_MIN	(2 * XMALLOC_BUCKET_FACTOR)

/**
 * Minimum fraction of the size we accept to waste in a block to avoid
 * a split.
 */
#define XMALLOC_WASTE_SHIFT		4	/* 1/16th of a block */

/**
 * Minimum amount of items we want to keep in each freelist.
 */
#define XMALLOC_BUCKET_MINCOUNT	4

/**
 * Correction offset due to bucket #0 having a minimum size.
 */
#define XMALLOC_BUCKET_OFFSET \
	((XMALLOC_SPLIT_MIN / XMALLOC_BUCKET_FACTOR) - 1)

/**
 * This contant defines the total number of buckets in the free list.
 */
#define XMALLOC_FREELIST_COUNT	\
	((XMALLOC_FACTOR_MAXSIZE / XMALLOC_BUCKET_FACTOR) + \
	((XMALLOC_MAXSIZE - XMALLOC_FACTOR_MAXSIZE) / XMALLOC_BLOCK_SIZE) - \
	XMALLOC_BUCKET_OFFSET)

/**
 * The cut-over index is the index of the first bucket using multiples of
 * XMALLOC_BLOCK_SIZE, or the last bucket using XMALLOC_BUCKET_FACTOR
 * multiples.
 */
#define XMALLOC_BUCKET_CUTOVER	\
	((XMALLOC_FACTOR_MAXSIZE / XMALLOC_BUCKET_FACTOR) - \
	1 - XMALLOC_BUCKET_OFFSET)

/**
 * Masks for rounding a given size to one of the supported allocation lengths.
 */
#define XMALLOC_FACTOR_MASK	(XMALLOC_BUCKET_FACTOR - 1)
#define XMALLOC_BLOCK_MASK	(XMALLOC_BLOCK_SIZE - 1)

/**
 * Thread-specific buckets.
 */
#define XM_THREAD_COUNT			THREAD_MAX
#define XM_THREAD_MAXSIZE		512		/* Maximum block length */
#define XM_THREAD_ALLOC_THRESH	4		/* Wait for that many allocations */

/**
 * This contant defines the total number of buckets in the thread-specific
 * free lists.  There is no block overhead in thread-specific blocks, hence
 * there is no offset correction.
 */
#define XMALLOC_CHUNKHEAD_COUNT	(XM_THREAD_MAXSIZE / XMALLOC_ALIGNBYTES)

/**
 * Magic size indication.
 *
 * Blocks allocated via walloc() have a size of WALLOC_MAX bytes at most.
 * The leading 16 bits of the 32-bit size quantity are used to flag walloc()
 * allocation to make sure the odd size is not a mistake.
 */
#define XMALLOC_MAGIC_FLAG		0x1U
#define XMALLOC_WALLOC_MAGIC	(0xa10c0000U | XMALLOC_MAGIC_FLAG)
#define XMALLOC_WALLOC_SIZE		(0x0000ffffU & ~XMALLOC_MAGIC_FLAG)

/**
 * Block coalescing options.
 */
#define XM_COALESCE_NONE	0			/**< No coalescing */
#define XM_COALESCE_BEFORE	(1 << 0)	/**< Coalesce with blocks before */
#define XM_COALESCE_AFTER	(1 << 1)	/**< Coalesce with blocks after */
#define XM_COALESCE_ALL		(XM_COALESCE_BEFORE | XM_COALESCE_AFTER)
#define XM_COALESCE_SMART	(1 << 2)	/**< Choose whether to coalesce */

/**
 * Bucket capacity management
 */
#define XM_BUCKET_MINSIZE	4			/**< Initial size */
#define XM_BUCKET_THRESHOLD	512			/**< Threshold for increments */
#define XM_BUCKET_INCREMENT	64			/**< Capacity increments */

/**
 * Freelist insertion burst threshold.
 */
#define XM_FREELIST_THRESH	1000		/**< Insertions per second */

/**
 * Amount of unsorted items we can keep at the tail of a freelist bucket.
 * We try to have all the pointers fit the same CPU L1/L2 cache line.
 * Unfortunately we have to guess its value here, but it's OK to be wrong.
 *
 * We don't know if the start of the unsorted zone will be aligned on a
 * cache line boundary anyway, but it helps keeping a reasonable amount of
 * unsorted items whilst not decreasing performance too much.
 */
#define XM_CPU_CACHELINE	64			/**< Bytes in cache line */
#define XM_BUCKET_UNSORTED	(XM_CPU_CACHELINE / PTRSIZE)

/**
 * Free list data structure for thread-specific allocations.
 *
 * Normally these chunks are handled without locks, that is the idea of having
 * thread-specific data structures.  However, sometimes we have cross-thread
 * freeing and in that case we turn on locking for the chunk.
 */
static struct xchunkhead {
	size_t blocksize;		/**< Block size handled by this list */
	size_t allocations;		/**< Number of allocations done */
	uint shared:1;			/**< A chunk was used during cross-thread frees */
	elist_t list;			/**< List of chunks (struct xchunk) */
} xchunkhead[XMALLOC_CHUNKHEAD_COUNT][XM_THREAD_COUNT];

enum xchunk_magic { XCHUNK_MAGIC = 0x45488613 };

/**
 * Per-thread structure linking blocks belonging to a thread but released
 * by other threads.
 *
 * Because chunks are thread-specific and use no locking, they serve memory
 * quickly and we want to preserve this ability.  However, there are legitimate
 * cases where we cannot avoid cross-thread freeing, for instance when building
 * an IPC queue between threads, messages being allocated by the sender and
 * possibly freed by the receiver.
 *
 * To preserve the no-locking condition on thread-specific chunks, we put
 * aside blocks freed by a foreign thread, linking them using the first word
 * of each block.  As soon as the owning thread starts allocating memory, it
 * will check whether there are pending blocks in this list and it will take
 * care of freeing each of them.
 *
 * Because this list is updated by foreign threads, it needs locking though,
 * but the penalty is only paid when freeing blocks out of a foreign thread.
 * Allocation remains a lock-free path.
 */
static struct xcross {
	spinlock_t lock;		/**< Thread-safe lock */
	size_t count;			/**< Amount of blocks chained */
	void *head;				/**< Head of block list to return to chunks */
	uint8 dead;				/**< Thread known to be dead */
} xcross[XM_THREAD_COUNT];

/**
 * Header for thread-specific chunks (pages).
 *
 * These chunks are organized like a zone, the header keeping track of the
 * necessary information about the objects in the chunk and linking chunks
 * handling the same object size.
 *
 * Objects allocated from thread-specific chunks bear no malloc header so it
 * is important to be able to check that the chunk is valid.  Hence the
 * field redundancy, plus additional consistency checks that create highly
 * unlikely conditions of mis-indentifying the chunk.
 *
 * This allows space-efficient memory usage since the cost of the header is
 * amortized among all the objects in the page.
 */
struct xchunk {
	enum xchunk_magic magic;	/* Magic number for consistency check */
	unsigned xc_size;			/* Object size */
	unsigned xc_stid;			/* Thread STID owning this page */
	unsigned xc_capacity;		/* Amount of items we can allocate  */
	unsigned xc_count;			/* Free items held */
	unsigned xc_free_offset;	/* Offset of first free item in page */
	struct xchunkhead *xc_head;	/* Chunk header */
	link_t xc_lnk;				/* Links chunks of identical size */
};

static inline void
xchunk_check(const struct xchunk * const xck)
{
	g_assert(xck != NULL);
	g_assert(XCHUNK_MAGIC == xck->magic);
}

/**
 * Free list data structure.
 *
 * This is an array of structures pointing to allocated sorted arrays
 * of pointers.  Each array contains blocks of identical sizes.
 *
 * The structure at index i tracks blocks of size:
 *
 *  with off = XMALLOC_BUCKET_OFFSET
 *
 *  - if i <= XMALLOC_BUCKET_CUTOVER, size = (i+1+off) * XMALLOC_BUCKET_FACTOR
 *  - otherwise size = XMALLOC_FACTOR_MAXSIZE +
 *                     (i - XMALLOC_BUCKET_CUTOVER) * XMALLOC_BLOCK_SIZE
 *
 * The above function is linear by chunk and continuous.
 */
static struct xfreelist {
	void **pointers;		/**< Sorted array of pointers */
	size_t count;			/**< Amount of pointers held */
	size_t capacity;		/**< Maximum amount of pointers that can be held */
	size_t blocksize;		/**< Block size handled by this list */
	size_t sorted;			/**< Amount of leading sorted pointers */
	time_t last_shrink;		/**< Last shrinking attempt */
	mutex_t lock;			/**< Bucket locking */
	uint shrinking:1;		/**< Is being shrinked */
	uint expand:1;			/**< Asked to expand by xgc() */
} xfreelist[XMALLOC_FREELIST_COUNT];

/**
 * Each bit set in this bit array indicates a freelist with blocks in it.
 *
 * The `xfreebits_slk' lock protects access to xfreebits[] and xfreelist_maxidx.
 */
static spinlock_t xfreebits_slk = SPINLOCK_INIT;
static bit_array_t xfreebits[BIT_ARRAY_SIZE(XMALLOC_FREELIST_COUNT)];
static size_t xfreelist_maxidx;		/**< Highest bucket with blocks */

#define XMALLOC_SHRINK_PERIOD		5	/**< Secs between shrinking attempts */
#define XMALLOC_XGC_SHRINK_PERIOD	60	/**< Idem, but from xgc() */

/**
 * Table containing the split lengths to use for blocks that do not fit
 * one of our discrete bucket sizes.
 *
 * For each possible size up to XMALLOC_MAXSIZE, by multiples of the
 * XMALLOC_ALIGNBYTES constraint, we have the two sizes to use to split
 * the block correctly.  If the second size is zero, it means an exact fit.
 * If the two sizes are zero, it means there is no possible 2-block split.
 */
static struct xsplit {
	unsigned short larger;
	unsigned short smaller;
} xsplit[XMALLOC_MAXSIZE / XMALLOC_ALIGNBYTES];

/**
 * Internal statistics collected.
 */
static struct xstats {
	uint64 allocations;					/**< Total # of allocations */
	uint64 allocations_zeroed;			/**< Total # of zeroing allocations */
	uint64 allocations_aligned;			/**< Total # of aligned allocations */
	uint64 allocations_plain;			/**< Total # of xpmalloc() calls */
	uint64 allocations_heap;			/**< Total # of xhmalloc() calls */
	uint64 alloc_via_freelist;			/**< Allocations from freelist */
	uint64 alloc_via_walloc;			/**< Allocations from walloc() */
	uint64 alloc_via_vmm;				/**< Allocations from VMM */
	uint64 alloc_via_sbrk;				/**< Allocations from sbrk() */
	uint64 alloc_via_thread_pool;		/**< Allocations from thread chunks */
	uint64 freeings;					/**< Total # of freeings */
	uint64 free_sbrk_core;				/**< Freeing sbrk()-allocated core */
	uint64 free_sbrk_core_released;		/**< Released sbrk()-allocated core */
	uint64 free_vmm_core;				/**< Freeing VMM-allocated core */
	uint64 free_coalesced_vmm;			/**< VMM-freeing of coalesced block */
	uint64 free_walloc;					/**< Freeing a walloc()'ed block */
	uint64 free_thread_pool;			/**< Freeing a thread-specific block */
	uint64 free_foreign_thread_pool;	/**< Freeing accross threads */
	uint64 sbrk_alloc_bytes;			/**< Bytes allocated from sbrk() */
	uint64 sbrk_freed_bytes;			/**< Bytes released via sbrk() */
	uint64 sbrk_wasted_bytes;			/**< Bytes wasted to align sbrk() */
	uint64 vmm_alloc_pages;				/**< Pages allocated via VMM */
	uint64 vmm_split_pages;				/**< VMM pages that were split */
	uint64 vmm_thread_pages;			/**< VMM pages for thread chunks */
	uint64 vmm_freed_pages;				/**< Pages released via VMM */
	uint64 aligned_via_freelist;		/**< Aligned memory from freelist */
	uint64 aligned_via_freelist_then_vmm;	/**< Aligned memory from VMM */
	uint64 aligned_via_vmm;				/**< Idem, no freelist tried */
	uint64 aligned_via_vmm_subpage;		/**< Idem, no freelist tried */
	uint64 aligned_via_zone;			/**< Aligned memory from zone */
	uint64 aligned_via_xmalloc;			/**< Aligned memory from xmalloc */
	uint64 aligned_freed;				/**< Freed aligned memory */
	uint64 aligned_free_false_positives;	/**< Aligned pointers not aligned */
	uint64 aligned_zones_created;		/**< Zones created for alignment */
	uint64 aligned_zones_destroyed;		/**< Alignment zones destroyed */
	uint64 aligned_overhead_bytes;		/**< Structural overhead */
	uint64 aligned_zone_blocks;			/**< Individual blocks in zone */
	uint64 aligned_zone_memory;			/**< Total memory used by zone blocks */
	uint64 aligned_vmm_blocks;			/**< Individual blocks as VMM pages */
	uint64 aligned_vmm_memory;			/**< Total memory used by aligned VMM */
	uint64 reallocs;					/**< Total # of reallocations */
	uint64 realloc_noop;				/**< Reallocs not doing anything */
	uint64 realloc_inplace_vmm_shrinking;	/**< Reallocs with inplace shrink */
	uint64 realloc_inplace_shrinking;		/**< Idem but from freelist */
	uint64 realloc_inplace_extension;		/**< Reallocs not moving data */
	uint64 realloc_coalescing_extension;	/**< Reallocs through coalescing */
	uint64 realloc_relocate_vmm_fragment;	/**< Reallocs of moved fragments */
	uint64 realloc_relocate_vmm_shrinked;	/**< Reallocs of moved fragments */
	uint64 realloc_relocate_smart_attempts;	/**< Attempts to move pointer */
	uint64 realloc_relocate_smart_success;	/**< Smart placement was OK */
	uint64 realloc_regular_strategy;		/**< Regular resizing strategy */
	uint64 realloc_from_thread_pool;		/**< Original was in thread pool */
	uint64 realloc_wrealloc;				/**< Used wrealloc() */
	uint64 realloc_converted_from_walloc;	/**< Converted from walloc() */
	uint64 realloc_promoted_to_walloc;		/**< Promoted to walloc() */
	uint64 freelist_insertions;				/**< Insertions in freelist */
	uint64 freelist_insertions_no_coalescing;	/**< Coalescing forbidden */
	uint64 freelist_bursts;					/**< Burst detection events */
	uint64 freelist_burst_insertions;		/**< Burst insertions in freelist */
	uint64 freelist_plain_insertions;		/**< Plain appending in freelist */
	uint64 freelist_unsorted_insertions;	/**< Insertions in unsorted list */
	uint64 freelist_coalescing_ignore_burst;/**< Ignored due to free burst */
	uint64 freelist_coalescing_ignore_vmm;	/**< Ignored due to VMM block */
	uint64 freelist_coalescing_ignored;		/**< Smart algo chose to ignore */
	uint64 freelist_coalescing_done;	/**< Successful coalescings */
	uint64 freelist_coalescing_failed;	/**< Failed coalescings */
	uint64 freelist_linear_lookups;		/**< Linear lookups in unsorted list */
	uint64 freelist_binary_lookups;		/**< Binary lookups in sorted list */
	uint64 freelist_short_yes_lookups;	/**< Quick find in sorted list */
	uint64 freelist_short_no_lookups;	/**< Quick miss in sorted list */
	uint64 freelist_partial_sorting;	/**< Freelist tail sorting */
	uint64 freelist_full_sorting;		/**< Freelist sorting of whole bucket */
	uint64 freelist_avoided_sorting;	/**< Avoided full sorting of bucket */
	uint64 freelist_sorted_superseding;	/**< Last sorted replaced last item */
	uint64 freelist_split;				/**< Block splitted on allocation */
	uint64 freelist_nosplit;			/**< Block not splitted on allocation */
	uint64 freelist_blocks;				/**< Amount of blocks in free list */
	uint64 freelist_memory;				/**< Memory held in freelist */
	uint64 xgc_runs;					/**< Amount of xgc() runs */
	uint64 xgc_throttled;				/**< Throttled calls to xgc() */
	uint64 xgc_time_throttled;			/**< Throttled due to running time */
	uint64 xgc_collected;				/**< Amount of xgc() calls collecting */
	uint64 xgc_blocks_collected;		/**< Amount of blocks collected */
	uint64 xgc_pages_collected;			/**< Amount of pages collected */
	uint64 xgc_coalesced_blocks;		/**< Amount of blocks coalesced */
	uint64 xgc_coalesced_memory;		/**< Amount of memory we coalesced */
	uint64 xgc_coalescing_useless;		/**< Useless coalescings of 2 blocks */
	uint64 xgc_coalescing_failed;		/**< Failed block coalescing */
	uint64 xgc_page_freeing_failed;		/**< Cannot free embedded pages */
	uint64 xgc_bucket_expansions;		/**< How often do we expand buckets */
	uint64 xgc_bucket_shrinkings;		/**< How often do we shrink buckets */
	size_t user_memory;					/**< Current user memory allocated */
	size_t user_blocks;					/**< Current amount of user blocks */
	memusage_t *user_mem;				/**< EMA tracker */
} xstats;
static spinlock_t xstats_slk = SPINLOCK_INIT;

#define XSTATS_LOCK			spinlock_hidden(&xstats_slk)
#define XSTATS_UNLOCK		spinunlock_hidden(&xstats_slk)

static uint32 xmalloc_debug;		/**< Debug level */
static bool safe_to_log;			/**< True when we can log */
static bool xmalloc_vmm_is_up;		/**< True when the VMM layer is up */
static size_t sbrk_allocated;		/**< Bytes allocated with sbrk() */
static bool xmalloc_grows_up = TRUE;	/**< Is the VM space growing up? */
static bool xmalloc_no_freeing;		/**< No longer release memory */
static bool xmalloc_no_wfree;		/**< No longer release memory via wfree() */
static bool xmalloc_crashing;		/**< Crashing mode, minimal servicing */

static void *lowest_break;			/**< Lowest heap address we know */
static void *current_break;			/**< Current known heap break */
static size_t xmalloc_pagesize;		/**< Cached page size */
static once_flag_t xmalloc_freelist_inited;
static once_flag_t xmalloc_xgc_installed;

static spinlock_t xmalloc_sbrk_slk = SPINLOCK_INIT;

static void xmalloc_freelist_add(void *p, size_t len, uint32 coalesce);
static void *xmalloc_freelist_alloc(size_t len, size_t *allocated);
static void xmalloc_freelist_setup(void);
static void xmalloc_split_setup(void);
static void *xmalloc_freelist_lookup(size_t len,
	const struct xfreelist *exclude, struct xfreelist **flp);
static void xmalloc_freelist_insert(void *p, size_t len,
	bool burst, uint32 coalesce);
static void *xfl_bucket_alloc(const struct xfreelist *flb,
	size_t size, bool core, size_t *allocated);
static void xmalloc_crash_hook(void);

#define xmalloc_debugging(lvl)	G_UNLIKELY(xmalloc_debug > (lvl) && safe_to_log)

#define XM_INVALID_PTR		((void *) 0xdeadbeef)

/*
 * Simplify dead-code removal by gcc, preventing #ifdef hell.
 */
#ifdef XMALLOC_ALLOW_WALLOC
#define allow_walloc()			1
#else
#define allow_walloc()			0
#endif

/**
 * Set debug level.
 */
void
set_xmalloc_debug(uint32 level)
{
	xmalloc_debug = level;
}

/**
 * Put the xmalloc layer in crashing mode.
 *
 * This is activated on assertion failures and other fatal conditions, and
 * is an irreversible operation.  Its purpose is to prevent any usage of
 * internal data structures that could be corrupted, yet allow basic memory
 * allocation during crashing.
 *
 * In crashing mode, allocations are done without any freelist updating,
 * and no freeing will occur.  The simplest algorithms are always chosen.
 */
G_GNUC_COLD void
xmalloc_crash_mode(void)
{
	xmalloc_crashing = TRUE;
	xmalloc_no_freeing = TRUE;
	xmalloc_no_wfree = TRUE;
}

/**
 * Comparison function for pointers.
 *
 * This is tailored to put at the tail of each freelist bucket the addresses
 * that are closer to the base of the virtual memory, in order to force
 * reusing of these addresses first (in the hope that the other unused entries
 * will end-up being coalesced and ultimately released).
 */
static inline int
xm_ptr_cmp(const void *a, const void *b)
{
	/* Larger addresses at the end of the array when addresses grow down */

	return xmalloc_grows_up ? ptr_cmp(b, a) : ptr_cmp(a, b);
}

/**
 * Called when the main callout queue is idle to attempt background compaction.
 */
static bool
xmalloc_idle_collect(void *unused_data)
{
	(void) unused_data;

	xgc();
	return TRUE;		/* Keep calling */
}

/**
 * Install periodic idle callback to run the freelist compactor.
 */
static G_GNUC_COLD void
xmalloc_xgc_install(void)
{
	cq_idle_add(cq_main(), xmalloc_idle_collect, NULL);
}

/**
 * Called when the VMM layer has been initialized.
 */
G_GNUC_COLD void
xmalloc_vmm_inited(void)
{
	STATIC_ASSERT(IS_POWER_OF_2(XMALLOC_BUCKET_FACTOR));
	STATIC_ASSERT(IS_POWER_OF_2(XMALLOC_BLOCK_SIZE));
	STATIC_ASSERT(0 == (XMALLOC_FACTOR_MASK & XMALLOC_SPLIT_MIN));
	STATIC_ASSERT(XMALLOC_SPLIT_MIN / 2 == XMALLOC_BUCKET_FACTOR);
	STATIC_ASSERT(1 == (((1 << WALLOC_MAX_SHIFT) - 1) & XMALLOC_WALLOC_MAGIC));

	xmalloc_vmm_is_up = TRUE;
	safe_to_log = TRUE;
	xmalloc_pagesize = compat_pagesize();
	xmalloc_grows_up = vmm_grows_upwards();
	xmalloc_freelist_setup();

#ifdef XMALLOC_IS_MALLOC
	vmm_malloc_inited();
#endif

	/*
	 * We wait for the VMM layer to be up before we install the xgc() idle
	 * thread in an attempt to tweak the self-bootstrapping path of this
	 * library and avoid creating some objects too early: we wish to avoid
	 * sbrk() allocation if possible.
	 */

	once_flag_run(&xmalloc_xgc_installed, xmalloc_xgc_install);
}

/**
 * Called to log which malloc() is used on the specified log agent.
 */
G_GNUC_COLD void
xmalloc_show_settings_log(logagent_t *la)
{
	log_info(la, "using %s", xmalloc_is_malloc() ?
		"our own malloc() replacement" : "native malloc()");
}

/**
 * Called to log which malloc() is used.
 *
 * @attention
 * This is called very early, and is used to record crash hooks for the
 * file as a side effect.
 */
G_GNUC_COLD void
xmalloc_show_settings(void)
{
	xmalloc_show_settings_log(log_agent_stderr_get());
	crash_hook_add(_WHERE_, xmalloc_crash_hook);
	if (NULL == xstats.user_mem) {
		memusage_t *mu = memusage_alloc("xmalloc", 0);
		XSTATS_LOCK;
		if (NULL == xstats.user_mem) {
			xstats.user_mem = mu;
			mu = NULL;
		}
		XSTATS_UNLOCK;
		memusage_free_null(&mu);
	}
}

/**
 * Round requested size to one of the supported allocation sizes.
 */
static inline size_t
xmalloc_round_blocksize(size_t len)
{
	/*
	 * Blocks larger than XMALLOC_MAXSIZE are allocated via the VMM layer.
	 */

	if G_UNLIKELY(len > XMALLOC_MAXSIZE)
		return round_pagesize(len);

	/*
	 * Blocks smaller than XMALLOC_FACTOR_MAXSIZE are allocated using the
	 * first sizing strategy: multiples of XMALLOC_BUCKET_FACTOR bytes,
	 * with a minimum of XMALLOC_SPLIT_MIN bytes.
	 */

	if (len <= XMALLOC_FACTOR_MAXSIZE) {
		size_t blen = (len + XMALLOC_FACTOR_MASK) & ~XMALLOC_FACTOR_MASK;
		if G_UNLIKELY(blen < XMALLOC_SPLIT_MIN)
			blen = XMALLOC_SPLIT_MIN;
		return blen;
	}

	/*
	 * Blocks smaller than XMALLOC_MAXSIZE are allocated using the second
	 * sizing strategy: multiples of XMALLOC_BLOCK_SIZE bytes.
	 */

	return (len + XMALLOC_BLOCK_MASK) & ~XMALLOC_BLOCK_MASK;
}

/**
 * Should we split a block?
 *
 * @param current		the current physical block size
 * @param wanted		the final physical block size after splitting
 */
static bool
xmalloc_should_split(size_t current, size_t wanted)
{
	size_t waste;

	g_assert(current >= wanted);

	waste = current - wanted;

	return waste >= XMALLOC_SPLIT_MIN &&
		(current >> XMALLOC_WASTE_SHIFT) <= waste;
}

#ifdef XMALLOC_ALLOW_WALLOC
/**
 * Is block length tagged as being that of a walloc()ed block?
 */
static inline ALWAYS_INLINE bool
xmalloc_is_walloc(size_t len)
{
	return XMALLOC_WALLOC_MAGIC == (len & ~XMALLOC_WALLOC_SIZE);
}

/**
 * Return size of walloc()ed block given a tagged length.
 */
static inline ALWAYS_INLINE size_t
xmalloc_walloc_size(size_t len)
{
	return len & XMALLOC_WALLOC_SIZE;
}
#else	/* !XMALLOC_ALLOW_WALLOC */
/*
 * Cannot have a walloc()-ed block, so make sure we have proper hardwired
 * definitions for these inlined routines.
 */

static inline ALWAYS_INLINE bool
xmalloc_is_walloc(size_t len)
{
	(void) len;
	return FALSE;
}

static inline ALWAYS_INLINE size_t
xmalloc_walloc_size(size_t len)
{
	(void) len;
	g_assert_not_reached();
}
#endif	/* XMALLOC_ALLOW_WALLOC */

/**
 * Allocate more core, when the VMM layer is still uninitialized.
 *
 * Allocation is done in a system-dependent way: sbrk() on UNIX,
 * HeapAlloc() on Windows.
 *
 * Memory allocated from the heap is rarely freed as such but can be recycled
 * through xfree() if it ends up being used by users of xmalloc().
 *
 * On Windows, HeapFree() can be used to free up the memory, but on UNIX only
 * memory contiguous to the heap break can be freed through calls to sbrk()
 * with a negative increment.  See xmalloc_freecore().
 *
 * @param len		amount of bytes requested
 * @param can_log	whether we're allowed to issue a log message
 *
 * @return pointer to more memory of at least ``len'' bytes.
 */
static void *
xmalloc_addcore_from_heap(size_t len, bool can_log)
{
	void *p;
	bool locked;

	g_assert(size_is_positive(len));
	g_assert(xmalloc_round(len) == len);

	/*
	 * Initialize the heap break point if not done so already.
	 */

	if G_UNLIKELY(NULL == lowest_break) {

#ifdef HAS_SBRK
		current_break = sbrk(0);
#else
		current_break = (void *) -1;
#endif	/* HAS_SBRK */

		lowest_break = current_break;
		if ((void *) -1 == current_break) {
			t_error("cannot get initial heap break address: %m");
		}
		xmalloc_freelist_setup();
	}

	/*
	 * The VMM layer has not been initialized yet: allocate from the heap.
	 */

#ifdef HAS_SBRK
	/*
	 * On FreeBSD, pthread_self() calls malloc() initially, hence we have
	 * a bootstrapping problem... Resolve it by checking whether we already
	 * have the spinlock, and if we do, check whether we're running as a
	 * single thread.  In which case we allow the call to continue, unlocked.
	 *		--RAM, 2012-05-19
	 */

	if G_UNLIKELY(spinlock_is_held(&xmalloc_sbrk_slk)) {
		if (thread_is_single()) {
			locked = FALSE;
			goto bypass;
		}
	}

	locked = TRUE;
	spinlock(&xmalloc_sbrk_slk);
bypass:
	p = sbrk(len);

	/*
	 * Ensure pointer is aligned.
	 */

	if G_UNLIKELY(xmalloc_round(p) != (size_t) p) {
		size_t missing = xmalloc_round(p) - (size_t) p;
		char *q;
		g_assert(size_is_positive(missing));
		q = sbrk(missing);
		g_assert(ptr_add_offset(p, len) == q);	/* Contiguous zone */
		p = ptr_add_offset(p, missing);
		XSTATS_LOCK;
		xstats.sbrk_wasted_bytes += missing;
		XSTATS_UNLOCK;
	}
#else
	(void) locked;
	t_error("cannot allocate core on this platform (%zu bytes)", len);
	return p = NULL;
#endif

	if ((void *) -1 == p) {
		if (locked)
			spinunlock(&xmalloc_sbrk_slk);
		t_error("cannot allocate more core (%zu bytes): %m", len);
	}

	/*
	 * Don't assume we're the only caller of sbrk(): move the current
	 * break pointer relatively to the allocated space rather than
	 * simply increasing our old break pointer by ``len''.
	 *
	 * On Windows we have no idea how heap addresses will be allocated so
	 * explicitly maintain both the lower and upper heap ranges.
	 */

	if (is_running_on_mingw()) {
		void *end = ptr_add_offset(p, len);
		if (ptr_cmp(p, lowest_break) < 0)
			lowest_break = p;
		if (ptr_cmp(end, current_break) > 0)
			current_break = end;
	} else {
		current_break = ptr_add_offset(p, len);
	}
	XSTATS_LOCK;
	sbrk_allocated += len;
	xstats.sbrk_alloc_bytes += len;
	XSTATS_UNLOCK;
	if (locked)
		spinunlock(&xmalloc_sbrk_slk);

	if (xmalloc_debugging(1) && can_log) {
		t_debug("XM added %zu bytes of heap core at %p", len, p);
	}

	return p;
}

/**
 * Check whether memory was allocated from the VMM layer or from the heap.
 *
 * On UNIX we know that heap memory is allocated contiguously starting from
 * the initial break and moving forward.
 *
 * on Windows we maintain the lowest and upper break ranges since we cannot
 * foresee how heap addresses will be allocated.
 */
static inline bool
xmalloc_isheap(const void *ptr, size_t len)
{
	if G_UNLIKELY(ptr_cmp(ptr, current_break) < 0) {
		/* Make sure whole region is under the break */
		g_assert(ptr_cmp(const_ptr_add_offset(ptr, len), current_break) <= 0);
		return ptr_cmp(ptr, lowest_break) >= 0;
	} else {
		return FALSE;
	}
}

/**
 * Attempt to free core.
 *
 * On UNIX systems, core memory (allocated on the heap through sbrk() calls)
 * can only be released when the end of the region to free is at the break
 * point.
 *
 * On Windows systems, core memory can always be freed via HeapFree() but that
 * does not guarantee that the memory is going to be returned to the system.
 * Indeed, the HeapAlloc() and HeapFree() routines are just glorified malloc()
 * and free() routines which handle the lower details to allocate the core.
 *
 * @return TRUE if memory was freed, FALSE otherwise.
 */
static bool
xmalloc_freecore(void *ptr, size_t len)
{
	g_assert(ptr != NULL);
	g_assert(size_is_positive(len));
	g_assert(xmalloc_round(len) == len);

	/*
	 * If the address lies within the break, there's nothing to do, unless
	 * the freed segment is at the end of the break.  The memory is not lost
	 * forever: it should be put back into the free list by the caller.
	 */

	spinlock(&xmalloc_sbrk_slk);

	if G_UNLIKELY(ptr_cmp(ptr, current_break) < 0) {
		const void *end = const_ptr_add_offset(ptr, len);

		XSTATS_LOCK;
		xstats.free_sbrk_core++;
		XSTATS_UNLOCK;

		/*
		 * Don't assume we're the only ones using sbrk(), check the actual
		 * break, not our cached value.
		 */

		if G_UNLIKELY(end == sbrk(0)) {
			void *old_break;
			bool success = FALSE;

			if (xmalloc_debugging(0)) {
				t_debug("XM releasing %zu bytes of trailing heap at %p",
					len, ptr);
			}

#ifdef HAS_SBRK
			old_break = sbrk(-len);
			if ((void *) -1 == old_break) {
				t_warning("XM cannot decrease break by %zu bytes: %m", len);
			} else {
				current_break = ptr_add_offset(old_break, -len);
				success = !is_running_on_mingw();	/* no sbrk(-x) on Windows */
			}
#endif	/* HAS_SBRK */
			g_assert(ptr_cmp(current_break, lowest_break) >= 0);
			if (success) {
				XSTATS_LOCK;
				xstats.free_sbrk_core_released++;
				xstats.sbrk_freed_bytes += len;
				XSTATS_UNLOCK;
			}
			spinunlock(&xmalloc_sbrk_slk);
			return success;
		} else {
			if (xmalloc_debugging(0)) {
				t_debug("XM releasing %zu bytes in middle of heap at %p",
					len, ptr);
			}
			spinunlock(&xmalloc_sbrk_slk);
			return FALSE;		/* Memory not freed */
		}
	}

	if (xmalloc_debugging(1))
		t_debug("XM releasing %zu bytes of core", len);

	spinunlock(&xmalloc_sbrk_slk);

	vmm_core_free(ptr, len);
	XSTATS_LOCK;
	xstats.free_vmm_core++;
	xstats.vmm_freed_pages += vmm_page_count(len);
	XSTATS_UNLOCK;

	return TRUE;
}

/**
 * Check whether pointer is valid.
 */
static bool
xmalloc_is_valid_pointer(const void *p, bool locked)
{
	if (xmalloc_round(p) != pointer_to_ulong(p))
		return FALSE;

	if G_UNLIKELY(xmalloc_no_freeing)
		return TRUE;	/* Don't validate if we're shutdowning */

	if G_LIKELY(xmalloc_vmm_is_up) {
		/*
		 * Can't call vmm_is_native_pointer() if we hold a lock for fear
		 * of creating a deadlock.
		 */
		return locked ||
			vmm_is_native_pointer(p) || xmalloc_isheap(p, sizeof p);
	} else {
		return xmalloc_isheap(p, sizeof p);
	}
}

/**
 * When pointer is invalid or mis-aligned, return the reason.
 *
 * @return reason why pointer is not valid, for logging.
 */
static const char *
xmalloc_invalid_ptrstr(const void *p)
{
	if (xmalloc_round(p) != pointer_to_ulong(p))
		return "not correctly aligned";

	if G_LIKELY(xmalloc_vmm_is_up) {
		if (vmm_is_native_pointer(p)) {
			return "valid VMM pointer!";		/* Should never happen */
		} else {
			if (xmalloc_isheap(p, sizeof p)) {
				return "valid heap pointer!";	/* Should never happen */
			} else {
				return "neither VMM nor heap pointer";
			}
		}
	} else {
		if (xmalloc_isheap(p, sizeof p)) {
			return "valid heap pointer!";		/* Should never happen */
		} else {
			return "not a heap pointer";
		}
	}
	g_assert_not_reached();
}

/**
 * Check that malloc header size is valid.
 */
static inline bool
xmalloc_is_valid_length(const void *p, size_t len)
{
	size_t rounded;
	size_t adjusted;

	if (!size_is_positive(len))
		return FALSE;

	rounded = xmalloc_round_blocksize(len);

	if G_LIKELY(rounded == len || round_pagesize(rounded) == len)
		return TRUE;

	/*
	 * Could have extra (unsplit due to minimum split size) data at the
	 * end of the block.  Remove this data and see whether size would be
	 * fitting.
	 */

	adjusted = len - XMALLOC_SPLIT_MIN / 2;		/* Half of split factor */
	if G_LIKELY(adjusted == xmalloc_round_blocksize(adjusted))
		return TRUE;

	/*
	 * Allow simplified posix_memalign() implementation: the rounded block
	 * can be up to XMALLOC_BLOCK_SIZE bytes longer when the size is larger
	 * than XMALLOC_FACTOR_MAXSIZE.  This is due to the fact that rounding
	 * to an alignment is not always compatible with the discrete malloc
	 * block sizes.
	 */

	if (len > XMALLOC_FACTOR_MAXSIZE && len <= XMALLOC_MAXSIZE)
		return TRUE;

	/*
	 * Have to cope with early heap allocations which are done by the libc
	 * before we enter our main(), making it impossible to initialize
	 * proper page size rounding.
	 */

	return xmalloc_isheap(p, len);
}

/**
 * Computes physical size of blocks in a chunk list given the chunk index.
 */
static inline G_GNUC_PURE size_t
xch_block_size_idx(size_t idx)
{
	return XMALLOC_ALIGNBYTES * (idx + 1);
}

/**
 * Find chunk index for a given block size.
 */
static inline G_GNUC_PURE size_t
xch_find_chunkhead_index(size_t len)
{
	g_assert(size_is_positive(len));
	g_assert(xmalloc_round(len) == len);
	g_assert(len <= XM_THREAD_MAXSIZE);
	g_assert(len >= XMALLOC_ALIGNBYTES);

	return len / XMALLOC_ALIGNBYTES - 1;
}

/**
 * Computes index of free list in the array.
 */
static inline size_t
xfl_index(const struct xfreelist *fl)
{
	size_t idx;

	idx = fl - &xfreelist[0];
	g_assert(size_is_non_negative(idx) && idx < G_N_ELEMENTS(xfreelist));

	return idx;
}

/**
 * Computes physical size of blocks in a given free list index.
 */
static inline G_GNUC_PURE size_t
xfl_block_size_idx(size_t idx)
{
	return (idx <= XMALLOC_BUCKET_CUTOVER) ?
		XMALLOC_BUCKET_FACTOR * (idx + 1 + XMALLOC_BUCKET_OFFSET) :
		XMALLOC_FACTOR_MAXSIZE +
			XMALLOC_BLOCK_SIZE * (idx - XMALLOC_BUCKET_CUTOVER);
}

/**
 * Computes physical size of blocks in a free list.
 */
static inline size_t
xfl_block_size(const struct xfreelist *fl)
{
	return xfl_block_size_idx(xfl_index(fl));
}

/**
 * Find freelist index for a given block size.
 */
static inline G_GNUC_PURE size_t
xfl_find_freelist_index(size_t len)
{
	g_assert(size_is_positive(len));
	g_assert(xmalloc_round_blocksize(len) == len);
	g_assert(len <= XMALLOC_MAXSIZE);
	g_assert(len >= XMALLOC_SPLIT_MIN);

	return (len <= XMALLOC_FACTOR_MAXSIZE) ? 
		len / XMALLOC_BUCKET_FACTOR - 1 - XMALLOC_BUCKET_OFFSET :
		XMALLOC_BUCKET_CUTOVER +
			(len - XMALLOC_FACTOR_MAXSIZE) / XMALLOC_BLOCK_SIZE;
}

/**
 * Find proper free list for a given block size.
 */
static inline struct xfreelist *
xfl_find_freelist(size_t len)
{
	size_t idx;

	idx = xfl_find_freelist_index(len);
	return &xfreelist[idx];
}

/**
 * Replace the buckets's array of pointers.
 *
 * @param fl		the freelist bucket
 * @param array		new array to use
 * @param len		length of array
 */
static void
xfl_replace_pointer_array(struct xfreelist *fl, void **array, size_t len)
{
	size_t used, size, capacity, i;
	void *ptr;

	g_assert(array != NULL);
	g_assert(size_is_non_negative(len));
	assert_mutex_is_owned(&fl->lock);
	g_assert(size_is_non_negative(fl->count));

	ptr = fl->pointers;							/* Can be NULL */
	used = sizeof(void *) * fl->count;
	size = sizeof(void *) * fl->capacity;
	capacity = len / sizeof(void *);

	g_assert(ptr != NULL || 0 == used);
	g_assert(len >= used);
	g_assert(capacity * sizeof(void *) == len);	/* Even split */
	g_assert(array != ptr);

	for (i = fl->count; i < capacity; i++) {
		array[i] = XM_INVALID_PTR;		/* Clear trailing (unused) entries */
	}

	memcpy(array, ptr, used);
	fl->pointers = array;
	fl->capacity = capacity;

	g_assert(fl->capacity >= fl->count);	/* Still has room for all items */

	/*
	 * Freelist bucket is now in a coherent state, we can unconditionally
	 * release the old bucket even if it ends up being put in the same bucket
	 * we just extended / shrunk.
	 *
	 * TODO: make sure there is no deadlock possible.  Inserting in the bucket
	 * will require grabing its mutex, and if another thread has it whilst
	 * it is waiting for the mutex we're holding for this bucket we're
	 * presently extending or shrinking, boom!.  Deadlock...
	 * We'll need to defer insertion in the freelist until after we released
	 * our fl->lock mutex.	--RAM, 2012-11-04
	 */

	if (ptr != NULL)
		xmalloc_freelist_add(ptr, size, XM_COALESCE_ALL);
}

/**
 * Remove trailing excess memory in pointers[], accounting for hysteresis.
 *
 * @return TRUE if we actually shrank the bucket.
 */
static bool
xfl_shrink(struct xfreelist *fl)
{
	void *new_ptr;
	void *old_ptr;
	size_t old_size, old_used, new_size, allocated_size;

	g_assert(fl->count < fl->capacity);
	g_assert(size_is_non_negative(fl->count));
	assert_mutex_is_owned(&fl->lock);

	old_ptr = fl->pointers;
	old_size = sizeof(void *) * fl->capacity;
	old_used = sizeof(void *) * fl->count;
	if (old_size >= XM_BUCKET_THRESHOLD * sizeof(void *)) {
		new_size = old_used + XM_BUCKET_INCREMENT * sizeof(void *);
	} else {
		new_size = old_used * 2;
	}

	/*
	 * Ensure we never free up a freelist bucket completely.
	 */

	new_size = MAX(XM_BUCKET_MINSIZE * sizeof(void *), new_size);
	new_size = xmalloc_round_blocksize(new_size);

	if (new_size >= old_size)
		return FALSE;

	new_ptr = xfl_bucket_alloc(fl, new_size, FALSE, &allocated_size);

	/*
	 * If there's nothing in the freelist, don't bother shrinking: we would
	 * need to get more core.
	 */

	if G_UNLIKELY(NULL == new_ptr)
		return FALSE;

	/*
	 * Detect possible recursion.
	 */

	/* freelist bucket is already locked */

	if G_UNLIKELY(fl->pointers != old_ptr) {
		if (xmalloc_debugging(0)) {
			t_debug("XM recursion during shrinking of freelist #%zu "
					"(%zu-byte block): already has new bucket at %p "
					"(count = %zu, capacity = %zu)",
					xfl_index(fl), fl->blocksize, (void *) fl->pointers,
					fl->count, fl->capacity);
		}

		g_assert(fl->capacity >= fl->count);	/* Shrinking was OK */
		g_assert(fl->pointers != new_ptr);

		/*
		 * The freelist structure is coherent, we can release the bucket
		 * we had allocated.
		 */

		if (xmalloc_debugging(1)) {
			t_debug("XM discarding allocated bucket %p (%zu bytes) for "
				"freelist #%zu", new_ptr, allocated_size, xfl_index(fl));
		}

		xmalloc_freelist_add(new_ptr, allocated_size, XM_COALESCE_ALL);
		return FALSE;
	}

	g_assert(allocated_size >= new_size);
	g_assert(new_ptr != old_ptr);
	g_assert(new_size >= old_used);

	fl->last_shrink = tm_time();

	/*
	 * If we allocated the same block size as before, free it immediately:
	 * no need to move around data.
	 */

	if G_UNLIKELY(old_size == allocated_size) {
		if (xmalloc_debugging(1)) {
			t_debug("XM discarding allocated bucket %p (%zu bytes) for "
				"freelist #%zu: same size as old bucket",
				new_ptr, allocated_size, xfl_index(fl));
		}
		xmalloc_freelist_add(new_ptr, allocated_size, XM_COALESCE_ALL);
		return FALSE;
	}

	xfl_replace_pointer_array(fl, new_ptr, allocated_size);

	if (xmalloc_debugging(1)) {
		t_debug("XM shrunk freelist #%zu (%zu-byte block) to %zu items"
			" (holds %zu): old size was %zu bytes, new is %zu, requested %zu,"
			" bucket at %p",
			xfl_index(fl), fl->blocksize, fl->capacity, fl->count,
			old_size, allocated_size, new_size, new_ptr);
	}

	return TRUE;
}

/*
 * Called after one block was removed from the freelist bucket.
 *
 * Resize the pointers[] array if needed and update the minimum freelist index
 * after an item was removed from the freelist.
 */
static void
xfl_count_decreased(struct xfreelist *fl, bool may_shrink)
{
	assert_mutex_is_owned(&fl->lock);

	/*
	 * Update maximum bucket index and clear freelist bit if we removed
	 * the last block from the list.
	 */

	if G_UNLIKELY(0 == fl->count) {
		size_t idx = xfl_index(fl);

		spinlock(&xfreebits_slk);
		bit_array_clear(xfreebits, idx);

		if G_UNLIKELY(idx == xfreelist_maxidx) {
			size_t i;

			i = bit_array_last_set(xfreebits, 0, XMALLOC_FREELIST_COUNT - 1);
			xfreelist_maxidx = (size_t) -1 == i ? 0 : i;

			g_assert(size_is_non_negative(xfreelist_maxidx));
			g_assert(xfreelist_maxidx < G_N_ELEMENTS(xfreelist));

			if (xmalloc_debugging(2)) {
				t_debug("XM max frelist index decreased to %zu",
					xfreelist_maxidx);
			}
		}
		spinunlock(&xfreebits_slk);
	}

	/*
	 * Make sure we resize the pointers[] array when we had enough removals.
	 */

	if (
		may_shrink && !fl->shrinking &&
		fl->capacity - fl->count >= XM_BUCKET_INCREMENT &&
		delta_time(tm_time(), fl->last_shrink) > XMALLOC_SHRINK_PERIOD
	) {
		/*
		 * Paranoid: prevent further shrinking attempts on same bucket.
		 * The bucket is locked by the current thread, so this is thread-safe
		 * and costs almost nothing.
		 */

		fl->shrinking = TRUE;
		xfl_shrink(fl);
		fl->shrinking = FALSE;
	}
}

/*
 * Would split block length end up being redistributed to the specified
 * freelist bucket?
 */
static bool
xfl_block_falls_in(const struct xfreelist *flb, size_t len)
{
	/*
	 * Mimic the algorithm used for insertion into the freelist to see which
	 * buckets we would end up inserting fragmented blocks to.
	 *
	 * See xmalloc_freelist_insert() for additional comments on the logic.
	 */

	if (len > XMALLOC_MAXSIZE) {
		if (xfl_find_freelist(XMALLOC_MAXSIZE) == flb)
			return TRUE;
		len %= XMALLOC_MAXSIZE;
	}

	if (len > XMALLOC_FACTOR_MAXSIZE) {
		size_t multiple = len & ~XMALLOC_BLOCK_MASK;

		if G_UNLIKELY(len - multiple == XMALLOC_SPLIT_MIN / 2) {
			if (len < 2 * XMALLOC_FACTOR_MAXSIZE) {
				multiple = XMALLOC_FACTOR_MAXSIZE / 2;
			} else {
				multiple = (len - XMALLOC_FACTOR_MAXSIZE) & ~XMALLOC_BLOCK_MASK;
			}
		}

		if (multiple != len) {
			if (xfl_find_freelist(multiple) == flb)
				return TRUE;

			len -= multiple;
		}

		if (len > XMALLOC_FACTOR_MAXSIZE)
			return TRUE;		/* Assume it could */
	}

	return xfl_find_freelist(len) == flb;
}

/**
 * Make sure pointer within freelist is valid.
 */
static void
assert_valid_freelist_pointer(const struct xfreelist *fl, const void *p)
{
	if (!xmalloc_is_valid_pointer(p, TRUE)) {
		t_error_from(_WHERE_,
			"invalid pointer %p in %zu-byte malloc freelist: %s",
			p, fl->blocksize, xmalloc_invalid_ptrstr(p));
	}

	if (*(size_t *) p != fl->blocksize) {
		size_t len = *(size_t *) p;
		if (!size_is_positive(len)) {
			t_error_from(_WHERE_, "detected free block corruption at %p: "
				"block in a bucket handling %zu bytes has corrupted length %zd",
				p, fl->blocksize, len);
		} else {
			t_error_from(_WHERE_, "detected free block corruption at %p: "
				"%zu-byte long block in a bucket handling %zu bytes",
				p, len, fl->blocksize);
		}
	}
}

/**
 * Remove from the free list the block selected by xmalloc_freelist_lookup().
 *
 * @param fl		the freelist bucket where allocation was done
 * @param p			the allocated pointer (for assertions only)
 */
static void
xfl_remove_selected(struct xfreelist *fl, void *p)
{
	size_t i;

	g_assert(size_is_positive(fl->count));
	g_assert(fl->count >= fl->sorted);
	assert_mutex_is_owned(&fl->lock);

	XSTATS_LOCK;
	xstats.freelist_blocks--;
	xstats.freelist_memory -= fl->blocksize;
	XSTATS_UNLOCK;

	/*
	 * See xmalloc_freelist_lookup() for the selection algorithm.
	 *
	 * Because we selected the last item of the array we have nothing
	 * to do but decrease the count.
	 */

	g_assert(p == fl->pointers[fl->count - 1]);		/* Removing last item */

	i = --fl->count;					/* Index of removed item */
	fl->pointers[i] = XM_INVALID_PTR;	/* Prevent accidental reuse */
	if (i < fl->sorted)
		fl->sorted--;

	/*
	 * Forbid any bucket shrinking as we could be in the middle of a bucket
	 * allocation and that could cause harmful recursion.
	 */

	xfl_count_decreased(fl, FALSE);
	mutex_unlock(&fl->lock);
}

/**
 * Allocate a block from the freelist, of given physical length, but without
 * performing any split if that would alter the specified freelist.
 *
 * @param flb		the freelist bucket for which we're allocating memory
 * @param len		the desired block length
 * @param allocated	the actual length allocated
 *
 * @return the block address we found, NULL if nothing was found.
 * The returned block is removed from the freelist.
 */
static void *
xfl_freelist_alloc(const struct xfreelist *flb, size_t len, size_t *allocated)
{
	struct xfreelist *fl;
	void *p;

	p = xmalloc_freelist_lookup(len, flb, &fl);

	if (p != NULL) {
		size_t blksize = fl->blocksize;

		g_assert(blksize >= len);

		xfl_remove_selected(fl, p);

		/*
		 * If the block is larger than the size we requested, the remainder
		 * is put back into the free list provided it does not fall into
		 * the bucket we're allocating for.
		 */

		if (len != blksize) {
			void *split;
			size_t split_len;

			split_len = blksize - len;

			if G_UNLIKELY(!xmalloc_should_split(blksize, len)) {
				XSTATS_LOCK;
				xstats.freelist_nosplit++;
				XSTATS_UNLOCK;
				goto no_split;
			}

			if G_LIKELY(!xfl_block_falls_in(flb, split_len)) {
				XSTATS_LOCK;
				xstats.freelist_split++;
				XSTATS_UNLOCK;
				if (xmalloc_grows_up) {
					/* Split the end of the block */
					split = ptr_add_offset(p, len);
				} else {
					/* Split the head of the block */
					split = p;
					p = ptr_add_offset(p, split_len);
				}

				if (xmalloc_debugging(3)) {
					t_debug("XM splitting large %zu-byte block at %p"
						" (need only %zu bytes: returning %zu bytes at %p)",
						blksize, p, len, split_len, split);
				}

				g_assert(split_len <= XMALLOC_MAXSIZE);

				xmalloc_freelist_insert(split, split_len,
					FALSE, XM_COALESCE_NONE);
				blksize = len;		/* We shrank the allocted block */
			} else {
				XSTATS_LOCK;
				xstats.freelist_nosplit++;
				XSTATS_UNLOCK;
				if (xmalloc_debugging(3)) {
					t_debug("XM not splitting large %zu-byte block at %p"
						" (need only %zu bytes but split %zu bytes would fall"
						" in freelist #%zu)",
						blksize, p, len, split_len, xfl_index(flb));
				}
			}
		}

	no_split:
		*allocated = blksize;	/* Could be larger than requested initially */
	}

	return p;
}


/**
 * Allocate memory for freelist buckets.
 *
 * @param flb		the freelist bucket for which we're allocating memory
 * @param size		amount of bytes needed
 * @param core		whether we can allocate core
 * @param allocated	where size of allocated block is returned.
 *
 * @return allocated chunk for the freelist bucket, along with the size of
 * the actual allocated block in ``allocated''.
 */
static void *
xfl_bucket_alloc(const struct xfreelist *flb,
	size_t size, bool core, size_t *allocated)
{
	size_t len;
	void *p;

	len = xmalloc_round_blocksize(size);

	if (len <= XMALLOC_MAXSIZE) {
		p = xfl_freelist_alloc(flb, len, allocated);
		if (p != NULL)
			return p;
	}

	if (!core)
		return NULL;

	if G_LIKELY(xmalloc_vmm_is_up) {
		len = round_pagesize(size);
		p = vmm_core_alloc(len);
		XSTATS_LOCK;
		xstats.vmm_alloc_pages += vmm_page_count(len);
		XSTATS_UNLOCK;
	} else {
		p = xmalloc_addcore_from_heap(len, TRUE);
	}

	*allocated = len;
	return p;
}

/**
 * Extend the free list pointers[] array.
 */
static void
xfl_extend(struct xfreelist *fl)
{
	void *new_ptr;
	void *old_ptr;
	size_t old_size, old_used, new_size = 0, allocated_size;

	assert_mutex_is_owned(&fl->lock);
	g_assert(fl->count >= fl->capacity || fl->expand);

	old_ptr = fl->pointers;
	old_size = sizeof(void *) * fl->capacity;
	old_used = sizeof(void *) * fl->count;

	if G_UNLIKELY(0 == old_size) {
		g_assert(NULL == fl->pointers);
		new_size = XM_BUCKET_MINSIZE * sizeof(void *);
	} else if (old_size < XM_BUCKET_THRESHOLD * sizeof(void *)) {
		new_size = old_size * 2;
	} else {
		new_size = old_size + XM_BUCKET_INCREMENT * sizeof(void *);
	}

	g_assert(new_size > old_size);

	if (xmalloc_debugging(1)) {
		t_debug("XM extending freelist #%zu (%zu-byte block) "
			"to %zu items, count = %zu, current bucket at %p -- "
			"requesting %zu bytes",
			xfl_index(fl), fl->blocksize, new_size / sizeof(void *),
			fl->count, old_ptr, new_size);
	}

	/*
	 * Because we're willing to allocate the bucket array using the freelist
	 * and we may end-up splitting the overhead to the bucket we're extending,
	 * we need a special allocation routine that will not split anything to
	 * the bucket we're extending and which also returns us the size of the
	 * block actually allocated (since it could be larger than requested).
	 *
	 * It could naturally happen that the block selected for the new bucket
	 * was listed in that same bucket we're extending, in which case the
	 * fl->count and the old bucket will be updated properly when we come back
	 * here. Because the count is accurate, it does not matter that we copy
	 * more data to the new bucket than there are now valid pointer entries.
	 */

	new_ptr = xfl_bucket_alloc(fl, new_size, TRUE, &allocated_size);
	g_assert(allocated_size >= new_size);

	/*
	 * Detect possible recursion.
	 */

	if G_UNLIKELY(fl->pointers != old_ptr) {
		if (xmalloc_debugging(0)) {
			t_debug("XM recursion during extension of freelist #%zu "
					"(%zu-byte block): already has new bucket at %p "
					"(count = %zu, capacity = %zu)",
					xfl_index(fl), fl->blocksize, (void *) fl->pointers,
					fl->count, fl->capacity);
		}

		g_assert(fl->capacity >= fl->count);	/* Extending was OK */
		g_assert(fl->pointers != new_ptr);

		/*
		 * The freelist structure is coherent, we can release the bucket
		 * we had allocated and if it causes it to be put back in this
		 * freelist, we may still safely recurse here.
		 */

		if (xmalloc_debugging(1)) {
			t_debug("XM discarding allocated bucket %p (%zu bytes) for "
				"freelist #%zu", new_ptr, allocated_size, xfl_index(fl));
		}

		xmalloc_freelist_add(new_ptr, allocated_size, XM_COALESCE_ALL);
		return;
	}

	/*
	 * If the freelist bucket has more items than before without having faced
	 * recursive extension (already detected and handled above), then we
	 * may have written beyond the bucket itself.
	 *
	 * This should never happen, hence the fatal error.
	 */

	if (old_used < fl->count * sizeof(void *)) {
		t_error_from(_WHERE_,
			"XM self-increase during extension of freelist #%zu "
			"(%zu-byte block): has more items than initial %zu "
			"(count = %zu, capacity = %zu)",
			xfl_index(fl), fl->blocksize, old_used / sizeof(void *),
			fl->count, fl->capacity);
	}

	xfl_replace_pointer_array(fl, new_ptr, allocated_size);
	fl->expand = FALSE;

	if (xmalloc_debugging(1)) {
		t_debug("XM extended freelist #%zu (%zu-byte block) to %zu items"
			" (holds %zu): new size is %zu bytes, requested %zu, bucket at %p",
			xfl_index(fl), fl->blocksize, fl->capacity, fl->count,
			allocated_size, new_size, new_ptr);
	}
}

/**
 * Sorting callback for items in the pointers[] array from a freelist bucket.
 */
static int
xfl_ptr_cmp(const void *a, const void *b)
{
	const void * const *ap = a, * const *bp = b;
	return xm_ptr_cmp(*ap, *bp);
}

#ifdef XMALLOC_SORT_SAFETY
/**
 * Verify that the freelist bucket is sorted.
 *
 * @param fl		the freelist bucket
 * @param low		first index expected to be sorted
 * @param count		amount of items to check
 * @param fmt		explaination message, printf()-like
 * @param ...		variable printf arguments for message
 */
static void G_GNUC_PRINTF(4, 5)
assert_xfl_sorted(const struct xfreelist *fl, size_t low, size_t count,
	const char *fmt, ...)
{
	size_t i;
	size_t high = size_saturate_add(low, count);
	const char *prev = fl->pointers[low];

	for (i = low + 1; i < high;  i++) {
		const char *cur = fl->pointers[i];

		if (xm_ptr_cmp(prev, cur) > 0) {
			va_list args;
			char buf[80];

			va_start(args, fmt);
			str_vbprintf(buf, sizeof buf, fmt, args);
			va_end(args);

			t_warning("XM freelist #%zu (%zu/%zu sorted) "
				"items %zu-%zu unsorted %s: "
				"breaks at item %zu",
				xfl_index(fl), fl->sorted, fl->count, low, high - 1, buf, i);

			t_error_from(_WHERE_, "freelist #%zu corrupted", xfl_index(fl));
		}

		prev = cur;
	}
}
#else
#define assert_xfl_sorted(...)
#endif	/* XMALLOC_SORT_SAFETY */

/**
 * Sort freelist bucket.
 */
static void
xfl_sort(struct xfreelist *fl)
{
	size_t unsorted;
	void **ary = fl->pointers;
	size_t x = fl->sorted;			/* Index of first unsorted item */

	assert_mutex_is_owned(&fl->lock);

	/*
	 * Items from 0 to fl->sorted are already fully sorted, so we only need
	 * to sort the tail and see whether it makes the whole thing sorted.
	 */

	unsorted = fl->count - x;

	if G_UNLIKELY(0 == unsorted)
		return;

	g_assert(size_is_positive(unsorted));

	/*
	 * Start by sorting the trailing unsorted items.
	 *
	 * Use xqsort() to ensure that no memory will be allocated.
	 */

	if G_LIKELY(unsorted > 1) {
		XSTATS_LOCK;
		xstats.freelist_partial_sorting++;
		XSTATS_UNLOCK;
		xqsort(&ary[x], unsorted, sizeof ary[0], xfl_ptr_cmp);
		assert_xfl_sorted(fl, x, unsorted, "after xqsort");
	}

	/*
	 * If the unsorted items are all greater than the last sorted item,
	 * then the whole array is now sorted.
	 */

	if (0 != x && 0 < xm_ptr_cmp(ary[x - 1], ary[x])) {
		/*
		 * Here we're merging two sorted sub-parts of the array, so it could
		 * be faster to use smsort().  However, our quicksort() is heavily
		 * optimized to perform very well on almost-sorted arrays, and it has
		 * a much lower overhead than smsort(), so we prefer xqsort().
		 *		--RAM, 2012-03-03
		 */

		XSTATS_LOCK;
		xstats.freelist_full_sorting++;
		XSTATS_UNLOCK;
		xqsort(ary, fl->count, sizeof ary[0], xfl_ptr_cmp);
		assert_xfl_sorted(fl, 0, fl->count, "after full qsort");
	} else {
		XSTATS_LOCK;
		xstats.freelist_avoided_sorting++;
		XSTATS_UNLOCK;
		assert_xfl_sorted(fl, 0, fl->count, "after nosort");
	}

	fl->sorted = fl->count;		/* Fully sorted now */

	if (xmalloc_debugging(1)) {
		t_debug("XM sorted %zu items from freelist #%zu (%zu bytes)",
			fl->count, xfl_index(fl), fl->blocksize);
	}
}

/**
 * Binary lookup for a matching block within free list array, and computation
 * of its insertion point.
 *
 * @return index within the sorted array where ``p'' is stored, -1 if not found.
 */
static G_GNUC_HOT inline size_t
xfl_binary_lookup(void **array, const void *p,
	size_t low, size_t high, size_t *low_ptr)
{
	size_t mid;

	/*
	 * Optimize if we have more than 4 items by looking whether the
	 * pointer falls within the min/max ranges.
	 */

	if G_LIKELY(high - low >= 4) {
		if G_UNLIKELY(array[low] == p) {
			XSTATS_LOCK;
			xstats.freelist_short_yes_lookups++;
			XSTATS_UNLOCK;
			return 0;
		}
		if (xm_ptr_cmp(p, array[low]) < 0) {
			if (low_ptr != NULL)
				*low_ptr = low;
			XSTATS_LOCK;
			xstats.freelist_short_no_lookups++;
			XSTATS_UNLOCK;
			return -1;
		}
		low++;
		if G_UNLIKELY(array[high] == p) {
			XSTATS_LOCK;
			xstats.freelist_short_yes_lookups++;
			XSTATS_UNLOCK;
			return high;
		}
		if (xm_ptr_cmp(p, array[high]) > 0) {
			if (low_ptr != NULL)
				*low_ptr = high + 1;
			XSTATS_LOCK;
			xstats.freelist_short_no_lookups++;
			XSTATS_UNLOCK;
			return -1;
		}
		high--;
	}

	/* Binary search */

	XSTATS_LOCK;
	xstats.freelist_binary_lookups++;
	XSTATS_UNLOCK;

	mid = low + (high - low) / 2;

	for (;;) {
		int c;

		if G_UNLIKELY(low > high || high > SIZE_MAX / 2) {
			mid = -1;		/* Not found */
			break;
		}

		c = xm_ptr_cmp(p, array[mid]);

		if G_UNLIKELY(0 == c)
			break;				/* Found */
		else if (c > 0)
			low = mid + 1;
		else
			high = mid - 1;

		mid = low + (high - low) / 2;
		G_PREFETCH_R(&array[mid]);
	}

	if (low_ptr != NULL)
		*low_ptr = low;

	return mid;
}

/**
 * Lookup for a block within a free list chunk.
 *
 * If ``low_ptr'' is non-NULL, it is written with the index where insertion
 * of a new item should happen (in which case the returned value must be -1).
 *
 * @return index within the ``pointers'' sorted array where ``p'' is stored,
 * -1 if not found.
 */
static G_GNUC_HOT size_t
xfl_lookup(struct xfreelist *fl, const void *p, size_t *low_ptr)
{
	size_t unsorted;

	assert_mutex_is_owned(&fl->lock);

	if G_UNLIKELY(0 == fl->count) {
		if (low_ptr != NULL)
			*low_ptr = 0;
		return -1;
	}

	assert_xfl_sorted(fl, 0, fl->sorted, "on entry in xfl_lookup");

	unsorted = fl->count - fl->sorted;

	if G_UNLIKELY(unsorted != 0) {
		size_t i;

		/* Binary search the leading sorted part, if any */

		if G_LIKELY(fl->sorted != 0) {
			i = xfl_binary_lookup(fl->pointers, p, 0, fl->sorted - 1, NULL);

			if ((size_t) -1 != i)
				return i;
		}

		/*
		 * Use a linear lookup when there are at most XM_BUCKET_UNSORTED
		 * unsorted items at the tail: this is expected to be held within
		 * a single CPU cacheline (provided its beginning is aligned).
		 * At worst it will cause 2 cache line loadings, but this should
		 * remain efficient.
		 */

		if G_LIKELY(unsorted <= XM_BUCKET_UNSORTED) {
			size_t total = fl->count;
			void **pointers = &fl->pointers[fl->sorted];

			XSTATS_LOCK;
			xstats.freelist_linear_lookups++;
			XSTATS_UNLOCK;

			for (i = fl->sorted; i < total; i++) {
				if (*pointers++ == p)
					return i;
			}

			if (low_ptr != NULL)
				*low_ptr = fl->count;	/* Array is unsorted, insert at end */

			return -1;
		}

		/* Sort it on the fly then before searching */

		xfl_sort(fl);
	}

	/* Binary search the entire (sorted) array */

	return xfl_binary_lookup(fl->pointers, p, 0, fl->count - 1, low_ptr);
}

/**
 * Delete slot ``idx'' within the free list.
 */
static void
xfl_delete_slot(struct xfreelist *fl, size_t idx)
{
	g_assert(size_is_positive(fl->count));
	g_assert(size_is_non_negative(idx) && idx < fl->count);
	g_assert(fl->count >= fl->sorted);
	assert_mutex_is_owned(&fl->lock);

	fl->count--;
	if (idx < fl->sorted)
		fl->sorted--;
	XSTATS_LOCK;
	xstats.freelist_blocks--;
	xstats.freelist_memory -= fl->blocksize;
	XSTATS_UNLOCK;

	if (idx < fl->count) {
		memmove(&fl->pointers[idx], &fl->pointers[idx + 1],
			(fl->count - idx) * sizeof(fl->pointers[0]));
	}

	/*
	 * Regardless of whether we removed the last item or whether we
	 * shifted down the pointers because we removed a middle index,
	 * the previous last slot is now unused.
	 */

	fl->pointers[fl->count] = XM_INVALID_PTR;	/* Prevent accidental reuse */
	xfl_count_decreased(fl, TRUE);
}

/**
 * Insert address in the free list.
 *
 * @param fl	the freelist bucket
 * @param p		address of the block to insert
 * @param burst	whether we're in a burst insertion mode
 */
static void
xfl_insert(struct xfreelist *fl, void *p, bool burst)
{
	size_t idx;
	bool sorted;

	/*
	 * We use a mutex and not a plain spinlock because we can recurse here
	 * through freelist bucket allocations.  A mutex allows us to relock
	 * an object we already locked in the same thread.
	 */

	mutex_lock(&fl->lock);

	g_assert(size_is_non_negative(fl->count));
	g_assert(fl->count <= fl->capacity);

	/*
	 * Since the extension can use the freelist's own blocks, it could
	 * conceivably steal one from this freelist.  It's therefore important
	 * to perform the extension before we compute the proper insertion
	 * index for the block.
	 */

	while (fl->count >= fl->capacity)
		xfl_extend(fl);

	sorted = fl->count == fl->sorted;

	assert_xfl_sorted(fl, 0, fl->sorted, "before %ssorted %s xfl_insert",
		sorted ? "" : "un", burst ? "bursty" : "normal");

	/*
	 * If we're in a burst condition, simply append to the bucket, without
	 * sorting the block.
	 *
	 * Note that we may insert in an unsorted list even outside a burst
	 * insertion condition, meaning the list was not used since the last
	 * time it became unsorted.
	 */

	if G_UNLIKELY(burst) {
		if (sorted) {
			idx = fl->count;		/* Append at the tail */

			/* List still sorted, see if trivial appending keeps it sorted */

			if (0 == idx || 0 < xm_ptr_cmp(p, fl->pointers[idx - 1])) {
				XSTATS_LOCK;
				xstats.freelist_plain_insertions++;
				XSTATS_UNLOCK;
				goto plain_insert;
			}
		}

		sorted = FALSE;		/* Appending will unsort the list */
	}

	if G_LIKELY(sorted) {
		/*
		 * Compute insertion index in the sorted array.
		 *
		 * At the same time, this allows us to make sure we're not dealing with
		 * a duplicate insertion.
		 */

		if G_UNLIKELY((size_t ) -1 != xfl_lookup(fl, p, &idx)) {
			mutex_unlock(&fl->lock);
			t_error_from(_WHERE_,
				"block %p already in free list #%zu (%zu bytes)",
				p, xfl_index(fl), fl->blocksize);
		}
	} else {
		idx = fl->count;		/* Append at the tail */
		XSTATS_LOCK;
		xstats.freelist_unsorted_insertions++;
		XSTATS_UNLOCK;
	}

	g_assert(size_is_non_negative(idx) && idx <= fl->count);

	/*
	 * Shift items if we're not inserting at the last position in the array.
	 */

	g_assert(fl->pointers != NULL);

	if G_LIKELY(idx < fl->count) {
		memmove(&fl->pointers[idx + 1], &fl->pointers[idx],
			(fl->count - idx) * sizeof(fl->pointers[0]));
	}

plain_insert:

	G_PREFETCH_W(p);
	G_PREFETCH_W(&fl->lock);

	fl->count++;
	if G_LIKELY(sorted)
		fl->sorted++;
	fl->pointers[idx] = p;
	XSTATS_LOCK;
	xstats.freelist_blocks++;
	xstats.freelist_memory += fl->blocksize;
	XSTATS_UNLOCK;

	assert_xfl_sorted(fl, 0, fl->sorted, "after %ssorted %s xfl_insert @ %zu",
		sorted ? "" : "un", burst ? "bursty" : "normal", idx);

	/*
	 * Set corresponding bit if this is the first block inserted in the list.
	 */

	if G_UNLIKELY(1 == fl->count) {
		size_t fidx = xfl_index(fl);

		spinlock(&xfreebits_slk);
		bit_array_set(xfreebits, fidx);

		/*
		 * Update maximum bucket index.
		 */

		if (xfreelist_maxidx < fidx) {
			xfreelist_maxidx = fidx;
			g_assert(xfreelist_maxidx < G_N_ELEMENTS(xfreelist));

			if (xmalloc_debugging(1)) {
				t_debug("XM max frelist index increased to %zu",
					xfreelist_maxidx);
			}
		}
		spinunlock(&xfreebits_slk);
	}

	/*
	 * To detect freelist corruptions, write the size of the block at the
	 * beginning of the block itself.
	 */

	*(size_t *) p = fl->blocksize;

	if (xmalloc_debugging(2)) {
		t_debug("XM inserted block %p in %sfree list #%zu (%zu bytes)",
			p, fl->sorted != fl->count ? "unsorted " : "",
			xfl_index(fl), fl->blocksize);
	}

	mutex_unlock(&fl->lock);	/* Issues final memory barrier */
}

/**
 * Initialize freelist buckets once.
 */
static G_GNUC_COLD void
xmalloc_freelist_init_once(void)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];

		fl->blocksize = xfl_block_size_idx(i);
		mutex_init(&fl->lock);

		g_assert_log(xfl_find_freelist_index(fl->blocksize) == i,
			"i=%zu, blocksize=%zu, inverted_index=%zu",
			i, fl->blocksize, xfl_find_freelist_index(fl->blocksize));

		g_assert(0 == fl->count);	/* Cannot be used already */
	}

	for (i = 0; i < XMALLOC_CHUNKHEAD_COUNT; i++) {
		size_t j;

		for (j = 0; j < XM_THREAD_COUNT; j++) {
			struct xchunkhead *ch = &xchunkhead[i][j];

			ch->blocksize = xch_block_size_idx(i);
			elist_init(&ch->list, offsetof(struct xchunk, xc_lnk));
		}
	}

	for (i = 0; i < G_N_ELEMENTS(xcross); i++) {
		struct xcross *xcr = &xcross[i];
		spinlock_init(&xcr->lock);
	}

	/*
	 * Split information is computed once and is required information as soon
	 * as the freelist is in use, to be able to handle freelist insertions.
	 */

	xmalloc_split_setup();
}

/**
 * Initial setup of the free list that cannot be conveniently initialized
 * by static declaration.
 */
static G_GNUC_COLD void
xmalloc_freelist_setup(void)
{
	once_flag_run(&xmalloc_freelist_inited, xmalloc_freelist_init_once);

	/*
	 * If the address space is not growing in the same direction as the
	 * initial default, we have to resort all the buckets.
	 */

	if (!xmalloc_grows_up) {
		size_t i;

		for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
			struct xfreelist *fl = &xfreelist[i];

			mutex_lock_hidden(&fl->lock);

			/* Sort with xqsort() to guarantee no memory allocation */

			if (0 != fl->count) {
				void **ary = fl->pointers;
				xqsort(ary, fl->count, sizeof ary[0], xfl_ptr_cmp);
				fl->sorted = fl->count;
			}

			mutex_unlock_hidden(&fl->lock);
		}
	}
}

/**
 * Solve split of block into two that exactly fit the freelist discrete
 * bucket sizes.
 *
 * @param len		length of block
 * @param larger	where larger block size is written
 * @param smaller	where smaller block size is written
 *
 * @return TRUE if we managed to find a solution, FALSE if block cannot
 * be split into two blocks.
 */
static bool
xmalloc_split_solve(size_t len, ushort *larger, ushort *smaller)
{
	size_t mid = len / 2;
	size_t l;

	for (l = len - XMALLOC_ALIGNBYTES; l >= mid; l -= XMALLOC_ALIGNBYTES) {
		size_t s = len - l;
		if (s < XMALLOC_SPLIT_MIN)
			continue;
		if (
			xmalloc_round_blocksize(l) == l &&
			xmalloc_round_blocksize(s) == s)
		{
			*larger = l;
			*smaller = s;
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * Initialize the xsplit[] array giving the block split sizes.
 */
static void
xmalloc_split_setup(void)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(xsplit); i++) {
		struct xsplit *xs = &xsplit[i];
		size_t len = (i + 1) * XMALLOC_ALIGNBYTES;

		if (len < XMALLOC_SPLIT_MIN)
			continue;

		/*
		 * We need to be able to split all blocks greater than
		 * XMALLOC_SPLIT_MIN bytes into two smaller blocks that
		 * fit our discrete bucket sizes.
		 */

		if (xmalloc_round_blocksize(len) == len) {
			xs->larger = len;
		} else {
			if (!xmalloc_split_solve(len, &xs->larger, &xs->smaller))
				t_error("xmalloc() cannot split %zu-byte blocks into 2 blocks",
					len);
		}
	}
}

/**
 * Fetch block splitting information for a given length.
 */
static struct xsplit *
xmalloc_split_info(const size_t len)
{
	g_assert(size_is_positive(len));
	g_assert(len >= XMALLOC_SPLIT_MIN);

	return &xsplit[(len - XMALLOC_ALIGNBYTES) / XMALLOC_ALIGNBYTES];
}

/**
 * Select block to allocate from freelist.
 */
static void *
xfl_select(struct xfreelist *fl)
{
	void *p;

	assert_mutex_is_owned(&fl->lock);
	g_assert(fl->count != 0);

	/*
	 * Depending on the way the virtual memory grows, we pick the largest
	 * or the smallest address to try to aggregate all the objects at
	 * the "base" of the memory space.
	 *
	 * Until the VMM layer is up, xmalloc_grows_up will be TRUE.  This is
	 * consistent with the fact that the heap always grows upwards on
	 * UNIX machines.
	 *
	 * The xm_ptr_cmp() routine makes sure the addresses we want to serve
	 * first are at the end of the array.
	 *
	 * When the array is unsorted, we can pick an address released recently
	 * and which was not sorted. It's not a problem as far as allocation goes,
	 * but we're always better off in the long term to allocate addresses
	 * at the beginning of the VM space, so we're checking to see whether
	 * we could be better off by selecting another address.
	 */

	p = fl->pointers[fl->count - 1];

	if G_UNLIKELY(fl->count != fl->sorted) {
		void **ary = fl->pointers;
		size_t i = fl->count - 1, j = (fl->sorted != 0) ? fl->sorted - 1 : 0;
		void *q = ary[j];

		g_assert(fl->sorted < fl->count);

		/*
		 * If the last sorted address makes up a better choice, select
		 * it instead, swapping the items and updating the sorted index
		 * if needed.
		 */

		if (xm_ptr_cmp(p, q) < 0) {
			ary[j] = p;
			ary[i] = q;

			if (j != 0 && xm_ptr_cmp(ary[j - 1], p) > 0)
				fl->sorted = j;

			p = q;		/* Will use this pointer instead */
			XSTATS_LOCK;
			xstats.freelist_sorted_superseding++;
			XSTATS_UNLOCK;
		}
	}

	return p;
}

/**
 * Look for a free block in the freelist for holding ``len'' bytes.
 *
 * @param len		the desired block length (including our overhead)
 * @param exclude	the bucket we need to skip
 * @param flp		if not-NULL, outputs the freelist the block was found in
 *
 * @return the block address we found, NULL if nothing was found.
 *
 * @attention
 * The block is not removed from the freelist and the address returned is not
 * the user address but the physical start of the block.
 * If the block is found, the corresponding bucket is mutex-locked.
 */
static void *
xmalloc_freelist_lookup(size_t len, const struct xfreelist *exclude,
	struct xfreelist **flp)
{
	size_t i;
	void *p = NULL;

	/*
	 * Compute the smallest freelist where we can find a suitable block,
	 * where we'll start looking, then iterate upwards to larger freelists.
	 */

	for (i = xfl_find_freelist_index(len); i <= xfreelist_maxidx; i++) {
		struct xfreelist *fl = &xfreelist[i];

		g_assert(size_is_non_negative(fl->count));

		if G_UNLIKELY(exclude == fl)
			continue;

		/*
		 * To avoid possible deadlocks, skip bucket if we cannot lock it.
		 */

		if (0 == fl->count || !mutex_trylock(&fl->lock))
			continue;

		if (0 == fl->count) {
			mutex_unlock(&fl->lock);
			continue;
		}

		*flp = fl;
		p = xfl_select(fl);

		if (xmalloc_debugging(8)) {
			t_debug("XM selected block %p in bucket %p "
				"(#%zu, %zu bytes) for %zu bytes",
				p, (void *) fl, i, fl->blocksize, len);
		}

		assert_valid_freelist_pointer(fl, p);
		break;
	}

	/*
	 * If block was found, mutex on fl->lock is held and will be cleared
	 * by xfl_remove_selected().
	 */

	return p;
}

/**
 * Coalesce block initially given by the values pointed at by ``base'' and 
 * ``len'' with contiguous blocks that are present in the freelists.
 *
 * The resulting block is not part of any freelist, just as the initial block
 * must not be part of any.
 *
 * The flags control whether we want to coalesce with the blocks before,
 * with the blocks after or with both.
 *
 * @return TRUE if coalescing did occur, updating ``base_ptr'' and ``len_ptr''
 * to reflect the coalesced block..
 */
static G_GNUC_HOT bool
xmalloc_freelist_coalesce(void **base_ptr, size_t *len_ptr,
	bool burst, uint32 flags)
{
	size_t smallsize;
	size_t i, j;
	void *base = *base_ptr;
	size_t len = *len_ptr;
	void *end;
	bool coalesced = FALSE;

	smallsize = xmalloc_pagesize / 2;

	/*
	 * When "smart" coalescing is requested and we're facing a block which
	 * can be put directly in the freelist (i.e. there is no special splitting
	 * to do as its size fits one of the existing buckets), look at whether
	 * it is smart to attempt any coalescing.
	 */

	if ((flags & XM_COALESCE_SMART) && xmalloc_round_blocksize(len) == len) {
		size_t idx;
		struct xfreelist *fl;

		/*
		 * Within a burst freeing, don't attempt coalescing if size is small.
		 */

		if G_UNLIKELY(burst) {
			if (len < smallsize) {
				XSTATS_LOCK;
				xstats.freelist_coalescing_ignore_burst++;
				XSTATS_UNLOCK;
				return FALSE;
			}
		}

		/*
		 * If block is larger than the maximum size of blocks we handle from
		 * the freelist, don't attempt any coalescing.
		 */

		if G_UNLIKELY(len >= XMALLOC_MAXSIZE) {
			if (xmalloc_debugging(6)) {
				t_debug("XM ignoring coalescing request for %zu-byte %p:"
					" would be larger than maxsize", len, base);
			}
			XSTATS_LOCK;
			xstats.freelist_coalescing_ignored++;
			XSTATS_UNLOCK;
			return FALSE;
		}

		idx = xfl_find_freelist_index(len);
		fl = &xfreelist[idx];

		/*
		 * If there are little blocks in the list, there's no need to coalesce.
		 * We want to keep a few blocks in each list for quicker allocations.
		 * Avoiding coalescing may mean avoiding further splitting if we have
		 * to re-allocate a block of the same size soon.
		 *
		 * However, if the length of the block is nearing a page size, we want
		 * to always attempt coalescing to be able to free up memory as soon
		 * as we can re-assemble a full page.
		 */

		if (fl->count < XMALLOC_BUCKET_MINCOUNT && len < smallsize) {
			if (xmalloc_debugging(6)) {
				t_debug("XM ignoring coalescing request for %zu-byte %p:"
					" target free list #%zu has only %zu item%s",
					len, base, idx, fl->count, 1 == fl->count ? "" : "s");
			}
			XSTATS_LOCK;
			xstats.freelist_coalescing_ignored++;
			XSTATS_UNLOCK;
			return FALSE;
		}
	}

	/*
	 * Since every block inserted in the freelist is not fully coalesced
	 * because we have to respect the discrete set of allowed block size,
	 * we have to perform coalescing iteratively in the hope of being able
	 * to recreate a block spanning over full pages that we can then free.
	 */

	end = ptr_add_offset(base, len);

	/*
	 * Look for a match before.
	 */

	for (i = 0; flags & XM_COALESCE_BEFORE; i++) {
		bool found_match = FALSE;

		for (j = 0; j <= xfreelist_maxidx; j++) {
			struct xfreelist *fl = &xfreelist[j];
			size_t blksize;
			void *before;
			size_t idx;

			if (0 == fl->count || !mutex_trylock(&fl->lock))
				continue;

			blksize = fl->blocksize;
			before = ptr_add_offset(base, -blksize);

			idx = xfl_lookup(fl, before, NULL);

			if G_UNLIKELY((size_t) -1 != idx) {
				if (xmalloc_debugging(6)) {
					t_debug("XM iter #%zu, "
						"coalescing previous %zu-byte [%p, %p[ "
						"from list #%zu with %zu-byte [%p, %p[",
						i, blksize, before, ptr_add_offset(before, blksize),
						j, ptr_diff(end, base), base, end);
				}

				xfl_delete_slot(fl, idx);
				base = before;
				found_match = coalesced = TRUE;
			}

			mutex_unlock(&fl->lock);
		}

		if (!found_match)
			break;
	}

	/*
	 * Look for a match after.
	 */

	for (i = 0; flags & XM_COALESCE_AFTER; i++) {
		bool found_match = FALSE;

		for (j = 0; j <= xfreelist_maxidx ; j++) {
			struct xfreelist *fl = &xfreelist[j];
			size_t idx;

			if (0 == fl->count || !mutex_trylock(&fl->lock))
				continue;

			idx = xfl_lookup(fl, end, NULL);

			if G_UNLIKELY((size_t) -1 != idx) {
				size_t blksize = fl->blocksize;

				if (xmalloc_debugging(6)) {
					t_debug("XM iter #%zu, "
						"coalescing next %zu-byte [%p, %p[ "
						"from list #%zu with %zu-byte [%p, %p[",
						i, blksize, end, ptr_add_offset(end, blksize),
						j, ptr_diff(end, base), base, end);
				}

				xfl_delete_slot(fl, idx);
				end = ptr_add_offset(end, blksize);
				found_match = coalesced = TRUE;
			}

			mutex_unlock(&fl->lock);
		}

		if (!found_match)
			break;
	}

	/*
	 * Update information for caller if we have coalesced something.
	 */

	if G_UNLIKELY(coalesced) {
		*base_ptr = base;
		*len_ptr = ptr_diff(end, base);
		XSTATS_LOCK;
		xstats.freelist_coalescing_done++;
		XSTATS_UNLOCK;
	} else {
		XSTATS_LOCK;
		xstats.freelist_coalescing_failed++;
		XSTATS_UNLOCK;
	}

	return coalesced;
}

/**
 * Free whole VMM pages embedded in the block, returning the fragments at the
 * head and the tail of the blocks.
 *
 * @param p			the start of the block
 * @param len		length of the block, in bytes
 * @param head		where start of leading fragment is written (``p'' usually)
 * @param head_len	where length of leading fragment is written
 * @param tail		where start of trailing fragment is written
 * @param tail_len	where length of trailing fragment is written
 *
 * @return TRUE if pages were freed and output parameters updated.
 */
static bool
xmalloc_free_pages(void *p, size_t len,
	void **head, size_t *head_len,
	void **tail, size_t *tail_len)
{
	void *page;
	const void *end;
	const void *vend;
	size_t plen, hlen, tlen;

	page = deconstify_pointer(vmm_page_start(p));
	end = ptr_add_offset(p, len);

	if (ptr_cmp(page, p) < 0) {
		page = ptr_add_offset(page, xmalloc_pagesize);
		if (ptr_cmp(page, end) >= 0)
			return FALSE;		/* Block is fully held in one VMM page */
	}

	/*
	 * The first VMM page in the block starts at ``page''.
	 * Look how many contiguous pages we have fully enclosed in the block.
	 */

	vend = vmm_page_start(end);

	g_assert(ptr_cmp(page, vend) <= 0);

	if (vend == page)
		return FALSE;			/* Block partially spread among two VMM pages */

	/*
	 * If head or tail falls below the minimum block size, don't free the
	 * page as we won't be able to put the remains back to the freelist.
	 */

	hlen = ptr_diff(page, p);
	if (hlen != 0 && hlen < XMALLOC_SPLIT_MIN)
		return FALSE;

	tlen = ptr_diff(end, vend);
	if (tlen != 0 && tlen < XMALLOC_SPLIT_MIN)
		return FALSE;

	*head = deconstify_pointer(p);
	*head_len = hlen;
	*tail = deconstify_pointer(vend);
	*tail_len = tlen;

	/*
	 * We can free the zone [page, vend[.
	 */

	if (xmalloc_debugging(1)) {
		t_debug(
			"XM releasing VMM [%p, %p[ (%zu bytes) within [%p, %p[ (%zu bytes)",
			page, vend, ptr_diff(vend, page), p, end, len);
	}

	plen = ptr_diff(vend, page);
	vmm_core_free(page, plen);

	XSTATS_LOCK;
	xstats.free_vmm_core++;
	xstats.vmm_freed_pages += vmm_page_count(plen);
	XSTATS_UNLOCK;

	return TRUE;
}

/**
 * Insert block in free list, with optional block coalescing.
 *
 * @param p			the address of the block
 * @param len		the physical length of the block
 * @param burst		if TRUE, we're within a burst of freelist insertions
 * @param coalesce	block coalescing flags
 */
static void
xmalloc_freelist_insert(void *p, size_t len, bool burst, uint32 coalesce)
{
	struct xfreelist *fl;

	/*
	 * First attempt to coalesce memory as much as possible if requested.
	 */

	XSTATS_LOCK;
	xstats.freelist_insertions++;
	XSTATS_UNLOCK;

	if (coalesce) {
		xmalloc_freelist_coalesce(&p, &len, burst, coalesce);
	} else {
		XSTATS_LOCK;
		xstats.freelist_insertions_no_coalescing++;
		XSTATS_UNLOCK;
	}

	/*
	 * Chunks of memory larger than XMALLOC_MAXSIZE need to be broken up
	 * into smaller blocks.  This can happen when we're putting heap memory
	 * back into the free list, or when a block larger than a page size is
	 * actually spread over two distinct VM pages.
	 */

	if G_UNLIKELY(len > XMALLOC_MAXSIZE) {
		if (xmalloc_debugging(3)) {
			t_debug("XM breaking up %s block %p (%zu bytes)",
				xmalloc_isheap(p, len) ? "heap" : "VMM", p, len);
		}

		while (len > XMALLOC_MAXSIZE) {
			fl = &xfreelist[XMALLOC_FREELIST_COUNT - 1];

			/*
			 * Ensure we're not left with a block whose size cannot
			 * be inserted.
			 */

			if G_UNLIKELY(len - fl->blocksize < XMALLOC_SPLIT_MIN) {
				fl = &xfreelist[XMALLOC_FREELIST_COUNT - 2];
			}

			xfl_insert(fl, p, burst);
			p = ptr_add_offset(p, fl->blocksize);
			len -= fl->blocksize;
		}

		/* FALL THROUGH */
	}

	/*
	 * Chunks larger than XMALLOC_FACTOR_MAXSIZE must be broken up if
	 * they don't have a proper supported length.
	 */

	if (len > XMALLOC_FACTOR_MAXSIZE) {
		struct xsplit *xs = xmalloc_split_info(len);

		/* Every size can be split as long as it is properly aligned */

		g_assert(xmalloc_round(len) == len);
		g_assert_log(0 != xs->larger, "len=%zu => smaller=%u, larger=%u",
			len, xs->smaller, xs->larger);

		if (0 != xs->smaller && xmalloc_debugging(3)) {
			t_debug("XM breaking up %s block %p (%zu bytes) into (%u, %u)",
				xmalloc_isheap(p, len) ? "heap" : "VMM", p, len,
				xs->larger, xs->smaller);
		}

		if (0 != xs->smaller) {
			fl = xfl_find_freelist(xs->smaller);
			xfl_insert(fl, p, burst);
			p = ptr_add_offset(p, xs->smaller);
			len -= xs->smaller;
		}

		/* FALL THROUGH */
	}

	fl = xfl_find_freelist(len);
	xfl_insert(fl, p, burst);
}

/**
 * Add memory chunk to free list, possibly releasing core.
 */
static void
xmalloc_freelist_add(void *p, size_t len, uint32 coalesce)
{
	static time_t last;
	static size_t calls;
	time_t now;
	bool coalesced = FALSE;
	bool is_heap, in_burst = FALSE;

	/*
	 * Detect bursts of xfree() calls because coalescing plus insertion
	 * in the sorted buckets can quickly raise the time spent since the
	 * algorithmic complexity becomes O(n^2).
	 *
	 * When we're dealing with less than XM_FREELIST_THRESH additions
	 * per second, we don't consider we're in a xfree() burst.
	 *
	 * Within a burst condition, we're allowing coalescing but insertions
	 * in the freelist are mere appending (no sorting).
	 * Sorting will be deferred up to the moment where we need to lookup
	 * an item in the freelist.
	 */

	now = tm_time();

	if G_UNLIKELY(now != last) {
		calls = 1;
		last = now;
	} else {
		calls++;
		if G_UNLIKELY(calls > XM_FREELIST_THRESH) {
			in_burst = TRUE;
			XSTATS_LOCK;
			xstats.freelist_burst_insertions++;
			if G_UNLIKELY(calls == XM_FREELIST_THRESH + 1)
				xstats.freelist_bursts++;
			XSTATS_UNLOCK;
		}
	}

	/*
	 * First attempt to coalesce memory as much as possible if requested.
	 *
	 * When dealing with blocks that are page-aligned, whose size is
	 * exactly a multiple of system pages and were allocated from the
	 * VMM layer, it would be harmful to attempt coalescing: we want to
	 * free those VMM pages right away.
	 */

	is_heap = xmalloc_isheap(p, len);
	if G_UNLIKELY(is_heap)
		coalesce &= ~XM_COALESCE_SMART;		/* Force coalescing within heap */

	if (coalesce) {
		if (
			vmm_page_start(p) != p ||
			round_pagesize(len) != len ||
			is_heap
		) {
			coalesced = xmalloc_freelist_coalesce(&p, &len, in_burst, coalesce);
		} else {
			if (xmalloc_debugging(4)) {
				t_debug(
					"XM not attempting coalescing of %zu-byte %s region at %p",
					len, is_heap ? "heap" : "VMM", p);
			}
			XSTATS_LOCK;
			xstats.freelist_coalescing_ignore_vmm++;
			XSTATS_UNLOCK;
		}
	}

	/*
	 * If we're dealing with heap memory, attempt to free it.
	 *
	 * If we're dealing with memory from the VMM layer and we got more than
	 * a page worth of data, release the empty pages to the system and put
	 * back the leading and trailing fragments to the free list.
	 */

	if G_UNLIKELY(is_heap) {
		/* Heap memory */
		if (xmalloc_freecore(p, len)) {
			if (xmalloc_debugging(1)) {
				t_debug("XM %zu bytes of heap released at %p, "
					"not adding to free list", len, p);
			}
			return;
		}
	} else {
		void *head;
		void *tail;
		size_t head_len, tail_len;

		/* Memory from the VMM layer */

		if (xmalloc_free_pages(p, len, &head, &head_len, &tail, &tail_len)) {
			if (xmalloc_debugging(3)) {
				if (head_len != 0 || tail_len != 0) {
					size_t npages = vmm_page_count(len);

					t_debug("XM freed %sembedded %zu page%s, "
						"%s head, %s tail",
						coalesced ? "coalesced " : "",
						npages, 1 == npages ? "" : "s",
						head_len != 0 ? "has" : "no",
						tail_len != 0 ? "has" : "no");
				} else {
					t_debug("XM freed %swhole %zu-byte region at %p",
						coalesced ? "coalesced " : "", len, p);
				}
			}

			if (coalesced) {
				XSTATS_LOCK;
				xstats.free_coalesced_vmm++;
				XSTATS_UNLOCK;
			}

			/*
			 * Head and tail are smaller than a page size but could still be
			 * larger than XMALLOC_MAXSIZE.
			 */

			if (head_len != 0) {
				g_assert(head == p);
				if (xmalloc_debugging(4)) {
					t_debug("XM freeing head of %p at %p (%zu bytes)",
						p, head, head_len);
				}
				if (coalesce & XM_COALESCE_BEFORE) {
					/* Already coalesced */
					xmalloc_freelist_insert(head, head_len,
						in_burst, XM_COALESCE_NONE);
				} else {
					/* Maybe there is enough before to free core again? */
					calls--;	/* Self-recursion, does not count */
					xmalloc_freelist_add(head, head_len, XM_COALESCE_BEFORE);
				}
			}
			if (tail_len != 0) {
				g_assert(
					ptr_add_offset(tail, tail_len) == ptr_add_offset(p, len));
				if (xmalloc_debugging(4)) {
					t_debug("XM freeing tail of %p at %p (%zu bytes)",
						p, tail, tail_len);
				}
				if (coalesce & XM_COALESCE_AFTER) {
					/* Already coalesced */
					xmalloc_freelist_insert(tail, tail_len,
						in_burst, XM_COALESCE_NONE);
				} else {
					/* Maybe there is enough after to free core again? */
					calls--;	/* Self-recursion, does not count */
					xmalloc_freelist_add(tail, tail_len, XM_COALESCE_AFTER);
				}
			}
			return;
		}
	}

	/*
	 * Fallback for unfreed core memory, or unfreed VMM subspace.
	 *
	 * Insert in freelist, without doing any coalescing since it was attempted
	 * at the beginning if requested, so we already attempted to coalesce
	 * as much as possible.
	 */

	xmalloc_freelist_insert(p, len, in_burst, XM_COALESCE_NONE);
}

/**
 * Grab block from selected freelist, known to hold available ones of at
 * least the required length.
 *
 * The block is possibly split, if needed, and the final allocated size is
 * returned in ``allocated''.
 *
 * @param fl		the freelist with free blocks of at least ``len'' bytes
 * @param block		the selected block from the freelist
 * @param length	the desired block length
 * @param split		whether we can split the block
 * @param allocated where we return the allocated block size (after split).
 *
 * @return adjusted pointer
 */
static void *
xmalloc_freelist_grab(struct xfreelist *fl,
	void *block, size_t length, bool split, size_t *allocated)
{
	size_t blksize = fl->blocksize;
	size_t len = length;
	void *p = block;

	g_assert(blksize >= len);

	xfl_remove_selected(fl, block);

	/*
	 * If the block is larger than the size we requested, the remainder
	 * is put back into the free list.
	 */

	if (len != blksize) {
		void *sp;			/* Split pointer */
		size_t split_len;

		split_len = blksize - len;

		if (split && xmalloc_should_split(blksize, len)) {
			XSTATS_LOCK;
			xstats.freelist_split++;
			XSTATS_UNLOCK;
			if (xmalloc_grows_up) {
				/* Split the end of the block */
				sp = ptr_add_offset(p, len);
			} else {
				/* Split the head of the block */
				sp = p;
				p = ptr_add_offset(p, split_len);
			}

			if (xmalloc_debugging(3)) {
				t_debug("XM splitting large %zu-byte block at %p"
					" (need only %zu bytes: returning %zu bytes at %p)",
					blksize, p, len, split_len, sp);
			}

			g_assert(split_len <= XMALLOC_MAXSIZE);

			xmalloc_freelist_insert(sp, split_len, FALSE, XM_COALESCE_NONE);
		} else {
			if (xmalloc_debugging(3)) {
				t_debug("XM NOT splitting %s %zu-byte block at %p"
					" (need only %zu bytes, split of %zu bytes too small)",
					split ? "large" : "(as requested)",
					blksize, p, len, split_len);
			}
			XSTATS_LOCK;
			xstats.freelist_nosplit++;
			XSTATS_UNLOCK;
			len = blksize;		/* Wasting some trailing bytes */
		}
	}

	*allocated = len;

	return p;
}

/**
 * Allocate a block from the freelist, of given physical length.
 *
 * @param len		the desired block length (including our overhead)
 * @param allocated	the length of the allocated block is returned there
 *
 * @return the block address we found, NULL if nothing was found.
 * The returned block is removed from the freelist.  When allocated, the
 * size of the block is returned via ``allocated''.
 */
static void *
xmalloc_freelist_alloc(size_t len, size_t *allocated)
{
	struct xfreelist *fl;
	void *p;

	p = xmalloc_freelist_lookup(len, NULL, &fl);

	if (p != NULL)
		p = xmalloc_freelist_grab(fl, p, len, TRUE, allocated);

	return p;
}

/**
 * Allocate a block from specified freelist, of given physical length.
 *
 * @param len		the desired block length (including our overhead)
 * @param allocated	the length of the allocated block is returned there
 *
 * @return the block address we found, NULL if nothing was found.
 * The returned block is removed from the freelist.  When allocated, the
 * size of the block is returned via ``allocated''.
 */
static void *
xmalloc_one_freelist_alloc(struct xfreelist *fl, size_t len, size_t *allocated)
{
	void *p;

	if (0 == fl->count)
		return NULL;

	mutex_lock(&fl->lock);

	if (0 == fl->count) {
		mutex_unlock(&fl->lock);
		return NULL;
	}

	p = xfl_select(fl);

	if (xmalloc_debugging(8)) {
		t_debug("XM selected block %p in requested bucket %p "
			"(#%zu, %zu bytes) for %zu bytes",
			p, (void *) fl, xfl_index(fl), fl->blocksize, len);
	}

	assert_valid_freelist_pointer(fl, p);

	/* Mutex released via xmalloc_freelist_grab() */

	return xmalloc_freelist_grab(fl, p, len, FALSE, allocated);
}

/**
 * Setup allocated block.
 *
 * @return the user pointer within the physical block.
 */
static void *
xmalloc_block_setup(void *p, size_t len)
{
	struct xheader *xh = p;

	if (xmalloc_debugging(9)) {
		t_debug("XM setup allocated %zu-byte block at %p (user %p)",
			len, p, ptr_add_offset(p, XHEADER_SIZE));
	}

	xh->length = len;
	return ptr_add_offset(p, XHEADER_SIZE);
}

/**
 * Setup walloc()ed block.
 *
 * @return the user pointer within the physical block.
 */
static void *
xmalloc_wsetup(void *p, size_t len)
{
	struct xheader *xh = p;

	if (xmalloc_debugging(9)) {
		t_debug("XM setup walloc()ed %zu-byte block at %p (user %p)",
			len, p, ptr_add_offset(p, XHEADER_SIZE));
	}

	/*
	 * Flag length specially so that we know this is a block allocated
	 * via walloc(), to be able to handle freeing and reallocations.
	 */

	g_assert(len <= WALLOC_MAX);
	g_assert(0 == (len & XMALLOC_MAGIC_FLAG));

	xh->length = (unsigned) len | XMALLOC_WALLOC_MAGIC;
	return ptr_add_offset(p, XHEADER_SIZE);
}

/**
 * Is xmalloc() remapped to malloc()?
 */
bool
xmalloc_is_malloc(void)
{
#ifdef XMALLOC_IS_MALLOC
	return TRUE;
#else
	return FALSE;
#endif
}

/**
 * Validate that pointer is the start of what appears to be a valid chunk.
 */
static bool
xmalloc_chunk_is_valid(const struct xchunk *xck)
{
	const struct xchunkhead *ch;

	if (XCHUNK_MAGIC != xck->magic)
		return FALSE;

	if (0 == xck->xc_size || xck->xc_size > XM_THREAD_MAXSIZE)
		return FALSE;

	if (xmalloc_round(xck->xc_size) != xck->xc_size)
		return FALSE;

	if (xck->xc_stid >= XM_THREAD_COUNT)
		return FALSE;

	if (xck->xc_count >= xck->xc_capacity)
		return FALSE;

	ch = &xchunkhead[xch_find_chunkhead_index(xck->xc_size)][xck->xc_stid];
	if (xck->xc_head != ch)
		return FALSE;

	if (xck->xc_capacity != (xmalloc_pagesize - sizeof *xck) / xck->xc_size)
		return FALSE;

	if (xck->xc_free_offset != 0 && xck->xc_free_offset < sizeof *xck)
		return FALSE;

	if (xck->xc_free_offset > xmalloc_pagesize - xck->xc_size)
		return FALSE;

	return TRUE;
}

/**
 * Cram a new chunk, linking each free block and making sure the first block
 * is the head of that list.
 */
static void
xmalloc_chunk_cram(struct xchunk *xck)
{
	void *start = ptr_add_offset(xck, xck->xc_free_offset);
	size_t size = xck->xc_size;
	void *last = ptr_add_offset(xck, xmalloc_pagesize - size);
	char *p = start, **next;

	g_assert(size < xmalloc_pagesize);

	while (ptr_cmp(&p[size], last) <= 0) {
		next = cast_to_void_ptr(p);
		p = *next = &p[size];
	}
	next = cast_to_void_ptr(p);
	*next = NULL;
}

/**
 * Allocate a new thread-specific chunk.
 */
static struct xchunk *
xmalloc_chunk_allocate(const struct xchunkhead *ch, unsigned stid)
{
	struct xchunk *xck;
	unsigned capacity, offset;

	/*
	 * Each allocated thread-specific chunk looks like this:
	 *
	 *       +------------------+
	 *       | Chunk header     | <---- struct xchunk
	 *       +------------------+
	 *       | Padding          |
	 *       +------------------+ ^
	 *       | Aligned block #1 | |
	 *       +------------------+ |
	 *       | Aligned block #2 | |
	 *       +------------------+ | Evenly split range
	 *       |..................| |
	 *       |..................| |
	 *       |..................| |
	 *       +------------------+ |
	 *       | Aligned block #n | |
	 *       +------------------+ v
	 * 
	 * Compute the offset within the page of the first aligned block,
	 * on its natural alignment boundary (not necessarily a power of 2).
	 */

	capacity = (xmalloc_pagesize - sizeof *xck) / ch->blocksize;
	offset = xmalloc_pagesize - capacity * ch->blocksize;

	xck = vmm_core_alloc(xmalloc_pagesize);
	xck->magic = XCHUNK_MAGIC;
	xck->xc_head = deconstify_pointer(ch);
	xck->xc_size = ch->blocksize;
	xck->xc_stid = stid;
	xck->xc_capacity = xck->xc_count = capacity;
	xck->xc_free_offset = offset;

	xmalloc_chunk_cram(xck);
	XSTATS_LOCK;
	xstats.vmm_thread_pages++;
	XSTATS_UNLOCK;

	return xck;
}

/**
 * Find chunk from which we can allocate a block.
 *
 * @return the address of a chunk with at least one free block, NULL if we
 * want to prevent allocation from the thread-specific pool.
 */
static struct xchunk *
xmalloc_chunk_find(struct xchunkhead *ch, unsigned stid)
{
	link_t *lk;
	struct xchunk *xck;

	for (lk = elist_first(&ch->list); lk != NULL; lk = elist_next(lk)) {
		xck = elist_data(&ch->list, lk);

		xchunk_check(xck);

		if (0 != xck->xc_count)
			goto found;
	}

	/*
	 * No free chunk, allocate a new one and move it to the head of the list.
	 *
	 * If the thread-pool is shared, it is not worth continuing to expand
	 * the thread-specific pool for sizes where we lose more from the memory
	 * alignment constraints in the chunk than the typical overhead we stuff
	 * at the front of each block: prefer regular allocations.
	 */

	if G_UNLIKELY(ch->shared) {
		unsigned capacity, overhead;

		/*
		 * If we no longer have any chunks, redirect to the main freelist.
		 * Regardless of the possible per-block overhead saving that this
		 * thread-specific pool could provide, we can nonetheless fragment
		 * the space with some sub-optimal allocation patterns.  Avoid it.
		 */

		if (0 == elist_count(&ch->list))
			return NULL;

		/*
		 * The overhead of each chunk is the largest between the size of
		 * the chunk overhead structure and the block size, due to alignment
		 * of the first available block.
		 */

		capacity = (xmalloc_pagesize - sizeof *xck) / ch->blocksize;
		overhead = MAX(sizeof *xck, ch->blocksize);

		if (overhead / capacity >= XHEADER_SIZE) {
			if (xmalloc_debugging(1)) {
				t_debug("XM not creating new %zu-byte blocks for thread #%u: "
					"shared blocks have %F bytes overhead (%u per page), "
					"currently has %zu chunk%s",
					ch->blocksize, stid, (double) overhead / capacity,
					capacity, elist_count(&ch->list),
					1 == elist_count(&ch->list) ? "" : "s");
			}
			return NULL;
		}

		if (xmalloc_debugging(1)) {
			t_debug("XM still creating new %zu-byte blocks for thread #%u: "
				"shared blocks have only %F bytes overhead (%u per page)",
				ch->blocksize, stid, (double) overhead / capacity,
				capacity);
		}
	}

	xck = xmalloc_chunk_allocate(ch, stid);
	elist_prepend(&ch->list, xck);

	if (xmalloc_debugging(1)) {
		t_debug("XM new chunk #%zu of %zu-byte blocks for thread #%u at %p",
			elist_count(&ch->list) - 1, ch->blocksize, stid, xck);
	}

	return xck;

found:
	/*
	 * Move the selected chunk to the head of the list.
	 */

	if (lk != elist_first(&ch->list)) {
		elist_link_remove(&ch->list, lk);
		elist_link_prepend(&ch->list, lk);
	}

	return xck;
}

/**
 * Allocate a block from given chunk pool.
 *
 * The pool is thread-specific and determines the block size.
 *
 * @return allocated block address, NULL if we cannot allocate from the
 * thread-specific pool.
 */
static void *
xmalloc_chunkhead_alloc(struct xchunkhead *ch, unsigned stid)
{
	struct xchunk *xck;
	void *p;
	void *next;

	xck = xmalloc_chunk_find(ch, stid);

	if G_UNLIKELY(NULL == xck)
		return NULL;

	xchunk_check(xck);
	g_assert(uint_is_positive(xck->xc_count));
	g_assert(xck->xc_count <= xck->xc_capacity);
	g_assert(xck->xc_free_offset < xmalloc_pagesize);
	g_assert(xck->xc_stid == stid);

	p = ptr_add_offset(xck, xck->xc_free_offset);
	xck->xc_count--;
	next = *(void **) p;		/* Next free block */
	if (next != NULL) {
		size_t offset = ptr_diff(next, xck);

		g_assert(0 != xck->xc_count);
		g_assert(size_is_positive(offset));
		g_assert(offset < xmalloc_pagesize);

		xck->xc_free_offset = offset;
	} else {
		g_assert(0 == xck->xc_count);

		xck->xc_free_offset = 0;
	}

	return p;
}

/**
 * Return block to thread-private chunk.
 */
static void
xmalloc_chunk_return(struct xchunk *xck, void *p)
{
	XSTATS_LOCK;
	xstats.user_memory -= xck->xc_size;
	xstats.user_blocks--;
	XSTATS_UNLOCK;

	/*
	 * If returning the block makes the whole chunk free, free that chunk.
	 * Otherwise put block back at the head of the chunk's free list.
	 */

	if G_UNLIKELY(xck->xc_capacity == xck->xc_count + 1) {
		struct xchunkhead *ch = xck->xc_head;

		/*
		 * Before freeing the chunk, zero the header part so as to make
		 * sure we will not mistake this for a valid header again.  Simply
		 * zeroing the magic number is not enough here, we want to prevent
		 * mistakes: freeing blocks on a page with an apparently valid header
		 * but which is not a thread-private chunk would corrupt memory.
		 */

		elist_remove(&ch->list, xck);
		ZERO(xck);
		vmm_core_free(xck, xmalloc_pagesize);
		XSTATS_LOCK;
		xstats.vmm_thread_pages--;
		XSTATS_UNLOCK;

		if (xmalloc_debugging(1)) {
			t_debug("XM freed chunk %p of %zu-byte blocks for thread #%u",
				xck, ch->blocksize, thread_small_id());
		}

		/*
		 * As soon as the thread clears all the chunks for a given size,
		 * turn off the "shared" status, giving thread another chance to
		 * grow its pool again in the absence of cross-thread freeing.
		 */

		if (0 == elist_count(&ch->list))
			ch->shared = FALSE;

	} else {
		void *head = 0 == xck->xc_free_offset ? NULL :
			ptr_add_offset(xck, xck->xc_free_offset);

		g_assert(xck->xc_free_offset < xmalloc_pagesize);

		*(void **) p = head;
		xck->xc_free_offset = ptr_diff(p, xck);
		xck->xc_count++;
	}
}

/**
 * Handle freeing of deferred blocks.
 *
 * These blocks are enqueued by other threads to let the thread owning the
 * thread-specific chunk release them to the appropriate chunks using a
 * lock-free path.
 */
static void
xmalloc_thread_free_deferred(unsigned stid)
{
	struct xchunk *xck;
	struct xcross *xcr;
	void *p, *next = NULL;
	size_t n;

	g_assert(size_is_non_negative(stid));
	g_assert(stid < G_N_ELEMENTS(xcross));

	xcr = &xcross[stid];
	spinlock(&xcr->lock);

	if (xmalloc_debugging(0)) {
		s_minidbg("XM starting handling deferred %zu block%s for thread #%u",
			xcr->count, 1 == xcr->count ? "" : "s", stid);
	}

	for (n = 0, p = xcr->head; p != NULL; p = next) {
		next = *(void **) p;
		n++;

		/*
		 * Validation of the chunk was done when block was enqueued, i.e.
		 * we know the pointer belongs to a thread-specific chunk belonging
		 * to this thread.
		 *
		 * Simply do a magic number validation to double-check the list,
		 * and a thread small ID comparison. We know the chunk cannot have
		 * been freed since we were holding some of its blocks in this list!
		 */

		xck = deconstify_pointer(vmm_page_start(p));

		g_assert_log(XCHUNK_MAGIC == xck->magic,
			"p=%p, xck=%p, xck->magic=%d", p, xck, xck->magic);
		g_assert_log(xck->xc_stid == stid,
			"xck->xc_stid=%u, stid=%u", xck->xc_stid, stid);

		if (xmalloc_debugging(5)) {
			s_minidbg("XM handling #%zu deferred %p to chunk %p (count=%u/%u)",
				n, p, xck, xck->xc_count, xck->xc_capacity);
		}

		xmalloc_chunk_return(xck, p);
	}

	g_assert(n == xcr->count);

	xcr->count = 0;
	xcr->head = NULL;

	spinunlock(&xcr->lock);

	if (xmalloc_debugging(0)) {
		t_debug("XM handled delayed free of %zu block%s in thread #%u",
			n, 1 == n ? "" : "s", stid);
	}
}

/**
 * Count chunks used by thread.
 */
static size_t
xmalloc_thread_chunk_count(unsigned stid)
{
	unsigned i;
	size_t count = 0;

	g_assert(uint_is_non_negative(stid));
	g_assert(stid < XM_THREAD_COUNT);

	for (i = 0; i < XMALLOC_CHUNKHEAD_COUNT; i++) {
		count += elist_count(&xchunkhead[i][stid].list);
	}

	return count;
}

/**
 * Called by the thread management layer when a thread is about to start.
 */
void
xmalloc_thread_starting(unsigned stid)
{
	struct xcross *xcr;

	g_assert(uint_is_non_negative(stid));
	g_assert(stid < XM_THREAD_COUNT);

	/*
	 * Mark the thread as "alive" so that freeing of any block belonging to
	 * the thread made by another thread will again be deferred.
	 */

	xcr = &xcross[stid];
	spinlock_hidden(&xcr->lock);
	xcr->dead = FALSE;
	spinunlock_hidden(&xcr->lock);
}

/**
 * Called by the thread management layer when a thread exits.
 */
void
xmalloc_thread_ended(unsigned stid)
{
	struct xcross *xcr;
	size_t i;

	g_assert(uint_is_non_negative(stid));
	g_assert(stid < XM_THREAD_COUNT);

	/*
	 * Mark the thread as "dead".  Until it is marked aligned again, all
	 * the blocks allocated by this thread which could be freed by other
	 * threads will be returned directly.
	 */

	xcr = &xcross[stid];
	spinlock_hidden(&xcr->lock);
	xcr->dead = TRUE;
	spinunlock_hidden(&xcr->lock);

	/*
	 * Since the thread is gone, there are no risks it can run now so we
	 * may safely process its cross-freed blocks to return them to the
	 * thread chunks, therefore freeing them if they no longer hold data.
	 *
	 * This is important since we have no guarantee the thread will be
	 * reused any time soon.
	 */

	xmalloc_thread_free_deferred(stid);

	/*
	 * Reset thread allocation counts per chunk, which is only useful
	 * when there is an empty chunk list: if we have unfreed chunks,
	 * then a new thread re-using this ID will be able to immediately
	 * use these chunks to allocate thread-private memory for the given size.
	 */

	for (i = 0; i < XMALLOC_CHUNKHEAD_COUNT; i++) {
		struct xchunkhead *ch = &xchunkhead[i][stid];

		if (0 == elist_count(&ch->list))
			ch->allocations = 0;
	}

	/*
	 * When debugging, see how may thread-private chunks we still have
	 * and emit an informative note if we have any.
	 *
	 * This does not necessarily indicate a memory leak since it is possible
	 * that the blocks allocated have been passed to another thread and will
	 * be freed later by that thread.
	 */

	if (xmalloc_debugging(0)) {
		size_t n = xmalloc_thread_chunk_count(stid);

		if (n != 0) {
			t_info("XM dead thread #%u still holds %zu thread-private chunk%s",
				stid, n , 1 == n ? "" : "s");
		}
	}
}

/**
 * Allocate a block from the thread-specific pool.
 *
 * @return allocated block of requested size, or NULL if no allocation was
 * possible.
 */
static void *
xmalloc_thread_alloc(const size_t len)
{
	unsigned stid;			/* Thread small ID */
	struct xchunkhead *ch;
	size_t idx;

	g_assert(size_is_non_negative(len));
	g_assert(len <= XM_THREAD_MAXSIZE);

	/*
	 * Before allocating from a thread-specific pool, we wait for a minimal
	 * amount of allocations done for the given size.  That way, if the thread
	 * only allocates a few blocks, we'll avoid dedicating a whole page to it
	 * for that block size.
	 */

	stid = thread_small_id();

	if G_UNLIKELY(stid >= XM_THREAD_COUNT)
		return NULL;

	idx = (0 == len) ? 0 : xch_find_chunkhead_index(len);
	ch = &xchunkhead[idx][stid];

	g_assert(MAX(len, XMALLOC_ALIGNBYTES) == ch->blocksize);

	if G_UNLIKELY(ch->allocations < XM_THREAD_ALLOC_THRESH) {
		ch->allocations++;
		return NULL;
	}

	/*
	 * Handle pending blocks in the cross-thread free list before allocating,
	 * in case there is a block that we can reuse immediately, preventing the
	 * creation of a new chunk.
	 */

	if G_UNLIKELY(xcross[stid].count != 0)
		xmalloc_thread_free_deferred(stid);

	return xmalloc_chunkhead_alloc(ch, stid);
}

/**
 * Check whether block belongs to a thread-specific pool.
 *
 * @param p			the user block pointer
 * @param stid		the thread's small ID
 * @param freeing	whether we may be freeing block
 *
 * @return the chunk to which block belongs, or NULL.
 */
static struct xchunk *
xmalloc_thread_get_chunk(const void *p, unsigned stid, bool freeing)
{
	struct xchunk *xck;
	unsigned offset;

	/*
	 * There is no malloc header for blocks allocated from the thread-specific
	 * pools, so we must see whether the page where the block lies is the
	 * start of a valid chunk.
	 */

	xck = deconstify_pointer(vmm_page_start(p));
	if (!xmalloc_chunk_is_valid(xck))
		return NULL;

	/*
	 * Make sure the block is correctly aligned within the chunk.
	 */

	offset = ptr_diff(ptr_add_offset(xck, xmalloc_pagesize), p);
	if (0 != offset % xck->xc_size) {
		t_error("thread #%u %s mis-aligned %u-byte %sblock %p",
			stid, freeing ? "freeing" : "accessing",
			xck->xc_size, xck->xc_stid == stid ? "" : "foreign ", p);
	}

	return xck;
}

/**
 * Computes length of block allocated from a thread-specific pool.
 *
 * @return length of block, 0 if it was not allocated through a pool.
 */
static size_t
xmalloc_thread_allocated(const void *p)
{
	struct xchunk *xck;
	unsigned stid;

	stid = thread_small_id();

	if G_UNLIKELY(stid >= XM_THREAD_COUNT)
		return FALSE;

	if (!xmalloc_is_valid_pointer(p, FALSE)) {
		t_error_from(_WHERE_, "attempt to access invalid pointer %p: %s",
			p, xmalloc_invalid_ptrstr(p));
	}

	/*
	 * Check whether the block lies on a thread-private chunk page.
	 */

	xck = xmalloc_thread_get_chunk(p, stid, FALSE);

	if (NULL == xck)
		return 0;

	return xck->xc_size;
}

/**
 * Attempt to free block if it belongs to a thread-specific pool.
 *
 * @return TRUE if we freed the block.
 */
static bool
xmalloc_thread_free(void *p)
{
	struct xchunk *xck;
	unsigned stid;
	struct xchunkhead *ch;

	stid = thread_small_id();

	if G_UNLIKELY(stid >= XM_THREAD_COUNT)
		return FALSE;

	if (!xmalloc_is_valid_pointer(p, FALSE)) {
		t_error_from(_WHERE_, "attempt to free invalid pointer %p: %s",
			p, xmalloc_invalid_ptrstr(p));
	}

	/*
	 * Check whether the block lies on a thread-private chunk page.
	 */

	xck = xmalloc_thread_get_chunk(p, stid, TRUE);

	if (NULL == xck)
		return FALSE;

	/*
	 * If a thread allocates a block, it usually is the one freeing it or
	 * reallocating it.  By construction we cannot put back a block in
	 * the thread-specific pool of another thread in a thread-safe way.
	 *
	 * Since there are legitimate use cases, we need to support cross-thread
	 * freeing efficiently: we flag the chunk as shared to avoid growing it
	 * too much from now on if it's not worth the waste (preferring allocation
	 * from the main freelists), and put the block into a thread-specific
	 * queue, processed by the owning thread to free the blocks.
	 */

	ch = xck->xc_head;

	if G_UNLIKELY(xck->xc_stid != stid) {
		struct xcross *xcr = &xcross[xck->xc_stid];

		/*
		 * We can't free the block here because it belongs to another thread's
		 * private pool for which there is no lock protection.
		 */

		if (!ch->shared) {
			ch->shared = TRUE;
			atomic_mb();

			if (xmalloc_debugging(2)) {
				t_debug("thread #%u freeing %u-byte block %p "
					"allocated by thread #%u",
					stid, xck->xc_size, p, xck->xc_stid);
			}
		}

		XSTATS_LOCK;
		xstats.free_foreign_thread_pool++;
		XSTATS_UNLOCK;

		/*
		 * Queue it for the owning thread to free later on by pre-pending it
		 * to the thread-specific chained list of deferred blocks.
		 *
		 * If the thread is flagged as "dead" however, then we're returning
		 * a block allocated by a thread that is no longer there, hence we
		 * can do it safely as long as we hold the lock.
		 */

		spinlock(&xcr->lock);
		if G_UNLIKELY(xcr->dead) {
			xmalloc_chunk_return(xck, p);
		} else {
			*(void **) p = xcr->head;
			xcr->head = p;
			xcr->count++;
		}
		spinunlock(&xcr->lock);

		if (xmalloc_debugging(5)) {
			/* Count may be wrong since we log outside the critical region */
			t_debug("XM deferred freeing of %u-byte block %p "
				"owned by thread #%u (%zu held)",
				xck->xc_size, p, xck->xc_stid, xcr->count);
		}

		return TRUE;		/* We handled the block, freeing is just delayed */
	}

	/*
	 * OK, block belongs to this thread, we can free safely.
	 */

	xmalloc_chunk_return(xck, p);

	/*
	 * Handle any other pending blocks in the cross-thread free list.
	 */

	if G_UNLIKELY(xcross[stid].count != 0)
		xmalloc_thread_free_deferred(stid);

	return TRUE;
}

#ifdef XMALLOC_IS_MALLOC
#undef malloc
#undef free
#undef realloc
#undef calloc

#define xmalloc malloc
#define xfree free
#define xrealloc realloc
#define xcalloc calloc

#define is_trapping_malloc()	1

#define XALIGN_MINSIZE	128	/**< Minimum alignment for xzalloc() */
#define XALIGN_SHIFT	7	/* 2**7 */
#define XALIGN_MASK		((1 << XALIGN_SHIFT) - 1)

#define xaligned(p)		(0 == (pointer_to_ulong(p) & XALIGN_MASK))

static bool xalign_free(const void *p);
static size_t xalign_allocated(const void *p);

#else	/* !XMALLOC_IS_MALLOC */
#define is_trapping_malloc()	0
#define xalign_allocated(p)		0
#define xalign_free(p)			FALSE
#define xaligned(p)				FALSE
#endif	/* XMALLOC_IS_MALLOC */

/**
 * Allocate a memory chunk capable of holding ``size'' bytes.
 *
 * If no memory is available, crash with a fatal error message.
 *
 * @param size			minimal size of block to allocate (user space)
 * @param can_walloc	whether small blocks can be allocated via walloc()
 * @param can_vmm		whether we can allocate core via the VMM layer
 *
 * @return allocated pointer (never NULL).
 */
static void *
xallocate(size_t size, bool can_walloc, bool can_vmm)
{
	size_t len;
	void *p;

	g_assert(size_is_non_negative(size));

	/*
	 * For compatibility with libc's malloc(), a size of 0 is allowed.
	 * We don't return NULL (although POSIX says we could) because some
	 * libc functions such as regcomp() would treat that as an out-of-memory
	 * condition.
	 *
	 * We need to look for slightly larger blocks to be able to stuff our
	 * overhead header in front of the allocated block to hold the size of
	 * the block.
	 */

	len = xmalloc_round_blocksize(xmalloc_round(size) + XHEADER_SIZE);
	XSTATS_LOCK;
	xstats.allocations++;
	XSTATS_UNLOCK;

	if G_UNLIKELY(xmalloc_no_wfree) {
		can_walloc = FALSE;

		/*
		 * In crashing mode activate a simple direct path: anything smaller
		 * than a page size is allocated via sbrk(), the rest is allocated
		 * via the VMM layer.
		 */

		if (xmalloc_crashing) {
			if (len < xmalloc_pagesize) {
				p = xmalloc_addcore_from_heap(len, FALSE);
			} else {
				p = vmm_core_alloc(round_pagesize(len));
			}
			return xmalloc_block_setup(p, len);
		}
	}

	/*
	 * First try to allocate from the freelist when the length is less than
	 * the maximum we handle there.
	 */

	if (len <= XMALLOC_MAXSIZE) {
		size_t allocated;

		/*
		 * If we can allocate a block from a thread-specific pool, we'll
		 * avoid any locking and also limit the block overhead.
		 */

		if (len - XHEADER_SIZE <= XM_THREAD_MAXSIZE && xmalloc_vmm_is_up) {
			allocated = xmalloc_round(size);	/* No malloc header */
			p = xmalloc_thread_alloc(allocated);

			if (p != NULL) {
				XSTATS_LOCK;
				xstats.alloc_via_thread_pool++;
				xstats.user_blocks++;
				xstats.user_memory += allocated;
				XSTATS_UNLOCK;
				memusage_add(xstats.user_mem, allocated);
				return p;
			}
		}

		/*
		 * Check for walloc() remapping.
		 */

		if (
			allow_walloc() &&
			len <= WALLOC_MAX - XHEADER_SIZE && can_walloc && xmalloc_vmm_is_up
		) {
			size_t i = xfl_find_freelist_index(len);
			struct xfreelist *fl = &xfreelist[i];

			/*
			 * Avoid freelist fragmentation when we can.
			 *
			 * As walloc() is possible, prefer this method unless we have a
			 * block available in the freelist that can be allocated without
			 * being split.
			 *
			 * Because walloc() is designed to prevent fragmentation, this
			 * is the best strategy as it leaves larger blocks in the free
			 * list and increases the chance of doing coalescing.
			 *
			 * The downside is that we can leave a large amount of memory
			 * unused in the freelist, but this is memory that we cannot
			 * release as it is fragmented, and it is better than a situation
			 * where we would have way too many small blocks in the freelist
			 * that we could not allocate anyway!
			 */

			p = xmalloc_one_freelist_alloc(fl, len, &allocated);

			/*
			 * Since zalloc() can round up the block size, we need to inspect
			 * the next free lists until we can match the block that zalloc()
			 * would allocate for the requested size.
			 */

			if (NULL == p) {
				size_t bsz = walloc_blocksize(size + XHEADER_SIZE);

				while (fl->blocksize < bsz && i < XMALLOC_FREELIST_COUNT - 1) {
					fl = &xfreelist[++i];
					p = xmalloc_one_freelist_alloc(fl, len, &allocated);
					if (p != NULL)
						goto allocated;
				}
			} else {
				goto allocated;
			}
		}

		/*
		 * Cannot do walloc(), or did not find any non-splitable blocks.
		 *
		 * Allocate from the free list then, splitting larger blocks as needed.
		 */

		p = xmalloc_freelist_alloc(len, &allocated);

		if (p != NULL) {
		allocated:
			G_PREFETCH_HI_W(p);			/* User is going to write in block */
			XSTATS_LOCK;
			xstats.alloc_via_freelist++;
			xstats.user_blocks++;
			xstats.user_memory += allocated;
			XSTATS_UNLOCK;
			memusage_add(xstats.user_mem, allocated);
			return xmalloc_block_setup(p, allocated);
		}
	}

	/*
	 * Need to allocate more core.
	 */

	if G_LIKELY(xmalloc_vmm_is_up && can_vmm) {
		size_t vlen;				/* Length of virual memory allocated */

		/*
		 * If we're allowed to use walloc() and the size is small-enough,
		 * prefer this method of allocation to minimize freelist fragmentation.
		 */

		if (allow_walloc() && can_walloc) {
			size_t wlen = xmalloc_round(size + XHEADER_SIZE);

			/*
			 * As soon as ``xmalloc_no_wfree'' is set, it means we're deep in
			 * shutdown time with wdestroy() being called.  Therefore, we can
			 * no longer allow any walloc().
			 *
			 * Note that walloc()ed blocks are not accounted for in user
			 * block / memory statistics: instead, they are accounted for
			 * by the zalloc() layer.
			 */

			if (wlen <= WALLOC_MAX) {
				p = walloc(wlen);
				if G_LIKELY(p != NULL) {
					XSTATS_LOCK;
					xstats.alloc_via_walloc++;
					XSTATS_UNLOCK;
					return xmalloc_wsetup(p, wlen);
				}

				/*
				 * walloc() can only fail when we recursed and it has not
				 * been able to allocate its internal zone array.
				 */
			}
		}

		/*
		 * The VMM layer is up, use it for all core allocations.
		 */

		vlen = round_pagesize(len);
		p = vmm_core_alloc(vlen);
		XSTATS_LOCK;
		xstats.vmm_alloc_pages += vmm_page_count(vlen);
		xstats.alloc_via_vmm++;
		xstats.user_blocks++;
		XSTATS_UNLOCK;

		if (xmalloc_debugging(1)) {
			t_debug("XM added %zu bytes of VMM core at %p", vlen, p);
		}

		G_PREFETCH_HI_W(p);			/* User is going to write in block */

		if (xmalloc_should_split(vlen, len)) {
			void *split = ptr_add_offset(p, len);
			xmalloc_freelist_insert(split, vlen-len, FALSE, XM_COALESCE_AFTER);
			XSTATS_LOCK;
			xstats.vmm_split_pages++;
			xstats.user_memory += len;
			XSTATS_UNLOCK;
			memusage_add(xstats.user_mem, len);
			return xmalloc_block_setup(p, len);
		} else {
			XSTATS_LOCK;
			xstats.user_memory += vlen;
			XSTATS_UNLOCK;
			memusage_add(xstats.user_mem, vlen);
			return xmalloc_block_setup(p, vlen);
		}
	} else {
		/*
		 * VMM layer not up yet, this must be very early memory allocation
		 * from the libc startup.  Allocate memory from the heap.
		 *
		 * When ``can_vmm'' is FALSE, we do not want to log anything since
		 * we are probably allocating memory from a logging routine and
		 * do not want any recursion to happen.
		 */

		p = xmalloc_addcore_from_heap(len, can_vmm);
		G_PREFETCH_HI_W(p);			/* User is going to write in block */

		XSTATS_LOCK;
		xstats.alloc_via_sbrk++;
		xstats.user_blocks++;
		xstats.user_memory += len;
		XSTATS_UNLOCK;
		memusage_add(xstats.user_mem, len);

		return xmalloc_block_setup(p, len);
	}

	g_assert_not_reached();
}

/**
 * Allocate a memory chunk capable of holding ``size'' bytes.
 *
 * If no memory is available, crash with a fatal error message.
 *
 * @return allocated pointer (never NULL).
 */
void *
xmalloc(size_t size)
{
	return xallocate(size, allow_walloc(), TRUE);
}

/**
 * Allocate a plain memory chunk capable of holding ``size'' bytes.
 *
 * If no memory is available, crash with a fatal error message.
 *
 * This is a "plain" malloc, not redirecting to walloc() for small-sized
 * objects, and therefore it can be used by low-level allocators for their
 * own data structures without fear of recursion.
 *
 * @return allocated pointer (never NULL).
 */
void *
xpmalloc(size_t size)
{
	XSTATS_LOCK;
	xstats.allocations_plain++;
	XSTATS_UNLOCK;

	return xallocate(size, FALSE, TRUE);
}

/**
 * Allocate a heap memory chunk capable of holding ``size'' bytes.
 *
 * If no memory is available, crash with a fatal error message.
 *
 * This is a "heap" malloc, explicitly using the heap to grab more memory.
 * Its use should be reserved to situations where we might be within a
 * memory allocation routine and we need to allocate more memory.
 *
 * @return allocated pointer (never NULL).
 */
void *
xhmalloc(size_t size)
{
	/*
	 * This routine MUST NOT log anything, either here nor in one of the
	 * routines being called.
	 */

	XSTATS_LOCK;
	xstats.allocations_heap++;
	XSTATS_UNLOCK;

	return xallocate(size, FALSE, FALSE);
}

/**
 * Allocate a memory chunk capable of holding ``size'' bytes and zero it.
 *
 * @return pointer to allocated zeroed memory.
 */
void *
xmalloc0(size_t size)
{
	void *p;

	p = xmalloc(size);
	memset(p, 0, size);

	XSTATS_LOCK;
	xstats.allocations_zeroed++;
	XSTATS_UNLOCK;

	return p;
}

/**
 * Allocate a memory chunk capable of holding ``size'' bytes and zero it.
 *
 * This is a "plain" malloc, not redirecting to walloc() for small-sized
 * objects, and therefore it can be used by low-level allocators for their
 * own data structures without fear of recursion.
 *
 * @return pointer to allocated zeroed memory.
 */
void *
xpmalloc0(size_t size)
{
	void *p;

	p = xpmalloc(size);
	memset(p, 0, size);

	XSTATS_LOCK;
	xstats.allocations_zeroed++;
	XSTATS_UNLOCK;

	return p;
}

/**
 * Allocate nmemb elements of size bytes each, zeroing the allocated memory.
 */
void *
xcalloc(size_t nmemb, size_t size)
{
	void *p;

	if (nmemb > 0 && size > 0 && size < ((size_t) -1) / nmemb) {
		size_t len = nmemb * size;

		p = xmalloc0(len);
	} else {
		p = NULL;
	}

	return p;
}

/**
 * A clone of strdup() using xmalloc().
 * The resulting string must be freed via xfree().
 *
 * @param str		the string to duplicate (can be NULL)
 *
 * @return a pointer to the new string.
 */
char *
xstrdup(const char *str)
{
	return str ? xcopy(str, 1 + strlen(str)) : NULL;
}

/**
 * A clone of strdup() using xpmalloc().
 * The resulting string must be freed via xfree().
 *
 * This is using a "plain" malloc, not redirecting to walloc() for small-sized
 * objects, and therefore it can be used by low-level allocators for their
 * own data structures without fear of recursion.
 *
 * @param str		the string to duplicate (can be NULL)
 *
 * @return a pointer to the new string.
 */
char *
xpstrdup(const char *str)
{
	return str ? xpcopy(str, 1 + strlen(str)) : NULL;
}

/**
 * Implementation of our strndup() clone.
 * The resulting string must be freed via xfree().
 *
 * @param str		the string to duplicate (can be NULL)
 * @param n			the maximum amount of characters to duplicate
 * @param plain		whether to use xpmalloc()
 *
 * @return a pointer to the new string.
 */
static char *
xstrndup_internal(const char *str, size_t n, bool plain)
{
	size_t len;
	char *res, *p;

	if G_UNLIKELY(NULL == str)
		return NULL;

	len = clamp_strlen(str, n);
	res = plain ? xpmalloc(len + 1) : xmalloc(len + 1);
	p = mempcpy(res, str, len);
	*p = '\0';

	return res;
}

/**
 * A clone of strndup() using xmalloc().
 * The resulting string must be freed via xfree().
 *
 * @param str		the string to duplicate (can be NULL)
 * @param n			the maximum amount of characters to duplicate
 *
 * @return a pointer to the new string.
 */
char *
xstrndup(const char *str, size_t n)
{
	return xstrndup_internal(str, n, FALSE);
}

/**
 * A clone of strndup() using xpmalloc().
 * The resulting string must be freed via xfree().
 *
 * @param str		the string to duplicate (can be NULL)
 * @param n			the maximum amount of characters to duplicate
 *
 * @return a pointer to the new string.
 */
char *
xpstrndup(const char *str, size_t n)
{
	return xstrndup_internal(str, n, TRUE);
}

/**
 * Free NULL-terminated array of strings, including the array itself.
 */
void
xstrfreev(char **str)
{
	char *p;
	char **vec = str;

	while (NULL != (p = *vec++))
		xfree(p);

	xfree(str);
}

/**
 * Computes user size of allocated block, 0 if not allocated via xmalloc().
 */
size_t
xallocated(const void *p)
{
	size_t len;
	const struct xheader *xh;

	if G_UNLIKELY(NULL == p)
		return 0;

	xh = const_ptr_add_offset(p, -XHEADER_SIZE);
	G_PREFETCH_R(&xh->length);

	if (is_trapping_malloc() && xaligned(p)) {
		len = xalign_allocated(p);
		if G_LIKELY(len != 0)
			return len;
	}

	len = xmalloc_thread_allocated(p);
	if (len != 0)
		return len;

	if (!xmalloc_is_valid_pointer(xh, FALSE))
		return 0;

	if (xmalloc_is_walloc(xh->length)) 
		return xmalloc_walloc_size(xh->length);

	if (!xmalloc_is_valid_length(xh, xh->length)) {
		t_error_from(_WHERE_,
			"corrupted malloc header for pointer %p: bad lengh %zu",
			p, xh->length);
	}

	return xh->length - XHEADER_SIZE;	/* User size, substract overhead */
}

/**
 * Free memory block allocated via xmalloc() or xrealloc().
 */
void
xfree(void *p)
{
	struct xheader *xh;

	/*
	 * Some parts of the libc can call free() with a NULL pointer.
	 * So we explicitly allow this to be able to replace free() correctly.
	 */

	if G_UNLIKELY(NULL == p)
		return;

	/*
	 * As soon as wdestroy() has been called, we're deep into shutdowning
	 * so don't bother freeing anything.
	 */

	if G_UNLIKELY(xmalloc_no_wfree)
		return;

	xstats.freeings++;
	xh = ptr_add_offset(p, -XHEADER_SIZE);
	G_PREFETCH_R(&xh->length);

	XSTATS_LOCK;
	xstats.freeings++;
	XSTATS_UNLOCK;

	/*
	 * Handle pointers returned by posix_memalign() and friends that
	 * would be aligned and therefore directly allocated by VMM or through
	 * zones.
	 *
	 * The xaligned() test checks whether the pointer is at least aligned
	 * to the minimum size we're aligning through special allocations, so
	 * that we don't invoke the costly xalign_free() if we can avoid it.
	 */

	if (is_trapping_malloc() && xaligned(p) && xalign_free(p))
		return;

	/*
	 * Handle thread-specific blocks early in the process since they do not
	 * have any malloc header.
	 */

	if (xmalloc_thread_free(p)) {
		XSTATS_LOCK;
		xstats.free_thread_pool++;
		XSTATS_UNLOCK;
		return;
	}

	if (!xmalloc_is_valid_pointer(xh, FALSE)) {
		t_error_from(_WHERE_, "attempt to free invalid pointer %p: %s",
			p, xmalloc_invalid_ptrstr(p));
	}

	/*
	 * Handle walloc()ed blocks specially.
	 *
	 * These are not accounted in xmalloc() blocks / memory stats since they
	 * are already accounted for by zalloc() stats.
	 */

	if (xmalloc_is_walloc(xh->length)) {
		XSTATS_LOCK;
		xstats.free_walloc++;
		XSTATS_UNLOCK;
		wfree(xh, xmalloc_walloc_size(xh->length));
		return;
	}

	/*
	 * Freeings to freelist are disabled at shutdown time.
	 */

	if G_UNLIKELY(xmalloc_no_freeing)
		return;

	if (!xmalloc_is_valid_length(xh, xh->length)) {
		t_error_from(_WHERE_,
			"corrupted malloc header for pointer %p: bad lengh %zu",
			p, xh->length);
	}

	XSTATS_LOCK;
	xstats.user_memory -= xh->length;
	xstats.user_blocks--;
	XSTATS_UNLOCK;
	memusage_remove(xstats.user_mem, xh->length);

	xmalloc_freelist_add(xh, xh->length, XM_COALESCE_ALL | XM_COALESCE_SMART);
}

/**
 * Reallocate a block allocated via xmalloc().
 *
 * @param p				original user pointer
 * @param size			new user-size
 * @param can_walloc	whether plain block can be reallocated with walloc()
 *
 * @return
 * If a NULL pointer is given, act as if xmalloc() had been called and
 * return a new pointer.
 * If the new size is 0, act as if xfree() had been called and return NULL.
 * Otherwise return a pointer to the reallocated block, which may be different
 * than the original pointer.
 */
static void *
xreallocate(void *p, size_t size, bool can_walloc)
{
	struct xheader *xh = ptr_add_offset(p, -XHEADER_SIZE);
	size_t newlen;
	void *np;
	unsigned stid;
	struct xchunk *xck;

	if (NULL == p)
		return xallocate(size, can_walloc, TRUE);

	if (0 == size) {
		xfree(p);
		return NULL;
	}

	/*
	 * Handle blocks from a thread-specific pool specially, since they have
	 * no malloc header and cannot be coalesced because they are allocated
	 * from zones with fix-sized blocks.
	 */

	stid = thread_small_id();
	xck = xmalloc_thread_get_chunk(p, stid, TRUE);

	if (xck != NULL) {
		if G_UNLIKELY(xmalloc_no_freeing) {
			can_walloc = FALSE;		/* Shutdowning, don't care */
			goto realloc_from_thread;
		}

		XSTATS_LOCK;
		xstats.reallocs++;
		XSTATS_UNLOCK;

		if (xmalloc_round(size) == xck->xc_size) {
			XSTATS_LOCK;
			xstats.realloc_noop++;
			XSTATS_UNLOCK;

			if (xmalloc_debugging(2)) {
				t_debug("XM realloc of %p to %zu bytes can be a noop "
					"(already in a %u-byte chunk for thread #%u)",
					p, size, xck->xc_size, stid);
			}

			return p;
		}

		goto realloc_from_thread;	/* Move block around */
	}
		
	if G_UNLIKELY(!xmalloc_is_valid_pointer(xh, FALSE)) {
		t_error_from(_WHERE_, "attempt to realloc invalid pointer %p: %s",
			p, xmalloc_invalid_ptrstr(p));
	}

	if (xmalloc_is_walloc(xh->length))
		goto realloc_from_walloc;

	if G_UNLIKELY(!xmalloc_is_valid_length(xh, xh->length)) {
		t_error_from(_WHERE_,
			"corrupted malloc header for pointer %p: bad length %ld",
			p, (long) xh->length);
	}

	if G_UNLIKELY(xmalloc_no_freeing) {
		can_walloc = FALSE;		/* Shutdowning, don't care */
		goto skip_coalescing;
	}

	/*
	 * Compute the size of the physical block we need, including overhead.
	 */

	newlen = xmalloc_round_blocksize(xmalloc_round(size) + XHEADER_SIZE);
	XSTATS_LOCK;
	xstats.reallocs++;
	XSTATS_UNLOCK;

	/*
	 * Identify blocks allocated from the VMM layer: they are page-aligned
	 * and their size is a multiple of the system's page size, and they are
	 * not located in the heap.
	 */

	if (
		round_pagesize(xh->length) == xh->length &&
		vmm_page_start(xh) == xh &&
		!xmalloc_isheap(xh, xh->length)
	) {
		newlen = round_pagesize(newlen);

		/*
		 * If the size remains the same in the VMM space, we have nothing
		 * to do unless we have a relocatable fragment.
		 */

		if (newlen == xh->length && vmm_is_relocatable(xh, xh->length)) {
			XSTATS_LOCK;
			xstats.realloc_relocate_vmm_fragment++;
			XSTATS_UNLOCK;
			goto relocate_vmm;
		}

		/*
		 * If the new size is smaller than the original, yet remains larger
		 * than a page size, we can call vmm_core_shrink() to shrink the block
		 * inplace or relocate it.
		 */

		if (newlen < xh->length) {
			if (vmm_is_relocatable(xh, newlen)) {
				XSTATS_LOCK;
				xstats.realloc_relocate_vmm_shrinked++;
				XSTATS_UNLOCK;
				goto relocate_vmm;
			}

			if (xmalloc_debugging(1)) {
				t_debug("XM using vmm_core_shrink() on "
					"%zu-byte block at %p (new size is %zu bytes)",
					xh->length, (void *) xh, newlen);
			}

			vmm_core_shrink(xh, xh->length, newlen);
			XSTATS_LOCK;
			xstats.realloc_inplace_vmm_shrinking++;
			xstats.user_memory -= xh->length - newlen;
			XSTATS_UNLOCK;
			memusage_remove(xstats.user_mem, xh->length - newlen);
			goto inplace;
		}

		/*
		 * If we have to extend the VMM region, we can skip all the coalescing
		 * logic since we have to allocate a new region.
		 */

		if (newlen > xh->length)
			goto skip_coalescing;

		if (xmalloc_debugging(2)) {
			t_debug("XM realloc of %p to %zu bytes can be a noop "
				"(already %zu-byte long VMM region)", p, size, xh->length);
		}

		XSTATS_LOCK;
		xstats.realloc_noop++;
		XSTATS_UNLOCK;

		return p;
	}

	/*
	 * We are not dealing with a whole VMM region.
	 *
	 * Normally we have nothing to do if the size remains the same.
	 *
	 * However, we use can use this opportunity to move around the block
	 * to a more strategic place in memory.
	 */

	if (newlen == xh->length) {
		if G_LIKELY(!xmalloc_isheap(p, size)) {
			struct xfreelist *fl;
			void *q;

			/*
			 * We don't want to split a block and we want a pointer closer
			 * to the base.
			 */

			q = xmalloc_freelist_lookup(newlen, NULL, &fl);

			XSTATS_LOCK;
			xstats.realloc_relocate_smart_attempts++;
			XSTATS_UNLOCK;

			if (q != NULL) {
				if (newlen == fl->blocksize && xm_ptr_cmp(xh, q) < 0) {
					xfl_remove_selected(fl, q);
					np = xmalloc_block_setup(q, newlen);

					XSTATS_LOCK;
					xstats.realloc_relocate_smart_success++;
					XSTATS_UNLOCK;

					if (xmalloc_debugging(1)) {
						t_debug("XM relocated %zu-byte block at %p to %p"
							" (pysical size is still %zu bytes,"
							" user size is %zu)",
							xh->length, (void *) xh, q, newlen, size);
					}

					goto relocate;
				} else {
					/*
					 * Release lock grabbed by xmalloc_freelist_lookup().
					 */

					mutex_unlock(&fl->lock);
				}
			}
		}

		if (xmalloc_debugging(2)) {
			t_debug("XM realloc of %p to %zu bytes can be a noop "
				"(already %zu-byte long from %s)",
				p, size, xh->length, xmalloc_isheap(p, size) ? "heap" : "VMM");
		}

		XSTATS_LOCK;
		xstats.realloc_noop++;
		XSTATS_UNLOCK;

		return p;
	}

	/*
	 * If the block is shrunk and its old size is less than XMALLOC_MAXSIZE,
	 * put the remainder back in the freelist.
	 */

	if (xh->length <= XMALLOC_MAXSIZE && newlen < xh->length) {
		size_t extra = xh->length - newlen;

		if G_UNLIKELY(!xmalloc_should_split(xh->length, newlen)) {
			if (xmalloc_debugging(2)) {
				t_debug("XM realloc of %p to %zu bytes can be a noop "
					"(already %zu-byte long from %s, not shrinking %zu bytes)",
					p, size, xh->length,
					xmalloc_isheap(p, size) ? "heap" : "VMM", extra);
			}

			XSTATS_LOCK;
			xstats.realloc_noop++;
			XSTATS_UNLOCK;

			return p;
		} else {
			void *end = ptr_add_offset(xh, newlen);

			if (xmalloc_debugging(1)) {
				t_debug("XM using inplace shrink on %zu-byte block at %p"
					" (new size is %zu bytes, splitting at %p)",
					xh->length, (void *) xh, newlen, end);
			}

			xmalloc_freelist_add(end, extra, XM_COALESCE_AFTER);

			XSTATS_LOCK;
			xstats.realloc_inplace_shrinking++;
			xstats.user_memory -= extra;
			XSTATS_UNLOCK;
			memusage_remove(xstats.user_mem, extra);

			goto inplace;
		}
	}

	/*
	 * If the new block size is not larger than XMALLOC_MAXSIZE and the
	 * old size is also under the same limit, try to see whether we have a
	 * neighbouring free block in the free list that would be large enough
	 * to accomodate the resizing.
	 *
	 * If we find a block after, it's a total win as we don't have to move
	 * any data.  If we find a block before, it's a partial win as we coalesce
	 * but we still need to move around some data.
	 */

	if (newlen <= XMALLOC_MAXSIZE && xh->length <= XMALLOC_MAXSIZE) {
		size_t i, needed, old_len = 0, freelist_idx;
		void *end;
		bool coalesced = FALSE;

		g_assert(newlen > xh->length);	/* Or would have been handled before */

		/*
		 * Extra amount needed, rounded to the next legit block size as found
		 * in the free list.
		 */

		needed = xmalloc_round_blocksize(newlen - xh->length);
		end = ptr_add_offset(xh, xh->length);
		freelist_idx = xfl_find_freelist_index(needed);

		/*
		 * Look for a match after the allocated block.
		 */

		for (i = freelist_idx; i <= xfreelist_maxidx && !coalesced; i++) {
			struct xfreelist *fl = &xfreelist[i];
			size_t idx;

			if (0 == fl->count || !mutex_trylock(&fl->lock))
				continue;

			idx = xfl_lookup(fl, end, NULL);

			if G_UNLIKELY((size_t) -1 != idx) {
				size_t blksize = fl->blocksize;
				size_t csize = blksize + xh->length;

				/*
				 * We must make sure that the resulting size of the block
				 * can enter the freelist in one of its buckets.
				 */

				if (xmalloc_round_blocksize(csize) != csize) {
					if (xmalloc_debugging(6)) {
						t_debug("XM realloc NOT coalescing next %zu-byte "
							"[%p, %p[ from list #%zu with [%p, %p[: invalid "
							"resulting size of %zu bytes",
							blksize, end, ptr_add_offset(end, blksize), i,
							(void *) xh, end, csize);
					}
					mutex_unlock(&fl->lock);
					break;
				}

				if (xmalloc_debugging(6)) {
					t_debug("XM realloc coalescing next %zu-byte "
						"[%p, %p[ from list #%zu with [%p, %p[ yielding "
						"%zu-byte block",
						blksize, end, ptr_add_offset(end, blksize), i,
						(void *) xh, end, csize);
				}
				xfl_delete_slot(fl, idx);
				end = ptr_add_offset(end, blksize);
				coalesced = TRUE;
			}
			mutex_unlock(&fl->lock);
		}

		/*
		 * If we coalesced we don't need to move data around, but we may end-up
		 * with a larger block which may need to be split.
		 */

		if G_UNLIKELY(coalesced) {
			void *split = ptr_add_offset(xh, newlen);
			size_t split_len = ptr_diff(end, xh) - newlen;

			g_assert(size_is_non_negative(split_len));

			/*
			 * We can split only if there is enough and when the split
			 * block size is one we can hold in our freelist.
			 */

			if (
				split_len >= XMALLOC_SPLIT_MIN &&
				xmalloc_round_blocksize(split_len) == split_len
			) {
				if (xmalloc_debugging(6)) {
					t_debug("XM realloc splitting large %zu-byte block at %p"
						" (need only %zu bytes: returning %zu bytes at %p)",
						ptr_diff(end, xh), (void *) xh, newlen,
						split_len, split);
				}

				g_assert(split_len <= XMALLOC_MAXSIZE);

				xmalloc_freelist_add(split, split_len, XM_COALESCE_AFTER);
			} else {
				/* Actual size ends up being larger than requested */
				newlen = ptr_diff(end, xh);
			}

			if (xmalloc_debugging(1)) {
				t_debug("XM realloc used inplace coalescing on "
					"%zu-byte block at %p (new size is %zu bytes)",
					xh->length, (void *) xh, newlen);
			}

			XSTATS_LOCK;
			xstats.realloc_inplace_extension++;
			xstats.user_memory += newlen - xh->length;
			XSTATS_UNLOCK;
			memusage_add(xstats.user_mem, newlen - xh->length);

			goto inplace;
		}

		/*
		 * Look for a match before.
		 */

		for (i = freelist_idx; i <= xfreelist_maxidx && !coalesced; i++) {
			struct xfreelist *fl = &xfreelist[i];
			size_t blksize;
			void *before;
			size_t idx;

			if (0 == fl->count || !mutex_trylock(&fl->lock))
				continue;

			blksize = fl->blocksize;
			before = ptr_add_offset(xh, -blksize);

			idx = xfl_lookup(fl, before, NULL);

			if G_UNLIKELY((size_t) -1 != idx) {
				size_t csize = blksize + xh->length;

				/*
				 * We must make sure that the resulting size of the block
				 * can enter the freelist in one of its buckets.
				 */

				if (xmalloc_round_blocksize(csize) != csize) {
					if (xmalloc_debugging(6)) {
						t_debug("XM realloc not coalescing previous "
							"%zu-byte [%p, %p[ from list #%zu with [%p, %p[: "
							"invalid resulting size of %zu bytes",
							blksize, before, ptr_add_offset(before, blksize), i,
							(void *) xh, end, csize);
					}
					mutex_unlock(&fl->lock);
					break;
				}

				if (xmalloc_debugging(6)) {
					t_debug("XM realloc coalescing previous %zu-byte "
						"[%p, %p[ from list #%zu with [%p, %p[",
						blksize, before, ptr_add_offset(before, blksize),
						i, (void *) xh, end);
				}
				xfl_delete_slot(fl, idx);
				old_len = xh->length - XHEADER_SIZE;	/* Old user size */
				xh = before;
				coalesced = TRUE;
			}

			mutex_unlock(&fl->lock);
		}

		/*
		 * If we coalesced with a block before, we need to move data around.
		 * Then we may also face a larger block than needed which needs to
		 * be split appropriately.
		 */

		if G_UNLIKELY(coalesced) {
			void *split = ptr_add_offset(xh, newlen);
			size_t split_len = ptr_diff(end, xh) - newlen;

			memmove(ptr_add_offset(xh, XHEADER_SIZE), p, old_len);

			g_assert(size_is_non_negative(split_len));

			/*
			 * We can split only if there is enough and when the split
			 * block size is one we can hold in our freelist.
			 */

			if (
				split_len >= XMALLOC_SPLIT_MIN &&
				xmalloc_round_blocksize(split_len) == split_len
			) {
				if (xmalloc_debugging(6)) {
					t_debug("XM realloc splitting large %zu-byte block at %p"
						" (need only %zu bytes: returning %zu bytes at %p)",
						ptr_diff(end, xh), (void *) xh, newlen,
						split_len, split);
				}

				g_assert(split_len <= XMALLOC_MAXSIZE);

				xmalloc_freelist_add(split, split_len, XM_COALESCE_AFTER);
			} else {
				/* Actual size ends up being larger than requested */
				newlen = ptr_diff(end, xh);
			}

			if (xmalloc_debugging(1)) {
				t_debug("XM realloc used coalescing with block preceding "
					"%zu-byte block at %p "
					"(new size is %zu bytes, new address is %p)",
					old_len + XHEADER_SIZE, ptr_add_offset(p, -XHEADER_SIZE),
					newlen, (void *) xh);
			}

			XSTATS_LOCK;
			xstats.realloc_coalescing_extension++;
			xstats.user_memory += newlen - old_len;
			XSTATS_UNLOCK;
			memusage_add(xstats.user_mem, newlen - old_len);

			return xmalloc_block_setup(xh, newlen);
		}

		/* FALL THROUGH */
	}

skip_coalescing:

	/*
	 * Regular case: allocate a new block, move data around, free old block.
	 */

	{
		struct xheader *nxh;
		bool converted;

		np = xallocate(size, allow_walloc() && can_walloc, TRUE);

		XSTATS_LOCK;
		xstats.realloc_regular_strategy++;
		XSTATS_UNLOCK;

		/*
		 * See whether plain block was converted to a walloc()ed one.
		 */

		nxh = ptr_add_offset(np, -XHEADER_SIZE);
		converted = xmalloc_is_walloc(nxh->length);

		if (converted) {
			g_assert(can_walloc);

			XSTATS_LOCK;
			xstats.realloc_promoted_to_walloc++;
			XSTATS_UNLOCK;
		}

		if (xmalloc_debugging(1)) {
			t_debug("XM realloc used regular strategy: "
				"%zu-byte block at %p %s %zu-byte block at %p",
				xh->length, (void *) xh,
				converted ? "converted to walloc()ed" : "moved to",
				size + XHEADER_SIZE, ptr_add_offset(np, -XHEADER_SIZE));
		}
	}

	/* FALL THROUGH */

relocate:
	{
		size_t old_size = xh->length - XHEADER_SIZE;

		g_assert(size_is_positive(old_size));

		memcpy(np, p, MIN(size, old_size));
		xfree(p);
	}

	return np;

relocate_vmm:
	{
		void *q;

		g_assert(xh->length >= newlen);

		q = vmm_core_alloc(newlen);
		np = xmalloc_block_setup(q, newlen);

		XSTATS_LOCK;
		xstats.vmm_alloc_pages += vmm_page_count(newlen);
		xstats.user_memory -= xh->length - newlen;
		XSTATS_UNLOCK;
		memusage_remove(xstats.user_mem, xh->length - newlen);

		if (xmalloc_debugging(1)) {
			t_debug("XM relocated %zu-byte VMM region at %p to %p"
				" (new pysical size is %zu bytes, user size is %zu)",
				xh->length, (void *) xh, q, newlen, size);
		}

		goto relocate;
	}

inplace:
	xh->length = newlen;
	return p;

realloc_from_walloc:
	{
		size_t old_len = xmalloc_walloc_size(xh->length);
		size_t new_len = xmalloc_round(size + XHEADER_SIZE);
		size_t old_size;

		/*
		 * If we disabled all freeings, we're deep into shutdown or in
		 * crashing mode, and we don't want to free anything or call wfree().
		 * Simply honour the reallocation request.
		 */

		if G_UNLIKELY(xmalloc_no_wfree) {
			np = xallocate(size, FALSE, TRUE);
			old_size = old_len - XHEADER_SIZE;
			g_assert(size_is_non_negative(old_size));
			memcpy(np, p, MIN(size, old_size));
			return np;
		}

		if (new_len <= WALLOC_MAX) {
			void *wp = wrealloc(xh, old_len, new_len);

			XSTATS_LOCK;
			xstats.realloc_wrealloc++;
			XSTATS_UNLOCK;

			if (xmalloc_debugging(1)) {
				t_debug("XM realloc used wrealloc(): "
					"%zu-byte block at %p %s %zu-byte block at %p",
					old_len, (void *) xh,
					old_len == new_len && 0 == ptr_cmp(xh, wp) ?
						"stays" : "moved to",
					new_len, wp);
			}

			return xmalloc_wsetup(wp, new_len);
		}

		/*
		 * Have to convert walloc() block to real malloc.
		 *
		 * Since walloc()ed blocks are not accounted in xmalloc() statistics,
		 * there's nothing to update during the conversion.
		 */

		np = xallocate(size, FALSE, TRUE);

		XSTATS_LOCK;
		xstats.realloc_converted_from_walloc++;
		XSTATS_UNLOCK;

		if (xmalloc_debugging(1)) {
			t_debug("XM realloc converted from walloc(): "
				"%zu-byte block at %p moved to %zu-byte block at %p",
				old_len, (void *) xh,
				size + XHEADER_SIZE, ptr_add_offset(np, -XHEADER_SIZE));
		}

		old_size = old_len - XHEADER_SIZE;

		g_assert(size_is_non_negative(old_size));

		memcpy(np, p, MIN(size, old_size));
		wfree(xh, old_len);

		return np;
	}

realloc_from_thread:
	{
		size_t old_size = xck->xc_size;

		np = xallocate(size, allow_walloc() && can_walloc, TRUE);

		XSTATS_LOCK;
		xstats.realloc_from_thread_pool++;
		xstats.realloc_regular_strategy++;
		XSTATS_UNLOCK;

		memcpy(np, p, MIN(size, old_size));
		xfree(p);
	}

	return np;
}

/**
 * Reallocate a block allocated via xmalloc().
 *
 * @param p				original user pointer
 * @param size			new user-size
 *
 * @return
 * If a NULL pointer is given, act as if xmalloc() had been called and
 * return a new pointer.
 * If the new size is 0, act as if xfree() had been called and return NULL.
 * Otherwise return a pointer to the reallocated block, which may be different
 * than the original pointer.
 */
void *
xrealloc(void *p, size_t size)
{
	return xreallocate(p, size, allow_walloc());
}

/**
 * Reallocate a block allocated via xmalloc(), forcing xpmalloc() if needed
 * to ensure walloc() is not used.
 *
 * @param p				original user pointer
 * @param size			new user-size
 *
 * @return
 * If a NULL pointer is given, act as if xmalloc() had been called and
 * return a new pointer.
 * If the new size is 0, act as if xfree() had been called and return NULL.
 * Otherwise return a pointer to the reallocated block, which may be different
 * than the original pointer.
 */
void *
xprealloc(void *p, size_t size)
{
	return xreallocate(p, size, FALSE);
}

/**
 * Marks the head of the current page used by xgc_alloc().
 */
struct xgc_page {
	void *next;				/**< Next page in the list */
};

/**
 * Records pages allocated by the simple xgc_alloc() routines.
 */
struct xgc_allocator {
	struct xgc_page *head;	/**< Head of page list */
	struct xgc_page *tail;	/**< Tail of page list */
	struct xgc_page *top;	/**< Top of current page */
	void *avail;			/**< First available memory on current page */
	size_t remain;			/**< Remaining size available on current page */
};

/**
 * A fragment spanning over several pages.
 */
struct xgc_fragment {
	const void *p;
	size_t len;
};

#define XGA_MASK		(MEM_ALIGNBYTES - 1)
#define xga_round(s)	((size_t) (((ulong) (s) + XGA_MASK) & ~XGA_MASK))
#define XGA_MAXLEN		64

/**
 * Allocate memory during garbage collection.
 *
 * @return pointer to memory of ``len'' bytes.
 */
static void *
xgc_alloc(struct xgc_allocator *xga, size_t len)
{
	size_t requested = xga_round(len);
	void *p;

	g_assert(requested <= XGA_MAXLEN);	/* Safety since we're so simple! */

	if (xga->remain < requested) {
		struct xgc_page *page;

		/* Waste remaining (at most XGA_MAXLEN), allocate a new page */

		page = vmm_core_alloc(xmalloc_pagesize);

		if (NULL == xga->head) {
			xga->head = xga->tail = page;
		} else {
			g_assert(xga->tail != NULL);
			g_assert(NULL == xga->tail->next);
			xga->tail->next = page;
			xga->tail = page;
		}

		page->next = NULL;
		xga->top = page;
		xga->remain = xmalloc_pagesize - sizeof(*xga->top);
		xga->avail = &page[1];
	}

	p = xga->avail;
	xga->avail = ptr_add_offset(p, requested);
	xga->remain -= requested;

	g_assert(size_is_non_negative(xga->remain));

	return p;
}

/**
 * Reclaim all the memory allocated during garbage collection through
 * the xgc_alloc() routine.
 */
static void
xgc_free_all(struct xgc_allocator *xga)
{
	struct xgc_page *p, *next;

	for (p = xga->head; p != NULL; p = next) {
		next = p->next;
		vmm_core_free(p, xmalloc_pagesize);
	}
}

/**
 * Coalescing / freeing bucket context.
 */
struct xgc_context {
	uint8 locked[XMALLOC_FREELIST_COUNT];
	size_t available[XMALLOC_FREELIST_COUNT];
	size_t count[XMALLOC_FREELIST_COUNT];
	size_t largest;			/**< Largest bucket count */
};

/**
 * Items that are organized in a red-black tree to record all block ranges.
 */
struct xgc_range {
	const void *start;		/**< First address in range */
	const void *end;		/**< First address beyond range */
	rbnode_t node;			/**< Embedded red-black tree structure */
	unsigned blocks;		/**< Amount of blocks making up this range */
	/* These fields updated during strategy planning and execution */
	unsigned head;			/**< Head part to keep, until first page */
	unsigned tail;			/**< Tail part, after last full page */
	uint8 strategy;			/**< Strategy code */
};

/**
 * Strategy codes.
 */
#define XGC_ST_COALESCE		1	/**< Coalesce block */
#define XGC_ST_FREE_PAGES	2	/**< Free embedded pages, release head/tail */

/**
 * Comparison function for (disjoint) ranges -- red-black tree callback.
 */
static int
xgc_range_cmp(const void *a, const void *b)
{
	const struct xgc_range *p = a, *q = b;

	if (ptr_cmp(p->end, q->start) <= 0)
		return -1;

	if (ptr_cmp(q->end, p->start) <= 0)
		return +1;

	return 0;		/* Overlapping ranges are equal */
}

/**
 * Add block to red-black tree, coalescing if needed.
 *
 * @param rbt		the red-black tree
 * @param start		starting address of block
 * @param len		length of block
 * @param xga		memory allocator used during xgc() run
 */
static void
xgc_block_add(erbtree_t *rbt, const void *start, size_t len,
	struct xgc_allocator *xga)
{
	const void *end = const_ptr_add_offset(start, len);
	struct xgc_range key;
	struct xgc_range *merged = NULL, *xr;

	/*
	 * Look whether we can coalesce with a block before it.
	 */

	key.start = const_ptr_add_offset(start, -1);
	key.end = start;
	merged = erbtree_lookup(rbt, &key);

	if (merged != NULL) {
		g_assert_log(merged->end == start,
			"merged=[%p, %p[, start=%p", merged->start, merged->end, start);
		merged->end = end;
		merged->blocks++;
	}

	/*
	 * Look whether we can coalesce with a block after it.
	 */

	key.start = end;
	key.end = const_ptr_add_offset(end, +1);
	xr = erbtree_lookup(rbt, &key);

	if (xr != NULL) {
		if (merged != NULL) {
			g_assert_log(merged->end == xr->start,
				"merged=[%p, %p[, xr=[%p, %p[",
				merged->start, merged->end, xr->start, xr->end);
			merged->end = xr->end;
			merged->blocks += xr->blocks;
			erbtree_remove(rbt, &xr->node);
		} else {
			g_assert_log(xr->start == end,
				"xr=[%p, %p[, end=%p", xr->start, xr->end, end);
			xr->start = start;
			merged = xr;
			merged->blocks++;
		}
	}

	/*
	 * Create a new node if we were not able to coalesce.
	 */

	if (NULL == merged) {
		const struct xgc_range *old;

		xr = xgc_alloc(xga, sizeof *xr);
		ZERO(xr);
		xr->start = start;
		xr->end = end;
		xr->blocks = 1;

		/*
		 * Save length of first block to help the strategy should end-up with
		 * two blocks being coalesced, with a length that does not fit the
		 * freelist.
		 */

		xr->head = ptr_diff(end, start);	/* Necessarily fits */
		old = erbtree_insert(rbt, &xr->node);

		g_assert_log(NULL == old,		/* Was not already present in tree */
			"xr=[%p, %p[, old=[%p, %p[ (%u block%s)",
			start, end, old->start, old->end,
			old->blocks, 1 == old->blocks ? "" : "s");
	}
}

static inline bool
xgc_freelist_has_room(size_t idx, struct xgc_context *xgctx)
{
	if G_UNLIKELY(!xgctx->locked[idx])
		return FALSE;

	if G_UNLIKELY(0 == xgctx->available[idx]) {
		struct xfreelist *fl = &xfreelist[idx];
		fl->expand = TRUE;		/* For next time */
		return FALSE;
	}

	return TRUE;
}

static inline void
xgc_freelist_inc(size_t idx, struct xgc_context *xgctx)
{
	xgctx->available[idx]--;
	xgctx->count[idx]++;
	if G_UNLIKELY(xgctx->largest < xgctx->count[idx])
		xgctx->largest = xgctx->count[idx];
}

/**
 * Check whether a given block is freeable. i.e. that there is room in the
 * bucket(s) where it would fall, ignoring any freeing that could occur
 * from these buckets due to coalescing.
 *
 * @param len		the length of the block
 * @param xgctx		the xgc() context
 * @param commit	if TRUE, commit the freeing by updating the context.
 *
 * @return TRUE if block is freeable, FALSE otherwise.
 */
static bool
xgc_block_is_freeable(size_t len, struct xgc_context *xgctx, bool commit)
{
	struct xsplit *xs;
	size_t i1, i2 = 0;

	if G_UNLIKELY(0 == len)
		return TRUE;

	g_assert(len >= XMALLOC_SPLIT_MIN);

	if (len > XMALLOC_MAXSIZE)
		return FALSE;

	/*
	 * Compute the freelists into which the block would end-up being freed.
	 */

	xs = xmalloc_split_info(len);
	i1 = xfl_find_freelist_index(xs->larger);

	if G_UNLIKELY(!xgc_freelist_has_room(i1, xgctx))
		return FALSE;

	if G_UNLIKELY(xs->smaller != 0) {
		i2 = xfl_find_freelist_index(xs->smaller);

		if G_UNLIKELY(!xgc_freelist_has_room(i2, xgctx))
			return FALSE;
	}

	/*
	 * OK, we can free the block.
	 */

	if (commit) {
		xgc_freelist_inc(i1, xgctx);
		if G_UNLIKELY(xs->smaller != 0)
			xgc_freelist_inc(i2, xgctx);
	}

	return TRUE;
}

/**
 * Decide on the fate of all the identified ranges.
 *
 * @return TRUE if range must be deleted.
 */
static bool
xgc_range_strategy(void *key, void *data)
{
	struct xgc_range *xr = key;
	struct xgc_context *xgctx = data;
	size_t len;

	/*
	 * If we have a range larger than a page size, coalesced or not,
	 * see whether we can chop its head and tail and free the amount
	 * of consecutive pages in-between:
	 *
	 *    <------------ range ------------>
	 *    +------+-----------------+------+
	 *    | head | ... n pages ... | tail |
	 *    +------+-----------------+------+
	 *           ^
	 *           page boundary
	 *
	 * The "n pages" can be freed provided the head and tail are larger
	 * than the minimum block length and there is room in the targeted
	 * free lists (one if the block length fits one of our discrete sizes,
	 * two if it needs to be further split among two lists).
	 *
	 * It can also happen that the range spans two pages but never a whole
	 * page:
	 *
	 *    <--- range --->
	 *    +-------------+----------+
	 *    |             |          |
	 *    +------^------+----------^
	 *           ^ page boundaries ^
	 *
	 * In which case we cannot release any page of course but that does
	 * not mean we cannot coalesce several smaller blocks that were
	 * merged into that range.
	 */

	if (ptr_diff(xr->end, xr->start) >= xmalloc_pagesize) {
		const void *pstart, *pend;

		pstart = vmm_page_next(xr->start);
		if G_UNLIKELY(ptr_diff(pstart, xr->start) == xmalloc_pagesize)
			pstart = xr->start;
		pend = vmm_page_start(xr->end);

		if (pstart == pend)
			goto no_page_freeable;

		/*
		 * We have at least one page that could be freed, but we need to
		 * make sure that the head and the tail are large enough to be
		 * put back into the freelist, if non-zero.
		 */

		xr->head = ptr_diff(pstart, xr->start);
		xr->tail = ptr_diff(xr->end, pend);

		if (xr->head != 0 && xr->head < XMALLOC_SPLIT_MIN) {
			pstart = const_ptr_add_offset(pstart, xmalloc_pagesize);
			xr->head += xmalloc_pagesize;
		}

		if (xr->tail != 0 && xr->tail < XMALLOC_SPLIT_MIN) {
			pend = const_ptr_add_offset(pend, -xmalloc_pagesize);
			xr->tail += xmalloc_pagesize;
		}

		if (ptr_cmp(pstart, pend) <= 0)
			goto no_page_freeable;

		if (!xgc_block_is_freeable(xr->head, xgctx, FALSE))
			goto cannot_free_page;

		if (!xgc_block_is_freeable(xr->tail, xgctx, FALSE))
			goto cannot_free_page;

		/*
		 * If the pages are heap memory, they cannot be VMM-released.
		 */

		if G_UNLIKELY(xmalloc_isheap(pstart, ptr_diff(pend, pstart)))
			goto cannot_free_page;

		/*
		 * Good, we can free the head, the tail and the middle pages.
		 */

		xgc_block_is_freeable(xr->head, xgctx, TRUE);
		xgc_block_is_freeable(xr->tail, xgctx, TRUE);
		xr->strategy = XGC_ST_FREE_PAGES;

		if (xmalloc_debugging(3)) {
			t_debug("XM GC [%p, %p[ (%zu bytes, %u blocks) handled as: "
				"%u-byte head, %u-byte tail, VMM range [%p, %p[ released",
				xr->start, xr->end, ptr_diff(xr->end, xr->start), xr->blocks,
				xr->head, xr->tail, pstart, pend);
		}

		return TRUE;

	cannot_free_page:
		XSTATS_LOCK;
		xstats.xgc_page_freeing_failed++;
		XSTATS_UNLOCK;

		/* FALL THROUGH */
	}

no_page_freeable:

	/*
	 * Range was not coalesced when it only contains a single block.
	 */

	if (1 == xr->blocks)
		return TRUE;			/* Delete it */

	/*
	 * A range can be coalesced with two blocks whose resulting size
	 * is not that of a freelist, in which case the block would need to
	 * be split again.  Maybe we could find a better split, i.e. create
	 * a block that would end up being larger than the largest of the two
	 * blocks we have?
	 *
	 * Note that three blocks or more can always be coalesced to create
	 * a larger block at least.
	 */

	len = ptr_diff(xr->end, xr->start);

	if G_UNLIKELY(2 == xr->blocks && len <= XMALLOC_MAXSIZE) {
		if (xmalloc_round_blocksize(len) != len) {
			unsigned b1 = xr->head;	/* First block we added to range */
			unsigned b2 = len - b1;	/* Second block */
			unsigned largest;
			struct xsplit *xs;

			largest = MAX(b1, b2);
			xs = xmalloc_split_info(largest);

			if (xs->larger <= largest) {
				/* Coalescing will not do better than current situation */
				XSTATS_LOCK;
				xstats.xgc_coalescing_useless++;
				XSTATS_UNLOCK;
				return TRUE;		/* Will not attempt any coalescing */
			}
		}
	}

	/*
	 * Blocks can be coalesced, make sure there is room in the targeted
	 * bucket(s).
	 */

	if G_UNLIKELY(!xgc_block_is_freeable(len, xgctx, TRUE)) {
		XSTATS_LOCK;
		xstats.xgc_coalescing_failed++;
		XSTATS_UNLOCK;
		return TRUE;			/* Will not attempt any coalescing */
	}

	xr->strategy = XGC_ST_COALESCE;

	if (xmalloc_debugging(3)) {
		t_debug("XM GC [%p, %p[ (%zu bytes, %u blocks) will be coalesced",
			xr->start, xr->end, ptr_diff(xr->end, xr->start), xr->blocks);
	}

	return FALSE;				/* Keep range */
}

struct xgc_processed {
	size_t coalesced;		/* Amount of blocks coalesced */
	size_t pages;			/* Amount of pages freed */
};

/**
 * Execute the strategy we came up with for the range.
 */
static void
xgc_range_process(void *key, void *data)
{
	struct xgc_range *xr = key;
	struct xgc_processed *xp = data;
	size_t len;
	void *p;

	p = deconstify_pointer(xr->start);
	len = ptr_diff(xr->end, xr->start);

	switch (xr->strategy) {
	case XGC_ST_COALESCE:
		xmalloc_freelist_insert(p, len, TRUE, XM_COALESCE_NONE);
		XSTATS_LOCK;
		xstats.xgc_coalesced_blocks += xr->blocks;
		xstats.xgc_coalesced_memory += len;
		xstats.xgc_blocks_collected--;	/* One block is put back */
		XSTATS_UNLOCK;
		xp->coalesced += xr->blocks;
		break;
	case XGC_ST_FREE_PAGES:
		{
			void *end = ptr_add_offset(p, len);
			void *q;
			size_t pages;

			if (xr->head != 0) {
				xmalloc_freelist_insert(p, xr->head, TRUE, XM_COALESCE_NONE);
				XSTATS_LOCK;
				xstats.xgc_blocks_collected--;	/* One block is put back */
				XSTATS_UNLOCK;
			}

			p = ptr_add_offset(p, xr->head);
			q = ptr_add_offset(end, -xr->tail);

			if (!xmalloc_freecore(p, ptr_diff(q, p))) {
				/*
				 * Can only happen for sbrk()-allocated core and we made
				 * sure this was VMM memory during strategy elaboration.
				 */
				t_error_from(_WHERE_, "unxepected core release error");
			}

			if (xr->tail != 0) {
				xmalloc_freelist_insert(q, xr->tail, TRUE, XM_COALESCE_NONE);
				if (0 == xr->head || xr->blocks > 1) {
					XSTATS_LOCK;
					xstats.xgc_blocks_collected--;	/* One block is put back */
					XSTATS_UNLOCK;
				}
			}

			pages = vmm_page_count(ptr_diff(q, p));
			XSTATS_LOCK;
			xstats.xgc_pages_collected += pages;
			XSTATS_UNLOCK;
			xp->pages += pages;
		}
		break;
	default:
		g_assert_not_reached();
	}
}

/**
 * Freelist fragment collector.
 *
 * Long-running programs can call this routine on a regular basis to reassemble
 * and free-up pages which are completely held in the freelist, althrough they
 * may be split as many individual free blocks.
 *
 * On-the-fly block coalescing is also performed to fight memory fragmentation
 * and avoid a high number of (unused) small blocks unable to satisfy demand
 * for larger blocks.
 *
 * Short-running programs do not need to bother at all.
 */
void
xgc(void)
{
	static time_t last_run, next_run;
	static spinlock_t xgc_slk = SPINLOCK_INIT;
	time_t now;
	unsigned i;
	size_t blocks;
	tm_t start;
	double start_cpu = 0.0;
	struct xgc_allocator xga;
	struct xgc_context xgctx;
	struct xgc_processed processed;
	void const **tmp;
	erbtree_t rbt;

	if (!xmalloc_vmm_is_up)
		return;

	if (!spinlock_try(&xgc_slk))
		return;

	/*
	 * Limit calls to one per second or to 1% of the execution time, as
	 * computed at the end (by setting the ``next_run'' variable).
	 */

	now = tm_time();
	if (last_run == now) {
		XSTATS_LOCK;
		xstats.xgc_throttled++;
		XSTATS_UNLOCK;
		goto done;
	};
	last_run = now;

	if (now < next_run) {
		XSTATS_LOCK;
		xstats.xgc_time_throttled++;
		XSTATS_UNLOCK;
		goto done;
	}

	tm_now_exact(&start);
	start_cpu = tm_cputime(NULL, NULL);

	XSTATS_LOCK;
	xstats.xgc_runs++;
	XSTATS_UNLOCK;

	/*
	 * From now on we cannot use any other memory allocator but VMM, since
	 * any memory allocation by this thread that would hit the freelist would
	 * trigger havoc: messing with our identified pages by using pointers that
	 * belong to them.
	 *
	 * We therefore use xgc_alloc() when we need to allocate dynamic memory,
	 * and this memory does not need to be individually freed but will be
	 * reclaimed as a whole through xgc_free_all() at the end of the garbage
	 * collection.
	 */

	blocks = 0;
	ZERO(&xgctx);
	ZERO(&xga);
	ZERO(&processed);

	/*
	 * Pass 1a: expand buckets that were flagged too small for coalescing,
	 * shrink buckets that are too large.
	 */

	for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];

		G_PREFETCH_R(&xfreelist[i + 1]);
		G_PREFETCH_R(&xfreelist[i + 1].lock);
		G_PREFETCH_W(&xgctx.locked[i + 1]);

		/*
		 * We do not keep buckets locked during this phase since extension
		 * or shrinking will cause further locks to be taken. Given other
		 * threads could be holding these locks and attempt to also grab one
		 * of the buckets we locked earlier in the sequence, that could lead
		 * to a deadlock.
		 */

		if G_UNLIKELY(fl->expand) {
			mutex_lock(&fl->lock);
			if G_UNLIKELY(fl->expand) {
				mutex_unlock(&fl->lock);
				continue;
			}
			if (xmalloc_debugging(1)) {
				t_debug("XM GC resizing freelist #%zu (cap=%zu, cnt=%zu)",
					xfl_index(fl), fl->capacity, fl->count);
			}
			xfl_extend(fl);
			XSTATS_LOCK;
			xstats.xgc_bucket_expansions++;
			XSTATS_UNLOCK;
			mutex_unlock(&fl->lock);
		} else if (
			fl->capacity > XM_BUCKET_MINSIZE &&
			delta_time(now, fl->last_shrink) > XMALLOC_XGC_SHRINK_PERIOD &&
			(
				0 == fl->count ||
				fl->capacity - fl->count >= XM_BUCKET_INCREMENT ||
				fl->capacity / fl->count >= 2
			)
		) {
			mutex_lock(&fl->lock);
			if G_UNLIKELY(
				fl->count != 0 &&
				fl->capacity - fl->count < XM_BUCKET_INCREMENT &&
				fl->capacity / fl->count < 2
			) {
				mutex_unlock(&fl->lock);
				continue;
			}
			fl->shrinking = TRUE;
			if (xfl_shrink(fl)) {
				XSTATS_LOCK;
				xstats.xgc_bucket_shrinkings++;
				XSTATS_UNLOCK;
			}
			fl->shrinking = FALSE;
			mutex_unlock(&fl->lock);
		}
	}

	/*
	 * Pass 1b: lock all buckets, compute largest bucket usage and record
	 * the available room in each bucket.
	 */

	for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];

		G_PREFETCH_R(&xfreelist[i + 1].count);
		G_PREFETCH_R(&xgctx.locked[i + 1]);
		G_PREFETCH_W(&xgctx.available[i + 1]);
		G_PREFETCH_W(&xgctx.count[i + 1]);

		if (!mutex_trylock(&fl->lock))
			continue;

		xgctx.locked[i] = TRUE;			/* Will keep bucket locked */

		if G_UNLIKELY(fl->count > xgctx.largest)
			xgctx.largest = fl->count;

		xgctx.available[i] = fl->capacity - fl->count;
		xgctx.count[i] = fl->count;
	}

	/*
	 * Pass 2: computes coalesced ranges for all the blocks.
	 */

	erbtree_init(&rbt, xgc_range_cmp, offsetof(struct xgc_range, node));

	for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];
		size_t j, blksize;

		if (!xgctx.locked[i])
			continue;

		g_assert(size_is_non_negative(fl->count));
		g_assert(size_is_non_negative(fl->sorted));
		g_assert(fl->count >= fl->sorted);

		blksize = fl->blocksize;		/* Actual physical block size */

		for (j = 0; j < fl->count; j++) {
			const void *p = fl->pointers[j];

			g_assert(p != NULL);		/* Or freelist corrupted */

			blocks++;
			xgc_block_add(&rbt, p, blksize, &xga);
		}
	}

	if (xmalloc_debugging(0)) {
		size_t ranges = erbtree_count(&rbt);
		t_debug("XM GC freelist holds %zu block%s defining %zu range%s",
			blocks, 1 == blocks ? "" : "s", ranges, 1 == ranges ? "" : "s");
	}

	/*
	 * Pass 3: decide on the fate of all the identified ranges.
	 */

	erbtree_foreach_remove(&rbt, xgc_range_strategy, &xgctx);

	if (xmalloc_debugging(0)) {
		size_t ranges = erbtree_count(&rbt);
		t_debug("XM GC left with %zu range%s to process",
			ranges, 1 == ranges ? "" : "s");
	}

	if (0 == erbtree_count(&rbt))
		goto unlock;

	/*
	 * Pass 4: strip blocks falling in ranges for which we have a strategy.
	 */

	xstats.xgc_collected++;

	tmp = vmm_alloc(xgctx.largest * sizeof(void *));

	for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];
		size_t j, blksize, old_count, sorted_stripped;
		void const **q = tmp;

		if (!xgctx.locked[i])
			continue;

		blksize = fl->blocksize;		/* Actual physical block size */
		old_count = fl->count;
		sorted_stripped = 0;

		/*
		 * Avoid O(n^2) operations by copying pointers we keep to a temporary
		 * buffer and then back to the bucket, requiring at most 2*n copies,
		 * regardless of the amount of stripped pointers and their location.
		 */

		g_assert(old_count <= xgctx.largest);

		for (j = 0; j < old_count; j++) {
			const void *p = fl->pointers[j];
			struct xgc_range key, *xr;

			G_PREFETCH_R(&fl->pointers[j + 1]);

			key.start = p;
			key.end = const_ptr_add_offset(p, +1);
			xr = erbtree_lookup(&rbt, &key);

			if (NULL == xr) {
				*q++ = p;
				continue;
			}

			XSTATS_LOCK;
			xstats.xgc_blocks_collected++;
			XSTATS_UNLOCK;

			fl->count--;
			if (j < fl->sorted)
				sorted_stripped++;		/* fl->pointers[] not updated yet */

			XSTATS_LOCK;
			xstats.freelist_blocks--;
			xstats.freelist_memory -= blksize;
			XSTATS_UNLOCK;
		}

		/*
		 * Copy back the kept items, if we removed anything.
		 */

		g_assert(UNSIGNED(q - tmp) == fl->count);	/* Accurate count */

		if (old_count != fl->count) {
			fl->sorted -= sorted_stripped;

			g_assert(size_is_non_negative(fl->count));
			g_assert(size_is_non_negative(fl->sorted));
			g_assert(fl->count >= fl->sorted);
			g_assert(fl->count < xgctx.largest);

			memcpy(fl->pointers, tmp, fl->count * sizeof fl->pointers[0]);
		}
	}

	vmm_free(tmp, xgctx.largest * sizeof(void *));

	/*
	 * Pass 5: execute the strategy.
	 */

	erbtree_foreach(&rbt, xgc_range_process, &processed);

	/*
	 * Pass 6: unlock buckets (in reverse order, for assertions).
	 */

unlock:
	for (i = G_N_ELEMENTS(xfreelist); i != 0; i--) {
		G_PREFETCH_W(&xfreelist[i - 2]);
		G_PREFETCH_W(&xfreelist[i - 2].lock);
		if (xgctx.locked[i - 1]) {
			struct xfreelist *fl = &xfreelist[i - 1];
			mutex_unlock(&fl->lock);
		}
	}

	xgc_free_all(&xga);

	/*
	 * Make sure we're not spending more than 1% of our running time in
	 * the GC, on average.  Since we're running once per second, this means
	 * we cannot allow a running time of more than 10 ms.
	 */

	{
		tm_t end;
		double end_cpu, real_elapsed, cpu_elapsed, elapsed;
		int increment;

		end_cpu = tm_cputime(NULL, NULL);
		tm_now_exact(&end);

		real_elapsed = tm_elapsed_us(&end, &start);
		cpu_elapsed = (end_cpu - start_cpu) * 1e6;	/* In usecs */
		if (end_cpu != 0.0 && real_elapsed > 2.0 * cpu_elapsed)
			elapsed = cpu_elapsed;
		else
			elapsed = (cpu_elapsed + real_elapsed) / 2.0;
		increment = elapsed <= 10000 ? 1 : (elapsed / 10000);
		next_run = now + increment;

		if (xmalloc_debugging(0)) {
			t_debug("XM GC took %'u usecs (CPU=%'u usecs) "
				"coalesced-blocks=%zu, freed-pages=%zu, next in %d sec%s",
				(uint) real_elapsed, (uint) cpu_elapsed,
				processed.coalesced, processed.pages,
				increment, 1 == increment ? "" : "s");
		}
	}

done:
	spinunlock(&xgc_slk);
}

/**
 * Signal that we're about to close down all activity.
 */
G_GNUC_COLD void
xmalloc_pre_close(void)
{
	/*
	 * It's still safe to log, however it's going to get messy with all
	 * the memory freeing activity.  Better avoid such clutter.
	 */

	safe_to_log = FALSE;		/* Turn logging off */
}

/**
 * Called later in the initialization chain once the properties have
 * been loaded.
 */
G_GNUC_COLD void
xmalloc_post_init(void)
{
	/*
	 * For the most part, the heap memory allocated before the VMM layer was
	 * brought up will NOT be reclaimable.  It is therefore lost, which
	 * mandates an unconditional message.
	 *
	 * Early use of malloc() can be the result of early stdio activity, but
	 * it really depends on platforms and conditions found during the early
	 * initializations.
	 *
	 * We have to use t_info() to prevent any memory allocation during logging.
	 * It is OK at this point since the VMM layer is now up.
	 */

	if (sbrk_allocated != 0) {
		t_info("malloc() allocated %zu bytes of heap (%zu remain)",
			sbrk_allocated, ptr_diff(current_break, lowest_break));
	}

	if (xmalloc_debugging(0)) {
		t_info("XM using %ld freelist buckets", (long) XMALLOC_FREELIST_COUNT);
	}
}

/**
 * Signal that we should stop freeing memory to the freelist.
 *
 * This is mostly useful during final cleanup when xmalloc() replaces malloc().
 */
G_GNUC_COLD void
xmalloc_stop_freeing(void)
{
	memusage_free_null(&xstats.user_mem);
	xmalloc_no_freeing = TRUE;
}

/**
 * Signal that we should stop freeing memory via wfree().
 *
 * This is mostly useful during final cleanup once wdestroy() has been called.
 */
G_GNUC_COLD void
xmalloc_stop_wfree(void)
{
	xmalloc_no_wfree = TRUE;
}

/**
 * Dump xmalloc usage statistics to specified logging agent.
 */
G_GNUC_COLD void
xmalloc_dump_usage_log(struct logagent *la, unsigned options)
{
	if (NULL == xstats.user_mem) {
		log_warning(la, "XM user memory usage stats not configured");
	} else {
		memusage_summary_dump_log(xstats.user_mem, la, options);
	}
}

/**
 * Dump xmalloc statistics to specified log agent.
 */
G_GNUC_COLD void
xmalloc_dump_stats_log(logagent_t *la, unsigned options)
{
	struct xstats stats;
#define DUMP(x)	log_info(la, "XM %s = %s", #x,		\
	(options & DUMP_OPT_PRETTY) ?					\
		uint64_to_gstring(stats.x) : uint64_to_string(stats.x))

	XSTATS_LOCK;
	stats = xstats;		/* struct copy under lock protection */
	XSTATS_UNLOCK;

	DUMP(allocations);
	DUMP(allocations_zeroed);
	DUMP(allocations_aligned);
	DUMP(allocations_plain);
	DUMP(alloc_via_freelist);
	DUMP(alloc_via_walloc);
	DUMP(alloc_via_vmm);
	DUMP(alloc_via_sbrk);
	DUMP(alloc_via_thread_pool);
	DUMP(freeings);
	DUMP(free_sbrk_core);
	DUMP(free_sbrk_core_released);
	DUMP(free_vmm_core);
	DUMP(free_coalesced_vmm);
	DUMP(free_walloc);
	DUMP(free_thread_pool);
	DUMP(free_foreign_thread_pool);
	DUMP(sbrk_alloc_bytes);
	DUMP(sbrk_freed_bytes);
	DUMP(sbrk_wasted_bytes);
	DUMP(vmm_alloc_pages);
	DUMP(vmm_split_pages);
	DUMP(vmm_thread_pages);
	DUMP(vmm_freed_pages);
	DUMP(aligned_via_freelist);
	DUMP(aligned_via_freelist_then_vmm);
	DUMP(aligned_via_vmm);
	DUMP(aligned_via_vmm_subpage);
	DUMP(aligned_via_zone);
	DUMP(aligned_via_xmalloc);
	DUMP(aligned_freed);
	DUMP(aligned_free_false_positives);
	DUMP(aligned_zones_created);
	DUMP(aligned_zones_destroyed);
	DUMP(aligned_overhead_bytes);
	DUMP(aligned_zone_blocks);
	DUMP(aligned_zone_memory);
	DUMP(aligned_vmm_blocks);
	DUMP(aligned_vmm_memory);
	DUMP(reallocs);
	DUMP(realloc_noop);
	DUMP(realloc_inplace_vmm_shrinking);
	DUMP(realloc_inplace_shrinking);
	DUMP(realloc_inplace_extension);
	DUMP(realloc_coalescing_extension);
	DUMP(realloc_relocate_vmm_fragment);
	DUMP(realloc_relocate_vmm_shrinked);
	DUMP(realloc_relocate_smart_attempts);
	DUMP(realloc_relocate_smart_success);
	DUMP(realloc_regular_strategy);
	DUMP(realloc_from_thread_pool);
	DUMP(realloc_wrealloc);
	DUMP(realloc_converted_from_walloc);
	DUMP(realloc_promoted_to_walloc);
	DUMP(freelist_insertions);
	DUMP(freelist_insertions_no_coalescing);
	DUMP(freelist_bursts);
	DUMP(freelist_burst_insertions);
	DUMP(freelist_plain_insertions);
	DUMP(freelist_unsorted_insertions);
	DUMP(freelist_coalescing_ignore_burst);
	DUMP(freelist_coalescing_ignore_vmm);
	DUMP(freelist_coalescing_ignored);
	DUMP(freelist_coalescing_done);
	DUMP(freelist_coalescing_failed);
	DUMP(freelist_linear_lookups);
	DUMP(freelist_binary_lookups);
	DUMP(freelist_short_yes_lookups);
	DUMP(freelist_short_no_lookups);
	DUMP(freelist_partial_sorting);
	DUMP(freelist_full_sorting);
	DUMP(freelist_avoided_sorting);
	DUMP(freelist_sorted_superseding);
	DUMP(freelist_split);
	DUMP(freelist_nosplit);
	DUMP(freelist_blocks);
	DUMP(freelist_memory);
	DUMP(xgc_runs);
	DUMP(xgc_throttled);
	DUMP(xgc_time_throttled);
	DUMP(xgc_collected);
	DUMP(xgc_blocks_collected);
	DUMP(xgc_pages_collected);
	DUMP(xgc_coalesced_blocks);
	DUMP(xgc_coalesced_memory);
	DUMP(xgc_coalescing_useless);
	DUMP(xgc_coalescing_failed);
	DUMP(xgc_page_freeing_failed);
	DUMP(xgc_bucket_expansions);
	DUMP(xgc_bucket_shrinkings);
	DUMP(user_memory);
	DUMP(user_blocks);

#undef DUMP
}

/**
 * Dump freelist status to specified log agent.
 */
G_GNUC_COLD void
xmalloc_dump_freelist_log(logagent_t *la)
{
	size_t i, j;
	uint64 bytes = 0;
	size_t blocks = 0;
	size_t largest = 0;
	struct {
		size_t chunks;
		uint64 freebytes;
		size_t freeblocks;
		size_t shared;
	} tstats[XM_THREAD_COUNT];

	for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];

		if (0 == fl->capacity)
			continue;

		bytes += fl->blocksize * fl->count;
		blocks = size_saturate_add(blocks, fl->count);

		if (0 != fl->count)
			largest = fl->blocksize;

		if (fl->sorted == fl->count) {
			log_info(la, "XM freelist #%zu (%zu bytes): cap=%zu, "
				"cnt=%zu, lck=%zu",
				i, fl->blocksize, fl->capacity, fl->count,
				mutex_held_depth(&fl->lock));
		} else {
			log_info(la, "XM freelist #%zu (%zu bytes): cap=%zu, "
				"sort=%zu/%zu, lck=%zu",
				i, fl->blocksize, fl->capacity, fl->sorted, fl->count,
				mutex_held_depth(&fl->lock));
		}
	}

	ZERO(&tstats);

	for (j = 0; j < XM_THREAD_COUNT; j++) {
		for (i = 0; i < XMALLOC_CHUNKHEAD_COUNT; i++) {
			struct xchunkhead *ch = &xchunkhead[i][j];
			link_t *lk;
			size_t tchunks = 0, tcap = 0, tcnt = 0;

			if (ch->shared)
				tstats[j].shared++;

			if (0 == elist_count(&ch->list))
				continue;

			for (lk = elist_first(&ch->list); lk != NULL; lk = elist_next(lk)) {
				struct xchunk *xck = elist_data(&ch->list, lk);

				tstats[j].chunks++;
				tstats[j].freebytes += xck->xc_count * xck->xc_size;
				tstats[j].freeblocks += xck->xc_count;
				tchunks++;
				tcap += xck->xc_capacity;
				tcnt += xck->xc_count;
			}

			log_info(la, "XM chunklist #%zu (%zu bytes, stid=%zu): cap=%zu, "
				"cnt=%zu, chk=%zu, shr=%c",
					i, ch->blocksize, j, tcap, tcnt, tchunks,
					ch->shared ? 'y' : 'n');
		}
	}

	log_info(la, "XM freelist holds %s bytes (%s) spread among %zu block%s",
		uint64_to_string(bytes), short_size(bytes, FALSE),
		blocks, 1 == blocks ? "" : "s");

	log_info(la, "XM freelist largest block is %zu bytes", largest);

	for (j = 0; j < XM_THREAD_COUNT; j++) {
		size_t pool;

		if (0 == tstats[j].chunks)
			continue;

		log_info(la, "XM thread #%zu holds %s bytes (%s) spread "
			"among %zu block%s", j,
			uint64_to_string(tstats[j].freebytes),
			short_size(tstats[j].freebytes, FALSE),
			tstats[j].freeblocks, 1 == tstats[j].freeblocks ? "" : "s");

		pool = size_saturate_mult(tstats[j].chunks, xmalloc_pagesize);

		log_info(la, "XM thread #%zu uses a pool of %zu bytes (%s, %zu page%s)",
			j, pool, short_size(pool, FALSE),
			tstats[j].chunks, 1 == tstats[j].chunks ? "" : "s");

		if (0 != tstats[j].shared) {
			log_warning(la, "XM thread #%zu has %zu size%s requiring locking",
				j, tstats[j].shared, 1 == tstats[j].shared ? "" : "s");
		}
	}
}

/**
 * Dump xmalloc statistics.
 */
G_GNUC_COLD void
xmalloc_dump_stats(void)
{
	s_info("XM running statistics:");
	xmalloc_dump_stats_log(log_agent_stderr_get(), 0);
	s_info("XM freelist status:");
	xmalloc_dump_freelist_log(log_agent_stderr_get());
}

#ifdef XMALLOC_IS_MALLOC
/***
 *** The following routines are only defined when xmalloc() replaces malloc()
 *** because glib 2.x uses these routines internally to allocate memory and
 *** expects this memory to be freed eventually by calling free().
 ***
 *** Since we are also trapping free(), we need to be able to handle these
 *** pointers correctly in free().  There is no need to bother with realloc()
 *** because none of the memory allocated there is supposed to be resized.
 ***
 *** Glib 2.x makes heavy use of posix_memalign() calls for small blocks and
 *** therefore it is necessary to implement strategies to limit the memory
 *** overhead per block, along with memory fragmentation.
 ***/

/*
 * To be efficient for regular use cases where the allocated memory is aligned
 * on the system's page boundary, we keep track of the base addresses and the
 * size of the corresponding blocks in a sorted table.
 *
 * Memory with alignment requirements larger than a page boundary are handled
 * by allocating larger zones where we're certain to find alignment, then
 * by releasing the parts that are not required.
 *
 * Memory with alignment requirement smaller than a page boundary are handled
 * by three different techniques:
 *
 * 1. For sizes larger or equal to the page size, allocate pages and waste the
 *    excess part at the tail of the last allocated page.
 *
 * 2. For alignments larger than or equal to XALIGN_MINSIZE and a size such
 *    as size <= alignment and size > alignment/2, use sub-blocks of
 *    alignment bytes crammed from a system page, as handled by xzalloc().
 *
 * 3. For all other cases, allocate through the freelist a larger zone and then
 *    put back the excess to the freelist, which can cause fragmentation!
 */

/**
 * Description of aligned memory blocks we keep track of.
 */
struct xaligned {
	const void *start;
	void *pdesc;	/**< struct xdesc* holds information on the page(s) */
};

static struct xaligned *aligned;	/**< All known aligned blocks and pages */
static size_t aligned_count;
static size_t aligned_capacity;

static spinlock_t xmalloc_zone_slk = SPINLOCK_INIT;
static spinlock_t xmalloc_xa_slk = SPINLOCK_INIT;

/**
 * Type of pages that we can describe.
 */
enum xpage_type {
	XPAGE_SET,
	XPAGE_ZONE
};

/**
 * Description of descriptor type held in the aligned array.
 */
struct xdesc_type {
	enum xpage_type type;	/**< Type of structure (have distinct sizes) */
};

/**
 * Descriptor for a page set.
 */
struct xdesc_set {
	enum xpage_type type;	/* MUST be first for structural equivalence */
	size_t len;				/**< Length in bytes of the page set */
};

/**
 * Descriptor for an allocation zone.
 *
 * Zones are linked together to make sure we can quickly find a page with
 * free blocks.
 */
struct xdesc_zone {
	enum xpage_type type;		/* MUST be first for structural equivalence */
	struct xdesc_zone *next;	/**< Next zone with same alignment */
	struct xdesc_zone *prev;	/**< Previous zone with same alignment */
	void *arena;				/**< Allocated zone arena */
	bit_array_t *bitmap;		/**< Allocation bitmap in page */
	size_t alignment;			/**< Zone alignment (also the block size) */
	size_t nblocks;				/**< Amount of blocks in the zone */
};

struct xdesc_zone **xzones;		/**< Array of known zones */
size_t xzones_capacity;			/**< Amount of zones in array */

/**
 * Descriptor type string.
 */
static const char *
xdesc_type_str(enum xpage_type type)
{
	switch (type) {
	case XPAGE_SET:		return "set";
	case XPAGE_ZONE:	return "zone";
	}

	return "UNKNOWN";
}

/**
 * Free a page descriptor.
 *
 * @param pdesc		page descriptor to free
 * @param p			aligned address for which we had the descriptor (logging)
 */
static void
xdesc_free(void *pdesc, const void *p)
{
	struct xdesc_type *xt = pdesc;

	if (xmalloc_debugging(2)) {
		size_t len = 0;

		switch (xt->type) {
		case XPAGE_SET:
			{
				struct xdesc_set *xs = pdesc;
				len = xs->len;
			}
			break;
		case XPAGE_ZONE:
			len = xmalloc_pagesize;
			break;
		}
		t_debug("XM forgot aligned %s %p (%zu bytes)",
			xdesc_type_str(xt->type), p, len);
	}

	switch (xt->type) {
	case XPAGE_SET:
		XSTATS_LOCK;
		xstats.aligned_overhead_bytes -= sizeof(struct xdesc_set);
		XSTATS_UNLOCK;
		break;
	case XPAGE_ZONE:
		XSTATS_LOCK;
		xstats.aligned_overhead_bytes -= sizeof(struct xdesc_zone);
		XSTATS_UNLOCK;
		break;
	}

	xfree(pdesc);
}

/**
 * Descriptor type string of an aligned entry.
 */
static const char *
xalign_type_str(const struct xaligned *xa)
{
	struct xdesc_type *xt;

	g_assert(xa != NULL);
	g_assert(xa->pdesc != NULL);

	xt = xa->pdesc;
	return xdesc_type_str(xt->type);
}

/**
 * Lookup for a page within the aligned page array.
 *
 * If ``low_ptr'' is non-NULL, it is written with the index where insertion
 * of a new item should happen (in which case the returned value must be -1).
 *
 * @return index within the array where ``p'' is stored, * -1 if not found.
 */
static G_GNUC_HOT size_t
xa_lookup(const void *p, size_t *low_ptr)
{
	size_t low = 0, high = aligned_count - 1;
	size_t mid = low + (high - low) / 2;

	/* Binary search */

	for (;;) {
		const struct xaligned *item;

		if G_UNLIKELY(low > high || high > SIZE_MAX / 2) {
			mid = -1;		/* Not found */
			break;
		}

		item = &aligned[mid];

		if (p > item->start)
			low = mid + 1;
		else if (p < item->start)
			high = mid - 1;
		else
			break;				/* Found */

		mid = low + (high - low) / 2;
		G_PREFETCH_R(&aligned[mid].start);
	}

	if (low_ptr != NULL)
		*low_ptr = low;

	return mid;
}

/**
 * Delete slot ``idx'' within the aligned array.
 */
static void
xa_delete_slot(size_t idx)
{
	g_assert(size_is_positive(aligned_count));
	g_assert(size_is_non_negative(idx) && idx < aligned_count);
	g_assert(aligned[idx].pdesc != NULL);

	xdesc_free(aligned[idx].pdesc, aligned[idx].start);
	aligned_count--;

	if (idx < aligned_count) {
		memmove(&aligned[idx], &aligned[idx + 1],
			(aligned_count - idx) * sizeof(aligned[0]));
	}
}

/**
 * Extend the "aligned" array.
 */
static void
xa_align_extend(void)
{
	size_t new_capacity;

	new_capacity = size_saturate_mult(aligned_capacity, 2);

	if (0 == new_capacity)
		new_capacity = 2;

	aligned = xrealloc(aligned, new_capacity * sizeof aligned[0]);
	XSTATS_LOCK;
	xstats.aligned_overhead_bytes +=
		(new_capacity - aligned_capacity) * sizeof aligned[0];
	XSTATS_UNLOCK;
	aligned_capacity = new_capacity;

	if (xmalloc_debugging(1)) {
		t_debug("XM aligned array capacity now %zu, starts at %p (%zu bytes)",
			aligned_capacity, (void *) aligned,
			new_capacity * sizeof aligned[0]);
	}
}

/**
 * Insert tuple (p, pdesc) in the list of aligned pages.
 */
static void
xa_insert(const void *p, void *pdesc)
{
	size_t idx;

	g_assert(size_is_non_negative(aligned_count));
	g_assert(aligned_count <= aligned_capacity);
	g_assert(vmm_page_start(p) == p);

	spinlock(&xmalloc_xa_slk);

	if G_UNLIKELY(aligned_count >= aligned_capacity)
		xa_align_extend();

	/*
	 * Compute insertion index in the sorted array.
	 *
	 * At the same time, this allows us to make sure we're not dealing with
	 * a duplicate insertion.
	 */

	if G_UNLIKELY((size_t ) -1 != xa_lookup(p, &idx)) {
		t_error_from(_WHERE_, "page %p already in aligned list (as page %s)",
			p, xalign_type_str(&aligned[idx]));
	}

	g_assert(size_is_non_negative(idx) && idx <= aligned_count);

	/*
	 * Shift items if we're not inserting at the last position in the array.
	 */

	g_assert(aligned != NULL);
	g_assert(idx <= aligned_count);

	if G_LIKELY(idx < aligned_count) {
		memmove(&aligned[idx + 1], &aligned[idx],
			(aligned_count - idx) * sizeof aligned[0]);
	}

	aligned_count++;
	aligned[idx].start = p;
	aligned[idx].pdesc = pdesc;

	spinunlock(&xmalloc_xa_slk);
}

/**
 * Insert tuple (p, set) in the list of aligned pages.
 */
static void
xa_insert_set(const void *p, size_t size)
{
	struct xdesc_set *xs;

	g_assert(size_is_positive(size));

	XMALLOC(xs);
	xs->type = XPAGE_SET;
	xs->len = size;

	xa_insert(p, xs);

	XSTATS_LOCK;
	xstats.aligned_overhead_bytes += sizeof *xs;
	xstats.vmm_alloc_pages += vmm_page_count(size);
	xstats.user_blocks++;
	xstats.user_memory += size;
	xstats.aligned_vmm_blocks++;
	xstats.aligned_vmm_memory += size;
	XSTATS_UNLOCK;
	memusage_add(xstats.user_mem, size);

	if (xmalloc_debugging(2)) {
		t_debug("XM recorded aligned %p (%zu bytes)", p, size);
	}
}

/**
 * Initialize the array of zones.
 */
static G_GNUC_COLD void
xzones_init(void)
{
	g_assert(NULL == xzones);

	xzones_capacity = highest_bit_set(xmalloc_pagesize) - XALIGN_SHIFT;
	g_assert(size_is_positive(xzones_capacity));

	xzones = xmalloc0(xzones_capacity * sizeof xzones[0]);
	XSTATS_LOCK;
	xstats.aligned_overhead_bytes += xzones_capacity * sizeof xzones[0];
	XSTATS_UNLOCK;
}

/**
 * Allocate a zone with blocks of ``alignment'' bytes each.
 *
 * @return new page descriptor for the zone.
 */
static struct xdesc_zone *
xzget(size_t alignment)
{
	struct xdesc_zone *xz;
	void *arena;
	size_t nblocks;

	g_assert(size_is_positive(alignment));
	g_assert(alignment < xmalloc_pagesize);

	arena = vmm_core_alloc(xmalloc_pagesize);
	nblocks = xmalloc_pagesize / alignment;

	g_assert(nblocks >= 2);		/* Because alignment < pagesize */

	xz = xmalloc0(sizeof *xz);
	xz->type = XPAGE_ZONE;
	xz->alignment = alignment;
	xz->arena = arena;
	xz->bitmap = xmalloc0(BIT_ARRAY_BYTE_SIZE(nblocks));
	xz->nblocks = nblocks;

	xa_insert(arena, xz);

	XSTATS_LOCK;
	xstats.vmm_alloc_pages++;
	xstats.aligned_zones_created++;
	xstats.aligned_overhead_bytes += sizeof *xz + BIT_ARRAY_BYTE_SIZE(nblocks);
	XSTATS_UNLOCK;

	if (xmalloc_debugging(2)) {
		t_debug("XM recorded aligned %p (%zu bytes) as %zu-byte zone",
			arena, xmalloc_pagesize, alignment);
	}

	return xz;
}

static void
xzdestroy(struct xdesc_zone *xz)
{
	/*
	 * Unlink structure from the zone list.
	 */

	if (xz->prev != NULL)
		xz->prev->next = xz->next;
	if (xz->next != NULL)
		xz->next->prev = xz->prev;

	if (xmalloc_debugging(2)) {
		t_debug("XM discarding %szone for %zu-byte blocks at %p",
			(NULL == xz->next && NULL == xz->prev) ? "last " : "",
			xz->alignment, xz->arena);
	}

	if G_UNLIKELY(NULL == xz->prev) {
		size_t zn;

		/*
		 * Was head of list, need to update the zone's head.
		 */

		zn = highest_bit_set(xz->alignment >> XALIGN_SHIFT);

		g_assert(xzones != NULL);
		g_assert(zn < xzones_capacity);
		g_assert(xzones[zn] == xz);

		xzones[zn] = xz->next;
	}

	xfree(xz->bitmap);
	vmm_core_free(xz->arena, xmalloc_pagesize);

	XSTATS_LOCK;
	xstats.vmm_freed_pages++;
	xstats.aligned_zones_destroyed++;
	xstats.aligned_overhead_bytes -= BIT_ARRAY_BYTE_SIZE(xz->nblocks);
	XSTATS_UNLOCK;
}

/**
 * Allocate an aligned block from a zone.
 *
 * @return pointer of allocated block.
 */
static void *
xzalloc(size_t alignment)
{
	size_t zn;
	struct xdesc_zone *xz, *xzf;
	size_t bn;
	void *p;

	g_assert(size_is_positive(alignment));
	g_assert(alignment >= XALIGN_MINSIZE);
	g_assert(is_pow2(alignment));
	g_assert(alignment < xmalloc_pagesize);

	spinlock(&xmalloc_zone_slk);

	if G_UNLIKELY(NULL == xzones)
		xzones_init();

	zn = highest_bit_set(alignment >> XALIGN_SHIFT);

	g_assert(zn < xzones_capacity);

	xz = xzones[zn];

	if G_UNLIKELY(NULL == xz)
		xz = xzones[zn] = xzget(alignment);

	/*
	 * Find which zone in the list has any free block available and compute
	 * the number of the first block available in the zone.
	 */

	bn = (size_t) -1;

	for (xzf = xz; xzf != NULL; xzf = xzf->next) {
		bn = bit_array_first_clear(xzf->bitmap, 0, xzf->nblocks - 1);
		if G_LIKELY((size_t) -1 != bn)
			break;
	}

	/*
	 * If we haven't found any zone with a free block, allocate a new one.
	 */

	if G_UNLIKELY((size_t) -1 == bn) {
		xzf = xzget(alignment);
		bn = 0;						/* Grab first block */
		g_assert(NULL == xz->prev);
		xzones[zn] = xzf;			/* New head of list */
		xzf->next = xz;
		xz->prev = xzf;
		xz = xzf;					/* Update head */
	}

	/*
	 * Mark selected block as used and compute the block's address.
	 */

	bit_array_set(xzf->bitmap, bn);
	p = ptr_add_offset(xzf->arena, bn * xzf->alignment);

	if (xmalloc_debugging(3)) {
		t_debug("XM allocated %zu-byte aligned block #%zu at %p from %p",
			xzf->alignment, bn, p, xzf->arena);
	}

	/*
	 * Place the zone where we allocated a block from at the top of the
	 * list unless there are no more free blocks in the zone or the block
	 * is already at the head.
	 *
	 * Because we attempt to keep zones with free blocks at the start of
	 * the list, it is unlikely we have to move around the block in the list.
	 */

	if G_UNLIKELY(bn != xzf->nblocks - 1 && xzf != xz) {
		if (xmalloc_debugging(2)) {
			t_debug("XM moving %zu-byte zone %p to head of zone list",
				xzf->alignment, xzf->arena);
		}
		g_assert(xzf->prev != NULL);		/* Not at start of list */
		g_assert(NULL == xz->prev);			/* Old head of list */
		xzf->prev->next = xzf->next;
		if (xzf->next != NULL)
			xzf->next->prev = xzf->prev;
		xzf->next = xz;
		xzf->prev = NULL;
		xz->prev = xzf;
		xzones[zn] = xzf;					/* New head of list */
	}

	XSTATS_LOCK;
	xstats.user_blocks++;
	xstats.user_memory += alignment;
	xstats.aligned_zone_blocks++;
	xstats.aligned_zone_memory += alignment;
	XSTATS_UNLOCK;
	memusage_add(xstats.user_mem, alignment);

	spinunlock(&xmalloc_zone_slk);

	return p;
}

/**
 * Free block from zone.
 *
 * @return TRUE if zone was all clear and freed.
 */
static bool
xzfree(struct xdesc_zone *xz, const void *p)
{
	size_t bn;

	g_assert(vmm_page_start(p) == xz->arena);

	spinlock(&xmalloc_zone_slk);

	bn = ptr_diff(p, xz->arena) / xz->alignment;

	g_assert(bn < xz->nblocks);
	g_assert(bit_array_get(xz->bitmap, bn));

	bit_array_clear(xz->bitmap, bn);

	XSTATS_LOCK;
	xstats.user_blocks--;
	xstats.user_memory -= xz->alignment;
	xstats.aligned_zone_blocks--;
	xstats.aligned_zone_memory -= xz->alignment;
	XSTATS_UNLOCK;
	memusage_remove(xstats.user_mem, xz->alignment);

	if ((size_t) -1 == bit_array_last_set(xz->bitmap, 0, xz->nblocks - 1)) {
		xzdestroy(xz);
		spinunlock(&xmalloc_zone_slk);
		return TRUE;
	} else {
		spinunlock(&xmalloc_zone_slk);
		return FALSE;
	}
}

/**
 * Compute size of block allocated on an aligned boundary, supposedly.
 *
 * @return length of physical block, 0 if block was not allocated by the
 * aligning layer.
 */
static size_t
xalign_allocated(const void *p)
{
	size_t idx;
	const void *start;
	struct xdesc_type *xt;
	bool lookup_was_safe;
	size_t len = 0;

	start = vmm_page_start(p);

	lookup_was_safe = spinlock_try(&xmalloc_xa_slk);

	idx = xa_lookup(start, NULL);

	if G_LIKELY((size_t) -1 == idx) {
		if (lookup_was_safe)
			spinunlock(&xmalloc_xa_slk);
		return 0;
	}

	if (!lookup_was_safe) {
		spinlock(&xmalloc_xa_slk);
		idx = xa_lookup(start, NULL);
		g_assert((size_t) -1 != idx);
	}

	xt = aligned[idx].pdesc;

	XSTATS_LOCK;
	xstats.aligned_freed++;
	XSTATS_UNLOCK;

	switch (xt->type) {
	case XPAGE_SET:
		{
			struct xdesc_set *xs = (struct xdesc_set *) xt;

			len = xs->len;
			g_assert(0 != len);
		}
		goto done;
	case XPAGE_ZONE:
		{
			struct xdesc_zone *xz = (struct xdesc_zone *) xt;

			len = xz->alignment;
			g_assert(0 != len);
		}
		goto done;
	}

	g_assert_not_reached();

done:
	spinunlock(&xmalloc_xa_slk);
	return len;
}

/**
 * Checks whether address is that of an aligned page or a sub-block we keep
 * track of and remove memory from the set of tracked blocks when found.
 *
 * @return TRUE if aligned block was found and freed, FALSE otherwise.
 */
static bool
xalign_free(const void *p)
{
	size_t idx;
	const void *start;
	struct xdesc_type *xt;
	bool lookup_was_safe;

	/*
	 * We do not only consider page-aligned pointers because we can allocate
	 * aligned page sub-blocks.  However, they are all located within a page
	 * so the enclosing page will be found if it is a sub-block.
	 */

	start = vmm_page_start(p);

	lookup_was_safe = spinlock_try(&xmalloc_xa_slk);

	idx = xa_lookup(start, NULL);

	if G_LIKELY((size_t) -1 == idx) {
		XSTATS_LOCK;
		xstats.aligned_free_false_positives++;
		XSTATS_UNLOCK;
		if (lookup_was_safe)
			spinunlock(&xmalloc_xa_slk);
		return FALSE;
	}

	if G_UNLIKELY(xmalloc_no_freeing) {
		if (lookup_was_safe)
			spinunlock(&xmalloc_xa_slk);
		return TRUE;
	}

	if (!lookup_was_safe) {
		spinlock(&xmalloc_xa_slk);
		idx = xa_lookup(start, NULL);
		g_assert((size_t) -1 != idx);
	}

	xt = aligned[idx].pdesc;
	XSTATS_LOCK;
	xstats.aligned_freed++;
	XSTATS_UNLOCK;

	switch (xt->type) {
	case XPAGE_SET:
		{
			struct xdesc_set *xs = (struct xdesc_set *) xt;
			size_t len = xs->len;

			g_assert(0 != len);
			xa_delete_slot(idx);
			vmm_core_free(deconstify_pointer(p), len);
			XSTATS_LOCK;
			xstats.vmm_freed_pages += vmm_page_count(len);
			xstats.user_memory -= len;
			xstats.user_blocks--;
			xstats.aligned_vmm_blocks--;
			xstats.aligned_vmm_memory -= len;
			XSTATS_UNLOCK;
			memusage_remove(xstats.user_mem, len);
		}
		goto done;
	case XPAGE_ZONE:
		{
			struct xdesc_zone *xz = (struct xdesc_zone *) xt;

			if (xzfree(xz, p))
				xa_delete_slot(idx);	/* Last block from zone freed */
		}
		goto done;
	}

	g_assert_not_reached();

done:
	spinunlock(&xmalloc_xa_slk);
	return TRUE;
}

/**
 * Block truncation flags, for debugging.
 */
enum truncation {
	TRUNCATION_NONE 		= 0,
	TRUNCATION_BEFORE		= (1 << 0),	
	TRUNCATION_AFTER		= (1 << 1),
	TRUNCATION_BOTH			= (TRUNCATION_BEFORE | TRUNCATION_AFTER)
};

static const char *
xa_truncation_str(enum truncation truncation)
{
	switch (truncation) {
	case TRUNCATION_NONE:	return "";
	case TRUNCATION_BEFORE:	return " with leading truncation";
	case TRUNCATION_AFTER:	return " with trailing truncation";
	case TRUNCATION_BOTH:	return " with side truncations";
	}

	return " with WEIRD truncation";
}

/**
 * Allocates size bytes and places the address of the allocated memory in
 * "*memptr". The address of the allocated memory will be a multiple of
 * "alignment", which must be a power of two and a multiple of sizeof(void *).
 *
 * If size is 0, then returns a pointer that can later be successfully passed
 * to free().
 *
 * @return 0 on success, or an error code (but the global "errno" is not set).
 */
int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *p;
	const char *method = "xmalloc";
	enum truncation truncation = TRUNCATION_NONE;

	if (!is_pow2(alignment))
		return EINVAL;

	if (0 != alignment % sizeof(void *))
		return EINVAL;

	XSTATS_LOCK;
	xstats.allocations_aligned++;
	XSTATS_UNLOCK;

	if G_UNLIKELY(alignment <= XMALLOC_ALIGNBYTES) {
		p = xmalloc(size);
		XSTATS_LOCK;
		xstats.aligned_via_xmalloc++;
		XSTATS_UNLOCK;
		goto done;
	}

	/*
	 * To be able to perform posix_memalign() calls before the VMM is fully up,
	 * use vmm_early_init() to launch the VM layer without notifying xmalloc()
	 * that the VMM is up, so that we do not start to register the garbage
	 * collector yet.
	 *
	 * Until vmm_init() is called, every call to posix_memalign() will cause
	 * this branch to be taken, but this is only a transient state, until
	 * it is safe to call vmm_init() to mark everything as fully initialized.
	 */

	if G_UNLIKELY(!xmalloc_vmm_is_up)
		vmm_early_init();

	/*
	 * If they want to align on some boundary, they better be allocating
	 * a block large enough to minimize waste.  Warn if that is not
	 * the case.
	 */

	if G_UNLIKELY(size <= alignment / 2) {
		if (xmalloc_debugging(0)) {
			t_carp("XM requested to allocate only %zu bytes "
				"with %zu-byte alignment", size, alignment);
		}
	}

	/*
	 * If they're requesting a block aligned to more than a system page size,
	 * allocate enough pages to get a proper alignment and free the rest.
	 */

	if G_UNLIKELY(alignment == xmalloc_pagesize) {
		p = vmm_core_alloc(size);	/* More than we need */
		method = "VMM";

		XSTATS_LOCK;
		xstats.aligned_via_vmm++;
		XSTATS_UNLOCK;

		/*
		 * There is no xmalloc() header for this block, hence we need to
		 * record the address to be able to free() the pointer.
		 */

		xa_insert_set(p, round_pagesize(size));
		goto done;
	} if (alignment > xmalloc_pagesize) {
		size_t rsize = round_pagesize(size);
		size_t nalloc = size_saturate_add(alignment, rsize);
		size_t mask = alignment - 1;
		unsigned long addr;
		void *end;

		p = vmm_core_alloc(nalloc);	/* More than we need */
		method = "VMM";

		XSTATS_LOCK;
		xstats.aligned_via_vmm++;
		XSTATS_UNLOCK;

		/*
		 * Is the address already properly aligned?
		 * If so, we just need to remove the excess pages at the end.
		 */

		addr = pointer_to_ulong(p);

		if (xmalloc_debugging(2)) {
			t_debug("XM alignement requirement %zu, "
				"allocated %zu at %p (%s aligned)",
				alignment, nalloc, p, (addr & ~mask) == addr ? "is" : "not");
		}

		if ((addr & ~mask) == addr) {
			end = ptr_add_offset(p, rsize);
			vmm_core_free(end, size_saturate_sub(nalloc, rsize));
			truncation = TRUNCATION_AFTER;

			if (xmalloc_debugging(2)) {
				t_debug("XM freed trailing %zu bytes at %p",
					size_saturate_sub(nalloc, rsize), end);
			}
		} else {
			void *q, *qend;

			/*
			 * Find next aligned address.
			 */

			addr = size_saturate_add(addr, mask) & ~mask;
			q = ulong_to_pointer(addr);
			end = ptr_add_offset(p, nalloc);

			if (xmalloc_debugging(2)) {
				t_debug("XM aligned %p to 0x%zx yields %p",
					p, alignment, q);
			}

			g_assert(ptr_cmp(q, end) <= 0);
			g_assert(ptr_cmp(ptr_add_offset(q, rsize), end) <= 0);

			/*
			 * Remove excess pages at the beginning and the end.
			 */

			g_assert(ptr_cmp(q, p) > 0);

			vmm_core_free(p, ptr_diff(q, p));				/* Beginning */
			qend = ptr_add_offset(q, rsize);

			if (xmalloc_debugging(2)) {
				t_debug("XM freed leading %zu bytes at %p",
					ptr_diff(q, p), p);
			}

			if (qend != end) {
				vmm_core_free(qend, ptr_diff(end, qend));	/* End */
				truncation = TRUNCATION_BOTH;

				if (xmalloc_debugging(2)) {
					t_debug("XM freed trailing %zu bytes at %p",
						ptr_diff(end, qend), qend);
				}
			} else {
				truncation = TRUNCATION_BEFORE;
			}

			p = q;		/* The selected page */
		}

		/*
		 * There is no xmalloc() header for this block, hence we need to
		 * record the address to be able to free() the pointer.
		 */

		xa_insert_set(p, rsize);
		goto done;
	}

	/*
	 * Requesting alignment of less than a page size is done by allocating
	 * a large block and trimming the unneeded parts.
	 */

	if (size >= xmalloc_pagesize) {
		size_t rsize = round_pagesize(size);

		p = vmm_core_alloc(rsize);		/* Necessarily aligned */

		/*
		 * There is no xmalloc() header for this block, hence we need to
		 * record the address to be able to free() the pointer.
		 * Unfortunately, we cannot trim anything since free() will require
		 * the total size of the allocated VMM block to be in-use.
		 */

		xa_insert_set(p, rsize);
		method = "plain VMM";

		XSTATS_LOCK;
		xstats.aligned_via_vmm++;
		XSTATS_UNLOCK;

		goto done;
	} else if (size > alignment / 2 && size <= alignment) {
		/*
		 * Blocks of a size close to their alignment get allocated from
		 * a dedicated zone to limit fragmentation within the freelist.
		 */

		p = xzalloc(alignment);
		method = "zone";

		XSTATS_LOCK;
		xstats.aligned_via_zone++;
		XSTATS_UNLOCK;

		goto done;
	} else if (
		size >= xmalloc_pagesize / 2 &&
		xmalloc_round_blocksize(size + alignment + XHEADER_SIZE) <=
			xmalloc_pagesize - XMALLOC_SPLIT_MIN
	) {
		size_t len;
		void *start, *u, *end, *uend;
		unsigned long addr;
		size_t mask = alignment - 1;

		g_assert(size < xmalloc_pagesize);

		/*
		 * Allocate at the tail of the page, on the proper alignment boundary.
		 */

		start = vmm_core_alloc(xmalloc_pagesize);
		len = xmalloc_round_blocksize(size + alignment) + XHEADER_SIZE;

		g_assert(len <= xmalloc_pagesize);

		p = ptr_add_offset(start, xmalloc_pagesize - len);
		u = ptr_add_offset(p, XHEADER_SIZE);	/* User pointer */
		addr = pointer_to_ulong(u);

		/*
		 * Align starting user address.
		 */
		
		if ((addr & ~mask) != addr) {
			addr = size_saturate_add(pointer_to_ulong(u), mask) & ~mask;
			u = ulong_to_pointer(addr);
			p = ptr_add_offset(u, -XHEADER_SIZE);
		}

		/*
		 * Put beginning of page back to freelist.
		 */

		if (p != start) {
			size_t before = ptr_diff(p, start);

			g_assert(size_is_positive(before));
			g_assert(before >= XMALLOC_SPLIT_MIN);

			/* Beginning of block, in excess */
			xmalloc_freelist_insert(start, before, FALSE, XM_COALESCE_BEFORE);
			truncation |= TRUNCATION_BEFORE;
		}

		/*
		 * Set up remainder as a malloc block.
		 */

		len = xmalloc_pagesize - ptr_diff(p, start);
		end = ptr_add_offset(start, xmalloc_pagesize);
		uend = ptr_add_offset(p, len);

		g_assert(ptr_diff(uend, end) <= 0);

		/*
		 * If there is excess, put back to freelist.
		 */

		if (uend != end) {
			size_t after = ptr_diff(end, uend);

			g_assert_log(size_is_non_negative(after),
				"p=%p, uend=%p, len=%zu, end=%p", p, uend, len, end);

			if (after >= XMALLOC_SPLIT_MIN) {
				/* End of block, in excess */
				xmalloc_freelist_insert(uend, after,
					FALSE, XM_COALESCE_AFTER);
				truncation |= TRUNCATION_AFTER;
			} else {
				len += after;	/* Not truncated */
			}
		}

		p = xmalloc_block_setup(p, len);	/* User pointer */
		method = "VMM trailing sub-page";

		XSTATS_LOCK;
		xstats.aligned_via_vmm_subpage++;
		XSTATS_UNLOCK;

		goto done;
	} else {
		size_t nalloc, len, blen;
		size_t mask = alignment - 1;
		unsigned long addr;
		void *u, *end;

		/*
		 * We add XHEADER_SIZE to account for the xmalloc() header.
		 *
		 * We add twice the alignment in case the first aligned address is
		 * too close to the start of the block (less than XMALLOC_SPLIT_MIN),
		 * so that we can move to the next aligned address safely.
		 */

		nalloc = size_saturate_add(alignment + alignment, size);
		len = xmalloc_round_blocksize(xmalloc_round(nalloc) + XHEADER_SIZE);

		/*
		 * Attempt to locate a block in the freelist.
		 */

		p = NULL;

		if (len <= XMALLOC_MAXSIZE)
			p = xmalloc_freelist_alloc(len, &nalloc);

		if (p != NULL) {
			end = ptr_add_offset(p, nalloc);
			method = "freelist";

			XSTATS_LOCK;
			xstats.aligned_via_freelist++;
			XSTATS_UNLOCK;
		} else {
			if (len >= xmalloc_pagesize) {
				size_t vlen = round_pagesize(len);

				p = vmm_core_alloc(vlen);
				end = ptr_add_offset(p, vlen);
				method = "freelist, then large VMM";

				XSTATS_LOCK;
				xstats.vmm_alloc_pages += vmm_page_count(vlen);
				XSTATS_UNLOCK;

				if (xmalloc_debugging(1)) {
					t_debug("XM added %zu bytes of VMM core at %p", vlen, p);
				}
			} else {
				p = vmm_core_alloc(xmalloc_pagesize);
				end = ptr_add_offset(p, xmalloc_pagesize);
				method = "freelist, then plain VMM";

				XSTATS_LOCK;
				xstats.vmm_alloc_pages++;
				XSTATS_UNLOCK;

				if (xmalloc_debugging(1)) {
					t_debug("XM added %zu bytes of VMM core at %p",
						xmalloc_pagesize, p);
				}
			}

			XSTATS_LOCK;
			xstats.aligned_via_freelist_then_vmm++;
			XSTATS_UNLOCK;
		}

		g_assert(p != NULL);

		/*
		 * This is the physical block size we want to return in the block
		 * header to flag it as a valid xmalloc()ed one.
		 *
		 * This may not be a valid xmalloc() block size, but that's OK.
		 */

		blen = xmalloc_round(size) + XHEADER_SIZE;

		/*
		 * Is the address already properly aligned?
		 *
		 * If so, we just need to put back the excess at the end into
		 * the freelist.
		 *
		 * The block we are about to return will have a regular xmalloc()
		 * header so it will be free()able normally.  However, we need to
		 * account for aligning the user pointer, not the one where the
		 * block is actually allocated.
		 */

		u = ptr_add_offset(p, XHEADER_SIZE);	/* User pointer */
		addr = pointer_to_ulong(u);

		if ((addr & ~mask) == addr) {
			void *split = ptr_add_offset(p, blen);
			size_t split_len = ptr_diff(end, split);

			g_assert(size_is_non_negative(split_len));

			if (split_len >= XMALLOC_SPLIT_MIN) {
				xmalloc_freelist_insert(split, split_len,
					FALSE, XM_COALESCE_AFTER);
				truncation = TRUNCATION_AFTER;
			} else {
				blen = ptr_diff(end, p);
			}

			p = xmalloc_block_setup(p, blen);	/* User pointer */
		} else {
			void *q, *uend;

			/*
			 * Find next aligned address.
			 */

			addr = size_saturate_add(pointer_to_ulong(u), mask) & ~mask;
		adjusted:
			u = ulong_to_pointer(addr);		/* Aligned user pointer */

			g_assert(ptr_cmp(u, end) <= 0);
			g_assert(ptr_cmp(ptr_add_offset(u, size), end) <= 0);

			/*
			 * Remove excess memory at the beginning and the end.
			 */

			g_assert(ptr_diff(u, p) >= XHEADER_SIZE);

			q = ptr_add_offset(u, -XHEADER_SIZE);	/* Physical block start */

			if (q != p) {
				size_t before = ptr_diff(q, p);

				g_assert(size_is_positive(before));

				/*
				 * If too close from the starting address, move to the next
				 * aligned one, which is safe because we allocated at least
				 * twice the alignment bytes.
				 */

				if G_UNLIKELY(before < XMALLOC_SPLIT_MIN) {
					addr += alignment;
					goto adjusted;
				}

				/* Beginning of block, in excess */
				xmalloc_freelist_insert(p, before, FALSE, XM_COALESCE_BEFORE);
				truncation |= TRUNCATION_BEFORE;
			}

			uend = ptr_add_offset(q, blen);

			if (uend != end) {
				size_t after = ptr_diff(end, uend);

				g_assert_log(size_is_non_negative(after),
					"p=%p, q=%p, blen=%zu, end=%p, uend=%p",
					p, q, blen, end, uend);

				if (after >= XMALLOC_SPLIT_MIN) {
					/* End of block, in excess */
					xmalloc_freelist_insert(uend, after,
						FALSE, XM_COALESCE_AFTER);
					truncation |= TRUNCATION_AFTER;
				} else {
					blen += after;	/* Not truncated */
				}
			}

			p = xmalloc_block_setup(q, blen);	/* User pointer */
		}

		XSTATS_LOCK;
		xstats.user_memory += blen;
		xstats.user_blocks++;
		XSTATS_UNLOCK;
		memusage_add(xstats.user_mem, blen);
	}

done:
	*memptr = p;

	if (xmalloc_debugging(1)) {
		t_debug("XM aligned %p (%zu bytes) on 0x%lx / %zu via %s%s",
			p, size, (unsigned long) alignment,
			alignment, method, xa_truncation_str(truncation));
	}

	/*
	 * Ensure memory is aligned properly.
	 */

	g_assert_log(
		pointer_to_ulong(p) == (pointer_to_ulong(p) & ~(alignment - 1)),
		"p=%p, alignment=%zu, aligned=%p",
		p, alignment,
		ulong_to_pointer(pointer_to_ulong(p) & ~(alignment - 1)));

	return G_UNLIKELY(NULL == p) ? ENOMEM : 0;
}

/**
 * Allocates size bytes and returns a pointer to the allocated memory.
 *
 * The memory address will be a multiple of "boundary", which must be a
 * power of two.
 *
 * @return allocated memory address, NULL on error with errno set.
 */
void *
memalign(size_t boundary, size_t size)
{
	void *p;
	int error;

	g_assert(is_pow2(boundary));

	error = posix_memalign(&p, boundary, size);

	if G_LIKELY(0 == error)
		return p;

	errno = error;
	return NULL;
}

/**
 * Allocates size bytes and returns a pointer to the allocated memory.
 * The memory address will be a multiple of the page size.
 *
 * @return allocated memory address.
 */
void *
valloc(size_t size)
{
	return memalign(xmalloc_pagesize, size);
}

#endif	/* XMALLOC_IS_MALLOC */

/**
 * Ensure freelist if correctly sorted, spot inconsistencies when it isn't.
 *
 * @return number of freelists with problems (0 meaning everything is OK).
 */
size_t
xmalloc_freelist_check(logagent_t *la, unsigned flags)
{
	size_t errors = 0;
	unsigned i;

	for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];
		unsigned j;
		const void *prev = NULL;
		bool bad = FALSE;
		bool unsorted = FALSE;
		bool locked = FALSE;

		if (NULL == fl->pointers)
			continue;

		/*
		 * Only lock buckets when it was explicitly requested.
		 *
		 * If XMALLOC_FLCF_UNLOCKED is specified, we still allow checking of
		 * unlocked buckets, albeit we warn if checking happens without the
		 * lock because we may encounter an inconsistency which does not exist.
		 */

		if (flags & XMALLOC_FLCF_LOCK) {
			if (mutex_trylock_hidden(&fl->lock)) {
				locked = TRUE;
			} else {
				if (0 == (flags & XMALLOC_FLCF_UNLOCKED)) {
					if (flags & (XMALLOC_FLCF_VERBOSE | XMALLOC_FLCF_LOGLOCK)) {
						log_warning(la,
							"XM freelist #%u skipped (already locked)", i);
					}
					continue;
				} else {
					log_warning(la,
						"XM freelist #%u will be checked without lock", i);
				}
			}
		}

		if (fl->capacity < fl->count) {
			if (flags & XMALLOC_FLCF_VERBOSE) {
				log_warning(la,
					"XM freelist #%u has corrupted count %zu (capacity %zu)",
					i, fl->count, fl->capacity);
			}
			bad = TRUE;
		}

		if (!mem_is_valid_range(fl->pointers, fl->capacity * sizeof(void *))) {
			if (flags & XMALLOC_FLCF_VERBOSE) {
				log_warning(la,
					"XM freelist #%u has corrupted pointer %p or capacity %zu",
					i, fl->pointers, fl->capacity);
			}
			bad = TRUE;
		}

		for (j = 0, prev = NULL; j < fl->count; j++) {
			const void *p = fl->pointers[j];
			size_t len;

			if (j > 0 && j < fl->sorted && xm_ptr_cmp(p, prev) <= 0) {
				if (!unsorted) {
					unsorted = TRUE;	/* Emit this info once per list */
					if (flags & XMALLOC_FLCF_VERBOSE) {
						if (fl->count == fl->sorted) {
							log_info(la,
								"XM freelist #%u has %zu item%s fully sorted",
								i, fl->count, 1 == fl->count ? "" : "s");
						} else {
							log_info(la,
								"XM freelist #%u has %zu/%zu item%s sorted",
								i, fl->sorted, fl->count,
								1 == fl->sorted ? "" : "s");
						}
					}
				}
				if (flags & XMALLOC_FLCF_VERBOSE) {
					log_warning(la,
						"XM item #%u p=%p in freelist #%u <= prev %p",
						j, p, i, prev);
				}
				bad = TRUE;
			}

			prev = p;

			if (!xmalloc_is_valid_pointer(p, locked)) {
				if (flags & XMALLOC_FLCF_VERBOSE) {
					log_warning(la,
						"XM item #%u p=%p in freelist #%u is invalid",
						j, p, i);
				}
				bad = TRUE;
				continue;	/* Prudent */
			}

			if (!mem_is_valid_ptr(p)) {
				if (flags & XMALLOC_FLCF_VERBOSE) {
					log_warning(la,
						"XM item #%u p=%p in freelist #%u is unreadable",
						j, p, i);
				}
				bad = TRUE;
				continue;	/* Prudent */
			}

			len = *(size_t *) p;
			if (len != fl->blocksize) {
				if (flags & XMALLOC_FLCF_VERBOSE) {
					log_warning(la,
						"XM item #%u p=%p in freelist #%u (%zu bytes) "
						"has improper length %zu", j, p, i, fl->blocksize, len);
				}
				bad = TRUE;
			}
		}

		if (i > xfreelist_maxidx && fl->count != 0) {
			if (flags & XMALLOC_FLCF_VERBOSE) {
				log_warning(la,
					"XM freelist #%u has %zu items and is above maxidx=%zu",
					i, fl->count, xfreelist_maxidx);
			}
			bad = TRUE;
		}

		if (flags & XMALLOC_FLCF_STATUS) {
			log_debug(la,
				"XM freelist #%u %s", i, bad ? "** CORRUPTED **" : "OK");
		}

		if (bad)
			errors++;

		if (locked)
			mutex_unlock_hidden(&fl->lock);
	}

	return errors;
}

/**
 * In case of crash, dump statistics and make some sanity checks.
 */
static G_GNUC_COLD void
xmalloc_crash_hook(void)
{
	/*
	 * When crashing log handlers will not use stdio nor allocate memory.
	 * Therefore it's OK to be using s_xxx() logging routines here.
	 */

	s_debug("XM heap is [%p, %p[", lowest_break, current_break);
	s_debug("XM xfreelist_maxidx = %zu", xfreelist_maxidx);
#ifdef XMALLOC_IS_MALLOC
	s_debug("XM xzones_capacity = %zu", xzones_capacity);
#endif
	s_debug("XM dumping virtual memory page map:");
	vmm_dump_pmap();
	xmalloc_dump_stats();

	s_debug("XM verifying freelist...");
	xmalloc_freelist_check(log_agent_stderr_get(),
		XMALLOC_FLCF_VERBOSE | XMALLOC_FLCF_LOCK | XMALLOC_FLCF_UNLOCKED);
}

/*
 * Internally, code willing to use xmalloc() ignores whether it is actually
 * trapping malloc, so we need to define suitable wrapping entry points here.
 */
#ifdef XMALLOC_IS_MALLOC
#undef xmalloc
#undef xfree
#undef xrealloc
#undef xcalloc

void *
xmalloc(size_t size)
{
	return malloc(size);
}

void *
xcalloc(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}

void
xfree(void *p)
{
	free(p);
}

void *
xrealloc(void *p, size_t size)
{
	return realloc(p, size);
}

/*
 * For recent MinGW startup, we need to remap strdup() as well to make sure
 * it calls our malloc().  If we let it resolve by Microsoft's C runtime, it
 * will call their malloc(), and we don't want that anyway.
 *
 * This fixed the problem encountered with recent MinGW startup which performed
 * strdup() calls, then called free() on the result.  Because our malloc() was
 * not called by strdup(), free() was raising a panic, letting the application
 * crash before entering main().
 *
 * In any case, on Windows it is better to remap strdup() as well when we supply
 * our own malloc() otherwise memory allocation will be done by Microsoft's
 * routines.
 */
#ifdef MINGW32
char *
strdup(const char *s)
{
	return xstrdup(s);
}
#endif	/* MINGW32 */

#endif	/* XMALLOC_IS_MALLOC */

/* vi: set ts=4 sw=4 cindent:  */
