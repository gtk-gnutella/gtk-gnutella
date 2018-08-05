/*
 * Copyright (c) 2011-2013, Raphael Manfredi
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
 * xmalloc() is thread-safe and will attempt to allocate small-enough blocks
 * from thread-private chunks, resulting in less lock contentions in the main
 * free list and faster operations since thread-private chunks do not need
 * to bother with block coalescing, each chunk handling blocks of the same size.
 *
 * It is completely safe to have a block allocated by a thread freed by another
 * thread, even if the block belongs to a thread-private chunk.  In that case,
 * the freeing is deferred until the owning thread gets a chance to process it
 * to return it to its pool -- there are really no locks on thread-private
 * chunks.
 *
 * @author Raphael Manfredi
 * @date 2011-2013
 */

#include "common.h"

#define XMALLOC_SOURCE

#include "xmalloc.h"

#include "array_util.h"
#include "atomic.h"
#include "bit_array.h"
#include "crash.h"			/* For crash_hook_add(), crash_oom() */
#include "dump_options.h"
#include "elist.h"
#include "endian.h"			/* For UINT32_ROTL() */
#include "entropy.h"
#include "erbtree.h"
#include "evq.h"
#include "hashing.h"
#include "log.h"
#include "mem.h"			/* For mem_is_valid_ptr() */
#include "mempcpy.h"
#include "memusage.h"
#include "misc.h"			/* For short_size() and clamp_strlen() */
#include "mutex.h"
#include "omalloc.h"
#include "once.h"
#include "palloc.h"
#include "pow2.h"
#include "sha1.h"
#include "signal.h"
#include "spinlock.h"
#include "str.h"			/* For str_vbprintf() */
#include "stringify.h"
#include "thread.h"
#include "tm.h"
#include "unsigned.h"
#include "vmm.h"
#include "win32dlp.h"
#include "xsort.h"

#include "override.h"		/* Must be the last header included */

#ifdef USE_MY_MALLOC			/* metaconfig symbol */
#define XMALLOC_IS_MALLOC		/* xmalloc() becomes malloc() */
#endif

#if 0
#define XMALLOC_SORT_SAFETY		/* Adds expensive sort checking assertions */
#endif
#if 0
#define XMALLOC_PTR_SAFETY		/* Adds costly pointer validation */
#endif
#if 0
#define XMALLOC_CHUNK_SAFETY	/* Adds expensive thread chunk checking */
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

#if 8 == XMALLOC_ALIGNBYTES
#define XMALLOC_ALIGNSHIFT		3
#elif 16 == XMALLOC_ALIGNBYTES
#define XMALLOC_ALIGNSHIFT		4
#elif 32 == XMALLOC_ALIGNBYTES
#define XMALLOC_ALIGNSHIFT		5
#elif 64 == XMALLOC_ALIGNBYTES
#define XMALLOC_ALIGNSHIFT		6
#else
#error "unexpected XMALLOC_ALIGNBYTES value"
#endif

/**
 * Header prepended to all allocated objects.
 */
struct xheader {
	size_t length;			/**< Length of the allocated block */
};

/*
 * In order to be able to let the C pre-processor compute the XHEADER_SIZE
 * value, we need to assume that the size of the xheader structure is going
 * to be that of its only field, and that the length of size_t is that of
 * a pointer.  These assumptions are reasonable and are verified by some of
 * the STATIC_ASSERT() lines in xmalloc_vmm_inited().
 */

#define XMALLOC_RND(x)	(((x) + XMALLOC_MASK) & ~XMALLOC_MASK)
#define XHEADER_SIZE	XMALLOC_RND(PTRSIZE)	/* PTRSIZE == sizeof(size_t) */

#if 8 == XHEADER_SIZE
#define XHEADER_SHIFT	3
#elif 16 == XHEADER_SIZE
#define XHEADER_SHIFT	4
#elif 32 == XHEADER_SIZE
#define XHEADER_SHIFT	5
#elif 64 == XHEADER_SIZE
#define XHEADER_SHIFT	6
#else
#error "unexpected XHEADER_SIZE value"
#endif

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
#define XMALLOC_BUCKET_SHIFT	MAX(XMALLOC_ALIGNSHIFT, XHEADER_SHIFT)
#define XMALLOC_BLOCK_SIZE		256
#define XMALLOC_BLOCK_SHIFT		8

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

/*
 * Any requested block with a size larger than XMALLOC_MAXSIZE will
 * be allocated through the VMM layer (in an effort to limit virtual
 * memory space fragmentation).
 */
#define XMALLOC_VIA_VMM(z)	((z) > XMALLOC_MAXSIZE)

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
	elist_t list;			/**< Chunks with free blocks (struct xchunk) */
	elist_t full;			/**< Chunks without free blocks (struct xchunk) */
} xchunkhead[XMALLOC_CHUNKHEAD_COUNT][XM_THREAD_COUNT];

/**
 * Per-thread indication of whether thread pool allocation is disabled.
 *
 * A thread known to allocate only a limited amount of memory during its
 * operation can give a hint to the malloc layer that no new chunk should
 * be added to the thread pool and that allocation should therefore be done
 * from the main free list.
 */
static uint8 xpool_disabled[XM_THREAD_COUNT];

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
	uint32 xc_tag;				/* Tag value derived from above 3 fields */
	uint32 xc_cksum;			/* Checksum of previous 4 header fields */
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
 * Per-bucket temporary list of blocks whose insertion to the bucket was
 * deferred due to the bucket being already locked by another thread.
 */
struct xdefer {
	spinlock_t lock;		/**< Thread-safe lock */
	size_t count;			/**< Amount of blocks chained */
	void *head;				/**< Head of block list to return to bucket */
};

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
	struct xdefer deferred;	/**< Deferred blocks */
	void **pointers;		/**< Sorted array of pointers */
	size_t count;			/**< Amount of pointers held */
	size_t capacity;		/**< Maximum amount of pointers that can be held */
	size_t blocksize;		/**< Block size handled by this list */
	size_t sorted;			/**< Amount of leading sorted pointers */
	time_t last_shrink;		/**< Last shrinking attempt */
	mutex_t lock;			/**< Bucket locking */
	uint extending:1;		/**< Is being extended */
	uint shrinking:1;		/**< Is being shrinked */
	uint retrofiting:1;		/**< Are we retrofiting deferred blocks? */
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
 * Thread-local pools used for allocations are single pages allocated by
 * the VMM layer.  In order to keep a reasonable amount of pages pre-allocated,
 * and avoid costly freeing operations (especially when coalescing is done),
 * we use a pool allocator to keep some pages around.
 */
static pool_t *xpages_pool;
static once_flag_t xpages_pool_inited;

/**
 * Internal statistics collected.
 *
 * The AU64() fields are atomically updated (without taking the stats lock).
 */
static struct xstats {
	uint64 allocations;					/**< Total # of allocations */
	AU64(allocations_zeroed);			/**< Total # of zeroing allocations */
	uint64 allocations_aligned;			/**< Total # of aligned allocations */
	AU64(allocations_heap);				/**< Total # of xhmalloc() calls */
	AU64(allocations_physical);			/**< Total # of xpmalloc() calls */
	AU64(allocations_in_handler);		/**< Allocations from sig handler */
	uint64 alloc_via_freelist;			/**< Allocations from freelist */
	uint64 alloc_via_vmm;				/**< Allocations from VMM */
	uint64 alloc_via_sbrk;				/**< Allocations from sbrk() */
	uint64 alloc_via_thread_pool;		/**< Allocations from thread chunks */
	AU64(alloc_forced_user_vmm);		/**< Allocations forced standalone VMM */
	uint64 freeings;					/**< Total # of freeings */
	AU64(freeings_in_handler);			/**< Freeings from sig handler */
	AU64(free_sbrk_core);				/**< Freeing sbrk()-allocated core */
	uint64 free_via_vmm;				/**< Standalone VMM block freed */
	uint64 free_sbrk_core_released;		/**< Released sbrk()-allocated core */
	uint64 free_vmm_core;				/**< Freeing VMM-allocated core */
	AU64(free_coalesced_vmm);			/**< VMM-freeing of coalesced block */
	uint64 free_thread_pool;			/**< Freeing a thread-specific block */
	AU64(free_foreign_thread_pool);		/**< Freeing accross threads */
	uint64 sbrk_alloc_bytes;			/**< Bytes allocated from sbrk() */
	uint64 sbrk_freed_bytes;			/**< Bytes released via sbrk() */
	uint64 sbrk_wasted_bytes;			/**< Bytes wasted to align sbrk() */
	uint64 vmm_alloc_pages;				/**< Core pages allocated via VMM */
	uint64 vmm_alloc_user_pages;		/**< User pages allocated via VMM */
	uint64 vmm_split_pages;				/**< VMM pages that were split */
	AU64(vmm_thread_pages);				/**< VMM pages for thread chunks */
	uint64 vmm_freed_pages;				/**< Core pages released via VMM */
	uint64 vmm_freed_user_pages;		/**< User pages released via VMM */
	uint64 vmm_user_blocks;				/**< Standalone VMM blocks still present */
	uint64 vmm_total_user_blocks;		/**< Total standalone VMM blocks created */
	uint64 aligned_via_freelist;		/**< Aligned memory from freelist */
	uint64 aligned_via_freelist_then_vmm;	/**< Aligned memory from VMM */
	uint64 aligned_via_vmm;				/**< Idem, no freelist tried */
	uint64 aligned_via_vmm_subpage;		/**< Idem, no freelist tried */
	uint64 aligned_via_zone;			/**< Aligned memory from zone */
	uint64 aligned_via_xmalloc;			/**< Aligned memory from xmalloc */
	AU64(aligned_lookups);				/**< Lookups for aligned memory info */
	uint64 aligned_freed;				/**< Freed aligned memory */
	AU64(aligned_free_false_positives);	/**< Aligned pointers not aligned */
	size_t aligned_zones_capacity;		/**< Max # of possible align zones */
	size_t aligned_zones_count;			/**< Actually created align zones */
	uint64 aligned_arenas_created;		/**< Arenas created for alignment */
	uint64 aligned_arenas_destroyed;		/**< Alignment arenas destroyed */
	uint64 aligned_overhead_bytes;		/**< Structural overhead */
	uint64 aligned_zone_blocks;			/**< Individual blocks in zone */
	uint64 aligned_zone_memory;			/**< Total memory used by zone blocks */
	uint64 aligned_vmm_blocks;			/**< Individual blocks as VMM pages */
	uint64 aligned_vmm_memory;			/**< Total memory used by aligned VMM */
	AU64(reallocs);						/**< Total # of reallocations */
	AU64(realloc_noop);					/**< Reallocs not doing anything */
	AU64(realloc_noop_same_vmm);		/**< Reallocs keeping VMM fragment */
	AU64(realloc_vmm);					/**< Reallocating a VMM block */
	AU64(realloc_vmm_moved);			/**< VMM relocation via a vmm_move() */
	uint64 realloc_via_vmm_shrink;		/**< VMM region inplace shrinking */
	uint64 realloc_via_vmm_move_shrink;	/**< Realloc with move + inplace shrink */
	uint64 realloc_inplace_shrinking;		/**< Idem but from freelist */
	uint64 realloc_inplace_extension;		/**< Reallocs not moving data */
	uint64 realloc_coalescing_extension;	/**< Reallocs through coalescing */
	AU64(realloc_relocate_smart_attempts);	/**< Attempts to move pointer */
	AU64(realloc_relocate_smart_success);	/**< Smart placement was OK */
	AU64(realloc_regular_strategy);			/**< Regular resizing strategy */
	AU64(realloc_from_thread_pool);			/**< Original was in thread pool */
	AU64(freelist_insertions);				/**< Insertions in freelist */
	AU64(freelist_insertions_no_coalescing);/**< Coalescing forbidden */
	uint64 freelist_insertions_deferred;	/**< Deferred insertions */
	uint64 freelist_deferred_processed;		/**< Deferred blocks processed */
	AU64(freelist_bursts);					/**< Burst detection events */
	AU64(freelist_burst_insertions);		/**< Burst insertions in freelist */
	AU64(freelist_plain_insertions);		/**< Plain appending in freelist */
	AU64(freelist_unsorted_insertions);		/**< Insertions in unsorted list */
	AU64(freelist_coalescing_ignore_burst);	/**< Ignored due to free burst */
	AU64(freelist_coalescing_ignore_vmm);	/**< Ignored due to VMM block */
	AU64(freelist_coalescing_ignored);		/**< Smart algo chose to ignore */
	AU64(freelist_coalescing_done);		/**< Successful coalescings */
	AU64(freelist_coalescing_failed);	/**< Failed coalescings */
	AU64(freelist_linear_lookups);		/**< Linear lookups in unsorted list */
	AU64(freelist_binary_lookups);		/**< Binary lookups in sorted list */
	AU64(freelist_short_yes_lookups);	/**< Quick find in sorted list */
	AU64(freelist_short_no_lookups);	/**< Quick miss in sorted list */
	AU64(freelist_partial_sorting);		/**< Freelist tail sorting */
	AU64(freelist_full_sorting);		/**< Freelist sorting of whole bucket */
	AU64(freelist_avoided_sorting);		/**< Avoided full sorting of bucket */
	AU64(freelist_sorted_superseding);	/**< Last sorted replaced last item */
	AU64(freelist_split);				/**< Block splitted on allocation */
	AU64(freelist_nosplit);				/**< Block not splitted on allocation */
	uint64 freelist_blocks;				/**< Amount of blocks in free list */
	uint64 freelist_memory;				/**< Memory held in freelist */
	AU64(xgc_runs);						/**< Amount of xgc() runs */
	AU64(xgc_time_throttled);			/**< Throttled due to running time */
	uint64 xgc_collected;				/**< Amount of xgc() calls collecting */
	uint64 xgc_avoided;					/**< Avoided xgc() due to no change */
	AU64(xgc_blocks_collected);			/**< Amount of blocks collected */
	uint64 xgc_pages_collected;			/**< Amount of pages collected */
	uint64 xgc_coalesced_blocks;		/**< Amount of blocks coalesced */
	uint64 xgc_coalesced_memory;		/**< Amount of memory we coalesced */
	AU64(xgc_coalescing_useless);		/**< Useless coalescings of 2 blocks */
	AU64(xgc_coalescing_failed);		/**< Failed block coalescing */
	AU64(xgc_page_freeing_failed);		/**< Cannot free embedded pages */
	AU64(xgc_bucket_expansions);		/**< How often do we expand buckets */
	AU64(xgc_bucket_shrinkings);		/**< How often do we shrink buckets */
	size_t user_memory;					/**< Current user memory allocated */
	size_t user_blocks;					/**< Current amount of user blocks */
	memusage_t *user_mem;				/**< EMA tracker */
	/* Counter to prevent digest from being the same twice in a row */
	AU64(xmalloc_stats_digest);
} xstats;
static spinlock_t xstats_slk = SPINLOCK_INIT;

#define XSTATS_LOCK			spinlock_hidden(&xstats_slk)
#define XSTATS_UNLOCK		spinunlock_hidden(&xstats_slk)

#define XSTATS_INCX(x)		AU64_INC(&xstats.x)
#define XSTATS_DECX(x)		AU64_DEC(&xstats.x)

static uint32 xmalloc_debug;		/**< Debug level */
static bool safe_to_log;			/**< True when we can log */
static bool xmalloc_vmm_is_up;		/**< True when the VMM layer is up */
static size_t sbrk_allocated;		/**< Bytes allocated with sbrk() */
static size_t sbrk_alignment;		/**< Adjustments for sbrk() alignment */
static bool xmalloc_grows_up = TRUE;	/**< Is the VM space growing up? */
static bool xmalloc_no_freeing;		/**< No longer release memory */
static bool xmalloc_crashing;		/**< Crashing mode, minimal servicing */
static long xmalloc_freelist_stamp;	/**< Updated each time we add to freelist */

static void *lowest_break;			/**< Lowest heap address we know */
static void *current_break;			/**< Current known heap break */
static size_t xmalloc_pagesize;		/**< Cached page size */
static once_flag_t xmalloc_freelist_inited;
static once_flag_t xmalloc_xgc_installed;
static once_flag_t xmalloc_vmm_setup_done;
static once_flag_t xmalloc_early_inited;

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
static void xfl_process_deferred(struct xfreelist *fl);

/*
 * Do we have deferred blocks that we can process right now?
 */
static inline bool
xfl_has_deferred(const struct xfreelist * const fl)
{
	return 0 != fl->deferred.count && !fl->extending && !fl->retrofiting;
}

#define xmalloc_debugging(lvl)	G_UNLIKELY(xmalloc_debug > (lvl) && safe_to_log)

#define XM_INVALID_PTR		((void *) 0xdeadbeef)

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
void G_COLD
xmalloc_crash_mode(void)
{
	xmalloc_crashing = TRUE;
	xmalloc_no_freeing = TRUE;
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
 * Pool allocation routine.
 */
static void *
xpages_pool_alloc(size_t len)
{
	return vmm_core_alloc(len);
}

/**
 * Pool freeing routine.
 */
static void
xpages_pool_free(void *p, size_t len, bool fragment)
{
	(void) fragment;

	vmm_core_free(p, len);
}

/**
 * Initialize the memory pool, used to allocate thread memory chunks.
 */
static void
xpages_pool_init(void)
{
	xpages_pool = pool_create("xmalloc thread chunks",
		xmalloc_pagesize, xpages_pool_alloc, xpages_pool_free, NULL);
}

/**
 * Install periodic idle callback to run the freelist compactor.
 */
static void G_COLD
xmalloc_xgc_install(void)
{
	evq_raw_idle_add(xmalloc_idle_collect, NULL);
}

/**
 * Minimal setup once the VMM layer is started.
 */
static void G_COLD
xmalloc_vmm_setup_once(void)
{
	xmalloc_grows_up = vmm_grows_upwards();
	xmalloc_pagesize = compat_pagesize();
	xmalloc_freelist_setup();
}

static void G_COLD
xmalloc_vmm_setup(void)
{
	once_flag_run(&xmalloc_vmm_setup_done, xmalloc_vmm_setup_once);
}

/**
 * Called when the VMM layer has been initialized.
 */
void G_COLD
xmalloc_vmm_inited(void)
{
	STATIC_ASSERT(sizeof(struct xheader) == sizeof(size_t));
	STATIC_ASSERT(XHEADER_SIZE == xmalloc_round(sizeof(struct xheader)));
	STATIC_ASSERT(PTRSIZE == sizeof(size_t));
	STATIC_ASSERT(IS_POWER_OF_2(XMALLOC_ALIGNBYTES));
	STATIC_ASSERT(IS_POWER_OF_2(XMALLOC_BUCKET_FACTOR));
	STATIC_ASSERT(IS_POWER_OF_2(XMALLOC_BLOCK_SIZE));
	STATIC_ASSERT(0 == (XMALLOC_FACTOR_MASK & XMALLOC_SPLIT_MIN));
	STATIC_ASSERT(XMALLOC_SPLIT_MIN / 2 == XMALLOC_BUCKET_FACTOR);
	STATIC_ASSERT(XMALLOC_ALIGNBYTES == (1 << XMALLOC_ALIGNSHIFT));
	STATIC_ASSERT(XHEADER_SIZE == (1 << XHEADER_SHIFT));
	STATIC_ASSERT(XMALLOC_BLOCK_SIZE == (1 << XMALLOC_BLOCK_SHIFT));

	xmalloc_vmm_is_up = TRUE;
	safe_to_log = TRUE;
	xmalloc_vmm_setup();

#ifdef XMALLOC_IS_MALLOC
	vmm_malloc_inited();
#endif
}

/**
 * Tells the xmalloc() layer that it runs in long-term process.
 *
 * A short-term process is not going to require aggressive strategies to
 * compact unused memory, hence it will not require that we install xgc().
 */
void G_COLD
xmalloc_long_term(void)
{
	/*
	 * We wait for the VMM layer to be up before we install the xgc() idle
	 * thread in an attempt to tweak the self-bootstrapping path of this
	 * library and avoid creating some objects too early: we wish to avoid
	 * sbrk() allocation if possible.
	 *
	 * The GC is now only installed then vmm_set_strategy() is called to
	 * install a long-term allocation strategy.  Hence we know that the VMM
	 * layer is up.
	 *		--RAM, 2015-12-02
	 */

	once_flag_run(&xmalloc_xgc_installed, xmalloc_xgc_install);
}

/**
 * Initialize the VMM layer minimally if not already done, and setup the
 * thread allocation pools.
 */
static void G_COLD
xmalloc_early_init(void)
{
	vmm_early_init();
	xmalloc_vmm_setup();
}

/**
 * Called to log which malloc() is used on the specified log agent.
 */
void G_COLD
xmalloc_show_settings_log(logagent_t *la)
{
	log_info(la, "using %s", xmalloc_is_malloc() ?
		"our own malloc() replacement" : "native malloc()");

	/*
	 * On Windows, we're performing dynamic patching of loaded libraries
	 * to redirect them to our malloc().
	 */

#ifdef MINGW32
	win32dlp_show_settings_log(la);
#endif
}

/**
 * Called to log which malloc() is used.
 *
 * @attention
 * This is called very early, and is used to record crash hooks for the
 * file as a side effect.
 */
void G_COLD
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

	if G_UNLIKELY(XMALLOC_VIA_VMM(len))
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
			s_error("cannot get initial heap break address: %m");
		}
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
	spinlock_hidden(&xmalloc_sbrk_slk);		/* Hidden for FreeBSD */
bypass:
	p = sbrk(len);

	/*
	 * When running under valgrind, we want to avoid false reports of
	 * uninitialized memory reads.  Since xmalloc_thread_get_chunk() can
	 * probe memory that has been allocated on the head, we need to make
	 * sure everything we get from sbrk() is indeed initialized to 0.
	 */

#ifndef ALLOW_UNINIT_VALUES
	if G_LIKELY((void *) -1 != p)
		memset(p, 0, len);
#endif

	/*
	 * Ensure pointer is aligned.
	 */

	if G_UNLIKELY(xmalloc_round(p) != (size_t) p && (void *) -1 != p) {
		size_t missing = xmalloc_round(p) - (size_t) p;
		char *q;
		g_assert(size_is_positive(missing));
		q = sbrk(missing);

#ifndef ALLOW_UNINIT_VALUES
		if G_LIKELY((void *) -1 != q)
			memset(q, 0, len);
#endif

		if G_UNLIKELY((void *) -1 == q) {
			p = (void *) -1;
		} else {
			g_assert(ptr_add_offset(p, len) == q);	/* Contiguous zone */
			p = ptr_add_offset(p, missing);
			XSTATS_LOCK;
			xstats.sbrk_wasted_bytes += missing;
			XSTATS_UNLOCK;
			sbrk_alignment += missing;
		}
	}
#else
	(void) locked;
	s_error("cannot allocate core on this platform (%zu bytes)", len);
	return p = NULL;
#endif

	if ((void *) -1 == p) {
		if (locked)
			spinunlock_hidden(&xmalloc_sbrk_slk);
		crash_oom("cannot allocate more core (%zu bytes): %m", len);
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
	xstats.alloc_via_sbrk++;
	xstats.sbrk_alloc_bytes += len;
	XSTATS_UNLOCK;
	if (locked)
		spinunlock_hidden(&xmalloc_sbrk_slk);

	if (xmalloc_debugging(1) && can_log) {
		s_debug("XM added %zu bytes of heap core at %p", len, p);
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
	 * In order to solve the bootstrapping problem on FreeBSD, where the
	 * thread layer calls malloc(), we need to grab this lock hidden so
	 * that we do not attempt to enter the thread layer and call thread_self().
	 *		--RAM, 2013-12-01
	 */

	spinlock_hidden(&xmalloc_sbrk_slk);

	/*
	 * If the address lies within the break, there's nothing to do, unless
	 * the freed segment is at the end of the break.  The memory is not lost
	 * forever: it should be put back into the free list by the caller.
	 */

	if G_UNLIKELY(ptr_cmp(ptr, current_break) < 0) {
		const void *end = const_ptr_add_offset(ptr, len);

		XSTATS_INCX(free_sbrk_core);

		/*
		 * Don't assume we're the only ones using sbrk(), check the actual
		 * break, not our cached value.
		 */

		if G_UNLIKELY(end == sbrk(0)) {
			void *old_break;
			bool success = FALSE;

			if (xmalloc_debugging(0)) {
				s_debug("XM releasing %zu bytes of trailing heap at %p",
					len, ptr);
			}

#ifdef HAS_SBRK
			old_break = sbrk(-len);
			if ((void *) -1 == old_break) {
				s_warning("XM cannot decrease break by %zu bytes: %m", len);
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
			spinunlock_hidden(&xmalloc_sbrk_slk);
			return success;
		} else {
			if (xmalloc_debugging(0)) {
				s_debug("XM releasing %zu bytes in middle of heap at %p",
					len, ptr);
			}
			spinunlock_hidden(&xmalloc_sbrk_slk);
			return FALSE;		/* Memory not freed */
		}
	}

	if (xmalloc_debugging(1))
		s_debug("XM releasing %zu bytes of core", len);

	spinunlock_hidden(&xmalloc_sbrk_slk);

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
		return locked || vmm_is_native_pointer(p) || xmalloc_isheap(ARYLEN(p));
	} else {
		return xmalloc_isheap(ARYLEN(p));
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
			if (xmalloc_isheap(ARYLEN(p))) {
				return "valid heap pointer!";	/* Should never happen */
			} else {
				return "neither VMM nor heap pointer";
			}
		}
	} else {
		if (xmalloc_isheap(ARYLEN(p))) {
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

	if G_UNLIKELY(XMALLOC_VIA_VMM(len))
		return round_pagesize(len) == len;

	rounded = xmalloc_round_blocksize(len);

	if G_LIKELY(rounded == len)
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

	/* We already know len <= XMALLOC_MAXSIZE here */

	if (len > XMALLOC_FACTOR_MAXSIZE)
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
static inline G_PURE size_t
xch_block_size_idx(size_t idx)
{
	return (idx + 1) << XMALLOC_ALIGNSHIFT;
}

/**
 * Find chunk index for a given block size.
 */
static inline G_PURE size_t
xch_find_chunkhead_index(size_t len)
{
	g_assert(size_is_positive(len));
	g_assert(xmalloc_round(len) == len);
	g_assert(len <= XM_THREAD_MAXSIZE);
	g_assert(len >= XMALLOC_ALIGNBYTES);

	return (len >> XMALLOC_ALIGNSHIFT) - 1;
}

/**
 * Computes index of free list in the array.
 */
static inline size_t
xfl_index(const struct xfreelist *fl)
{
	size_t idx;

	idx = fl - &xfreelist[0];
	g_assert(size_is_non_negative(idx) && idx < N_ITEMS(xfreelist));

	return idx;
}

/**
 * Computes physical size of blocks in a given free list index.
 */
static inline G_PURE size_t
xfl_block_size_idx(size_t idx)
{
	return (idx <= XMALLOC_BUCKET_CUTOVER) ?
		XMALLOC_BUCKET_FACTOR * (idx + 1 + XMALLOC_BUCKET_OFFSET) :
		XMALLOC_FACTOR_MAXSIZE +
			XMALLOC_BLOCK_SIZE * (idx - XMALLOC_BUCKET_CUTOVER);
}

/**
 * Find freelist index for a given block size.
 */
static inline G_PURE size_t
xfl_find_freelist_index(size_t len)
{
	g_assert_log(size_is_positive(len), "len=%zd", len);
	g_assert_log(xmalloc_round_blocksize(len) == len, "len=%zu", len);
	g_assert_log(!XMALLOC_VIA_VMM(len), "len=%zu", len);
	g_assert_log(len >= XMALLOC_SPLIT_MIN, "len=%zu", len);

	return (len <= XMALLOC_FACTOR_MAXSIZE) ?
		(len >> XMALLOC_BUCKET_SHIFT) - 1 - XMALLOC_BUCKET_OFFSET :
		XMALLOC_BUCKET_CUTOVER +
			((len - XMALLOC_FACTOR_MAXSIZE) >> XMALLOC_BLOCK_SHIFT);
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

	assert_mutex_is_owned(&fl->lock);

	g_assert(array != NULL);
	g_assert_log(size_is_positive(len), "len=%zu", len);
	g_assert(size_is_non_negative(fl->count));

	ptr = fl->pointers;							/* Can be NULL */
	used = sizeof(void *) * fl->count;
	size = sizeof(void *) * fl->capacity;
	capacity = len / sizeof(void *);

	g_assert(ptr != NULL || 0 == used);
	g_assert((size == 0) == (NULL == ptr));
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
	 * Make sure there is no deadlock possible.  Inserting in the bucket
	 * will require grabing its mutex, and if another thread has it whilst
	 * it is waiting for the mutex we're holding for this bucket we're
	 * presently extending or shrinking, boom!.  Deadlock...
	 * We'll need to defer insertion in the freelist until after we released
	 * our fl->lock mutex.
	 *		--RAM, 2012-11-04
	 *
	 * Added xfl_insert_careful() to make sure there are no deadlocks, which
	 * can occur anytime we attempt to lock two freelist buckets in the same
	 * execution thread.
	 *		--RAM, 2013-09-27
	 */

	/*
	 * HACK ALERT: using "size != 0" instead of original "ptr != NULL" because
	 * the latter causes assertions failures under gcc 4.9 with optimizations:
	 * the "ptr != NULL" test wrongly succeeds but size is 0 (and ptr is
	 * actually NULL hence the test should never have succeeded).  Could be a
	 * wrong pointer aliasing computation by the optimizer, hence using "size"
	 * is safe because it's an integer value?
	 *		--RAM, 2014-08-26
	 */

	if (size != 0)		/* i.e. ptr != NULL as well, see assertions above */
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

	assert_mutex_is_owned(&fl->lock);

	g_assert(fl->count < fl->capacity);
	g_assert(size_is_non_negative(fl->count));
	g_assert(fl->shrinking);

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
			s_debug("XM recursion during shrinking of freelist #%zu "
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
			s_debug("XM discarding allocated bucket %p (%zu bytes) for "
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
			s_debug("XM discarding allocated bucket %p (%zu bytes) for "
				"freelist #%zu: same size as old bucket",
				new_ptr, allocated_size, xfl_index(fl));
		}
		xmalloc_freelist_add(new_ptr, allocated_size, XM_COALESCE_ALL);

		return FALSE;
	}

	xfl_replace_pointer_array(fl, new_ptr, allocated_size);

	if (xmalloc_debugging(1)) {
		s_debug("XM shrunk freelist #%zu (%zu-byte block) to %zu items"
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
			g_assert(xfreelist_maxidx < N_ITEMS(xfreelist));

			if (xmalloc_debugging(2)) {
				s_debug("XM max frelist index decreased to %zu",
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
		fl->capacity > (fl->count + fl->deferred.count) &&
		fl->capacity - (fl->count + fl->deferred.count) >=
			XM_BUCKET_INCREMENT &&
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

#ifdef XMALLOC_PTR_SAFETY
/**
 * Make sure pointer within freelist is valid.
 */
static void
assert_valid_freelist_pointer(const struct xfreelist *fl, const void *p)
{
	if (!xmalloc_is_valid_pointer(p, TRUE)) {
		s_error_from(_WHERE_,
			"invalid pointer %p in %zu-byte malloc freelist: %s",
			p, fl->blocksize, xmalloc_invalid_ptrstr(p));
	}

	if (*(size_t *) p != fl->blocksize) {
		size_t len = *(size_t *) p;
		if (!size_is_positive(len)) {
			s_error_from(_WHERE_, "detected free block corruption at %p: "
				"block in a bucket handling %zu bytes has corrupted length %zd",
				p, fl->blocksize, len);
		} else {
			s_error_from(_WHERE_, "detected free block corruption at %p: "
				"%zu-byte long block in a bucket handling %zu bytes",
				p, len, fl->blocksize);
		}
	}
}
#else
static void
assert_valid_freelist_pointer(const struct xfreelist *fl, const void *p)
{
	(void) fl;
	(void) p;
	/* Disabled */
}
#endif	/* XMALLOC_PTR_SAFETY */

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

	assert_mutex_is_owned(&fl->lock);

	g_assert(size_is_positive(fl->count));
	g_assert(fl->count >= fl->sorted);
	g_assert_log(fl->count <= fl->capacity,
		"count=%zu, capacity=%zu", fl->count, fl->capacity);

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
				XSTATS_INCX(freelist_nosplit);
				goto no_split;
			}

			if G_LIKELY(!xfl_block_falls_in(flb, split_len)) {
				XSTATS_INCX(freelist_split);
				if (xmalloc_grows_up) {
					/* Split the end of the block */
					split = ptr_add_offset(p, len);
				} else {
					/* Split the head of the block */
					split = p;
					p = ptr_add_offset(p, split_len);
				}

				if (xmalloc_debugging(3)) {
					s_debug("XM splitting large %zu-byte block at %p"
						" (need only %zu bytes: returning %zu bytes at %p)",
						blksize, p, len, split_len, split);
				}

				g_assert(split_len <= XMALLOC_MAXSIZE);

				xmalloc_freelist_insert(split, split_len,
					FALSE, XM_COALESCE_NONE);
				blksize = len;		/* We shrank the allocted block */
			} else {
				XSTATS_INCX(freelist_nosplit);
				if (xmalloc_debugging(3)) {
					s_debug("XM not splitting large %zu-byte block at %p"
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

	if (!XMALLOC_VIA_VMM(len)) {
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

	g_assert(fl->extending);
	g_assert_log(fl->count == fl->capacity || fl->expand,
		"count=%zu, capacity=%zu, expand=%s",
		fl->count, fl->capacity, bool_to_string(fl->expand));

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
		s_debug("XM extending freelist #%zu (%zu-byte block) "
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
			s_debug("XM recursion during extension of freelist #%zu "
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
			s_debug("XM discarding allocated bucket %p (%zu bytes) for "
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
		s_error_from(_WHERE_,
			"XM self-increase during extension of freelist #%zu "
			"(%zu-byte block): has more items than initial %zu "
			"(count = %zu, capacity = %zu)",
			xfl_index(fl), fl->blocksize, old_used / sizeof(void *),
			fl->count, fl->capacity);
	}

	xfl_replace_pointer_array(fl, new_ptr, allocated_size);
	fl->expand = FALSE;

	if (xmalloc_debugging(1)) {
		s_debug("XM extended freelist #%zu (%zu-byte block) to %zu items"
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
static void G_PRINTF(4, 5)
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
			str_vbprintf(ARYLEN(buf), fmt, args);
			va_end(args);

			s_warning("XM freelist #%zu (%zu/%zu sorted) "
				"items %zu-%zu unsorted %s: "
				"breaks at item %zu",
				xfl_index(fl), fl->sorted, fl->count, low, high - 1, buf, i);

			s_error_from(_WHERE_, "freelist #%zu corrupted", xfl_index(fl));
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
		XSTATS_INCX(freelist_partial_sorting);
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

		XSTATS_INCX(freelist_full_sorting);
		xqsort(ary, fl->count, sizeof ary[0], xfl_ptr_cmp);
		assert_xfl_sorted(fl, 0, fl->count, "after full qsort");
	} else {
		XSTATS_INCX(freelist_avoided_sorting);
		assert_xfl_sorted(fl, 0, fl->count, "after nosort");
	}

	fl->sorted = fl->count;		/* Fully sorted now */

	if (xmalloc_debugging(1)) {
		s_debug("XM sorted %zu items from freelist #%zu (%zu bytes)",
			fl->count, xfl_index(fl), fl->blocksize);
	}
}

/**
 * Binary lookup for a matching block within free list array, and computation
 * of its insertion point.
 *
 * @return index within the sorted array where ``p'' is stored, -1 if not found.
 */
static inline size_t G_HOT
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
			XSTATS_INCX(freelist_short_yes_lookups);
			return 0;
		}
		if (xm_ptr_cmp(p, array[low]) < 0) {
			if (low_ptr != NULL)
				*low_ptr = low;
			XSTATS_INCX(freelist_short_no_lookups);
			return -1;
		}
		low++;
		if G_UNLIKELY(array[high] == p) {
			XSTATS_INCX(freelist_short_yes_lookups);
			return high;
		}
		if (xm_ptr_cmp(p, array[high]) > 0) {
			if (low_ptr != NULL)
				*low_ptr = high + 1;
			XSTATS_INCX(freelist_short_no_lookups);
			return -1;
		}
		high--;
	}

	/* Binary search */

	XSTATS_INCX(freelist_binary_lookups);

	high++;		/* Refers to first off-bound item */

	for (;;) {
		int c;

		if G_UNLIKELY(low >= high) {
			mid = (size_t) -1;	/* Not found */
			break;
		}

		mid = (low + high) / 2;
		c = xm_ptr_cmp(p, array[mid]);

		if G_UNLIKELY(0 == c)
			break;				/* Found */
		else if (c > 0)
			low = mid + 1;
		else
			high = mid;			/* Not -1 since high is unsigned */

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
static size_t G_HOT
xfl_lookup(struct xfreelist *fl, const void *p, size_t *low_ptr)
{
	size_t unsorted;

	assert_mutex_is_owned(&fl->lock);

	/*
	 * We only process deferred blocks (reintegrating them in the bucket)
	 * when we're not trying to insert into the bucket.  We know we're
	 * about to insert when the caller is supplying a non-NULL low_ptr.
	 */

	if G_UNLIKELY(NULL == low_ptr && xfl_has_deferred(fl))
		xfl_process_deferred(fl);

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

			XSTATS_INCX(freelist_linear_lookups);

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
	assert_mutex_is_owned(&fl->lock);

	g_assert(size_is_positive(fl->count));
	g_assert(size_is_non_negative(idx) && idx < fl->count);
	g_assert(fl->count >= fl->sorted);
	g_assert_log(fl->count <= fl->capacity,
		"count=%zu, capacity=%zu", fl->count, fl->capacity);

	if (idx < fl->sorted)
		fl->sorted--;

	XSTATS_LOCK;
	xstats.freelist_blocks--;
	xstats.freelist_memory -= fl->blocksize;
	XSTATS_UNLOCK;

	ARRAY_REMOVE_DEC(fl->pointers, idx, fl->count);

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

	assert_mutex_is_owned(&fl->lock);

	g_assert(size_is_non_negative(fl->count));
	g_assert_log(fl->count <= fl->capacity,
		"count=%zu, capacity=%zu", fl->count, fl->capacity);

	/*
	 * Since the extension can use the freelist's own blocks, it could
	 * conceivably steal one from this freelist.  It's therefore important
	 * to perform the extension before we compute the proper insertion
	 * index for the block.
	 */

	while (fl->count >= fl->capacity) {
		g_assert(!fl->extending);
		fl->extending = TRUE;
		xfl_extend(fl);
		fl->extending = FALSE;
	}

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
				XSTATS_INCX(freelist_plain_insertions);
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
			s_error_from(_WHERE_,
				"block %p already in free list #%zu (%zu bytes)",
				p, xfl_index(fl), fl->blocksize);
		}
	} else {
		idx = fl->count;		/* Append at the tail */
		XSTATS_INCX(freelist_unsorted_insertions);
	}

	g_assert(size_is_non_negative(idx) && idx <= fl->count);

	/*
	 * Shift items if we're not inserting at the last position in the array.
	 */

	g_assert(fl->pointers != NULL);

	ARRAY_MAKEROOM(fl->pointers, idx, fl->count, fl->capacity);

plain_insert:

	g_assert_log(fl->count < fl->capacity,
		"count=%zu, capacity=%zu", fl->count, fl->capacity);

	G_PREFETCH_W(p);
	G_PREFETCH_W(&fl->lock);

	fl->count++;
	if G_LIKELY(sorted)
		fl->sorted++;
	fl->pointers[idx] = p;
	XSTATS_LOCK;
	xstats.freelist_blocks++;
	xstats.freelist_memory += fl->blocksize;
	xmalloc_freelist_stamp++;		/* Let GC know it can run */
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
			g_assert(xfreelist_maxidx < N_ITEMS(xfreelist));

			if (xmalloc_debugging(1)) {
				s_debug("XM max frelist index increased to %zu",
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
		s_debug("XM inserted block %p in %sfree list #%zu (%zu bytes)",
			p, fl->sorted != fl->count ? "unsorted " : "",
			xfl_index(fl), fl->blocksize);
	}
}

/**
 * Process deferred blocks in freelist.
 */
static void
xfl_process_deferred(struct xfreelist *fl)
{
	struct xdefer *xdf = &fl->deferred;
	size_t n = 0;

	assert_mutex_is_owned(&fl->lock);

	/*
	 * By flagging that we are processing deferred blocks, we prevent any
	 * other routine from calling us again because we have more than one
	 * pending block: that would needlessly cause recursion and consume
	 * stack space, without control.
	 */

	g_assert(!fl->retrofiting);

	fl->retrofiting = TRUE;

	for (;;) {
		spinlock(&xdf->lock);
		if (0 != xdf->count) {
			void *p;

			p = xdf->head;
			xdf->head = *(void **) p;	/* Next block in list, or NULL */
			xdf->count--;
			spinunlock(&xdf->lock);

			if (xmalloc_debugging(5)) {
				s_minidbg("XM %s() handling deferred block %p "
					"in free list #%zu (%zu bytes), with %zu more",
					G_STRFUNC, p, xfl_index(fl), fl->blocksize, xdf->count);
			}

			g_assert(p != NULL);

			xfl_insert(fl, p, TRUE);
			n++;
		} else {
			spinunlock(&xdf->lock);
			break;
		}
	}

	fl->retrofiting = FALSE;

	XSTATS_LOCK;
	xstats.freelist_deferred_processed += n;
	XSTATS_UNLOCK;

	if (n != 0 && xmalloc_debugging(0)) {
		s_minidbg("XM %s() handled %zu deferred block%s "
			"in free list #%zu (%zu bytes)",
			G_STRFUNC, n, plural(n), xfl_index(fl), fl->blocksize);
	}
}

/**
 * Defer insertion of the block in the specified freelist.
 *
 * This is called when we were unable to lock the freelist bucket prior to
 * calling xlf_insert() and we need to put the block in a temporary list
 * which will be processed when it is safe to do so.
 *
 * @param fl		the freelist bucket
 * @param p			address of the block to insert
 */
static void
xfl_defer(struct xfreelist *fl, void *p)
{
	struct xdefer *xdf = &fl->deferred;

	if (xmalloc_debugging(5)) {
		s_minidbg("XM %s() enqueuing deferred block %p "
			"in free list #%zu (%zu bytes), with %zu already present",
			G_STRFUNC, p, xfl_index(fl), fl->blocksize, xdf->count);
	}

	/*
	 * We cannot deadlock because we're only grabbing the lock on the
	 * deferred list, which is kept for a short period of time, without
	 * calling any other routine.
	 *
	 * The list structure is kept using the first pointer of the block,
	 * since we cannot allocate any memory here.
	 */

	spinlock(&xdf->lock);
	g_assert(xdf->count != 0 || NULL == xdf->head);
	*(void **) p = xdf->head;
	xdf->head = p;
	xdf->count++;
	spinunlock(&xdf->lock);

	XSTATS_LOCK;
	xstats.freelist_insertions_deferred++;
	xmalloc_freelist_stamp++;		/* Let GC know it can run */
	XSTATS_UNLOCK;
}

/**
 * Carefully insert address in the free list.
 *
 * We're careful to prevent deadlocks here: we attempt to lock the bucket and
 * if we can't, we put the block in a temporary list where it will be picked
 * later.
 *
 * @param fl		the freelist bucket
 * @param p			address of the block to insert
 * @param burst		whether we're in a burst insertion mode
 */
static void
xfl_insert_careful(struct xfreelist *fl, void *p, bool burst)
{
	bool locked;

	/*
	 * We use a mutex and not a plain spinlock because we can recurse here
	 * through freelist bucket allocations.  A mutex allows us to relock
	 * an object we already locked in the same thread.
	 */

	locked = mutex_trylock(&fl->lock);

	/*
	 * If we could lock the bucket, then we can safely insert the block.
	 *
	 * If we cannot lock the bucket, the block is inserted into the
	 * deferred list.
	 */

	if (locked) {
		/*
		 * If the bucket is already in the process of being extended, do not
		 * attempt to re-insert anything inside, as we may not have any room
		 * in it.  Better to defer the block in that case.
		 */

		if G_UNLIKELY(fl->extending) {
			mutex_unlock(&fl->lock);	/* Do not hold the bucket's lock */
			xfl_defer(fl, p);
		} else {
			xfl_insert(fl, p, burst);

			/*
			 * Since we have the lock on the bucket, we can safely process
			 * deferred blocks.
			 */

			if (xfl_has_deferred(fl))
				xfl_process_deferred(fl);

			mutex_unlock(&fl->lock);	/* Issues final memory barrier */
		}
	} else {
		xfl_defer(fl, p);
	}
}

/**
 * Initialize freelist buckets once.
 */
static void G_COLD
xmalloc_freelist_init_once(void)
{
	size_t i;

	for (i = 0; i < N_ITEMS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];

		fl->blocksize = xfl_block_size_idx(i);
		mutex_init(&fl->lock);
		spinlock_init(&fl->deferred.lock);

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
			elist_init(&ch->full, offsetof(struct xchunk, xc_lnk));
		}
	}

	for (i = 0; i < N_ITEMS(xcross); i++) {
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
static void G_COLD
xmalloc_freelist_setup(void)
{
	once_flag_run(&xmalloc_freelist_inited, xmalloc_freelist_init_once);

	/*
	 * If the address space is not growing in the same direction as the
	 * initial default, we have to resort all the buckets.
	 */

	if (!xmalloc_grows_up) {
		size_t i;

		for (i = 0; i < N_ITEMS(xfreelist); i++) {
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

	for (i = 0; i < N_ITEMS(xsplit); i++) {
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
				s_error("xmalloc() cannot split %zu-byte blocks into 2 blocks",
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

	return &xsplit[(len - XMALLOC_ALIGNBYTES) >> XMALLOC_ALIGNSHIFT];
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
	g_assert_log(fl->count <= fl->capacity,
		"count=%zu, capacity=%zu", fl->count, fl->capacity);

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
			XSTATS_INCX(freelist_sorted_superseding);
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

		if G_UNLIKELY(xfl_has_deferred(fl))
			xfl_process_deferred(fl);

		if (0 == fl->count) {
			mutex_unlock(&fl->lock);
			continue;
		}

		*flp = fl;
		p = xfl_select(fl);

		if (xmalloc_debugging(8)) {
			s_debug("XM selected block %p in bucket %p "
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
static bool G_HOT
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
				XSTATS_INCX(freelist_coalescing_ignore_burst);
				return FALSE;
			}
		}

		/*
		 * If block is larger than the maximum size of blocks we handle from
		 * the freelist, don't attempt any coalescing.
		 */

		if G_UNLIKELY(len > XMALLOC_MAXSIZE) {
			if (xmalloc_debugging(6)) {
				s_debug("XM ignoring coalescing request for %zu-byte %p:"
					" would be larger than maxsize", len, base);
			}
			XSTATS_INCX(freelist_coalescing_ignored);
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
				s_debug("XM ignoring coalescing request for %zu-byte %p:"
					" target free list #%zu has only %zu item%s",
					len, base, idx, fl->count, plural(fl->count));
			}
			XSTATS_INCX(freelist_coalescing_ignored);
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
					s_debug("XM iter #%zu, "
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
					s_debug("XM iter #%zu, "
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
		XSTATS_INCX(freelist_coalescing_done);
	} else {
		XSTATS_INCX(freelist_coalescing_failed);
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
		s_debug(
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

	XSTATS_INCX(freelist_insertions);

	if (coalesce & XM_COALESCE_ALL) {
		xmalloc_freelist_coalesce(&p, &len, burst, coalesce);
	} else {
		XSTATS_INCX(freelist_insertions_no_coalescing);
	}

	/*
	 * Chunks of memory larger than XMALLOC_MAXSIZE need to be broken up
	 * into smaller blocks.  This can happen when we're putting heap memory
	 * back into the free list, or when a block larger than a page size is
	 * actually spread over two distinct VM pages.
	 */

	if G_UNLIKELY(len > XMALLOC_MAXSIZE) {
		if (xmalloc_debugging(3)) {
			s_debug("XM breaking up %s block %p (%zu bytes)",
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

			xfl_insert_careful(fl, p, burst);
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
			s_debug("XM breaking up %s block %p (%zu bytes) into (%u, %u)",
				xmalloc_isheap(p, len) ? "heap" : "VMM", p, len,
				xs->larger, xs->smaller);
		}

		if (0 != xs->smaller) {
			fl = xfl_find_freelist(xs->smaller);
			xfl_insert_careful(fl, p, burst);
			p = ptr_add_offset(p, xs->smaller);
			len -= xs->smaller;
		}

		/* FALL THROUGH */
	}

	fl = xfl_find_freelist(len);
	xfl_insert_careful(fl, p, burst);
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
			XSTATS_INCX(freelist_burst_insertions);
			if G_UNLIKELY(calls == XM_FREELIST_THRESH + 1)
				XSTATS_INCX(freelist_bursts);
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

	if (coalesce & XM_COALESCE_ALL) {
		if (
			vmm_page_start(p) != p ||
			round_pagesize(len) != len ||
			is_heap
		) {
			coalesced = xmalloc_freelist_coalesce(&p, &len, in_burst, coalesce);
		} else {
			if (xmalloc_debugging(4)) {
				s_debug(
					"XM not attempting coalescing of %zu-byte VMM region at %p",
					len, p);
			}
			XSTATS_INCX(freelist_coalescing_ignore_vmm);
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
				s_debug("XM %zu bytes of heap released at %p, "
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

					s_debug("XM freed %sembedded %zu page%s, "
						"%s head, %s tail",
						coalesced ? "coalesced " : "",
						npages, plural(npages),
						head_len != 0 ? "has" : "no",
						tail_len != 0 ? "has" : "no");
				} else {
					s_debug("XM freed %swhole %zu-byte region at %p",
						coalesced ? "coalesced " : "", len, p);
				}
			}

			if (coalesced)
				XSTATS_INCX(free_coalesced_vmm);

			/*
			 * Head and tail are smaller than a page size but could still be
			 * larger than XMALLOC_MAXSIZE.
			 */

			if (head_len != 0) {
				g_assert(head == p);
				if (xmalloc_debugging(4)) {
					s_debug("XM freeing head of %p at %p (%zu bytes)",
						p, head, head_len);
				}
				if (coalesce & XM_COALESCE_BEFORE) {
					/* Already coalesced */
					uint32 flags = coalesced & ~XM_COALESCE_ALL;
					xmalloc_freelist_insert(head, head_len, in_burst, flags);
				} else {
					/* Maybe there is enough before to free core again? */
					calls--;	/* Self-recursion, does not count */
					xmalloc_freelist_add(head, head_len,
						(coalesce & ~XM_COALESCE_AFTER) | XM_COALESCE_BEFORE);
				}
			}
			if (tail_len != 0) {
				g_assert(
					ptr_add_offset(tail, tail_len) == ptr_add_offset(p, len));
				if (xmalloc_debugging(4)) {
					s_debug("XM freeing tail of %p at %p (%zu bytes)",
						p, tail, tail_len);
				}
				if (coalesce & XM_COALESCE_AFTER) {
					/* Already coalesced */
					uint32 flags = coalesced & ~XM_COALESCE_ALL;
					xmalloc_freelist_insert(tail, tail_len, in_burst, flags);
				} else {
					/* Maybe there is enough after to free core again? */
					calls--;	/* Self-recursion, does not count */
					xmalloc_freelist_add(tail, tail_len,
						(coalesce & ~XM_COALESCE_BEFORE) | XM_COALESCE_AFTER);
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

	xmalloc_freelist_insert(p, len, in_burst, coalesce & ~XM_COALESCE_ALL);
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
 * @param allocated where we return the allocated block size (after split).
 *
 * @return adjusted pointer
 */
static void *
xmalloc_freelist_grab(struct xfreelist *fl,
	void *block, size_t length, size_t *allocated)
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

		if (xmalloc_should_split(blksize, len)) {
			XSTATS_INCX(freelist_split);
			if (xmalloc_grows_up) {
				/* Split the end of the block */
				sp = ptr_add_offset(p, len);
			} else {
				/* Split the head of the block */
				sp = p;
				p = ptr_add_offset(p, split_len);
			}

			if (xmalloc_debugging(3)) {
				s_debug("XM splitting large %zu-byte block at %p"
					" (need only %zu bytes: returning %zu bytes at %p)",
					blksize, p, len, split_len, sp);
			}

			g_assert(split_len <= XMALLOC_MAXSIZE);

			xmalloc_freelist_insert(sp, split_len, FALSE, XM_COALESCE_NONE);
		} else {
			if (xmalloc_debugging(3)) {
				s_debug("XM NOT splitting (as requested) %zu-byte block at %p"
					" (need only %zu bytes, split of %zu bytes too small)",
					blksize, p, len, split_len);
			}
			XSTATS_INCX(freelist_nosplit);
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

	if G_UNLIKELY(p != NULL)
		p = xmalloc_freelist_grab(fl, p, len, allocated);

	return p;
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
		s_debug("XM setup allocated %zu-byte block at %p (user %p)",
			len, p, ptr_add_offset(p, XHEADER_SIZE));
	}

	xh->length = len;
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
 * Compute checksum of the "constant" part of the chunk header.
 */
static inline uint32
xmalloc_chunk_checksum(const struct xchunk *xck)
{
	return
		xck->xc_stid +
		UINT32_ROTL(xck->xc_size, 10) +
		UINT32_ROTL(xck->xc_tag, 16) +
		UINT32_ROTL(xck->xc_capacity, 20);
}

/**
 * Compute tag (32-bit simple hash) for the chunk header.
 */
static inline uint32
xmalloc_chunk_tag(const struct xchunk *xck)
{
	/*
	 * We roughly know the data ranges for each of these variables,
	 * all positive:
	 *
	 * 		xc_size <= XM_THREAD_MAXSIZE (512)
	 * 		xc_stid < THREAD_MAX (64)
	 *		xc_capacity <= 4096 / 8 = 512
	 *
	 * This makes the tag we compute below completely unique for a valid chunk,
	 * with no collision possible.
	 *
	 * Now of course when computing the tag over a random buffer, where none
	 * of the values are constrained, we can get a collision.
	 */

	return
		UINT32_ROTL(xck->xc_size, 10) +
		UINT32_ROTL(xck->xc_stid, 24) +
		xck->xc_capacity;
}

/**
 * Validate that pointer is the start of what appears to be a valid chunk.
 */
static bool G_HOT
xmalloc_chunk_is_valid(const struct xchunk *xck)
{
	/*
	 * Collision avoidance is impossible, but we are trying to make them highly
	 * unlikely -- if it happens, this will create a memory corruption at
	 * runtime, but what are the actual chances?
	 *
	 * The start of the page must bear the chunk magic tag (32-bit value),
	 * the computed tag must match what is being stored there (collisions
	 * possible when dealing with random values) and the checksum (computed
	 * again by mixing the same chunk values differently plus the tag) must
	 * also match.
	 *
	 * At the tag level, 96 bits are "hashed" into 32 bits.  There are 2^(96-32)
	 * collisions to be expected, i.e. 2^64 (amount of different values that
	 * are going to hash to the same tag).
	 *
	 * To minimize the risk, we check that the values are within the expected
	 * boundaries, without disrupting the execution flow with too many branches
	 * (hence the summing of boolean values).
	 */

	return
		XCHUNK_MAGIC == xck->magic &&		/* Fastest discriminent */
		5 == (
			/* All these boolean expressions must be TRUE(1) for a valid chunk */
			(xck->xc_stid < XM_THREAD_COUNT) +
			(xck->xc_size <= XM_THREAD_MAXSIZE) +
			(xck->xc_size != 0) +
			(xmalloc_round(xck->xc_size) == xck->xc_size) +
			(xck->xc_capacity < 4096 / XMALLOC_ALIGNBYTES)	/* 4096 = page size */
		) &&
		xmalloc_chunk_tag(xck) == xck->xc_tag &&
		xmalloc_chunk_checksum(xck) == xck->xc_cksum;
}

#ifdef XMALLOC_CHUNK_SAFETY
/**
 * Is pointer that of a valid block in the chunk?
 */
static bool
xmalloc_chunk_valid_ptr(const struct xchunk *xck, const void *p)
{
	unsigned blocksize = xck->xc_head->blocksize;
	unsigned capacity, offset;
	const void *start, *end = const_ptr_add_offset(xck, xmalloc_pagesize);

	/*
	 * See diagram in xmalloc_chunk_allocate() to understand the logic here.
	 */

	capacity = (xmalloc_pagesize - sizeof *xck) / blocksize;
	offset = xmalloc_pagesize - capacity * blocksize;
	start = const_ptr_add_offset(xck, offset);

	/* Block must be within the allocatable range within the chunk */
	if G_UNLIKELY(ptr_cmp(p, start) < 0 || ptr_cmp(p, end) >= 0)
		return FALSE;

	/* Block must be properly aligned within the chunk */
	if G_UNLIKELY(0 != ptr_diff(end, p) % blocksize)
		return FALSE;

	return TRUE;
}

/**
 * Make sure the pointer is that of an allocatable block in the chunk.
 *
 * @param xck		the chunk where block is supposed to be allocated from
 * @param p			the memory block start address (user pointer)
 */
static void
assert_chunk_upointer_valid(const struct xchunk *xck, const void *p)
{
	if G_LIKELY(xmalloc_chunk_valid_ptr(xck, p))
		return;

	s_error_from(_WHERE_,
		"invalid chunk user pointer %p in %zu-byte chunk %p for %s [#%u]",
		p, xck->xc_head->blocksize, xck, thread_id_name(xck->xc_stid),
		xck->xc_stid);
}

/**
 * Make sure the chunk freelist is consistent.
 *
 * @param xck		the thread chunk to check
 * @param stid		the thread ID to which chunk belongs
 * @param local		TRUE if we're running in the context of the thread
 */
static void
assert_chunk_freelist_valid(const struct xchunk *xck, unsigned stid, bool local)
{
	unsigned free_items, free_count;
	const void *p;

	g_assert(xmalloc_chunk_is_valid(xck));
	g_assert_log(!local || xck->xc_stid == stid,
		"%s(): xck->xc_stid=%u, stid=%u", G_STRFUNC, xck->xc_stid, stid);

	free_count = xck->xc_count;		/* Expected amount of free items */
	free_items = 0;
	p = const_ptr_add_offset(xck, xck->xc_free_offset);

	while (xmalloc_chunk_valid_ptr(xck, p)) {
		free_items++;
		p = *(void **) p;			/* Next free block */
	}

	if G_UNLIKELY(free_count != xck->xc_count) {
		s_error_from(_WHERE_,
			"race condition whilst checking %zu-byte chunk %p for %s [#%u]",
			xck->xc_head->blocksize, xck, thread_id_name(xck->xc_stid),
			xck->xc_stid);
	}

	if G_LIKELY(free_items == free_count)
		return;

	s_error_from(_WHERE_,
		"corrupted freelist in %zu-byte chunk %p for %s [#%u]: "
		"expected %u free block%s, found %u",
		xck->xc_head->blocksize, xck, thread_id_name(xck->xc_stid),
		xck->xc_stid, free_count, plural(free_count), free_items);
}
#else
#define assert_chunk_freelist_valid(x,s,l)
#define assert_chunk_upointer_valid(x,p)
#endif	/* XMALLOC_CHUNK_SAFETY */

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

	/*
	 * Try to allocate from the page pool if available.
	 */

	if G_LIKELY(xpages_pool != NULL)
		xck = palloc(xpages_pool);
	else
		xck = vmm_core_alloc(xmalloc_pagesize);

	ZERO(xck);
	xck->magic = XCHUNK_MAGIC;
	xck->xc_head = deconstify_pointer(ch);
	xck->xc_size = ch->blocksize;
	xck->xc_stid = stid;
	xck->xc_capacity = xck->xc_count = capacity;
	xck->xc_free_offset = offset;

	/*
	 * This is used as a sanity check to validate that the chunk structure
	 * is that of a valid chunk.
	 */

	xck->xc_tag = xmalloc_chunk_tag(xck);
	xck->xc_cksum = xmalloc_chunk_checksum(xck);

	g_assert(xmalloc_chunk_is_valid(xck));

	xmalloc_chunk_cram(xck);
	XSTATS_INCX(vmm_thread_pages);

	assert_chunk_freelist_valid(xck, stid, TRUE);

	return xck;
}

/**
 * Find chunk from which we can allocate a block.
 *
 * @param ch		the chunk head (determining the block size implicitly)
 * @param stid		thread ID for which we are allocating
 *
 * @return the address of a chunk with at least one free block, NULL if we
 * want to prevent allocation from the thread-specific pool.
 */
static struct xchunk *
xmalloc_chunk_find(struct xchunkhead *ch, unsigned stid)
{
	struct xchunk *xck;

	/*
	 * When they disable the use of the thread pool, we no longer grow the
	 * existing thread pool, but we use it whilst there is room (a thread may
	 * start with a non-empty pool when the previous thread using this stid
	 * had allocated blocks that have been passed to other threads and not
	 * freed, or which leaked).
	 *
	 * Hence look whether there is already a chunk that could be used to
	 * allocate memory regardless of the setting, and only if we cannot find
	 * any free chunk will we bail out when thread pools have been disabled.
	 */

	xck = elist_head(&ch->list);	/* Only contains chunks with free space */
	if G_LIKELY(xck != NULL)
		return xck;

	if G_UNLIKELY(xpool_disabled[stid])
		return NULL;		/* Pool usage disabled, refuse to grow pool */

	/*
	 * No free chunk, allocate a new one.
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

		if (0 == elist_count(&ch->list) + elist_count(&ch->full))
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
				s_debug("XM not creating new %zu-byte blocks for thread #%u: "
					"shared blocks have %F bytes overhead (%u per page), "
					"currently has %zu chunk%s",
					ch->blocksize, stid, (double) overhead / capacity,
					capacity, elist_count(&ch->list),
					plural(elist_count(&ch->list)));
			}
			return NULL;
		}

		if (xmalloc_debugging(1)) {
			s_debug("XM still creating new %zu-byte blocks for thread #%u: "
				"shared blocks have only %F bytes overhead (%u per page)",
				ch->blocksize, stid, (double) overhead / capacity,
				capacity);
		}
	}

	/*
	 * Allocate a new chunk in the thread pool, inserted in the list of chunks
	 * to be used for the block size defined by the chunk head.
	 */

	xck = xmalloc_chunk_allocate(ch, stid);
	elist_prepend(&ch->list, xck);

	if (xmalloc_debugging(1)) {
		s_debug("XM new chunk #%zu of %zu-byte blocks for thread #%u at %p",
			elist_count(&ch->list) - 1, ch->blocksize, stid, xck);
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

	assert_chunk_freelist_valid(xck, stid, TRUE);

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

		/*
		 * Chunk is full, remove it from the list of chunks and put it
		 * in the full list.
		 */

		elist_remove(&ch->list, xck);
		elist_append(&ch->full, xck);
	}

	assert_chunk_freelist_valid(xck, stid, TRUE);

	return p;
}

/**
 * Return block to thread-private chunk.
 *
 * @param xck		the chunk to which we want to return the block
 * @param p			start of allocated block in chunk
 * @param local		whether we're running in thread owning the chunk
 */
static void
xmalloc_chunk_return(struct xchunk *xck, void *p, bool local)
{
	(void) local;		/* Only used when safety chunk assertion are enabled */

	assert_chunk_upointer_valid(xck, p);
	assert_chunk_freelist_valid(xck, thread_small_id(), local);

	/*
	 * If returning the block makes the whole chunk free, free that chunk.
	 */

	if G_UNLIKELY(xck->xc_capacity == xck->xc_count + 1) {
		struct xchunkhead *ch = xck->xc_head;

		elist_remove(&ch->list, xck);

		XSTATS_LOCK;
		xstats.freeings++;			/* Not counted in xfree() */
		xstats.free_thread_pool++;
		xstats.user_memory -= xck->xc_size;
		xstats.user_blocks--;
		XSTATS_UNLOCK;
		XSTATS_DECX(vmm_thread_pages);

		/*
		 * Before freeing the chunk, zero the header part so as to make
		 * sure we will not mistake this for a valid header again.  Simply
		 * zeroing the magic number is not enough here, we want to prevent
		 * mistakes: freeing blocks on a page with an apparently valid header
		 * but which is not a thread-private chunk would corrupt memory.
		 */

		ZERO(xck);

		/*
		 * If the memory pool allocator is configured, return the page
		 * to that pool so as to maybe reuse it soon for another thread or
		 * for another chunk in the current thread..
		 *
		 * We need to allocate the pool on the free path. not on the allocation
		 * path to avoid auto-initialization problems leading to a deadlock.
		 * The pool is useless until we need to free a thread chunk anyway.
		 */

		if G_LIKELY(xpages_pool != NULL)
			pfree(xpages_pool, xck);
		else if (once_flag_run_safe(&xpages_pool_inited, xpages_pool_init))
			pfree(xpages_pool, xck);
		else
			vmm_core_free(xck, xmalloc_pagesize);

		if (xmalloc_debugging(1)) {
			s_debug("XM freed chunk %p of %zu-byte blocks for thread #%u",
				xck, ch->blocksize, thread_small_id());
		}

		/*
		 * As soon as the thread clears all the chunks for a given size,
		 * turn off the "shared" status, giving thread another chance to
		 * grow its pool again in the absence of cross-thread freeing.
		 */

		if (0 == elist_count(&ch->list) + elist_count(&ch->full))
			ch->shared = FALSE;

	} else {
		void *head = 0 == xck->xc_free_offset ? NULL :
			ptr_add_offset(xck, xck->xc_free_offset);

		XSTATS_LOCK;
		xstats.freeings++;			/* Not counted in xfree() */
		xstats.free_thread_pool++;
		xstats.user_memory -= xck->xc_size;
		xstats.user_blocks--;
		XSTATS_UNLOCK;

		g_assert(uint_is_non_negative(xck->xc_free_offset));
		g_assert(xck->xc_free_offset < xmalloc_pagesize);

		*(void **) p = head;
		xck->xc_free_offset = ptr_diff(p, xck);

		/*
		 * If the chunk was empty and now has one free block, remove
		 * it from the full list and put it back in the list of chunks
		 * with free space.
		 */

		if G_UNLIKELY(0 == xck->xc_count++) {
			struct xchunkhead *ch = xck->xc_head;
			elist_remove(&ch->full, xck);
			elist_append(&ch->list, xck);
		}

		assert_chunk_freelist_valid(xck, thread_small_id(), local);
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
xmalloc_thread_free_deferred(unsigned stid, bool local)
{
	struct xchunk *xck;
	struct xcross *xcr;
	void *p, *next = NULL;
	size_t n, size = 0;

	g_assert(size_is_non_negative(stid));
	g_assert(stid < N_ITEMS(xcross));

	xcr = &xcross[stid];

	/*
	 * We need to prevent recursive calls to that routine, which can happen
	 * in some auto-initialization configurations, due to the need to allocate
	 * pools on the free path (but we can be on the allocation path presently).
	 *
	 * Since we can delay the freeing of the deferred blocks for some time,
	 * we do nothing if we cannot grab the spinlock: given it's a lock used by
	 * one thread, not being able to grab it means we're already freeing
	 * deferred blocks (and implies we're on the allocation path, initializing
	 * the memory pool to cache the freed thread chunks).
	 *		--RAM, 2015-09-27
	 */

	if (!spinlock_try(&xcr->lock))
		return;

	if G_LIKELY(0 == xcr->count) {
		spinunlock(&xcr->lock);
		return;
	}

	if (xmalloc_debugging(0)) {
		s_minidbg("XM starting handling deferred %zu block%s for %s",
			xcr->count, plural(xcr->count), thread_id_name(stid));
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

		size += xck->xc_size;
		xmalloc_chunk_return(xck, p, local);
	}

	g_assert(n == xcr->count);

	xcr->count = 0;
	xcr->head = NULL;

	spinunlock(&xcr->lock);

	if (xmalloc_debugging(0)) {
		s_debug("XM handled delayed free of %zu block%s (%zu bytes) in %s",
			n, plural(n), size, thread_id_name(stid));
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
 * Set or disable usage of the thread-specific pool for the current thread.
 *
 * By default, each thread starts with the thread-specific pool enabled.
 * At thread creation time, one may specify THREAD_F_NO_POOL to turn the pool
 * off before the thread starts running.
 *
 * @param on		if TRUE, enable using / growing a local thread pool.
 *
 * @return previous setting for the thread regarding pool usage.
 */
bool
xmalloc_thread_set_local_pool(bool on)
{
	unsigned stid = thread_small_id();
	bool old;

	old = !xpool_disabled[stid];	/* TRUE means pool was allowed */
	xpool_disabled[stid] = booleanize(!on);

	return old;
}

/**
 * @return whether given thread uses a local thread pool.
 */
bool
xmalloc_thread_uses_local_pool(unsigned stid)
{
	g_assert(stid < XM_THREAD_COUNT);

	return !xpool_disabled[stid];
}

/**
 * Called by the thread management layer when a thread is about to start
 * to configure usage of the thread pool.
 *
 * @param stid		thread ID of starting thread
 * @param disable	whether to disable the thread pool
 */
void
xmalloc_thread_disable_local_pool(unsigned stid, bool disable)
{
	g_assert(stid < XM_THREAD_COUNT);

	xpool_disabled[stid] = booleanize(disable);
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
	 * Mark the thread as "dead".  Until it is marked alive again, all
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

	xmalloc_thread_free_deferred(stid, FALSE);

	/*
	 * Reset thread allocation counts per chunk, which is only useful
	 * when there is an empty chunk list: if we have unfreed chunks,
	 * then a new thread re-using this ID will be able to immediately
	 * use these chunks to allocate thread-private memory for the given size.
	 */

	for (i = 0; i < XMALLOC_CHUNKHEAD_COUNT; i++) {
		struct xchunkhead *ch = &xchunkhead[i][stid];

		if (0 == elist_count(&ch->list) + elist_count(&ch->full))
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
			s_info("XM dead thread #%u still holds %zu thread-private chunk%s",
				stid, n , plural(n));
		}
	}
}

/**
 * Allocate a block from the thread-specific pool.
 *
 * @param stid		thread small ID
 * @param len		size of block to allocate
 *
 * @return allocated block of requested size, or NULL if no allocation was
 * possible.
 */
static void *
xmalloc_thread_alloc(unsigned stid, const size_t len)
{
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
		xmalloc_thread_free_deferred(stid, TRUE);

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
	if G_UNLIKELY(0 != offset % xck->xc_size) {
		s_error("thread #%u %s mis-aligned %u-byte %sblock %p",
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

	/*
	 * We need to compute the thread small ID, but we use this opportunity to
	 * also check whether we are being called from a signal handler.
	 *
	 * Note that the signal_in_unsafe_handler_stid() routine will return TRUE
	 * if it cannot compute a proper thread ID, meaning we're probably
	 * discovering a new thread: we thus need to call thread_small_id() in
	 * that case.
	 */

	if (signal_in_unsafe_handler_stid(&stid)) {
		if (THREAD_UNKNOWN_ID == stid) {
			stid = thread_small_id();
		} else {
			XSTATS_INCX(freeings_in_handler);
			s_minicarp_once("%s(): %s freeing %p from signal handler",
				G_STRFUNC, thread_safe_id_name(stid), p);
		}
	}

	if G_UNLIKELY(stid >= XM_THREAD_COUNT)
		return FALSE;

	/*
	 * Handle any other pending blocks in the cross-thread free list.
	 */

	if G_UNLIKELY(xcross[stid].count != 0)
		xmalloc_thread_free_deferred(stid, TRUE);

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
				s_debug("thread #%u freeing %u-byte block %p "
					"allocated by thread #%u",
					stid, xck->xc_size, p, xck->xc_stid);
			}
		}

		XSTATS_INCX(free_foreign_thread_pool);

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
			xmalloc_chunk_return(xck, p, FALSE);
		} else {
			*(void **) p = xcr->head;
			xcr->head = p;
			xcr->count++;
		}
		spinunlock(&xcr->lock);

		if (xmalloc_debugging(5)) {
			/* Count may be wrong since we log outside the critical region */
			s_debug("XM deferred freeing of %u-byte block %p "
				"owned by thread #%u (%zu held)",
				xck->xc_size, p, xck->xc_stid, xcr->count);
		}

		return TRUE;		/* We handled the block, freeing is just delayed */
	}

	/*
	 * OK, block belongs to this thread, we can free safely.
	 */

	xmalloc_chunk_return(xck, p, TRUE);

	return TRUE;
}

#ifdef XMALLOC_IS_MALLOC
#undef malloc
#undef free
#undef realloc
#undef calloc

/*
 * The "e_" prefix is there because xmalloc(), xfree() and friends are already
 * remapped in "xmalloc.h" to embed them and prevent conflicts with some
 * system libraries that already define them.
 *		--RAM, 2016-10-28
 */

#define e_xmalloc malloc
#define e_xfree free
#define e_xrealloc realloc
#define e_xcalloc calloc

#define is_trapping_malloc()	1

#define XALIGN_SHIFT	7	/* 2**7 */
#define XALIGN_MASK		((1 << XALIGN_SHIFT) - 1)
#define XALIGN_MINSIZE	(1U << XALIGN_SHIFT) /**< Min alignment for xzalloc() */

#define is_xaligned(p)	(0 == (pointer_to_ulong(p) & XALIGN_MASK))

static bool xalign_free(const void *p);
static size_t xalign_allocated(const void *p);

#else	/* !XMALLOC_IS_MALLOC */
#define is_trapping_malloc()	0
#define xalign_allocated(p)		0
#define xalign_free(p)			FALSE
#define is_xaligned(p)			FALSE
#endif	/* XMALLOC_IS_MALLOC */

/**
 * Allocate a memory chunk capable of holding ``size'' bytes.
 *
 * If no memory is available, crash with a fatal error message.
 *
 * @param size			minimal size of block to allocate (user space)
 * @param can_vmm		whether we can allocate core via the VMM layer
 * @param can_thread	whether we can allocate from a thread-private pool
 *
 * @return allocated pointer (never NULL).
 */
static void *
xallocate(size_t size, bool can_vmm, bool can_thread)
{
	size_t len;
	void *p;
	uint stid;
	size_t vlen;		/* Length of virual memory allocated via VMM if needed */
	bool via_vmm;		/* If TRUE, do a user-VMM allocation */

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

	if G_UNLIKELY(xmalloc_no_freeing ) {
		/*
		 * In crashing mode activate a simple direct path: anything smaller
		 * than a page size is allocated via omalloc(), the rest is allocated
		 * via the VMM layer.  Things will never get freed at this stage.
		 */

		if (xmalloc_crashing) {
			len = xmalloc_round_blocksize(xmalloc_round(size) + XHEADER_SIZE);
			if (len < xmalloc_pagesize) {
				p = omalloc(len);
			} else {
				p = vmm_alloc(round_pagesize(len));
			}
			return xmalloc_block_setup(p, len);
		}
	}

	/*
	 * If we are in a signal handler, do NOT use a thread-specific allocation
	 * path since it is done without locks and is therefore totally unsafe
	 * when running within an asynchronous signal handler!
	 *
	 * Not that the other common path is much safer, but at least we have locks
	 * and we can see whether the lock is taken from the outside (albeit with
	 * a race condition window between the time the lock is taken and the time
	 * it gets registered in the thread element).
	 */

	if (signal_in_unsafe_handler_stid(&stid) && THREAD_UNKNOWN_ID != stid) {
		can_thread = FALSE;
		XSTATS_INCX(allocations_in_handler);
		s_minicarp_once("%s(): %s trying to allocate %zu bytes "
			"from signal handler",
			G_STRFUNC, thread_safe_id_name(stid), size);
	}


	/*
	 * If we can allocate a block from a thread-specific pool, we'll
	 * avoid any locking and also limit the block overhead.
	 */

	if (size <= XM_THREAD_MAXSIZE && can_thread) {
		size_t allocated;

		/*
		 * This contorsion is necessary for FreeBSD, because its threading
		 * layer calls malloc() and we do not want to enter once_flag_run()
		 * before we're sufficiently advanced in the C runtime initialization:
		 * we must avoid mutexes, which would call thread_self() and risk
		 * recursing to our malloc().
		 *
		 * When the VMM is up, it will mean the C runtime initialization is
		 * fully done and therefore we should be able to call thread_self()
		 * without causing another allocation.
		 *		--RAM, 2013-12-01
		 */

		if G_UNLIKELY(!ONCE_DONE(xmalloc_early_inited)) {
			if (!xmalloc_vmm_is_up)
				goto skip_pool;

			once_flag_run(&xmalloc_early_inited, xmalloc_early_init);
		}

		allocated = xmalloc_round(size);	/* No malloc header */

		if (THREAD_UNKNOWN_ID == stid)
			stid = thread_small_id();		/* Discovering a new thread */

		p = xmalloc_thread_alloc(stid, allocated);

		if G_LIKELY(p != NULL) {
			XSTATS_LOCK;
			xstats.allocations++;
			xstats.alloc_via_thread_pool++;
			xstats.user_blocks++;
			xstats.user_memory += allocated;
			XSTATS_UNLOCK;
			memusage_add(xstats.user_mem, allocated);
			return p;
		}
	}

skip_pool:

	/*
	 * These early checks will determine whether we can afford to allocate
	 * from the freelist, or whether we will be better forcing a VMM user
	 * block to avoid memory fragmentation.
	 */

	len = xmalloc_round_blocksize(xmalloc_round(size) + XHEADER_SIZE);
	vlen = round_pagesize(len);
	via_vmm = XMALLOC_VIA_VMM(len);

	/*
	 * If we have a block smaller than the size for always choosing VMM,
	 * look at whether the block will be split.  If not, then we can
	 * live with the lost memory space and use VMM allocation.
	 *		--RAM, 2017-11-03
	 */

	if (!via_vmm && !xmalloc_should_split(vlen, len)) {
		if G_LIKELY(xmalloc_vmm_is_up && can_vmm) {
			via_vmm = TRUE;
			XSTATS_INCX(alloc_forced_user_vmm);
		}
	}

	/*
	 * First try to allocate from the freelist when the length is less than
	 * the maximum we handle there and we do not want to force a VMM allocation.
	 */

	if G_LIKELY(!via_vmm) {
		size_t allocated;

		p = xmalloc_freelist_alloc(len, &allocated);

		if (p != NULL) {
			G_PREFETCH_HI_W(p);			/* User is going to write in block */
			XSTATS_LOCK;
			xstats.allocations++;
			xstats.alloc_via_freelist++;
			xstats.user_blocks++;
			xstats.user_memory += allocated;
			XSTATS_UNLOCK;
			memusage_add(xstats.user_mem, allocated);
			return xmalloc_block_setup(p, allocated);
		}
	}

	/*
	 * Need to allocate the user block via the VMM layer, if up; otherwise
	 * from the heap.
	 */

	if G_LIKELY(xmalloc_vmm_is_up && can_vmm) {
		/*
		 * The VMM layer is up, use it for all allocations.
		 *
		 * The VMM layer distinguishes between "user" memory and "core" memory.
		 * The "user" memory is a standalone user block that will be deallocated
		 * as a whole, the "core" memory is memory that can be fragmented,
		 * split and reallocated before ending-up being freed.
		 */

		if (via_vmm)
			p = vmm_alloc(vlen);			/* That's a standalone user block */
		else
			p = vmm_core_alloc(vlen);		/* Parts of block will be core */

		if (xmalloc_debugging(1)) {
			s_debug("XM allocated %zu bytes via \"%s\" VMM at %p",
				vlen, via_vmm ? "user" : "core", p);
		}

		G_PREFETCH_HI_W(p);			/* User is going to write in block */

		/*
		 * Common statistics updates, whether we end-up allocating a block
		 * as core or as user memory.
		 */

		XSTATS_LOCK;
		xstats.allocations++;
		xstats.alloc_via_vmm++;
		xstats.user_blocks++;

		/*
		 * We no longer attempt to split the tail of large blocks, the ones
		 * we allocate as standalone blocks: this tends to fragment memory over
		 * the long run and is not efficient.
		 *
		 * Hence large blocks we allocate will be treated as user memory and
		 * managed as such.
		 *
		 *		--RAM, 2017-11-02
		 */

		if (!via_vmm) {
			/* Necessarily split, since we did not force user VMM allocation */
			void *split = ptr_add_offset(p, len);
			xstats.vmm_split_pages++;
			xstats.user_memory += len;
			xstats.vmm_alloc_pages += vmm_page_count(vlen);
			XSTATS_UNLOCK;
			memusage_add(xstats.user_mem, len);
			xmalloc_freelist_insert(split, vlen-len, FALSE, XM_COALESCE_AFTER);
			return xmalloc_block_setup(p, len);
		} else {
			xstats.vmm_user_blocks++;	/* Counts standalone blocks */
			xstats.vmm_total_user_blocks++;
			xstats.vmm_alloc_user_pages += vmm_page_count(vlen);
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
		xstats.allocations++;
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
	return xallocate(size, TRUE, TRUE);
}

/**
 * Allocate a memory chunk capable of holding ``size'' bytes.
 *
 * If no memory is available, crash with a fatal error message.
 *
 * This is a "physical" allocation that skips thread pools.  Such a block
 * should be reallocated using xprealloc() to ensure it stays out of thread
 * pools.
 *
 * One reason to use this call is to be able to ensure that there will be
 * a header before the allocated block to provide the block size.
 *
 * @return allocated pointer (never NULL).
 */
void *
xpmalloc(size_t size)
{
	XSTATS_INCX(allocations_physical);
	return xallocate(size, TRUE, FALSE);
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

	XSTATS_INCX(allocations_heap);
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
	XSTATS_INCX(allocations_zeroed);

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
	size_t len;
	char *res, *p;

	g_assert(size_is_non_negative(n));

	if G_UNLIKELY(NULL == str)
		return NULL;

	len = clamp_strlen(str, n);
	res = xmalloc(len + 1);
	p = mempcpy(res, str, len);
	*p = '\0';

	return res;
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
 * Computes user size of allocated block.
 */
size_t
xallocated(const void *p)
{
	size_t len;
	const struct xheader *xh;

	if G_UNLIKELY(NULL == p)
		return 0;

#ifdef XMALLOC_PTR_SAFETY
	if (!xmalloc_is_valid_pointer(p, FALSE)) {
		s_error_from(_WHERE_, "%s() given an invalid pointer %p: %s",
			G_STRFUNC, p, xmalloc_invalid_ptrstr(p));
	}
#endif

	xh = const_ptr_add_offset(p, -XHEADER_SIZE);
	G_PREFETCH_R(&xh->length);

	if (is_trapping_malloc() && is_xaligned(p)) {
		len = xalign_allocated(p);
		if G_LIKELY(len != 0)
			return len;
	}

	len = xmalloc_thread_allocated(p);
	if (len != 0)
		return len;

	if (!xmalloc_is_valid_length(xh, xh->length)) {
		s_error_from(_WHERE_,
			"corrupted malloc header for pointer %p: bad lengh %zu",
			p, xh->length);
	}

	return xh->length - XHEADER_SIZE;	/* User size, substract overhead */
}

/**
 * Computes user size of allocated block via xpmalloc().
 */
size_t
xpallocated(const void *p)
{
	const struct xheader *xh;

	if G_UNLIKELY(NULL == p)
		return 0;

#ifdef XMALLOC_PTR_SAFETY
	if (!xmalloc_is_valid_pointer(p, FALSE)) {
		s_error_from(_WHERE_, "%s() given an invalid pointer %p: %s",
			G_STRFUNC, p, xmalloc_invalid_ptrstr(p));
	}
#endif

	xh = const_ptr_add_offset(p, -XHEADER_SIZE);

	if (!xmalloc_is_valid_length(xh, xh->length)) {
		s_error_from(_WHERE_,
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
	bool is_vmm;

	/*
	 * Some parts of the libc can call free() with a NULL pointer.
	 * So we explicitly allow this to be able to replace free() correctly.
	 */

	if G_UNLIKELY(NULL == p)
		return;

	xh = ptr_add_offset(p, -XHEADER_SIZE);

	/*
	 * Handle thread-specific blocks early in the process since they do not
	 * have any malloc header.
	 */

	if (xmalloc_thread_free(p))
		return;

	/*
	 * Handle pointers returned by posix_memalign() and friends that
	 * would be aligned and therefore directly allocated by VMM or through
	 * zones.
	 *
	 * The is_xaligned() test checks whether the pointer is at least aligned
	 * to the minimum size we're aligning through special allocations, so
	 * that we don't invoke the costly xalign_free() if we can avoid it.
	 */

	if (is_trapping_malloc() && is_xaligned(p) && xalign_free(p))
		return;

#ifdef XMALLOC_PTR_SAFETY
	if (!xmalloc_is_valid_pointer(p, FALSE)) {
		s_error_from(_WHERE_, "attempt to free invalid pointer %p: %s",
			p, xmalloc_invalid_ptrstr(p));
	}
#endif

	/*
	 * Freeings to freelist are disabled at shutdown time.
	 */

	if G_UNLIKELY(xmalloc_no_freeing)
		return;

	if (!xmalloc_is_valid_length(xh, xh->length)) {
		s_error_from(_WHERE_,
			"corrupted malloc header for pointer %p: bad lengh %zu",
			p, xh->length);
	}

	XSTATS_LOCK;
	xstats.freeings++;
	xstats.user_memory -= xh->length;
	xstats.user_blocks--;
	XSTATS_UNLOCK;
	memusage_remove(xstats.user_mem, xh->length);

	/*
	 * Detect whether we are freeing a standalone VMM region: that's a user
	 * region and it can be quickly handled here and returned directly to
	 * the VMM layer.
	 * 		--RAM, 2017-11-02
	 */

	is_vmm = FALSE;

	if G_UNLIKELY(
		XMALLOC_VIA_VMM(xh->length) &&
		!xmalloc_isheap(xh, xh->length)
	) {
		if (vmm_page_start(xh) != xh) {
			s_error_from(_WHERE_,
				"corrupted malloc header for pointer %p: bad lengh %zu "
				"since block start %p is not page-aligned",
				p, xh->length, xh);
		}
		is_vmm = TRUE;
	}

	/*
	 * Blocks smallers than XMALLOC_MAXSIZE bytes may also be a standalone
	 * VMM region if aligned on a page and the size is consistent.
	 * 		--RAM, 2017-11-03
	 */

	if (
		!is_vmm &&
		round_pagesize(xh->length) == xh->length &&
		vmm_page_start(xh) == xh &&
		!xmalloc_isheap(xh, xh->length)
	) {
		is_vmm = TRUE;
	}

	if (is_vmm) {
		XSTATS_LOCK;
		xstats.vmm_freed_user_pages += vmm_page_count(xh->length);
		xstats.free_via_vmm++;
		xstats.vmm_user_blocks--;
		XSTATS_UNLOCK;

		vmm_free(xh, xh->length);
		return;
	}

	/*
	 * Because of FreeBSD, we do not run xmalloc_early_init() on the early
	 * allocation path, when we handle sbrk() allocations.  However, when
	 * the first free() starts to come around, it's safe to perform the early
	 * freelist setup.  We need it anyway to return the block there!
	 *		--RAM. 2013-12-01
	 */

	ONCE_FLAG_RUN(xmalloc_early_inited, xmalloc_early_init);

	xmalloc_freelist_add(xh, xh->length, XM_COALESCE_ALL | XM_COALESCE_SMART);
}

/**
 * Reallocate a block allocated via xmalloc().
 *
 * @param p				original user pointer
 * @param size			new user-size
 * @param can_thread	whether thread memory pools can be used
 *
 * @return
 * If a NULL pointer is given, act as if xmalloc() had been called and
 * return a new pointer.
 * If the new size is 0, act as if xfree() had been called and return NULL.
 * Otherwise return a pointer to the reallocated block, which may be different
 * from the original pointer.
 */
static void *
xreallocate(void *p, size_t size, bool can_thread)
{
	struct xheader *xh = ptr_add_offset(p, -XHEADER_SIZE);
	size_t newlen;
	void *np;
	unsigned stid;
	struct xchunk *xck;
	bool is_vmm;

	if (NULL == p)
		return xallocate(size, TRUE, can_thread);

	if (0 == size) {
		xfree(p);
		return NULL;
	}

	/*
	 * We need to compute the thread small ID, but we use this opportunity to
	 * also check whether we are being called from a signal handler.
	 *
	 * Note that the signal_in_unsafe_handler_stid() routine will return TRUE
	 * if it cannot compute a proper thread ID, meaning we're probably
	 * discovering a new thread: we thus need to call thread_small_id() in
	 * that case.
	 */

	if (signal_in_unsafe_handler_stid(&stid)) {
		if (THREAD_UNKNOWN_ID == stid) {
			stid = thread_small_id();
		} else {
			XSTATS_INCX(allocations_in_handler);
			s_minicarp_once("%s(): %s reallocating to %zu bytes "
				"from signal handler",
				G_STRFUNC, thread_safe_id_name(stid), size);
		}
	}

	/*
	 * Handle blocks from a thread-specific pool specially, since they have
	 * no malloc header and cannot be coalesced because they are allocated
	 * from zones with fix-sized blocks.
	 */

	xck = xmalloc_thread_get_chunk(p, stid, TRUE);

	if (xck != NULL) {
		if G_UNLIKELY(xmalloc_no_freeing || !can_thread)
			goto realloc_from_thread;

		XSTATS_INCX(reallocs);

		if (xmalloc_round(size) == xck->xc_size) {
			XSTATS_INCX(realloc_noop);

			if (xmalloc_debugging(2)) {
				s_debug("XM realloc of %p to %zu bytes can be a noop "
					"(already in a %u-byte chunk for thread #%u)",
					p, size, xck->xc_size, stid);
			}

			return p;
		}

		goto realloc_from_thread;	/* Move block around */
	}

#ifdef XMALLOC_PTR_SAFETY
	if G_UNLIKELY(!xmalloc_is_valid_pointer(xh, FALSE)) {
		s_error_from(_WHERE_, "attempt to realloc invalid pointer %p: %s",
			p, xmalloc_invalid_ptrstr(p));
	}
#endif

	if G_UNLIKELY(!xmalloc_is_valid_length(xh, xh->length)) {
		s_error_from(_WHERE_,
			"corrupted malloc header for pointer %p: bad length %ld",
			p, (long) xh->length);
	}

	if G_UNLIKELY(xmalloc_no_freeing)
		goto skip_coalescing;

	/*
	 * Compute the size of the physical block we need, including overhead.
	 */

	newlen = xmalloc_round_blocksize(xmalloc_round(size) + XHEADER_SIZE);
	XSTATS_INCX(reallocs);

	/*
	 * Identify blocks allocated from the VMM layer: they are page-aligned
	 * and their size is a multiple of the system's page size, and they are
	 * not located in the heap.
	 */

	is_vmm = FALSE;

	if (XMALLOC_VIA_VMM(xh->length) && !xmalloc_isheap(xh, xh->length)) {
		if (vmm_page_start(xh) != xh) {
			s_error_from(_WHERE_,
				"corrupted malloc header for pointer %p: bad lengh %zu "
				"since block start %p is not page-aligned",
				p, xh->length, xh);
		}
		is_vmm = TRUE;
	}

	if (
		!is_vmm &&
		round_pagesize(xh->length) == xh->length &&
		vmm_page_start(xh) == xh &&
		!xmalloc_isheap(xh, xh->length)
	) {
		is_vmm = TRUE;
	}


	if (is_vmm) {
		newlen = round_pagesize(newlen);
		XSTATS_INCX(realloc_vmm);

		/*
		 * If the size remains the same in the VMM space, we have nothing
		 * to do unless we have a relocatable fragment.
		 */

		if (newlen == xh->length) {
			void *q = vmm_move(xh, xh->length);
			if (q == xh) {
				XSTATS_INCX(realloc_noop);
				XSTATS_INCX(realloc_noop_same_vmm);
				return p;
			} else if (xmalloc_debugging(1)) {
				struct xheader *nxh = q;
				s_debug("XM relocated %zu-byte VMM region at %p to %p"
					" (new pysical size is %zu bytes, user size is %zu)",
					nxh->length, (void *) xh, q, newlen, size);
			}
			XSTATS_INCX(realloc_vmm_moved);
			return ptr_add_offset(q, XHEADER_SIZE);
		}

		/*
		 * If the new size is smaller than the original, we can attempt to
		 * first move the block and then shrink it inplace.
		 *
		 * Note that if the block was allocated as a standalone VM region
		 * but was smaller than XMALLOC_MAXSIZE, it remains a VM region
		 * when shrinking: we will remove whole pages, and possibly lose
		 * memory space.
		 */

		if (newlen < xh->length) {
			size_t oldlen = xh->length;
			void *q = vmm_move(xh, xh->length);
			vmm_shrink(q, oldlen, newlen);
			if (xmalloc_debugging(1)) {
				struct xheader *nxh = q;
				s_debug("XM relocated %zu-byte VMM region at %p to %p"
					" (shrunk to new pysical size %zu bytes, user size is %zu)",
					nxh->length, (void *) xh, q, newlen, size);
			}
			XSTATS_LOCK;
			xstats.user_memory -= oldlen - newlen;
			if (q != xh)
				xstats.realloc_via_vmm_move_shrink++;
			else
				xstats.realloc_via_vmm_shrink++;
			XSTATS_UNLOCK;
			memusage_remove(xstats.user_mem, oldlen - newlen);
			return xmalloc_block_setup(q, newlen);
		}

		/*
		 * We either have to extend the VMM region, or change its nature from
		 * a standalone VMM region to a freelist-managed block.
		 *
		 * We can skip all the coalescing logic since we have to allocate
		 * a new region.
		 */

		goto skip_coalescing;
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

			XSTATS_INCX(realloc_relocate_smart_attempts);

			if (q != NULL) {
				if (newlen == fl->blocksize && xm_ptr_cmp(xh, q) < 0) {
					xfl_remove_selected(fl, q);
					np = xmalloc_block_setup(q, newlen);

					XSTATS_INCX(realloc_relocate_smart_success);

					if (xmalloc_debugging(1)) {
						s_debug("XM relocated %zu-byte block at %p to %p"
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
			s_debug("XM realloc of %p to %zu bytes can be a noop "
				"(already %zu-byte long from %s)",
				p, size, xh->length, xmalloc_isheap(p, size) ? "heap" : "VMM");
		}

		XSTATS_INCX(realloc_noop);
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
				s_debug("XM realloc of %p to %zu bytes can be a noop "
					"(already %zu-byte long from %s, not shrinking %zu bytes)",
					p, size, xh->length,
					xmalloc_isheap(p, size) ? "heap" : "VMM", extra);
			}

			XSTATS_INCX(realloc_noop);
			return p;
		} else {
			void *end = ptr_add_offset(xh, newlen);

			if (xmalloc_debugging(1)) {
				s_debug("XM using inplace shrink on %zu-byte block at %p"
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
						s_debug("XM realloc NOT coalescing next %zu-byte "
							"[%p, %p[ from list #%zu with [%p, %p[: invalid "
							"resulting size of %zu bytes",
							blksize, end, ptr_add_offset(end, blksize), i,
							(void *) xh, end, csize);
					}
					mutex_unlock(&fl->lock);
					break;
				}

				if (xmalloc_debugging(6)) {
					s_debug("XM realloc coalescing next %zu-byte "
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
					s_debug("XM realloc splitting large %zu-byte block at %p"
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
				s_debug("XM realloc used inplace coalescing on "
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
						s_debug("XM realloc not coalescing previous "
							"%zu-byte [%p, %p[ from list #%zu with [%p, %p[: "
							"invalid resulting size of %zu bytes",
							blksize, before, ptr_add_offset(before, blksize), i,
							(void *) xh, end, csize);
					}
					mutex_unlock(&fl->lock);
					break;
				}

				if (xmalloc_debugging(6)) {
					s_debug("XM realloc coalescing previous %zu-byte "
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
					s_debug("XM realloc splitting large %zu-byte block at %p"
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
				s_debug("XM realloc used coalescing with block preceding "
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

	np = xallocate(size, TRUE, can_thread);

	XSTATS_INCX(realloc_regular_strategy);

	if (xmalloc_debugging(1)) {
		s_debug("XM realloc used regular strategy: "
			"%zu-byte block at %p moved to %zu-byte block at %p",
			xh->length, (void *) xh,
			size + XHEADER_SIZE, ptr_add_offset(np, -XHEADER_SIZE));
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

inplace:
	xh->length = newlen;
	return p;

realloc_from_thread:
	{
		size_t old_size = xck->xc_size;

		np = xallocate(size, TRUE, can_thread);

		XSTATS_INCX(realloc_from_thread_pool);
		XSTATS_INCX(realloc_regular_strategy);

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
 * from the original pointer.
 */
void *
xrealloc(void *p, size_t size)
{
	return xreallocate(p, size, TRUE);
}

/**
 * Reallocate a block allocated via xmalloc(), forcing xpmalloc() if needed.
 *
 * @param p				original user pointer
 * @param size			new user-size
 *
 * @return
 * If a NULL pointer is given, act as if xmalloc() had been called and
 * return a new pointer.
 * If the new size is 0, act as if xfree() had been called and return NULL.
 * Otherwise return a pointer to the reallocated block, which may be different
 * from the original pointer.
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
		 * Save length of first block to help the strategy should we end-up
		 * with two blocks being coalesced, and a length that does not fit
		 * the freelist.
		 */

		xr->head = ptr_diff(end, start);	/* Necessarily fits */
		old = erbtree_insert(rbt, &xr->node);

		g_assert_log(NULL == old,		/* Was not already present in tree */
			"xr=[%p, %p[, old=[%p, %p[ (%u block%s)",
			start, end, old->start, old->end,
			old->blocks, plural(old->blocks));
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

	if G_UNLIKELY(XMALLOC_VIA_VMM(len))
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
			s_debug("XM GC [%p, %p[ (%zu bytes, %u blocks) handled as: "
				"%u-byte head, %u-byte tail, VMM range [%p, %p[ released",
				xr->start, xr->end, ptr_diff(xr->end, xr->start), xr->blocks,
				xr->head, xr->tail, pstart, pend);
		}

		return FALSE;				/* Keep range */

	cannot_free_page:
		XSTATS_INCX(xgc_page_freeing_failed);

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

	if G_UNLIKELY(2 == xr->blocks && !XMALLOC_VIA_VMM(len)) {
		if (xmalloc_round_blocksize(len) != len) {
			unsigned b1 = xr->head;	/* First block we added to range */
			unsigned b2 = len - b1;	/* Second block */
			unsigned largest;
			struct xsplit *xs;

			largest = MAX(b1, b2);
			xs = xmalloc_split_info(largest);

			if (xs->larger <= largest) {
				/* Coalescing will not do better than current situation */
				XSTATS_INCX(xgc_coalescing_useless);
				return TRUE;		/* Will not attempt any coalescing */
			}
		}
	}

	/*
	 * Blocks can be coalesced, make sure there is room in the targeted
	 * bucket(s).
	 */

	if G_UNLIKELY(!xgc_block_is_freeable(len, xgctx, TRUE)) {
		XSTATS_INCX(xgc_coalescing_failed);
		return TRUE;			/* Will not attempt any coalescing */
	}

	xr->strategy = XGC_ST_COALESCE;

	if (xmalloc_debugging(3)) {
		s_debug("XM GC [%p, %p[ (%zu bytes, %u blocks) will be coalesced",
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
		XSTATS_UNLOCK;
		XSTATS_DECX(xgc_blocks_collected);	/* One block is put back */
		xp->coalesced += xr->blocks;
		break;
	case XGC_ST_FREE_PAGES:
		{
			void *end = ptr_add_offset(p, len);
			void *q;
			size_t pages;

			if (xr->head != 0) {
				xmalloc_freelist_insert(p, xr->head, TRUE, XM_COALESCE_NONE);
				XSTATS_DECX(xgc_blocks_collected);	/* One block is put back */
			}

			p = ptr_add_offset(p, xr->head);
			q = ptr_add_offset(end, -xr->tail);

			if (!xmalloc_freecore(p, ptr_diff(q, p))) {
				/*
				 * Can only happen for sbrk()-allocated core and we made
				 * sure this was VMM memory during strategy elaboration.
				 */
				s_error_from(_WHERE_, "unxepected core release error");
			}

			if (xr->tail != 0) {
				xmalloc_freelist_insert(q, xr->tail, TRUE, XM_COALESCE_NONE);
				if (0 == xr->head || xr->blocks > 1)
					XSTATS_DECX(xgc_blocks_collected);	/* Block is put back */
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
	static time_t next_run;
	static spinlock_t xgc_slk = SPINLOCK_INIT;
	static long last_freelist_stamp;
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
	size_t deferred_buckets = 0, deferred_blocks = 0;

	if (!xmalloc_vmm_is_up)
		return;

	/*
	 * If there has been no changes in the freelist (no insertions nor any
	 * deferred block pending), we do not need to spend time here.
	 */

	XSTATS_LOCK;

	if (last_freelist_stamp == xmalloc_freelist_stamp)
		goto avoided;

	XSTATS_UNLOCK;

	if (!spinlock_try(&xgc_slk))
		return;

	/*
	 * Limit calls to 1% of the execution time, as computed at the end
	 * (by setting the ``next_run'' variable).
	 */

	now = tm_time();

	if (now < next_run) {
		XSTATS_INCX(xgc_time_throttled);
		goto done;
	}

	tm_now_exact(&start);
	start_cpu = tm_cputime(NULL, NULL);

	XSTATS_INCX(xgc_runs);

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
	 * shrink buckets that are too large, return deferred blocks if any.
	 */

	for (i = 0; i < N_ITEMS(xfreelist); i++) {
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

		if G_UNLIKELY(0 != fl->deferred.count) {
			mutex_lock(&fl->lock);
			if (xfl_has_deferred(fl)) {
				deferred_buckets++;
				deferred_blocks += fl->deferred.count;
				xfl_process_deferred(fl);
			}
			mutex_unlock(&fl->lock);
		}

		if G_UNLIKELY(fl->expand) {
			mutex_lock(&fl->lock);

			if G_UNLIKELY(!fl->expand) {
				mutex_unlock(&fl->lock);
				continue;
			}
			if (xmalloc_debugging(1)) {
				s_debug("XM GC resizing freelist #%zu (cap=%zu, cnt=%zu)",
					xfl_index(fl), fl->capacity, fl->count);
			}

			g_assert(!fl->extending);
			fl->extending = TRUE;
			xfl_extend(fl);
			fl->extending = FALSE;

			XSTATS_INCX(xgc_bucket_expansions);
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

			g_assert(!fl->shrinking);
			fl->shrinking = TRUE;
			if (xfl_shrink(fl))
				XSTATS_INCX(xgc_bucket_shrinkings);
			fl->shrinking = FALSE;

			mutex_unlock(&fl->lock);
		}
	}

	if (xmalloc_debugging(0) && 0 != deferred_buckets) {
		s_debug("XM GC processed %zu bucket%s with %zu deferred block%s",
			deferred_buckets, plural(deferred_buckets),
			deferred_blocks, plural(deferred_blocks));
	}

	/*
	 * Pass 1b: lock all buckets, compute largest bucket usage and record
	 * the available room in each bucket.
	 */

	for (i = 0; i < N_ITEMS(xfreelist); i++) {
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

		g_assert_log(fl->count <= fl->capacity,
			"count=%zu, capacity=%zu in freelist #%zu (%zu-byte block)",
			fl->count, fl->capacity, xfl_index(fl), fl->blocksize);
	}

	/*
	 * Pass 2: computes coalesced ranges for all the blocks.
	 */

	erbtree_init(&rbt, xgc_range_cmp, offsetof(struct xgc_range, node));

	for (i = 0; i < N_ITEMS(xfreelist); i++) {
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
		s_debug("XM GC freelist holds %zu block%s defining %zu range%s",
			blocks, plural(blocks), ranges, plural(ranges));
	}

	/*
	 * Pass 3: decide on the fate of all the identified ranges.
	 */

	erbtree_foreach_remove(&rbt, xgc_range_strategy, &xgctx);

	if (xmalloc_debugging(0)) {
		size_t ranges = erbtree_count(&rbt);
		s_debug("XM GC left with %zu range%s to process",
			ranges, plural(ranges));
	}

	if (0 == erbtree_count(&rbt))
		goto unlock;

	/*
	 * Pass 4: strip blocks falling in ranges for which we have a strategy.
	 */

	xstats.xgc_collected++;

	/*
	 * Even though this is technically a "user" block, we perform a "core"
	 * allocation because we must not enter the thread-magazine allocators
	 * from the xmalloc garbage collector!
	 */

	tmp = vmm_core_alloc(xgctx.largest * sizeof(void *));

	for (i = 0; i < N_ITEMS(xfreelist); i++) {
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

			XSTATS_INCX(xgc_blocks_collected);

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
			g_assert_log(fl->count <= fl->capacity,
				"count=%zu, capacity=%zu in freelist #%zu (%zu-byte block)",
				fl->count, fl->capacity, xfl_index(fl), fl->blocksize);

			memcpy(fl->pointers, tmp, fl->count * sizeof fl->pointers[0]);
		}
	}

	vmm_core_free(tmp, xgctx.largest * sizeof(void *));

	/*
	 * Pass 5: execute the strategy.
	 */

	erbtree_foreach(&rbt, xgc_range_process, &processed);

	/*
	 * Pass 6: unlock buckets (in reverse order, for assertions).
	 */

unlock:
	for (i = N_ITEMS(xfreelist); i != 0; i--) {
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
			s_debug("XM GC took %'u usecs (CPU=%'u usecs) "
				"coalesced-blocks=%zu, freed-pages=%zu, next in %d sec%s",
				(uint) real_elapsed, (uint) cpu_elapsed,
				processed.coalesced, processed.pages,
				increment, plural(increment));
		}
	}

done:
	XSTATS_LOCK;
	last_freelist_stamp = xmalloc_freelist_stamp;
	XSTATS_UNLOCK;

	spinunlock(&xgc_slk);
	return;

avoided:
	if (xmalloc_debugging(0)) {
		s_debug("XM GC call avoided (no freelist change)");
	}

	xstats.xgc_avoided++;
	XSTATS_UNLOCK;
}

/**
 * Signal that we're about to close down all activity.
 */
void G_COLD
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
void G_COLD
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
	 * We have to use s_info() to prevent any memory allocation during logging.
	 * It is OK at this point since the VMM layer is now up.
	 */

	if (sbrk_allocated != 0) {
		s_info("malloc() allocated %zu bytes of heap (%zu remain)",
			sbrk_allocated,
			ptr_diff(current_break, lowest_break) - sbrk_alignment);

		if (sbrk_alignment != 0)
			s_info("addded %zu byte%s to heap base for %zu-byte alignment",
				sbrk_alignment, plural(sbrk_alignment), xmalloc_round(1));
	}

	if (xmalloc_debugging(0)) {
		s_info("XM using %ld freelist buckets", (long) XMALLOC_FREELIST_COUNT);
	}
}

/**
 * Signal that we should stop freeing memory to the freelist.
 *
 * This is mostly useful during final cleanup when xmalloc() replaces malloc().
 */
void G_COLD
xmalloc_stop_freeing(void)
{
	memusage_free_null(&xstats.user_mem);
	xmalloc_no_freeing = TRUE;
}

/**
 * Generate a SHA1 digest of the current xmalloc statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
xmalloc_stats_digest(sha1_t *digest)
{
	uint32 n = entropy_nonce();

	/*
	 * Don't take locks to read the statistics, to enhance unpredictability.
	 */

	XSTATS_INCX(xmalloc_stats_digest);
	SHA1_COMPUTE_NONCE(xstats, &n, digest);
}

/**
 * Dump xmalloc usage statistics to specified logging agent.
 */
void G_COLD
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
void G_COLD
xmalloc_dump_stats_log(logagent_t *la, unsigned options)
{
	struct xstats stats;

	XSTATS_LOCK;
	stats = xstats;		/* struct copy under lock protection */
	XSTATS_UNLOCK;
	bool groupped = booleanize(options & DUMP_OPT_PRETTY);

#define DUMP(x)	log_info(la, "XM %s = %s", #x,		\
	uint64_to_string_grp(stats.x, groupped))

#define DUMP64(x) G_STMT_START {							\
	uint64 v = AU64_VALUE(&xstats.x);						\
	log_info(la, "XM %s = %s", #x,							\
		uint64_to_string_grp(v, groupped));					\
} G_STMT_END

#define DUMPV(x)	log_info(la, "XM %s = %s", #x,			\
	size_t_to_string_grp(x, groupped))

	/*
	 * On Windows, we're performing dynamic patching of loaded libraries
	 * to redirect them to our malloc(), hence we need to include the
	 * status of our patching activity as part of the malloc() stats.
	 */

#ifdef MINGW32
	win32dlp_dump_stats_log(la, options);
#endif

	DUMP(allocations);
	DUMP64(allocations_zeroed);
	DUMP(allocations_aligned);
	DUMP64(allocations_heap);
	DUMP64(allocations_physical);
	DUMP64(allocations_in_handler);
	DUMP(alloc_via_freelist);
	DUMP(alloc_via_vmm);
	DUMP(alloc_via_sbrk);
	DUMP(alloc_via_thread_pool);
	DUMP64(alloc_forced_user_vmm);
	DUMP(freeings);
	DUMP64(freeings_in_handler);
	DUMP(free_via_vmm);
	DUMP64(free_sbrk_core);
	DUMP(free_sbrk_core_released);
	DUMP(free_vmm_core);
	DUMP64(free_coalesced_vmm);
	DUMP(free_thread_pool);
	DUMP64(free_foreign_thread_pool);
	DUMP(sbrk_alloc_bytes);
	DUMP(sbrk_freed_bytes);
	DUMP(sbrk_wasted_bytes);
	DUMP(vmm_alloc_pages);
	DUMP(vmm_alloc_user_pages);
	DUMP(vmm_freed_pages);
	DUMP(vmm_freed_user_pages);
	DUMP64(vmm_thread_pages);
	DUMP(vmm_user_blocks);
	DUMP(vmm_total_user_blocks);
	DUMP(aligned_via_freelist);
	DUMP(aligned_via_freelist_then_vmm);
	DUMP(aligned_via_vmm);
	DUMP(aligned_via_vmm_subpage);
	DUMP(aligned_via_zone);
	DUMP(aligned_via_xmalloc);
	DUMP64(aligned_lookups);
	DUMP(aligned_freed);
	DUMP64(aligned_free_false_positives);
	DUMP(aligned_zones_capacity);
	DUMP(aligned_zones_count);
	DUMP(aligned_arenas_created);
	DUMP(aligned_arenas_destroyed);
	DUMP(aligned_overhead_bytes);
	DUMP(aligned_zone_blocks);
	DUMP(aligned_zone_memory);
	DUMP(aligned_vmm_blocks);
	DUMP(aligned_vmm_memory);
	DUMP64(reallocs);
	DUMP64(realloc_noop);
	DUMP64(realloc_noop_same_vmm);
	DUMP64(realloc_vmm);
	DUMP64(realloc_vmm_moved);
	DUMP(realloc_via_vmm_shrink);
	DUMP(realloc_via_vmm_move_shrink);
	DUMP(realloc_inplace_shrinking);
	DUMP(realloc_inplace_extension);
	DUMP(realloc_coalescing_extension);
	DUMP64(realloc_relocate_smart_attempts);
	DUMP64(realloc_relocate_smart_success);
	DUMP64(realloc_regular_strategy);
	DUMP64(realloc_from_thread_pool);
	DUMP64(freelist_insertions);
	DUMP64(freelist_insertions_no_coalescing);
	DUMP(freelist_insertions_deferred);
	DUMP(freelist_deferred_processed);
	DUMP64(freelist_bursts);
	DUMP64(freelist_burst_insertions);
	DUMP64(freelist_plain_insertions);
	DUMP64(freelist_unsorted_insertions);
	DUMP64(freelist_coalescing_ignore_burst);
	DUMP64(freelist_coalescing_ignore_vmm);
	DUMP64(freelist_coalescing_ignored);
	DUMP64(freelist_coalescing_done);
	DUMP64(freelist_coalescing_failed);
	DUMP64(freelist_linear_lookups);
	DUMP64(freelist_binary_lookups);
	DUMP64(freelist_short_yes_lookups);
	DUMP64(freelist_short_no_lookups);
	DUMP64(freelist_partial_sorting);
	DUMP64(freelist_full_sorting);
	DUMP64(freelist_avoided_sorting);
	DUMP64(freelist_sorted_superseding);
	DUMP64(freelist_split);
	DUMP64(freelist_nosplit);
	DUMP(freelist_blocks);
	DUMP(freelist_memory);

	{
		size_t chunk_pool_count, chunk_pool_capacity;

		if G_LIKELY(xpages_pool != NULL) {
			chunk_pool_count = pool_count(xpages_pool);
			chunk_pool_capacity = pool_capacity(xpages_pool);
		} else {
			chunk_pool_count = chunk_pool_capacity = 0;
		}

		DUMPV(chunk_pool_count);
		DUMPV(chunk_pool_capacity);
	}

	DUMP64(xgc_runs);
	DUMP64(xgc_time_throttled);
	DUMP(xgc_collected);
	DUMP(xgc_avoided);
	DUMP64(xgc_blocks_collected);
	DUMP(xgc_pages_collected);
	DUMP(xgc_coalesced_blocks);
	DUMP(xgc_coalesced_memory);
	DUMP64(xgc_coalescing_useless);
	DUMP64(xgc_coalescing_failed);
	DUMP64(xgc_page_freeing_failed);
	DUMP64(xgc_bucket_expansions);
	DUMP64(xgc_bucket_shrinkings);
	DUMP(user_memory);
	DUMP(user_blocks);

	DUMP64(xmalloc_stats_digest);

#undef DUMP
#undef DUMP64
#undef DUMPV
}

/**
 * Dump freelist status to specified log agent.
 */
void G_COLD
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

	for (i = 0; i < N_ITEMS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];

		if (0 == fl->capacity)
			continue;

		bytes += fl->blocksize * fl->count;
		blocks = size_saturate_add(blocks, fl->count);

		if (0 != fl->count)
			largest = fl->blocksize;

		if (fl->sorted == fl->count) {
			log_info(la, "XM freelist #%zu (%zu bytes): cap=%zu, "
				"cnt=%zu, def=%zu, lck=%zu",
				i, fl->blocksize, fl->capacity, fl->count,
				fl->deferred.count, mutex_held_depth(&fl->lock));
		} else {
			log_info(la, "XM freelist #%zu (%zu bytes): cap=%zu, "
				"sort=%zu/%zu, def=%zu, lck=%zu",
				i, fl->blocksize, fl->capacity, fl->sorted, fl->count,
				fl->deferred.count, mutex_held_depth(&fl->lock));
		}
	}

	ZERO(&tstats);

	for (j = 0; j < XM_THREAD_COUNT; j++) {
		for (i = 0; i < XMALLOC_CHUNKHEAD_COUNT; i++) {
			struct xchunkhead *ch = &xchunkhead[i][j];
			size_t tchunks = 0, tcap = 0, tcnt = 0;
			struct xchunk *xck;

			if (ch->shared)
				tstats[j].shared++;

			if (0 == elist_count(&ch->list) + elist_count(&ch->full))
				continue;

			ELIST_FOREACH_DATA(&ch->list, xck) {
				xchunk_check(xck);
				tstats[j].chunks++;
				tstats[j].freebytes += xck->xc_count * xck->xc_size;
				tstats[j].freeblocks += xck->xc_count;
				tchunks++;
				tcap += xck->xc_capacity;
				tcnt += xck->xc_count;
			}

			ELIST_FOREACH_DATA(&ch->full, xck) {
				xchunk_check(xck);
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
		blocks, plural(blocks));

	log_info(la, "XM freelist largest block is %zu bytes", largest);

	for (j = 0; j < XM_THREAD_COUNT; j++) {
		size_t pool;

		if (0 == tstats[j].chunks)
			continue;

		log_info(la, "XM thread #%zu holds %s bytes (%s) spread "
			"among %zu block%s", j,
			uint64_to_string(tstats[j].freebytes),
			short_size(tstats[j].freebytes, FALSE),
			tstats[j].freeblocks, plural(tstats[j].freeblocks));

		pool = size_saturate_mult(tstats[j].chunks, xmalloc_pagesize);

		log_info(la, "XM thread #%zu uses a pool of %zu bytes (%s, %zu page%s)",
			j, pool, short_size(pool, FALSE),
			tstats[j].chunks, plural(tstats[j].chunks));

		if (0 != tstats[j].shared) {
			log_warning(la, "XM thread #%zu has %zu size%s requiring locking",
				j, tstats[j].shared, plural(tstats[j].shared));
		}
	}
}

/**
 * Dump xmalloc statistics.
 */
void G_COLD
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
static mutex_t xmalloc_xa_lk = MUTEX_INIT;

#define XMALLOC_XA_LOCK				mutex_lock(&xmalloc_xa_lk)
#define XMALLOC_XA_UNLOCK			mutex_unlock(&xmalloc_xa_lk)

#define XMALLOC_XA_LOCK_HIDDEN		mutex_lock_hidden(&xmalloc_xa_lk)
#define XMALLOC_XA_UNLOCK_HIDDEN	mutex_unlock_hidden(&xmalloc_xa_lk)

#define assert_xmalloc_xa_is_locked()	\
	assert_mutex_is_owned(&xmalloc_xa_lk)

/**
 * Type of pages that we can describe.
 */
enum xpage_type {
	XPAGE_SET,		/* Set of pages allocated contiguously */
	XPAGE_ZONE		/* An arena used by the zone allocator */
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

enum xzone_magic { XZONE_MAGIC = 0x26ac7d9b };

/**
 * A zone allocator descriptor.
 */
struct xzone {
	enum xzone_magic magic;		/**< Magic number */
	elist_t arenas;				/**< List of arenas in the zone */
	spinlock_t lock;			/**< Zone lock */
	size_t alignment;			/**< Zone alignment (also the block size) */
	int ashift;					/**< Alignment bit shift */
};

static inline void
xzone_check(const struct xzone * const z)
{
	g_assert(z != NULL);
	g_assert(XZONE_MAGIC == z->magic);
}

#define XZONE_LOCK(z)		spinlock(&(z)->lock)
#define XZONE_UNLOCK(z)		spinunlock(&(z)->lock)
#define XZONE_IS_LOCKED(z)	spinlock_is_held(&(z)->lock)

/**
 * Descriptor for an allocation arena within a zone allocator.
 *
 * Arenas are linked together to make sure we can quickly find a page with
 * free blocks.
 */
struct xdesc_zone {
	enum xpage_type type;		/* MUST be first for structural equivalence */
	struct xzone *zone;			/**< Zone to which this arena belongs to */
	link_t zone_link;			/**< Links zones with same alignment */
	void *arena;				/**< Allocated zone arena */
	bit_array_t *bitmap;		/**< Allocation bitmap in page */
	size_t nblocks;				/**< Amount of blocks in the zone */
};

struct xzone **xzones;			/**< Array of known zones */
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
		s_debug("XM forgot aligned %s %p (%zu bytes)",
			xdesc_type_str(xt->type), p, len);
	}

	switch (xt->type) {
	case XPAGE_SET:
		XSTATS_LOCK;
		xstats.aligned_overhead_bytes -= sizeof(struct xdesc_set);
		XSTATS_UNLOCK;
		goto done;
	case XPAGE_ZONE:
		XSTATS_LOCK;
		xstats.aligned_overhead_bytes -= sizeof(struct xdesc_zone);
		XSTATS_UNLOCK;
		goto done;
	}

	g_assert_not_reached();

done:
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
static size_t G_HOT
xa_lookup(const void *p, size_t *low_ptr)
{
	const struct xaligned
		*low = &aligned[0],
		*high = &aligned[aligned_count - 1],
		*mid;

	XSTATS_INCX(aligned_lookups);

	if G_UNLIKELY(0 == aligned_count) {
		if (low_ptr != NULL)
			*low_ptr = 0;
		return (size_t) -1;
	}

	/* Binary search */

	for (;;) {
		if G_UNLIKELY(low > high) {
			mid = NULL;		/* Not found */
			break;
		}

		mid = low + (high - low) / 2;

		if (p > mid->start)
			low = mid + 1;
		else if (p < mid->start)
			high = mid - 1;		/* -1 OK since pointers cannot reach page 0 */
		else
			break;				/* Found */
	}

	if (low_ptr != NULL)
		*low_ptr = low - &aligned[0];

	return NULL == mid ? (size_t) -1 : (size_t) (mid - &aligned[0]);
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
	assert_xmalloc_xa_is_locked();

	xdesc_free(aligned[idx].pdesc, aligned[idx].start);

	ARRAY_REMOVE_DEC(aligned, idx, aligned_count);
}

/**
 * Extend the "aligned" array.
 */
static void
xa_align_extend(void)
{
	size_t new_capacity;

	assert_xmalloc_xa_is_locked();

	new_capacity = size_saturate_mult(aligned_capacity, 2);

	if (0 == new_capacity)
		new_capacity = 2;

	XREALLOC_ARRAY(aligned, new_capacity);

	XSTATS_LOCK;
	xstats.aligned_overhead_bytes +=
		(new_capacity - aligned_capacity) * sizeof aligned[0];
	XSTATS_UNLOCK;

	aligned_capacity = new_capacity;

	if (xmalloc_debugging(1)) {
		s_debug("XM aligned array capacity now %zu, starts at %p (%zu bytes)",
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

	XMALLOC_XA_LOCK;

	if G_UNLIKELY(aligned_count >= aligned_capacity)
		xa_align_extend();

	/*
	 * Compute insertion index in the sorted array.
	 *
	 * At the same time, this allows us to make sure we're not dealing with
	 * a duplicate insertion.
	 */

	if G_UNLIKELY((size_t ) -1 != xa_lookup(p, &idx)) {
		s_error_from(_WHERE_, "page %p already in aligned list (as page %s)",
			p, xalign_type_str(&aligned[idx]));
	}

	g_assert(size_is_non_negative(idx) && idx <= aligned_count);

	/*
	 * Shift items if we're not inserting at the last position in the array.
	 */

	g_assert(aligned != NULL);

	ARRAY_MAKEROOM(aligned, idx, aligned_count, aligned_capacity);

	aligned_count++;
	aligned[idx].start = p;
	aligned[idx].pdesc = pdesc;

	XMALLOC_XA_UNLOCK;
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
	xstats.vmm_alloc_user_pages += vmm_page_count(size);
	xstats.user_blocks++;
	xstats.user_memory += size;
	xstats.aligned_vmm_blocks++;
	xstats.aligned_vmm_memory += size;
	XSTATS_UNLOCK;
	memusage_add(xstats.user_mem, size);

	if (xmalloc_debugging(2)) {
		s_debug("XM recorded aligned %p (%zu bytes)", p, size);
	}
}

/**
 * Initialize the array of zones.
 */
static void G_COLD
xzones_init(void)
{
	g_assert(spinlock_is_held(&xmalloc_zone_slk));
	g_assert(NULL == xzones);

	xzones_capacity = highest_bit_set(xmalloc_pagesize) - XALIGN_SHIFT;
	g_assert(size_is_positive(xzones_capacity));

	OMALLOC0_ARRAY(xzones, xzones_capacity);	/* Never freed! */

	XSTATS_LOCK;
	xstats.aligned_overhead_bytes += xzones_capacity * sizeof xzones[0];
	xstats.aligned_zones_capacity = xzones_capacity;
	XSTATS_UNLOCK;
}

/**
 * Allocate a new zone capable of allocating aligned objects.
 *
 * @param alignment		alignment constraint, which is also the block size
 *
 * @return a new zone allocator, to get aligned objects of ``alignment'' bytes.
 */
static struct xzone *
xzget(size_t alignment)
{
	struct xzone *z;

	g_assert(size_is_positive(alignment));
	g_assert(alignment < xmalloc_pagesize);
	g_assert(is_pow2(alignment));

	OMALLOC0(z);				/* Never freed! */
	z->magic = XZONE_MAGIC;
	z->alignment = alignment;
	z->ashift = highest_bit_set(alignment);
	elist_init(&z->arenas, offsetof(struct xdesc_zone, zone_link));
	spinlock_init(&z->lock);

	XSTATS_LOCK;
	xstats.aligned_overhead_bytes += sizeof *z;
	xstats.aligned_zones_count++;
	XSTATS_UNLOCK;

	return z;
}

/**
 * Allocate a zone arena with blocks of ``alignment'' bytes each.
 *
 * @param z		the zone to which the arena belongs to
 *
 * @return new page descriptor for the zone.
 */
static struct xdesc_zone *
xzarena(struct xzone *z)
{
	struct xdesc_zone *xz;
	void *arena;
	size_t nblocks;

	xzone_check(z);

	arena = vmm_core_alloc(xmalloc_pagesize);
	nblocks = xmalloc_pagesize / z->alignment;

	g_assert(nblocks >= 2);		/* Because alignment < pagesize */

	XMALLOC0(xz);
	xz->type = XPAGE_ZONE;
	xz->arena = arena;
	xz->bitmap = xmalloc0(BIT_ARRAY_BYTE_SIZE(nblocks));
	xz->nblocks = nblocks;
	xz->zone = z;

	xa_insert(arena, xz);

	XSTATS_LOCK;
	xstats.vmm_alloc_pages++;
	xstats.aligned_arenas_created++;
	xstats.aligned_overhead_bytes += sizeof *xz + BIT_ARRAY_BYTE_SIZE(nblocks);
	XSTATS_UNLOCK;

	if (xmalloc_debugging(2)) {
		s_debug("XM recorded aligned %p (%zu bytes) as %zu-byte zone",
			arena, xmalloc_pagesize, z->alignment);
	}

	return xz;
}

/**
 * Free arena belonging to zone.
 *
 * Upon entry, the zone must be locked and it will be unlocked.
 *
 * @param z		the zone allocator to which arena belong
 * @param xz	the allocation arena to free
 */
static void
xzdestroy(struct xzone *z, struct xdesc_zone *xz)
{
	g_assert(XZONE_IS_LOCKED(z));

	elist_remove(&z->arenas, xz);
	xz->zone = NULL;
	XZONE_UNLOCK(z);

	/*
	 * The zone arena is now detached from the zone allocator and cannot
	 * be found when allocating.  The descriptor is not freed yet.
	 */

	if (xmalloc_debugging(2)) {
		size_t cnt;

		XZONE_LOCK(z);
		cnt = elist_count(&z->arenas);
		XZONE_UNLOCK(z);

		s_debug("XM discarding %szone arena for %zu-byte blocks at %p",
			0 == cnt ? "last " : "", z->alignment, xz->arena);
	}

	xfree(xz->bitmap);
	vmm_core_free(xz->arena, xmalloc_pagesize);

	XSTATS_LOCK;
	xstats.vmm_freed_pages++;
	xstats.aligned_arenas_destroyed++;
	xstats.aligned_overhead_bytes -= BIT_ARRAY_BYTE_SIZE(xz->nblocks);
	XSTATS_UNLOCK;

	/*
	 * The zone descriptor ``xz'' will be freed when xa_delete_slot()
	 * is called.
	 */
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
	struct xzone *z;
	struct xdesc_zone *xz;
	size_t bn;
	void *p;

	g_assert(size_is_positive(alignment));
	g_assert(alignment >= XALIGN_MINSIZE);
	g_assert(is_pow2(alignment));
	g_assert(alignment < xmalloc_pagesize);

	zn = highest_bit_set(alignment >> XALIGN_SHIFT);

	/*
	 * Find proper zone allocator for this alignment, and allocate a new
	 * one if none existed already.
	 */

	g_assert(NULL == xzones || zn < xzones_capacity);

	if G_UNLIKELY(NULL == xzones || NULL == (z = xzones[zn])) {
		spinlock(&xmalloc_zone_slk);

		if (NULL == xzones)
			xzones_init();

		if (NULL == (z = xzones[zn]))
			z = xzones[zn] = xzget(alignment);

		spinunlock(&xmalloc_zone_slk);
	}

	xzone_check(z);
	XZONE_LOCK(z);

	/*
	 * Find which zone in the list has any free block available and compute
	 * the number of the first block available in the zone.
	 */

	bn = (size_t) -1;

	ELIST_FOREACH_DATA(&z->arenas, xz) {
		g_assert(xz->zone == z);
		bn = bit_array_first_clear(xz->bitmap, 0, xz->nblocks - 1);
		if G_LIKELY((size_t) -1 != bn)
			break;
	}

	/*
	 * If we haven't found any arena with a free block, allocate a new one.
	 */

	if G_UNLIKELY((size_t) -1 == bn) {
		xz = xzarena(z);
		elist_prepend(&z->arenas, xz);
		bn = 0;						/* Grab first block of new arena */
	}

	/*
	 * Mark selected block as used and compute the block's address.
	 */

	bit_array_set(xz->bitmap, bn);
	p = ptr_add_offset(xz->arena, bn << z->ashift);

	if (xmalloc_debugging(3)) {
		s_debug("XM allocated %zu-byte aligned block #%zu at %p from %p",
			z->alignment, bn, p, xz->arena);
	}

	/*
	 * Place the zone where we allocated a block from at the top of the
	 * list unless there are no more free blocks in the zone.
	 *
	 * Because we attempt to keep zones with free blocks at the start of
	 * the list, it is unlikely we have to move around the block in the list.
	 */

	if (bn != xz->nblocks - 1) {
		if (xmalloc_debugging(2) && xz != elist_head(&z->arenas)) {
			s_debug("XM moving %zu-byte zone %p to head of zone list",
				z->alignment, xz->arena);
		}
		elist_moveto_head(&z->arenas, xz);
	}

	XZONE_UNLOCK(z);

	XSTATS_LOCK;
	xstats.user_blocks++;
	xstats.user_memory += alignment;
	xstats.aligned_zone_blocks++;
	xstats.aligned_zone_memory += alignment;
	XSTATS_UNLOCK;
	memusage_add(xstats.user_mem, alignment);

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
	struct xzone *z;
	size_t bn;
	bool cleared;

	g_assert(vmm_page_start(p) == xz->arena);

	z = xz->zone;
	xzone_check(z);
	XZONE_LOCK(z);

	bn = ptr_diff(p, xz->arena) >> z->ashift;

	g_assert(bn < xz->nblocks);
	g_assert(bit_array_get(xz->bitmap, bn));

	bit_array_clear(xz->bitmap, bn);

	if ((size_t) -1 == bit_array_last_set(xz->bitmap, 0, xz->nblocks - 1)) {
		xzdestroy(z, xz);
		cleared = TRUE;		/* Releases zone's lock */
	} else {
		XZONE_UNLOCK(z);
		cleared = FALSE;
	}

	XSTATS_LOCK;
	xstats.freeings++;		/* Not counted in xfree() */
	xstats.aligned_freed++;
	xstats.user_blocks--;
	xstats.user_memory -= z->alignment;
	xstats.aligned_zone_blocks--;
	xstats.aligned_zone_memory -= z->alignment;
	XSTATS_UNLOCK;
	memusage_remove(xstats.user_mem, z->alignment);

	return cleared;
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
	size_t len = 0;

	start = vmm_page_start(p);

	XMALLOC_XA_LOCK_HIDDEN;

	idx = xa_lookup(start, NULL);

	if G_LIKELY((size_t) -1 == idx) {
		XMALLOC_XA_UNLOCK_HIDDEN;
		return 0;
	}

	xt = aligned[idx].pdesc;

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
			struct xzone *z = xz->zone;

			xzone_check(z);
			len = z->alignment;
			g_assert(0 != len);
		}
		goto done;
	}

	g_assert_not_reached();

done:
	XMALLOC_XA_UNLOCK_HIDDEN;
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

	/*
	 * We do not only consider page-aligned pointers because we can allocate
	 * aligned page sub-blocks.  However, they are all located within a page
	 * so the enclosing page will be found if it is a sub-block.
	 */

	start = vmm_page_start(p);
	XMALLOC_XA_LOCK;

	idx = xa_lookup(start, NULL);

	if G_LIKELY((size_t) -1 == idx) {
		XMALLOC_XA_UNLOCK;
		XSTATS_INCX(aligned_free_false_positives);
		return FALSE;
	}

	if G_UNLIKELY(xmalloc_no_freeing) {
		XMALLOC_XA_UNLOCK;
		return TRUE;
	}

	xt = aligned[idx].pdesc;

	switch (xt->type) {
	case XPAGE_SET:
		{
			struct xdesc_set *xs = (struct xdesc_set *) xt;
			size_t len = xs->len;

			g_assert(0 != len);
			xa_delete_slot(idx);
			XMALLOC_XA_UNLOCK;
			vmm_free(deconstify_pointer(p), len);

			XSTATS_LOCK;
			xstats.freeings++;		/* Not counted in xfree() */
			xstats.aligned_freed++;
			xstats.vmm_freed_user_pages += vmm_page_count(len);
			xstats.user_memory -= len;
			xstats.user_blocks--;
			xstats.aligned_vmm_blocks--;
			xstats.aligned_vmm_memory -= len;
			XSTATS_UNLOCK;
			memusage_remove(xstats.user_mem, len);
		}
		return TRUE;
	case XPAGE_ZONE:
		{
			struct xdesc_zone *xz = (struct xdesc_zone *) xt;

			XMALLOC_XA_UNLOCK;

			if G_UNLIKELY(xzfree(xz, p)) {
				XMALLOC_XA_LOCK;
				xa_delete_slot(idx);	/* Last block from zone arena freed */
				XMALLOC_XA_UNLOCK;
			}
		}
		return TRUE;
	}

	g_assert_not_reached();
	return FALSE;
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

	if G_UNLIKELY(alignment <= XMALLOC_ALIGNBYTES) {
		p = xmalloc(size);
		XSTATS_LOCK;
		xstats.allocations_aligned++;
		xstats.aligned_via_xmalloc++;
		XSTATS_UNLOCK;
		goto done;
	}

	/*
	 * To be able to perform posix_memalign() calls before the VMM is fully up,
	 * use vmm_early_init() to launch the VM layer without notifying xmalloc()
	 * that the VMM is up, so that we do not start to register the garbage
	 * collector yet.
	 */

	ONCE_FLAG_RUN(xmalloc_early_inited, xmalloc_early_init);

	/*
	 * If they want to align on some boundary, they better be allocating
	 * a block large enough to minimize waste.  Warn if that is not
	 * the case.
	 */

	if G_UNLIKELY(size <= alignment / 2) {
		if (xmalloc_debugging(0)) {
			s_carp("XM requested to allocate only %zu bytes "
				"with %zu-byte alignment", size, alignment);
		}
	}

	/*
	 * If they're requesting a block aligned to more than a system page size,
	 * allocate enough pages to get a proper alignment and free the rest.
	 */

	if G_UNLIKELY(alignment == xmalloc_pagesize) {
		p = vmm_alloc(size);	/* More than we need, user block */
		method = "VMM";

		XSTATS_LOCK;
		xstats.allocations_aligned++;
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

		p = vmm_alloc(nalloc);	/* More than we need, user block */
		method = "VMM";

		XSTATS_LOCK;
		xstats.allocations_aligned++;
		xstats.aligned_via_vmm++;
		XSTATS_UNLOCK;

		/*
		 * Is the address already properly aligned?
		 * If so, we just need to remove the excess pages at the end.
		 */

		addr = pointer_to_ulong(p);

		if (xmalloc_debugging(2)) {
			s_debug("XM alignement requirement %zu, "
				"allocated %zu at %p (%s aligned)",
				alignment, nalloc, p, (addr & ~mask) == addr ? "is" : "not");
		}

		if ((addr & ~mask) == addr) {
			end = ptr_add_offset(p, rsize);
			vmm_free(end, size_saturate_sub(nalloc, rsize));
			truncation = TRUNCATION_AFTER;

			if (xmalloc_debugging(2)) {
				s_debug("XM freed trailing %zu bytes at %p",
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
				s_debug("XM aligned %p to 0x%zx yields %p",
					p, alignment, q);
			}

			g_assert(ptr_cmp(q, end) <= 0);
			g_assert(ptr_cmp(ptr_add_offset(q, rsize), end) <= 0);

			/*
			 * Remove excess pages at the beginning and the end.
			 */

			g_assert(ptr_cmp(q, p) > 0);

			vmm_free(p, ptr_diff(q, p));				/* Beginning */
			qend = ptr_add_offset(q, rsize);

			if (xmalloc_debugging(2)) {
				s_debug("XM freed leading %zu bytes at %p",
					ptr_diff(q, p), p);
			}

			if (qend != end) {
				vmm_free(qend, ptr_diff(end, qend));	/* End */
				truncation = TRUNCATION_BOTH;

				if (xmalloc_debugging(2)) {
					s_debug("XM freed trailing %zu bytes at %p",
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

		p = vmm_alloc(rsize);		/* Necessarily aligned */

		/*
		 * There is no xmalloc() header for this block, hence we need to
		 * record the address to be able to free() the pointer.
		 * Unfortunately, we cannot trim anything since free() will require
		 * the total size of the allocated VMM block to be in-use.
		 */

		xa_insert_set(p, rsize);
		method = "plain VMM";

		XSTATS_LOCK;
		xstats.allocations_aligned++;
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
		xstats.allocations_aligned++;
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
		xstats.allocations_aligned++;
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

		if (!XMALLOC_VIA_VMM(len))
			p = xmalloc_freelist_alloc(len, &nalloc);

		if (p != NULL) {
			end = ptr_add_offset(p, nalloc);
			method = "freelist";

			XSTATS_LOCK;
			xstats.allocations_aligned++;
			xstats.aligned_via_freelist++;
			XSTATS_UNLOCK;
		} else {
			if (len >= xmalloc_pagesize) {
				size_t vlen = round_pagesize(len);

				p = vmm_core_alloc(vlen);
				end = ptr_add_offset(p, vlen);
				method = "freelist, then large VMM";

				XSTATS_LOCK;
				xstats.allocations_aligned++;
				xstats.aligned_via_freelist_then_vmm++;
				xstats.vmm_alloc_pages += vmm_page_count(vlen);
				XSTATS_UNLOCK;

				if (xmalloc_debugging(1)) {
					s_debug("XM added %zu bytes of VMM core at %p", vlen, p);
				}
			} else {
				p = vmm_core_alloc(xmalloc_pagesize);
				end = ptr_add_offset(p, xmalloc_pagesize);
				method = "freelist, then plain VMM";

				XSTATS_LOCK;
				xstats.aligned_via_freelist_then_vmm++;
				xstats.allocations_aligned++;
				xstats.vmm_alloc_pages++;
				XSTATS_UNLOCK;

				if (xmalloc_debugging(1)) {
					s_debug("XM added %zu bytes of VMM core at %p",
						xmalloc_pagesize, p);
				}
			}
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
		s_debug("XM aligned %p (%zu bytes) on 0x%lx / %zu via %s%s",
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

	/*
	 * Suspend the other threads to avoid concurrent memory allocation
	 * whilst we scan the freelist.
	 */

	thread_suspend_others(FALSE);

	for (i = 0; i < N_ITEMS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];
		unsigned j;
		const void *prev = NULL;
		bool bad = FALSE;
		bool unsorted = FALSE;
		bool locked = FALSE;

		if (NULL == fl->pointers)
			continue;

		/*
		 * Before possibly taking the bucket's lock, attempt to reserve
		 * some amount in the logging agent, in case we're emitting to a
		 * string: we do not want to be called to expand the internal string
		 * and have a bucket locked.
		 *
		 * Note that we do reserve even if XMALLOC_FLCF_LOCK is not set to
		 * avoid altering the bucket whilst we scan it, through string
		 * extension.
		 */

		log_agent_reserve(la, 4096);	/* Arbitrary, large amount */

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
								i, fl->count, plural(fl->count));
						} else {
							log_info(la,
								"XM freelist #%u has %zu/%zu item%s sorted",
								i, fl->sorted, fl->count,
								plural(fl->sorted));
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
						"XM item #%u p=%p in freelist #%u is invalid: %s",
						j, p, i, xmalloc_invalid_ptrstr(p));
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

	thread_unsuspend_others();

	return errors;
}

/**
 * In case of crash, dump statistics and make some sanity checks.
 */
static void G_COLD
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
 *
 * Note the leading "e_" in names to embed them and prevent conflicts with
 * similar symbols on some system libraries.
 *		--RAM, 2011-10-28
 */
#ifdef XMALLOC_IS_MALLOC
#undef e_xmalloc
#undef e_xfree
#undef e_xrealloc
#undef e_xcalloc

void *
e_xmalloc(size_t size)
{
	return malloc(size);
}

void *
e_xcalloc(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}

void
e_xfree(void *p)
{
	free(p);
}

void *
e_xrealloc(void *p, size_t size)
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
