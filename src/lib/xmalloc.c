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
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "xmalloc.h"
#include "bit_array.h"
#include "crash.h"			/* For crash_hook_add() */
#include "dump_options.h"
#include "glib-missing.h"
#include "log.h"
#include "memusage.h"
#include "misc.h"			/* For short_size() */
#include "pow2.h"
#include "random.h"
#include "stringify.h"
#include "tm.h"
#include "unsigned.h"
#include "vmm.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

#if 1
#define XMALLOC_IS_MALLOC		/* xmalloc() becomes malloc() */
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
	time_t last_shrink;		/**< Last shrinking attempt */
} xfreelist[XMALLOC_FREELIST_COUNT];

/**
 * Each bit set in this bit array indicates a freelist with blocks in it.
 */
static bit_array_t xfreebits[BIT_ARRAY_SIZE(XMALLOC_FREELIST_COUNT)];

#define XMALLOC_SHRINK_PERIOD	5	/**< Seconds between shrinking attempts */

/**
 * Internal statistics collected.
 */
static struct {
	guint64 allocations;				/**< Total # of allocations */
	guint64 allocations_zeroed;			/**< Total # of zeroing allocations */
	guint64 allocations_aligned;		/**< Total # of aligned allocations */
	guint64 allocations_plain;			/**< Total # of xpmalloc() calls */
	guint64 alloc_via_freelist;			/**< Allocations from freelist */
	guint64 alloc_via_walloc;			/**< Allocations from walloc() */
	guint64 alloc_via_vmm;				/**< Allocations from VMM */
	guint64 alloc_via_sbrk;				/**< Allocations from sbrk() */
	guint64 freeings;					/**< Total # of freeings */
	guint64 free_sbrk_core;				/**< Freeing sbrk()-allocated core */
	guint64 free_sbrk_core_released;	/**< Released sbrk()-allocated core */
	guint64 free_vmm_core;				/**< Freeing VMM-allocated core */
	guint64 free_coalesced_vmm;			/**< VMM-freeing of coalesced block */
	guint64 free_walloc;				/**< Freeing a walloc()'ed block */
	guint64 sbrk_alloc_bytes;			/**< Bytes allocated from sbrk() */
	guint64 sbrk_freed_bytes;			/**< Bytes released via sbrk() */
	guint64 vmm_alloc_pages;			/**< Pages allocated via VMM */
	guint64 vmm_split_pages;			/**< VMM pages that were split */
	guint64 vmm_freed_pages;			/**< Pages released via VMM */
	guint64 aligned_via_freelist;		/**< Aligned memory from freelist */
	guint64 aligned_via_freelist_then_vmm;	/**< Aligned memory from VMM */
	guint64 aligned_via_vmm;				/**< Idem, no freelist tried */
	guint64 aligned_via_zone;				/**< Aligned memory from zone */
	guint64 aligned_via_xmalloc;			/**< Aligned memory from xmalloc */
	guint64 aligned_freed;					/**< Freed aligned memory */
	guint64 aligned_free_false_positives;	/**< Aligned pointers not aligned */
	guint64 aligned_zones_created;			/**< Zones created for alignment */
	guint64 aligned_zones_destroyed;		/**< Alignment zones destroyed */
	guint64 aligned_overhead_bytes;			/**< Structural overhead */
	guint64 reallocs;						/**< Total # of reallocations */
	guint64 realloc_noop;					/**< Reallocs not doing anything */
	guint64 realloc_inplace_vmm_shrinking;	/**< Reallocs with inplace shrink */
	guint64 realloc_inplace_shrinking;		/**< Idem but from freelist */
	guint64 realloc_inplace_extension;		/**< Reallocs not moving data */
	guint64 realloc_coalescing_extension;	/**< Reallocs through coalescing */
	guint64 realloc_relocate_vmm_fragment;	/**< Reallocs of moved fragments */
	guint64 realloc_relocate_vmm_shrinked;	/**< Reallocs of moved fragments */
	guint64 realloc_relocate_smart_attempts;	/**< Attempts to move pointer */
	guint64 realloc_relocate_smart_success;		/**< Smart placement was OK */
	guint64 realloc_regular_strategy;		/**< Regular resizing strategy */
	guint64 realloc_wrealloc;				/**< Used wrealloc() */
	guint64 realloc_converted_from_walloc;	/**< Converted from walloc() */
	guint64 realloc_promoted_to_walloc;		/**< Promoted to walloc() */
	guint64 freelist_insertions;			/**< Insertions in freelist */
	guint64 freelist_insertions_no_coalescing;	/**< Coalescing forbidden */
	guint64 freelist_further_breakups;		/**< Breakups due to extra size */
	guint64 freelist_coalescing_ignore_vmm;	/**< Ignored due to VMM block */
	guint64 freelist_coalescing_ignored;	/**< Smart algo chose to ignore */
	guint64 freelist_coalescing_done;		/**< Successful coalescings */
	guint64 freelist_coalescing_failed;		/**< Failed coalescings */
	guint64 freelist_split;				/**< Block splitted on allocation */
	guint64 freelist_nosplit;			/**< Block not splitted on allocation */
	size_t user_memory;					/**< Current user memory allocated */
	size_t user_blocks;					/**< Current amount of user blocks */
	memusage_t *user_mem;				/**< EMA tracker */
} xstats;

static size_t xfreelist_maxidx;		/**< Highest bucket with blocks */
static guint32 xmalloc_debug;		/**< Debug level */
static gboolean safe_to_log;		/**< True when we can log */
static gboolean xmalloc_vmm_is_up;	/**< True when the VMM layer is up */
static gboolean xmalloc_random_up;	/**< True when we can use random numbers */
static size_t sbrk_allocated;		/**< Bytes allocated with sbrk() */
static gboolean xmalloc_grows_up = TRUE;	/**< Is the VM space growing up? */
static gboolean xmalloc_no_freeing;	/**< No longer release memory */
static gboolean xmalloc_no_wfree;	/**< No longer release memory via wfree() */

static void *initial_break;			/**< Initial heap break */
static void *current_break;			/**< Current known heap break */

static void xmalloc_freelist_add(void *p, size_t len, guint32 coalesce);
static void *xmalloc_freelist_alloc(size_t len, size_t *allocated);
static void xmalloc_freelist_setup(void);
static void *xmalloc_freelist_lookup(size_t len, struct xfreelist **flp);
static void xmalloc_freelist_insert(void *p, size_t len, guint32 coalesce);
static void *xfl_bucket_alloc(const struct xfreelist *flb,
	size_t size, gboolean core, size_t *allocated);
static void xmalloc_crash_hook(void);

#define xmalloc_debugging(lvl)	G_UNLIKELY(xmalloc_debug > (lvl) && safe_to_log)

/**
 * Set debug level.
 */
void
set_xmalloc_debug(guint32 level)
{
	xmalloc_debug = level;
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
	xmalloc_grows_up = vmm_grows_upwards();
	xmalloc_freelist_setup();

#ifdef XMALLOC_IS_MALLOC
	vmm_malloc_inited();
#endif
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
	xstats.user_mem = memusage_alloc("xmalloc", 0);
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
static gboolean
xmalloc_should_split(size_t current, size_t wanted)
{
	size_t waste;

	g_assert(current >= wanted);

	waste = current - wanted;

	return waste >= XMALLOC_SPLIT_MIN &&
		(current >> XMALLOC_WASTE_SHIFT) <= waste;
}

/**
 * Is block length tagged as being that of a walloc()ed block?
 */
static inline ALWAYS_INLINE gboolean
xmalloc_is_walloc(size_t len)
{
	return XMALLOC_WALLOC_MAGIC == (len & XMALLOC_WALLOC_MAGIC);
}

/**
 * Return size of walloc()ed block given a tagged length.
 */
static inline ALWAYS_INLINE size_t
xmalloc_walloc_size(size_t len)
{
	return len & XMALLOC_WALLOC_SIZE;
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
 *
 * @return pointer to more memory of at least ``len'' bytes.
 */
static void *
xmalloc_addcore_from_heap(size_t len)
{
	void *p;

	g_assert(size_is_positive(len));
	g_assert(xmalloc_round(len) == len);

	/*
	 * Initialize the heap break point if not done so already.
	 */

	if G_UNLIKELY(NULL == initial_break) {

#ifdef HAS_SBRK
		current_break = sbrk(0);
#else
		current_break = (void *) -1;
#endif	/* HAS_SBRK */

		initial_break = current_break;
		if ((void *) -1 == current_break) {
			t_error(NULL, "cannot get initial heap break address: %m");
		}
		xmalloc_freelist_setup();
	}

	/*
	 * The VMM layer has not been initialized yet: allocate from the heap.
	 */

#ifdef HAS_SBRK
	p = sbrk(len);
#else
	t_error(NULL, "cannot allocate core on this platform (%zu bytes)", len);
	return p = NULL;
#endif

	if ((void *) -1 == p) {
		t_error(NULL, "cannot allocate more core (%zu bytes): %m", len);
	}

	/*
	 * Don't assume we're the only caller of sbrk(): move the current
	 * break pointer relatively to the allocated space rather than
	 * simply increasing our old break pointer by ``len''.
	 */

	current_break = ptr_add_offset(p, len);
	sbrk_allocated += len;
	xstats.sbrk_alloc_bytes += len;

	if (xmalloc_debugging(1)) {
		t_debug(NULL, "XM added %zu bytes of heap core at %p", len, p);
	}

	return p;
}

/**
 * Check whether memory was allocated from the VMM layer or from the heap.
 *
 * On UNIX we know that heap memory is allocated contiguously starting from
 * the initial break and moving forward.
 *
 * On Windows we emulate the behaviour of sbrk() and therefore can use the same
 * logic as on UNIX.
 */
static inline gboolean
xmalloc_isheap(const void *ptr, size_t len)
{
	if G_UNLIKELY(ptr_cmp(ptr, current_break) < 0) {
		/* Make sure whole region is under the break */
		g_assert(ptr_cmp(const_ptr_add_offset(ptr, len), current_break) <= 0);
		return ptr_cmp(ptr, initial_break) >= 0;
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
static gboolean
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

	if G_UNLIKELY(ptr_cmp(ptr, current_break) < 0) {
		const void *end = const_ptr_add_offset(ptr, len);

		xstats.free_sbrk_core++;

		/*
		 * Don't assume we're the only ones using sbrk(), check the actual
		 * break, not our cached value.
		 */

		if G_UNLIKELY(end == sbrk(0)) {
			void *old_break;
			gboolean success = FALSE;

			if (xmalloc_debugging(0)) {
				t_debug(NULL, "XM releasing %zu bytes of trailing heap", len);
			}

#ifdef HAS_SBRK
			old_break = sbrk(-len);
			if ((void *) -1 == old_break) {
				t_warning(NULL,
					"XM cannot decrease break by %zu bytes: %m", len);
			} else {
				current_break = ptr_add_offset(old_break, -len);
				success = !is_running_on_mingw();	/* no sbrk(-x) on Windows */
			}
#endif	/* HAS_SBRK */
			g_assert(ptr_cmp(current_break, initial_break) >= 0);
			if (success) {
				xstats.free_sbrk_core_released++;
				xstats.sbrk_freed_bytes += len;
			}
			return success;
		} else {
			if (xmalloc_debugging(0)) {
				t_debug(NULL, "XM releasing %zu bytes in middle of heap", len);
			}
			return FALSE;		/* Memory not freed */
		}
	}

	if (xmalloc_debugging(1))
		t_debug(NULL, "XM releasing %zu bytes of core", len);

	vmm_core_free(ptr, len);
	xstats.free_vmm_core++;
	xstats.vmm_freed_pages += vmm_page_count(len);

	return TRUE;
}

/**
 * Check whether pointer is valid.
 */
static gboolean
xmalloc_is_valid_pointer(const void *p)
{
	if (xmalloc_round(p) != pointer_to_ulong(p))
		return FALSE;

	if G_UNLIKELY(xmalloc_no_freeing)
		return TRUE;	/* Don't validate if we're shutdowning */

	if G_LIKELY(xmalloc_vmm_is_up) {
		return vmm_is_native_pointer(p) || xmalloc_isheap(p, sizeof p);
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
static inline gboolean
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
	 * Have to cope with early heap allocations which are done by the libc
	 * before we enter our main(), making it impossible to initialize
	 * proper page size rounding.
	 */

	return xmalloc_isheap(p, len);
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
static inline size_t
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
 * Remove trailing excess memory in pointers[], accounting for hysteresis.
 */
static void
xfl_shrink(struct xfreelist *fl)
{
	void *new_ptr;
	void *old_ptr;
	size_t old_size, old_used, new_size, allocated_size;

	g_assert(fl->count < fl->capacity);
	g_assert(size_is_non_negative(fl->count));

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
		return;

	new_ptr = xfl_bucket_alloc(fl, new_size, FALSE, &allocated_size);

	/*
	 * If there's nothing in the freelist, don't bother shrinking: we would
	 * need to get more core.
	 */

	if G_UNLIKELY(NULL == new_ptr)
		return;

	/*
	 * Detect possible recursion.
	 */

	if G_UNLIKELY(fl->pointers != old_ptr) {
		if (xmalloc_debugging(0)) {
			t_debug(NULL, "XM recursion during shrinking of freelist #%zu "
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
			t_debug(NULL, "XM discarding allocated bucket %p (%zu bytes) for "
				"freelist #%zu", new_ptr, allocated_size, xfl_index(fl));
		}

		xmalloc_freelist_add(new_ptr, allocated_size, XM_COALESCE_ALL);
		return;
	}

	g_assert(allocated_size >= new_size);
	g_assert(new_ptr != old_ptr);

	fl->last_shrink = tm_time();

	/*
	 * If we allocated the same block size as before, free it immediately:
	 * no need to move around data.
	 */

	if G_UNLIKELY(old_size == allocated_size) {
		if (xmalloc_debugging(1)) {
			t_debug(NULL, "XM discarding allocated bucket %p (%zu bytes) for "
				"freelist #%zu: same size as old bucket",
				new_ptr, allocated_size, xfl_index(fl));
		}
		xmalloc_freelist_add(new_ptr, allocated_size, XM_COALESCE_ALL);
		return;
	}

	memcpy(new_ptr, old_ptr, old_used);

	fl->pointers = new_ptr;
	fl->capacity = allocated_size / sizeof(void *);

	g_assert(fl->capacity >= fl->count);	/* Still has room for all items */

	if (xmalloc_debugging(1)) {
		t_debug(NULL, "XM shrunk freelist #%zu (%zu-byte block) to %zu items"
			" (holds %zu): old size was %zu bytes, new is %zu, requested %zu,"
			" bucket at %p",
			xfl_index(fl), fl->blocksize, fl->capacity, fl->count,
			old_size, allocated_size, new_size, new_ptr);
	}

	/*
	 * Freelist bucket is now in a coherent state, we can unconditionally
	 * release the old bucket even if it ends up being put in the same bucket
	 * we just shrank.
	 */

	xmalloc_freelist_add(old_ptr, old_size, XM_COALESCE_ALL);
}

/*
 * Called after one block was removed from the freelist bucket.
 *
 * Resize the pointers[] array if needed and update the minimum freelist index
 * after an item was removed from the freelist.
 */
static void
xfl_count_decreased(struct xfreelist *fl, gboolean may_shrink)
{
	/*
	 * Update maximum bucket index and clear freelist bit if we removed
	 * the last block from the list.
	 */

	if G_UNLIKELY(0 == fl->count) {
		size_t idx = xfl_index(fl);

		bit_array_clear(xfreebits, idx);

		if G_UNLIKELY(idx == xfreelist_maxidx) {
			size_t i;

			i = bit_array_last_set(xfreebits, 0, XMALLOC_FREELIST_COUNT - 1);
			xfreelist_maxidx = (size_t) -1 == i ? 0 : i;

			g_assert(size_is_non_negative(xfreelist_maxidx));
			g_assert(xfreelist_maxidx < G_N_ELEMENTS(xfreelist));

			if (xmalloc_debugging(2)) {
				t_debug(NULL, "XM max frelist index decreased to %zu",
					xfreelist_maxidx);
			}
		}
	}

	/*
	 * Make sure we resize the pointers[] array when we had enough removals.
	 */

	if (
		may_shrink &&
		(fl->capacity - fl->count) >= XM_BUCKET_INCREMENT &&
		delta_time(tm_time(), fl->last_shrink) > XMALLOC_SHRINK_PERIOD
	) {
		xfl_shrink(fl);
	}
}

/*
 * Would split block length end up being redistributed to the specified
 * freelist bucket?
 */
static gboolean
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
	if (!xmalloc_is_valid_pointer(p)) {
		t_error_from(_WHERE_, NULL,
			"invalid pointer %p in %zu-byte malloc freelist: %s",
			p, fl->blocksize, xmalloc_invalid_ptrstr(p));
	}

	if (*(size_t *) p != fl->blocksize) {
		size_t len = *(size_t *) p;
		if (!size_is_positive(len)) {
			t_error_from(_WHERE_, NULL,
				"detected free block corruption at %p: "
				"block in a bucket handling %zu bytes has corrupted length %zd",
				p, fl->blocksize, len);
		} else {
			t_error_from(_WHERE_, NULL,
				"detected free block corruption at %p: "
				"%zu-byte long block in a bucket handling %zu bytes",
				p, len, fl->blocksize);
		}
	}
}

/**
 * Remove from the free list the block selected by xmalloc_freelist_lookup().
 */
static void
xfl_remove_selected(struct xfreelist *fl)
{
	g_assert(size_is_positive(fl->count));

	fl->count--;

	/*
	 * See xmalloc_freelist_lookup() for the selection algorithm.
	 *
	 * If we selected the last item of the array (the typical setup on
	 * UNIX machines where the VM space grows downwards from the end
	 * of the VM space), then we have nothing to do.
	 *
	 * Otherwise, we have to switch the remaining items downwards by
	 * one position (first item of the pointers[] array was selected).
	 */

	if (xmalloc_grows_up && fl->count != 0) {
		memmove(&fl->pointers[0], &fl->pointers[1],
			fl->count * sizeof fl->pointers[0]);
	}

	/*
	 * Forbid any bucket shrinking as we could be in the middle of a bucket
	 * allocation and that could cause harmful recursion.
	 */

	xfl_count_decreased(fl, FALSE);
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

	p = xmalloc_freelist_lookup(len, &fl);

	if (p != NULL) {
		size_t blksize = fl->blocksize;

		g_assert(blksize >= len);

		xfl_remove_selected(fl);

		/*
		 * Allocating from the bucket itself is OK, but when debugging it's
		 * nice to trace as it happens.
		 */

		if G_UNLIKELY(fl == flb) {
			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM allocated %zu-byte long block at %p "
					"for freelist #%zu from itself (count down to %zu)",
					fl->blocksize, p, xfl_index(fl), fl->count);
			}
		}

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
				xstats.freelist_nosplit++;
				goto no_split;
			}

			if G_LIKELY(!xfl_block_falls_in(flb, split_len)) {
				xstats.freelist_split++;
				if (xmalloc_grows_up) {
					/* Split the end of the block */
					split = ptr_add_offset(p, len);
				} else {
					/* Split the head of the block */
					split = p;
					p = ptr_add_offset(p, split_len);
				}

				if (xmalloc_debugging(3)) {
					t_debug(NULL, "XM splitting large %zu-byte block at %p"
						" (need only %zu bytes: returning %zu bytes at %p)",
						blksize, p, len, split_len, split);
				}

				g_assert(split_len <= XMALLOC_MAXSIZE);

				xmalloc_freelist_insert(split, split_len, XM_COALESCE_NONE);
				blksize = len;		/* We shrank the allocted block */
			} else {
				xstats.freelist_nosplit++;
				if (xmalloc_debugging(3)) {
					t_debug(NULL, "XM not splitting large %zu-byte block at %p"
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
	size_t size, gboolean core, size_t *allocated)
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
		xstats.vmm_alloc_pages += vmm_page_count(len);
	} else {
		p = xmalloc_addcore_from_heap(len);
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

	g_assert(fl->count >= fl->capacity);

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
		t_debug(NULL, "XM extending freelist #%zu (%zu-byte block) "
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
			t_debug(NULL, "XM recursion during extension of freelist #%zu "
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
		 * freelist, we may still safely recurse here since.
		 */

		if (xmalloc_debugging(1)) {
			t_debug(NULL, "XM discarding allocated bucket %p (%zu bytes) for "
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
		t_error_from(_WHERE_, NULL,
			"XM self-increase during extension of freelist #%zu "
			"(%zu-byte block): has more items than initial %zu "
			"(count = %zu, capacity = %zu)",
			xfl_index(fl), fl->blocksize, old_used / sizeof(void *),
			fl->count, fl->capacity);
	}

	g_assert(new_ptr != old_ptr);

	memcpy(new_ptr, old_ptr, old_used);
	fl->pointers = new_ptr;
	fl->capacity = allocated_size / sizeof(void *);

	g_assert(fl->capacity > fl->count);		/* Extending was OK */

	if (xmalloc_debugging(1)) {
		t_debug(NULL, "XM extended freelist #%zu (%zu-byte block) to %zu items"
			" (holds %zu): new size is %zu bytes, requested %zu, bucket at %p",
			xfl_index(fl), fl->blocksize, fl->capacity, fl->count,
			allocated_size, new_size, new_ptr);
	}

	/*
	 * Freelist bucket is now in a coherent state, we can unconditionally
	 * release the old bucket even if it ends up being put in the same bucket
	 * we just extended.
	 */

	if (old_ptr != NULL) {
		xmalloc_freelist_add(old_ptr, old_size, XM_COALESCE_ALL);
	}
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
xfl_lookup(const struct xfreelist *fl, const void *p, size_t *low_ptr)
{
	size_t low, mid, high;
	void **pointers;
	size_t count = fl->count;

	if G_UNLIKELY(0 == count) {
		if (low_ptr != NULL)
			*low_ptr = 0;
		return -1;
	}

	/*
	 * Optimize if we have more than 4 items by looking whether the
	 * pointer falls within the min/max ranges.
	 */

	pointers = fl->pointers;
	high = count - 1;
	low = 0;

	if G_LIKELY(count > 4) {
		if G_UNLIKELY(pointers[0] == p)
			return 0;
		if (ptr_cmp(p, pointers[0]) < 0) {
			if (low_ptr != NULL) {
				*low_ptr = 0;
				return -1;
			}
		}
		low++;
		if G_UNLIKELY(pointers[high] == p)
			return high;
		if (ptr_cmp(p, pointers[high]) > 0) {
			if (low_ptr != NULL) {
				*low_ptr = count;
				return -1;
			}
		}
		high--;
	}

	/* Binary search */

	for (;;) {
		const void *item;

		if G_UNLIKELY(low > high || high > SIZE_MAX / 2) {
			mid = -1;		/* Not found */
			break;
		}

		mid = low + (high - low) / 2;
		item = pointers[mid];

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
 * Delete slot ``idx'' within the free list.
 */
static void
xfl_delete_slot(struct xfreelist *fl, size_t idx)
{
	g_assert(size_is_positive(fl->count));
	g_assert(size_is_non_negative(idx) && idx < fl->count);

	fl->count--;
	if (idx < fl->count) {
		memmove(&fl->pointers[idx], &fl->pointers[idx + 1],
			(fl->count - idx) * sizeof(fl->pointers[0]));
	}

	xfl_count_decreased(fl, TRUE);
}

/**
 * Insert address in the free list.
 */
static void
xfl_insert(struct xfreelist *fl, void *p)
{
	size_t idx;

	g_assert(size_is_non_negative(fl->count));
	g_assert(fl->count <= fl->capacity);

	/*
	 * Since the extension can use the freelist's own blocks, it could
	 * conceivably steal one from this freelist.  It's therefore important
	 * to perform the extension before we compute the proper insertion
	 * index for the block.
	 */

	if (fl->count >= fl->capacity)
		xfl_extend(fl);

	/*
	 * Compute insertion index in the sorted array.
	 *
	 * At the same time, this allows us to make sure we're not dealing with
	 * a duplicate insertion.
	 */

	if G_UNLIKELY((size_t ) -1 != xfl_lookup(fl, p, &idx)) {
		t_error_from(_WHERE_, NULL,
			"block %p already in free list #%zu (%zu bytes)",
			p, xfl_index(fl), fl->blocksize);
	}

	g_assert(size_is_non_negative(idx) && idx <= fl->count);

	/*
	 * Shift items if we're not inserting at the last position in the array.
	 */

	g_assert(fl->pointers != NULL);
	g_assert(idx <= fl->count);

	if G_LIKELY(idx < fl->count) {
		memmove(&fl->pointers[idx + 1], &fl->pointers[idx],
			(fl->count - idx) * sizeof(fl->pointers[0]));
	}

	fl->count++;
	fl->pointers[idx] = p;

	/*
	 * Set corresponding bit if this is the first block inserted in the list.
	 */

	if G_UNLIKELY(1 == fl->count) {
		size_t fidx = xfl_index(fl);

		bit_array_set(xfreebits, fidx);

		/*
		 * Update maximum bucket index.
		 */

		if (xfreelist_maxidx < fidx) {
			xfreelist_maxidx = fidx;
			g_assert(xfreelist_maxidx < G_N_ELEMENTS(xfreelist));

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM max frelist index increased to %zu",
					xfreelist_maxidx);
			}
		}
	}

	/*
	 * To detect freelist corruptions, write the size of the block at the
	 * beginning of the block itself.
	 */

	*(size_t *) p = fl->blocksize;

	if (xmalloc_debugging(2)) {
		t_debug(NULL, "XM inserted block %p in free list #%zu (%zu bytes)",
			p, xfl_index(fl), fl->blocksize);
	}
}

/**
 * Initial setup of the free list that cannot be conveniently initialized
 * by static declaration.
 */
static G_GNUC_COLD void
xmalloc_freelist_setup(void)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];

		fl->blocksize = xfl_block_size_idx(i);

		g_assert_log(xfl_find_freelist_index(fl->blocksize) == i,
			"i=%zu, blocksize=%zu, inverted_index=%zu",
			i, fl->blocksize, xfl_find_freelist_index(fl->blocksize));
	}
}

/**
 * Look for a free block in the freelist for holding ``len'' bytes.
 *
 * @param len		the desired block length (including our overhead)
 * @param flp		if not-NULL, outputs the freelist the block was found in
 *
 * @return the block address we found, NULL if nothing was found.
 *
 * @attention
 * The block is not removed from the freelist and the address returned is not
 * the user address but the physical start of the block.
 */
static void *
xmalloc_freelist_lookup(size_t len, struct xfreelist **flp)
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

		if (0 == fl->count)
			continue;

		/*
		 * Depending on the way the virtual memory grows, we pick the largest
		 * or the smallest address to try to aggregate all the objects at
		 * the "base" of the memory space.
		 *
		 * Until the VMM layer is up, xmalloc_grows_up will be TRUE.  This is
		 * consistent with the fact that the heap always grows upwards on
		 * UNIX machines.
		 */

		p = xmalloc_grows_up ? fl->pointers[0] : fl->pointers[fl->count - 1];
		if (flp != NULL)
			*flp = fl;

		if (xmalloc_debugging(8)) {
			t_debug(NULL, "XM selected block %p in bucket %p "
				"(#%zu, %zu bytes) for %zu bytes",
				p, (void *) fl, i, fl->blocksize, len);
		}

		assert_valid_freelist_pointer(fl, p);
		break;
	}

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
static G_GNUC_HOT gboolean
xmalloc_freelist_coalesce(void **base_ptr, size_t *len_ptr, guint32 flags)
{
	static size_t smallsize;
	size_t i, j;
	void *base = *base_ptr;
	size_t len = *len_ptr;
	void *end;
	gboolean coalesced = FALSE;

	if G_UNLIKELY(0 == smallsize) {
		smallsize = compat_pagesize() / 2;
	}

	/*
	 * When "smart" coalescing is requested and we're facing a block which
	 * can be put directly in the freelist (i.e. there is no special splitting
	 * to do as its size fits one of the existing buckets), look at whether
	 * it is smart to attempt any coalescing.
	 */

	if ((flags & XM_COALESCE_SMART) && xmalloc_round_blocksize(len) == len) {
		size_t idx = xfl_find_freelist_index(len);
		struct xfreelist *fl = &xfreelist[idx];

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
				t_debug(NULL, "XM ignoring coalescing request for %zu-byte %p:"
					" target free list #%zu has only %zu item%s",
					len, base, idx, fl->count, 1 == fl->count ? "" : "s");
			}
			xstats.freelist_coalescing_ignored++;
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
		gboolean found_match = FALSE;

		for (j = 0; j <= xfreelist_maxidx; j++) {
			struct xfreelist *fl = &xfreelist[j];
			size_t blksize;
			void *before;
			size_t idx;

			if (0 == fl->count)
				continue;

			blksize = fl->blocksize;
			before = ptr_add_offset(base, -blksize);

			/*
			 * Avoid costly lookup if the pointer cannot be found.
			 */

			idx = xfl_lookup(fl, before, NULL);

			if G_UNLIKELY((size_t) -1 != idx) {
				if (xmalloc_debugging(6)) {
					t_debug(NULL, "XM iter #%zu, "
						"coalescing previous %zu-byte [%p, %p[ "
						"from list #%zu with %zu-byte [%p, %p[",
						i, blksize, before, ptr_add_offset(before, blksize),
						j, ptr_diff(end, base), base, end);
				}

				xfl_delete_slot(fl, idx);
				base = before;
				found_match = coalesced = TRUE;
			}
		}

		if (!found_match)
			break;
	}

	/*
	 * Look for a match after.
	 */

	for (i = 0; flags & XM_COALESCE_AFTER; i++) {
		gboolean found_match = FALSE;

		for (j = 0; j <= xfreelist_maxidx ; j++) {
			struct xfreelist *fl = &xfreelist[j];
			size_t idx;

			if (0 == fl->count)
				continue;

			idx = xfl_lookup(fl, end, NULL);

			if G_UNLIKELY((size_t) -1 != idx) {
				size_t blksize = fl->blocksize;

				if (xmalloc_debugging(6)) {
					t_debug(NULL, "XM iter #%zu, "
						"coalescing next %zu-byte [%p, %p[ "
						"from list #%zu with %zu-byte [%p, %p[",
						i, blksize, end, ptr_add_offset(end, blksize),
						j, ptr_diff(end, base), base, end);
				}

				xfl_delete_slot(fl, idx);
				end = ptr_add_offset(end, blksize);
				found_match = coalesced = TRUE;
			}
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
		xstats.freelist_coalescing_done++;
	} else {
		xstats.freelist_coalescing_failed++;
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
static gboolean
xmalloc_free_pages(void *p, size_t len,
	void **head, size_t *head_len,
	void **tail, size_t *tail_len)
{
	size_t pagesize = compat_pagesize();
	void *page;
	const void *end;
	const void *vend;
	size_t plen, hlen, tlen;

	page = deconstify_gpointer(vmm_page_start(p));
	end = ptr_add_offset(p, len);

	if (ptr_cmp(page, p) < 0) {
		page = ptr_add_offset(page, pagesize);
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

	*head = deconstify_gpointer(p);
	*head_len = hlen;
	*tail = deconstify_gpointer(vend);
	*tail_len = tlen;

	/*
	 * We can free the zone [page, vend[.
	 */

	if (xmalloc_debugging(1)) {
		t_debug(NULL,
			"XM releasing VMM [%p, %p[ (%zu bytes) within [%p, %p[ (%zu bytes)",
			page, vend, ptr_diff(vend, page), p, end, len);
	}

	plen = ptr_diff(vend, page);
	vmm_core_free(page, plen);

	xstats.free_vmm_core++;
	xstats.vmm_freed_pages += vmm_page_count(plen);

	return TRUE;
}

/**
 * Insert block in free list, with optional block coalescing.
 */
static void
xmalloc_freelist_insert(void *p, size_t len, guint32 coalesce)
{
	struct xfreelist *fl;

	/*
	 * First attempt to coalesce memory as much as possible if requested.
	 */

	xstats.freelist_insertions++;

	if (coalesce) {
		xmalloc_freelist_coalesce(&p, &len, coalesce);
	} else {
		xstats.freelist_insertions_no_coalescing++;
	}

	/*
	 * Chunks of memory larger than XMALLOC_MAXSIZE need to be broken up
	 * into smaller blocks.  This can happen when we're putting heap memory
	 * back into the free list, or when a block larger than a page size is
	 * actually spread over two distinct VM pages..
	 */

	if G_UNLIKELY(len > XMALLOC_MAXSIZE) {
		if (xmalloc_debugging(3)) {
			t_debug(NULL, "XM breaking up %s block %p (%zu bytes)",
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

			xfl_insert(fl, p);
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
		size_t multiple;

		multiple = len & ~XMALLOC_BLOCK_MASK;

		/*
		 * Watch out for blocks having a trailing unsplit part and which
		 * will therefore not end up with a completely valid blocksize if
		 * they are blindly put in the largest freelist first.
		 */

		if G_UNLIKELY(len - multiple == XMALLOC_SPLIT_MIN / 2) {
			if (len < 2 * XMALLOC_FACTOR_MAXSIZE) {
				multiple = XMALLOC_FACTOR_MAXSIZE / 2;
			} else {
				multiple = (len - XMALLOC_FACTOR_MAXSIZE) & ~XMALLOC_BLOCK_MASK;
			}
			if (xmalloc_debugging(3)) {
				t_debug(NULL, "XM specially adjusting length of %zu: "
					"breaking into %zu and %zu bytes",
					len, multiple, len - multiple);
			}
		}

	split_again:
		if (multiple != len) {
			if (xmalloc_debugging(3)) {
				t_debug(NULL, "XM breaking up %s block %p (%zu bytes)",
					xmalloc_isheap(p, len) ? "heap" : "VMM", p, len);
			}

			fl = xfl_find_freelist(multiple);
			xfl_insert(fl, p);
			p = ptr_add_offset(p, multiple);
			len -= multiple;
		}

		/*
		 * Again, when facing an initial length of 2048+4 = 2052 bytes,
		 * we would end up with 1028 bytes here, which is still not good
		 * enough.  As soon as we break under the XMALLOC_FACTOR_MAXSIZE
		 * limit, we'll hit buckets with multiple of the alignbytes constant,
		 * so we will always be able to find a matching bucket.
		 */

		if (len > XMALLOC_FACTOR_MAXSIZE) {
		 	/*
		 	 * The split bucket is chosen randomly so as to not artificially
			 * raise the amount of blocks held in a given freelist.  We can
			 * only use the random values after initialization.
			 */

			if G_LIKELY(xmalloc_random_up) {
				size_t bucket = random_value(
					XMALLOC_BUCKET_CUTOVER - XMALLOC_BUCKET_OFFSET);
				multiple = xfl_block_size_idx(bucket);
			} else {
				multiple = XMALLOC_FACTOR_MAXSIZE / 2;
			}

			if G_UNLIKELY(len - multiple < XMALLOC_SPLIT_MIN) {
				multiple -= XMALLOC_BUCKET_FACTOR;
				g_assert(size_is_positive(multiple));
				g_assert(multiple >= XMALLOC_SPLIT_MIN);
			}

			if (xmalloc_debugging(3)) {
				t_debug(NULL, "XM further adjusting remaining length of %zu: "
					"breaking into %zu and %zu bytes",
					len, multiple, len - multiple);
			}

			xstats.freelist_further_breakups++;
			goto split_again;
		}

		/* FALL THROUGH */
	}

	fl = xfl_find_freelist(len);
	xfl_insert(fl, p);
}

/**
 * Add memory chunk to free list, possibly releasing core.
 */
static void
xmalloc_freelist_add(void *p, size_t len, guint32 coalesce)
{
	gboolean coalesced = FALSE;

	/*
	 * First attempt to coalesce memory as much as possible if requested.
	 *
	 * When dealing with blocks that are page-aligned, whose size is
	 * exactly a multiple of system pages and where allocated from the
	 * VMM layer, it would be harmful to attempt coalescing: we want to
	 * free those VMM pages right away.
	 */

	if (coalesce) {
		if (
			vmm_page_start(p) != p ||
			round_pagesize(len) != len ||
			xmalloc_isheap(p, len)
		) {
			coalesced = xmalloc_freelist_coalesce(&p, &len, coalesce);
		} else {
			if (xmalloc_debugging(4)) {
				t_debug(NULL,
					"XM not attempting coalescing of %zu-byte VMM region at %p",
					len, p);
			}
			xstats.freelist_coalescing_ignore_vmm++;
		}
	}

	/*
	 * If we're dealing with heap memory, attempt to free it.
	 *
	 * If we're dealing with memory from the VMM layer and we got more than
	 * a page worth of data, release the empty pages to the system and put
	 * back the leading and trailing fragments to the free list.
	 */

	if G_UNLIKELY(xmalloc_isheap(p, len)) {
		/* Heap memory */
		if (xmalloc_freecore(p, len)) {
			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM %zu bytes of heap released at %p, "
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
					size_t npages = len / compat_pagesize();

					t_debug(NULL, "XM freed %sembedded %zu page%s, "
						"%s head, %s tail",
						coalesced ? "coalesced " : "",
						npages, 1 == npages ? "" : "s",
						head_len != 0 ? "has" : "no",
						tail_len != 0 ? "has" : "no");
				} else {
					t_debug(NULL, "XM freed %swhole %zu-byte region at %p",
						coalesced ? "coalesced " : "", len, p);
				}
			}

			if (coalesced)
				xstats.free_coalesced_vmm++;

			/*
			 * Head and tail are smaller than a page size but could still be
			 * larger than XMALLOC_MAXSIZE.
			 */

			if (head_len != 0) {
				g_assert(head == p);
				if (xmalloc_debugging(4)) {
					t_debug(NULL, "XM freeing head of %p at %p (%zu bytes)",
						p, head, head_len);
				}
				if (coalesce & XM_COALESCE_BEFORE) {
					/* Already coalesced */
					xmalloc_freelist_insert(head, head_len, XM_COALESCE_NONE);
				} else {
					/* Maybe there is enough before to free core again? */
					xmalloc_freelist_add(head, head_len, XM_COALESCE_BEFORE);
				}
			}
			if (tail_len != 0) {
				g_assert(
					ptr_add_offset(tail, tail_len) == ptr_add_offset(p, len));
				if (xmalloc_debugging(4)) {
					t_debug(NULL, "XM freeing tail of %p at %p (%zu bytes)",
						p, tail, tail_len);
				}
				if (coalesce & XM_COALESCE_AFTER) {
					/* Already coalesced */
					xmalloc_freelist_insert(tail, tail_len, XM_COALESCE_NONE);
				} else {
					/* Maybe there is enough after to free core again? */
					xmalloc_freelist_add(head, head_len, XM_COALESCE_AFTER);
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

	xmalloc_freelist_insert(p, len, XM_COALESCE_NONE);
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

	p = xmalloc_freelist_lookup(len, &fl);

	if (p != NULL) {
		size_t blksize = fl->blocksize;

		g_assert(blksize >= len);

		xfl_remove_selected(fl);

		/*
		 * If the block is larger than the size we requested, the remainder
		 * is put back into the free list.
		 */

		if (len != blksize) {
			void *split;
			size_t split_len;

			split_len = blksize - len;

			if (xmalloc_should_split(blksize, len)) {
				xstats.freelist_split++;
				if (xmalloc_grows_up) {
					/* Split the end of the block */
					split = ptr_add_offset(p, len);
				} else {
					/* Split the head of the block */
					split = p;
					p = ptr_add_offset(p, split_len);
				}

				if (xmalloc_debugging(3)) {
					t_debug(NULL, "XM splitting large %zu-byte block at %p"
						" (need only %zu bytes: returning %zu bytes at %p)",
						blksize, p, len, split_len, split);
				}

				g_assert(split_len <= XMALLOC_MAXSIZE);

				xmalloc_freelist_insert(split, split_len, XM_COALESCE_NONE);
			} else {
				if (xmalloc_debugging(3)) {
					t_debug(NULL, "XM NOT splitting large %zu-byte block at %p"
						" (need only %zu bytes, split of %zu bytes too small)",
						blksize, p, len, split_len);
				}
				xstats.freelist_nosplit++;
				len = blksize;		/* Wasting some trailing bytes */
			}
		}
		*allocated = len;
	}

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
		t_debug(NULL, "XM setup allocated %zu-byte block at %p (user %p)",
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
		t_debug(NULL, "XM setup walloc()ed %zu-byte block at %p (user %p)",
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
gboolean
xmalloc_is_malloc(void)
{
#ifdef XMALLOC_IS_MALLOC
	return TRUE;
#else
	return FALSE;
#endif
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

static gboolean xalign_free(const void *p);

#else	/* !XMALLOC_IS_MALLOC */
#define is_trapping_malloc()	0
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
 *
 * @return allocated pointer (never NULL).
 */
static void *
xallocate(size_t size, gboolean can_walloc)
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
	xstats.allocations++;

	/*
	 * First try to allocate from the freelist when the length is less than
	 * the maximum we handle there.
	 */

	if (len <= XMALLOC_MAXSIZE) {
		size_t allocated;
		p = xmalloc_freelist_alloc(len, &allocated);
		if (p != NULL) {
			xstats.alloc_via_freelist++;
			xstats.user_blocks++;
			xstats.user_memory += allocated;
			memusage_add(xstats.user_mem, allocated);
			return xmalloc_block_setup(p, allocated);
		}
	}

	/*
	 * Need to allocate more core.
	 */

	if G_LIKELY(xmalloc_vmm_is_up) {
		static size_t pagesize;

		if G_UNLIKELY(0 == pagesize) {
			pagesize = compat_pagesize();
		}

		/*
		 * If we're allowed to use walloc() and the size is small-enough,
		 * prefer this method of allocation to minimize freelist fragmentation.
		 */

		if (can_walloc) {
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

			if (wlen <= WALLOC_MAX && !xmalloc_no_wfree) {
				p = walloc(wlen);
				xstats.alloc_via_walloc++;
				return xmalloc_wsetup(p, wlen);
			}
		}

		/*
		 * The VMM layer is up, use it for all core allocations.
		 */

		xstats.alloc_via_vmm++;
		xstats.user_blocks++;

		if (len >= pagesize) {
			size_t vlen = round_pagesize(len);
			p = vmm_core_alloc(vlen);
			xstats.vmm_alloc_pages += vmm_page_count(vlen);
			xstats.user_memory += vlen;
			memusage_add(xstats.user_mem, vlen);

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM added %zu bytes of VMM core at %p", vlen, p);
			}

			return xmalloc_block_setup(p, vlen);
		} else {
			p = vmm_core_alloc(pagesize);
			xstats.vmm_alloc_pages++;
			xstats.user_memory += pagesize;
			memusage_add(xstats.user_mem, pagesize);

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM added %zu bytes of VMM core at %p",
					pagesize, p);
			}

			if (xmalloc_should_split(pagesize, len)) {
				void *split = ptr_add_offset(p, len);
				xmalloc_freelist_insert(split,
					pagesize - len, XM_COALESCE_AFTER);
				xstats.vmm_split_pages++;
				return xmalloc_block_setup(p, len);
			} else {
				return xmalloc_block_setup(p, pagesize);
			}
		}
	} else {
		/*
		 * VMM layer not up yet, this must be very early memory allocation
		 * from the libc startup.  Allocate memory from the heap.
		 */

		p = xmalloc_addcore_from_heap(len);
		xstats.alloc_via_sbrk++;
		xstats.user_blocks++;
		xstats.user_memory += len;
		memusage_add(xstats.user_mem, len);

		if (xmalloc_debugging(0)) {
			t_debug(NULL, "XM added %zu bytes of heap core at %p", len, p);
		}

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
	return xallocate(size, TRUE);
}

/**
 * Allocate a memory chunk capable of holding ``size'' bytes.
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
	xstats.allocations_plain++;
	return xallocate(size, FALSE);
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
	xstats.allocations_zeroed++;

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
	xstats.allocations_zeroed++;

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

	xh = ptr_add_offset(p, -XHEADER_SIZE);
	xstats.freeings++;

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

	if (!xmalloc_is_valid_pointer(xh)) {
		t_error_from(_WHERE_, NULL, "attempt to free invalid pointer %p: %s",
			p, xmalloc_invalid_ptrstr(p));
	}

	/*
	 * Handle walloc()ed blocks specially.
	 *
	 * These are not accounted in xmalloc() blocks / memory stats since they
	 * are already accounted for by zalloc() stats.
	 */

	if (xmalloc_is_walloc(xh->length)) {
		xstats.free_walloc++;
		wfree(xh, xmalloc_walloc_size(xh->length));
		return;
	}

	/*
	 * Freeings to freelist are disabled at shutdown time.
	 */

	if G_UNLIKELY(xmalloc_no_freeing)
		return;

	if (!xmalloc_is_valid_length(xh, xh->length)) {
		t_error_from(_WHERE_, NULL,
			"corrupted malloc header for pointer %p: bad lengh %zu",
			p, xh->length);
	}

	xstats.user_memory -= xh->length;
	xstats.user_blocks--;
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
xreallocate(void *p, size_t size, gboolean can_walloc)
{
	struct xheader *xh = ptr_add_offset(p, -XHEADER_SIZE);
	size_t newlen;
	void *np;

	if (NULL == p)
		return xallocate(size, can_walloc);

	if (0 == size) {
		xfree(p);
		return NULL;
	}

	if G_UNLIKELY(!xmalloc_is_valid_pointer(xh)) {
		t_error_from(_WHERE_, NULL, "attempt to realloc invalid pointer %p: %s",
			p, xmalloc_invalid_ptrstr(p));
	}

	if (xmalloc_is_walloc(xh->length))
		goto realloc_from_walloc;

	if G_UNLIKELY(!xmalloc_is_valid_length(xh, xh->length)) {
		t_error_from(_WHERE_, NULL,
			"corrupted malloc header for pointer %p: bad length %ld",
			p, (long) xh->length);
	}

	/*
	 * Compute the size of the physical block we need, including overhead.
	 */

	newlen = xmalloc_round_blocksize(xmalloc_round(size) + XHEADER_SIZE);
	xstats.reallocs++;

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
			xstats.realloc_relocate_vmm_fragment++;
			goto relocate_vmm;
		}

		/*
		 * If the new size is smaller than the original, yet remains larger
		 * than a page size, we can call vmm_core_shrink() to shrink the block
		 * inplace or relocate it.
		 */

		if (newlen < xh->length) {
			if (vmm_is_relocatable(xh, newlen)) {
				xstats.realloc_relocate_vmm_shrinked++;
				goto relocate_vmm;
			}

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM using vmm_core_shrink() on "
					"%zu-byte block at %p (new size is %zu bytes)",
					xh->length, (void *) xh, newlen);
			}

			vmm_core_shrink(xh, xh->length, newlen);
			xstats.realloc_inplace_vmm_shrinking++;
			xstats.user_memory -= xh->length - newlen;
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
			t_debug(NULL, "XM realloc of %p to %zu bytes can be a noop "
				"(already %zu-byte long VMM region)", p, size, xh->length);
		}

		xstats.realloc_noop++;

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

			q = xmalloc_freelist_lookup(newlen, &fl);
			xstats.realloc_relocate_smart_attempts++;

			if (
				q != NULL && newlen == fl->blocksize &&
				(xmalloc_grows_up ? +1 : -1) * ptr_cmp(q, xh) < 0
			) {
				xfl_remove_selected(fl);
				np = xmalloc_block_setup(q, newlen);
				xstats.realloc_relocate_smart_success++;

				if (xmalloc_debugging(1)) {
					t_debug(NULL, "XM relocated %zu-byte block at %p to %p"
						" (pysical size is still %zu bytes, user size is %zu)",
						xh->length, (void *) xh, q, newlen, size);
				}

				goto relocate;
			}
		}

		if (xmalloc_debugging(2)) {
			t_debug(NULL, "XM realloc of %p to %zu bytes can be a noop "
				"(already %zu-byte long from %s)",
				p, size, xh->length, xmalloc_isheap(p, size) ? "heap" : "VMM");
		}

		xstats.realloc_noop++;
		return p;
	}

	/*
	 * If the block is shrinked and its old size is less than XMALLOC_MAXSIZE,
	 * put the remainder back in the freelist.
	 */

	if (xh->length <= XMALLOC_MAXSIZE && newlen < xh->length) {
		size_t extra = xh->length - newlen;

		if G_UNLIKELY(!xmalloc_should_split(xh->length, newlen)) {
			if (xmalloc_debugging(2)) {
				t_debug(NULL, "XM realloc of %p to %zu bytes can be a noop "
					"(already %zu-byte long from %s, not shrinking %zu bytes)",
					p, size, xh->length,
					xmalloc_isheap(p, size) ? "heap" : "VMM", extra);
			}
			xstats.realloc_noop++;
			return p;
		} else {
			void *end = ptr_add_offset(xh, newlen);

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM using inplace shrink on %zu-byte block at %p"
					" (new size is %zu bytes, splitting at %p)",
					xh->length, (void *) xh, newlen, end);
			}

			xmalloc_freelist_add(end, extra, XM_COALESCE_AFTER);
			xstats.realloc_inplace_shrinking++;
			xstats.user_memory -= extra;
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
		size_t i, needed, old_len, freelist_idx;
		void *end;
		gboolean coalesced = FALSE;

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

		for (i = freelist_idx; i <= xfreelist_maxidx; i++) {
			struct xfreelist *fl = &xfreelist[i];
			size_t idx;

			if (0 == fl->count)
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
						t_debug(NULL, "XM realloc NOT coalescing next %zu-byte "
							"[%p, %p[ from list #%zu with [%p, %p[: invalid "
							"resulting size of %zu bytes",
							blksize, end, ptr_add_offset(end, blksize), i,
							(void *) xh, end, csize);
					}
					break;
				}

				if (xmalloc_debugging(6)) {
					t_debug(NULL, "XM realloc coalescing next %zu-byte "
						"[%p, %p[ from list #%zu with [%p, %p[ yielding "
						"%zu-byte block",
						blksize, end, ptr_add_offset(end, blksize), i,
						(void *) xh, end, csize);
				}
				xfl_delete_slot(fl, idx);
				end = ptr_add_offset(end, blksize);
				coalesced = TRUE;
				break;
			}
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
					t_debug(NULL,
						"XM realloc splitting large %zu-byte block at %p"
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
				t_debug(NULL, "XM realloc used inplace coalescing on "
					"%zu-byte block at %p (new size is %zu bytes)",
					xh->length, (void *) xh, newlen);
			}

			xstats.realloc_inplace_extension++;
			xstats.user_memory += newlen - xh->length;
			memusage_add(xstats.user_mem, newlen - xh->length);
			goto inplace;
		}

		/*
		 * Look for a match before.
		 */

		for (i = freelist_idx; i <= xfreelist_maxidx; i++) {
			struct xfreelist *fl = &xfreelist[i];
			size_t blksize;
			void *before;
			size_t idx;

			if (0 == fl->count)
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
						t_debug(NULL, "XM realloc not coalescing previous "
							"%zu-byte [%p, %p[ from list #%zu with [%p, %p[: "
							"invalid resulting size of %zu bytes",
							blksize, before, ptr_add_offset(before, blksize), i,
							(void *) xh, end, csize);
					}
					break;
				}

				if (xmalloc_debugging(6)) {
					t_debug(NULL, "XM realloc coalescing previous %zu-byte "
						"[%p, %p[ from list #%zu with [%p, %p[",
						blksize, before, ptr_add_offset(before, blksize),
						i, (void *) xh, end);
				}
				xfl_delete_slot(fl, idx);
				old_len = xh->length - XHEADER_SIZE;	/* Old user size */
				xh = before;
				coalesced = TRUE;
				break;
			}
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
					t_debug(NULL,
						"XM realloc splitting large %zu-byte block at %p"
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
				t_debug(NULL, "XM realloc used coalescing with block preceding "
					"%zu-byte block at %p "
					"(new size is %zu bytes, new address is %p)",
					old_len + XHEADER_SIZE, ptr_add_offset(p, -XHEADER_SIZE),
					newlen, (void *) xh);
			}

			xstats.realloc_coalescing_extension++;
			xstats.user_memory += newlen - old_len;
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
		gboolean converted;

		np = xallocate(size, can_walloc);
		xstats.realloc_regular_strategy++;

		/*
		 * See whether plain block was converted to a walloc()ed one.
		 */

		nxh = ptr_add_offset(np, -XHEADER_SIZE);
		converted = xmalloc_is_walloc(nxh->length);

		if (converted) {
			g_assert(can_walloc);
			xstats.realloc_promoted_to_walloc++;
		}

		if (xmalloc_debugging(1)) {
			t_debug(NULL, "XM realloc used regular strategy: "
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

		xstats.vmm_alloc_pages += vmm_page_count(newlen);
		xstats.user_memory -= xh->length - newlen;
		memusage_remove(xstats.user_mem, xh->length - newlen);

		if (xmalloc_debugging(1)) {
			t_debug(NULL, "XM relocated %zu-byte VMM region at %p to %p"
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

		if (new_len <= WALLOC_MAX) {
			void *wp = wrealloc(xh, old_len, new_len);
			xstats.realloc_wrealloc++;

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM realloc used wrealloc(): "
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

		np = xmalloc(size);
		xstats.realloc_converted_from_walloc++;

		if (xmalloc_debugging(1)) {
			t_debug(NULL, "XM realloc converted from walloc(): "
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
	return xreallocate(p, size, TRUE);
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
		t_info(NULL, "malloc() allocated %zu bytes of heap (%zu remain)",
			sbrk_allocated, ptr_diff(current_break, initial_break));
	}

	if (xmalloc_debugging(0)) {
		t_info(NULL, "XM using %ld freelist buckets",
			(long) XMALLOC_FREELIST_COUNT);
	}

	xmalloc_random_up = TRUE;	/* Can use random numbers now */
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
#define DUMP(x)	log_info(la, "XM %s = %s", #x,		\
	(options & DUMP_OPT_PRETTY) ?					\
		uint64_to_gstring(xstats.x) : uint64_to_string(xstats.x))

	DUMP(allocations);
	DUMP(allocations_zeroed);
	DUMP(allocations_aligned);
	DUMP(allocations_plain);
	DUMP(alloc_via_freelist);
	DUMP(alloc_via_walloc);
	DUMP(alloc_via_vmm);
	DUMP(alloc_via_sbrk);
	DUMP(freeings);
	DUMP(free_sbrk_core);
	DUMP(free_sbrk_core_released);
	DUMP(free_vmm_core);
	DUMP(free_coalesced_vmm);
	DUMP(free_walloc);
	DUMP(sbrk_alloc_bytes);
	DUMP(sbrk_freed_bytes);
	DUMP(vmm_alloc_pages);
	DUMP(vmm_split_pages);
	DUMP(vmm_freed_pages);
	DUMP(aligned_via_freelist);
	DUMP(aligned_via_freelist_then_vmm);
	DUMP(aligned_via_vmm);
	DUMP(aligned_via_zone);
	DUMP(aligned_via_xmalloc);
	DUMP(aligned_freed);
	DUMP(aligned_free_false_positives);
	DUMP(aligned_zones_created);
	DUMP(aligned_zones_destroyed);
	DUMP(aligned_overhead_bytes);
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
	DUMP(realloc_wrealloc);
	DUMP(realloc_converted_from_walloc);
	DUMP(realloc_promoted_to_walloc);
	DUMP(freelist_insertions);
	DUMP(freelist_insertions_no_coalescing);
	DUMP(freelist_further_breakups);
	DUMP(freelist_coalescing_ignore_vmm);
	DUMP(freelist_coalescing_ignored);
	DUMP(freelist_coalescing_done);
	DUMP(freelist_coalescing_failed);
	DUMP(freelist_split);
	DUMP(freelist_nosplit);

#undef DUMP
#define DUMP(x)	log_info(la, "XM %s = %s", #x,		\
	(options & DUMP_OPT_PRETTY) ?					\
		uint64_to_gstring(xstats.x) : uint64_to_string(xstats.x))

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
	size_t i;
	guint64 bytes = 0;
	size_t blocks = 0;

	for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];

		if (0 == fl->capacity)
			continue;

		bytes += fl->blocksize * fl->count;
		blocks = size_saturate_add(blocks, fl->count);

		log_info(la, "XM freelist #%zu (%zu bytes): capacity=%zu, count=%zu",
			i, fl->blocksize, fl->capacity, fl->count);
	}

	log_info(la, "XM freelist holds %s bytes (%s) spread among %zu block%s",
		uint64_to_string(bytes), short_size(bytes, FALSE),
		blocks, 1 == blocks ? "" : "s");
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
 *    the size <= alignment and size > alignment/2, use sub-blocks of
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
			len = compat_pagesize();
			break;
		}
		t_debug(NULL, "XM forgot aligned %s %p (%zu bytes)",
			xdesc_type_str(xt->type), p, len);
	}

	switch (xt->type) {
	case XPAGE_SET:
		xstats.aligned_overhead_bytes -= sizeof(struct xdesc_set);
		break;
	case XPAGE_ZONE:
		xstats.aligned_overhead_bytes -= sizeof(struct xdesc_zone);
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
	size_t mid;

	/* Binary search */

	for (;;) {
		const struct xaligned *item;

		if G_UNLIKELY(low > high || high > SIZE_MAX / 2) {
			mid = -1;		/* Not found */
			break;
		}

		mid = low + (high - low) / 2;
		item = &aligned[mid];

		if (p > item->start)
			low = mid + 1;
		else if (p < item->start)
			high = mid - 1;
		else
			break;				/* Found */
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
	size_t new_capacity = size_saturate_mult(aligned_capacity, 2);

	if (0 == new_capacity)
		new_capacity = 2;

	aligned = xrealloc(aligned, new_capacity * sizeof aligned[0]);
	xstats.aligned_overhead_bytes +=
		(new_capacity - aligned_capacity) * sizeof aligned[0];
	aligned_capacity = new_capacity;

	if (xmalloc_debugging(1)) {
		t_debug(NULL,
			"XM aligned array capacity now %zu, starts at %p (%zu bytes)",
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

	if G_UNLIKELY(aligned_count >= aligned_capacity)
		xa_align_extend();

	/*
	 * Compute insertion index in the sorted array.
	 *
	 * At the same time, this allows us to make sure we're not dealing with
	 * a duplicate insertion.
	 */

	if G_UNLIKELY((size_t ) -1 != xa_lookup(p, &idx)) {
		t_error_from(_WHERE_, NULL,
			"page %p already in aligned list (as page %s)",
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
}

/**
 * Insert tuple (p, set) in the list of aligned pages.
 */
static void
xa_insert_set(const void *p, size_t size)
{
	struct xdesc_set *xs;

	g_assert(size_is_positive(size));

	xs = xmalloc(sizeof *xs);
	xs->type = XPAGE_SET;
	xs->len = size;

	xa_insert(p, xs);

	xstats.aligned_overhead_bytes += sizeof *xs;
	xstats.vmm_alloc_pages += vmm_page_count(size);
	xstats.user_blocks++;
	xstats.user_memory += size;
	memusage_add(xstats.user_mem, size);

	if (xmalloc_debugging(2)) {
		t_debug(NULL, "XM recorded aligned %p (%zu bytes)", p, size);
	}
}

/**
 * Initialize the array of zones.
 */
static G_GNUC_COLD void
xzones_init(void)
{
	g_assert(NULL == xzones);

	xzones_capacity = highest_bit_set(compat_pagesize()) - XALIGN_SHIFT;
	g_assert(size_is_positive(xzones_capacity));

	xzones = xmalloc(xzones_capacity * sizeof xzones[0]);
	xstats.aligned_overhead_bytes += xzones_capacity * sizeof xzones[0];
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
	size_t pagesize = compat_pagesize();

	g_assert(size_is_positive(alignment));
	g_assert(alignment < pagesize);

	arena = vmm_core_alloc(pagesize);
	nblocks = pagesize / alignment;

	g_assert(nblocks >= 2);		/* Because alignment < pagesize */

	xz = xmalloc0(sizeof *xz);
	xz->type = XPAGE_ZONE;
	xz->alignment = alignment;
	xz->arena = arena;
	xz->bitmap = xmalloc0(BIT_ARRAY_BYTE_SIZE(nblocks));
	xz->nblocks = nblocks;

	xa_insert(arena, xz);

	xstats.vmm_alloc_pages++;
	xstats.aligned_zones_created++;
	xstats.aligned_overhead_bytes += sizeof *xz + BIT_ARRAY_BYTE_SIZE(nblocks);

	if (xmalloc_debugging(2)) {
		t_debug(NULL, "XM recorded aligned %p (%zu bytes) as %zu-byte zone",
			arena, pagesize, alignment);
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
		t_debug(NULL, "XM discarding %szone for %zu-byte blocks at %p",
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
	vmm_core_free(xz->arena, compat_pagesize());

	xstats.vmm_freed_pages++;
	xstats.aligned_zones_destroyed++;
	xstats.aligned_overhead_bytes -= BIT_ARRAY_BYTE_SIZE(xz->nblocks);
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
	g_assert(alignment < compat_pagesize());

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
		t_debug(NULL, "XM allocated %zu-byte aligned block #%zu at %p from %p",
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
			t_debug(NULL, "XM moving %zu-byte zone %p to head of zone list",
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

	xstats.user_blocks++;
	xstats.user_memory += alignment;
	memusage_add(xstats.user_mem, alignment);

	return p;
}

/**
 * Free block from zone.
 *
 * @return TRUE if zone was all clear and freed.
 */
static gboolean
xzfree(struct xdesc_zone *xz, const void *p)
{
	size_t bn;

	g_assert(vmm_page_start(p) == xz->arena);

	bn = ptr_diff(p, xz->arena) / xz->alignment;

	g_assert(bn < xz->nblocks);
	g_assert(bit_array_get(xz->bitmap, bn));

	bit_array_clear(xz->bitmap, bn);

	xstats.user_blocks--;
	xstats.user_memory -= xz->alignment;
	memusage_remove(xstats.user_mem, xz->alignment);

	if ((size_t) -1 == bit_array_last_set(xz->bitmap, 0, xz->nblocks - 1)) {
		xzdestroy(xz);
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Checks whether address is that of an aligned page or a sub-block we keep
 * track of and remove memory from the set of tracked blocks when found.
 *
 * @return TRUE if aligned block was found and freed, FALSE otherwise.
 */
static gboolean
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

	idx = xa_lookup(start, NULL);

	if G_LIKELY((size_t) -1 == idx) {
		xstats.aligned_free_false_positives++;
		return FALSE;
	}

	if G_UNLIKELY(xmalloc_no_freeing)
		return TRUE;

	xt = aligned[idx].pdesc;
	xstats.aligned_freed++;

	switch (xt->type) {
	case XPAGE_SET:
		{
			struct xdesc_set *xs = (struct xdesc_set *) xt;
			size_t len = xs->len;

			g_assert(0 != len);
			xa_delete_slot(idx);
			vmm_core_free(deconstify_gpointer(p), len);
			xstats.vmm_freed_pages += vmm_page_count(len);
			xstats.user_memory -= len;
			xstats.user_blocks--;
			memusage_remove(xstats.user_mem, len);
		}
		return TRUE;
	case XPAGE_ZONE:
		{
			struct xdesc_zone *xz = (struct xdesc_zone *) xt;

			if (xzfree(xz, p))
				xa_delete_slot(idx);	/* Last block from zone freed */
		}
		return TRUE;
	}

	g_assert_not_reached();
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
	size_t pagesize;
	const char *method = "xmalloc";
	enum truncation truncation = TRUNCATION_NONE;

	if (!is_pow2(alignment))
		return EINVAL;

	if (0 != alignment % sizeof(void *))
		return EINVAL;

	xstats.allocations_aligned++;

	if G_UNLIKELY(alignment <= XMALLOC_ALIGNBYTES) {
		p = xmalloc(size);
		xstats.aligned_via_xmalloc++;
		goto done;
	}

	if G_UNLIKELY(!xmalloc_vmm_is_up)
		return ENOMEM;		/* Cannot allocate without the VMM layer */

	/*
	 * If they want to align on some boundary, they better be allocating
	 * a block large enough to minimize waste.  Warn if that is not
	 * the case.
	 */

	if G_UNLIKELY(size <= alignment / 2) {
		if (xmalloc_debugging(0)) {
			t_carp(NULL, "XM requested to allocate only %zu bytes "
				"with %zu-byte alignment", size, alignment);
		}
	}

	/*
	 * If they're requesting a block aligned to more than a system page size,
	 * allocate enough pages to get a proper alignment and free the rest.
	 */

	pagesize = compat_pagesize();

	if G_UNLIKELY(alignment == pagesize) {
		p = vmm_core_alloc(size);	/* More than we need */
		method = "VMM";

		xstats.aligned_via_vmm++;

		/*
		 * There is no xmalloc() header for this block, hence we need to
		 * record the address to be able to free() the pointer.
		 */

		xa_insert_set(p, round_pagesize(size));
		goto done;
	} if (alignment > pagesize) {
		size_t rsize = round_pagesize(size);
		size_t nalloc = size_saturate_add(alignment, rsize);
		size_t mask = alignment - 1;
		unsigned long addr;
		void *end;

		p = vmm_core_alloc(nalloc);	/* More than we need */
		method = "VMM";

		xstats.aligned_via_vmm++;

		/*
		 * Is the address already properly aligned?
		 * If so, we just need to remove the excess pages at the end.
		 */

		addr = pointer_to_ulong(p);

		if (xmalloc_debugging(2)) {
			t_debug(NULL, "XM alignement requirement %zu, "
				"allocated %zu at %p (%s aligned)",
				alignment, nalloc, p, (addr & ~mask) == addr ? "is" : "not");
		}

		if ((addr & ~mask) == addr) {
			end = ptr_add_offset(p, rsize);
			vmm_core_free(end, size_saturate_sub(nalloc, rsize));
			truncation = TRUNCATION_AFTER;

			if (xmalloc_debugging(2)) {
				t_debug(NULL, "XM freed trailing %zu bytes at %p",
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
				t_debug(NULL, "XM aligned %p to 0x%x yields %p",
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
				t_debug(NULL, "XM freed leading %zu bytes at %p",
					ptr_diff(q, p), p);
			}

			if (qend != end) {
				vmm_core_free(qend, ptr_diff(end, qend));	/* End */
				truncation = TRUNCATION_BOTH;

				if (xmalloc_debugging(2)) {
					t_debug(NULL, "XM freed trailing %zu bytes at %p",
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

	if (size >= pagesize) {
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

		xstats.aligned_via_vmm++;
		goto done;
	} else if (size > alignment / 2 && size <= alignment) {
		/*
		 * Blocks of a size close to their alignment get allocated from
		 * a dedicated zone to limit fragmentation within the freelist.
		 */

		p = xzalloc(alignment);
		method = "zone";
		xstats.aligned_via_zone++;
		goto done;
	} else {
		size_t nalloc, len, blen;
		size_t mask = alignment - 1;
		unsigned long addr;
		void *u, *end;

		/*
		 * We add XHEADER_SIZE to account for the xmalloc() header.
		 */

		nalloc = size_saturate_add(alignment, size);
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
			xstats.aligned_via_freelist++;
		} else {
			if (len >= pagesize) {
				size_t vlen = round_pagesize(len);

				p = vmm_core_alloc(vlen);
				end = ptr_add_offset(p, vlen);
				method = "freelist, then large VMM";
				xstats.vmm_alloc_pages += vmm_page_count(vlen);

				if (xmalloc_debugging(1)) {
					t_debug(NULL, "XM added %zu bytes of VMM core at %p",
						vlen, p);
				}
			} else {
				p = vmm_core_alloc(pagesize);
				end = ptr_add_offset(p, pagesize);
				method = "freelist, then plain VMM";
				xstats.vmm_alloc_pages++;

				if (xmalloc_debugging(1)) {
					t_debug(NULL, "XM added %zu bytes of VMM core at %p",
						pagesize, p);
				}
			}
			xstats.aligned_via_freelist_then_vmm++;
		}

		g_assert(p != NULL);

		/*
		 * This is the physical block size we want to return in the block
		 * header to flag it as a valid xmalloc()ed one.
		 */

		blen = xmalloc_round_blocksize(xmalloc_round(size) + XHEADER_SIZE);

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
				xmalloc_freelist_insert(split, split_len, XM_COALESCE_AFTER);
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
			u = ulong_to_pointer(addr);		/* Aligned user pointer */

			g_assert(ptr_cmp(u, end) <= 0);
			g_assert(ptr_cmp(ptr_add_offset(u, size), end) <= 0);

			/*
			 * Remove excess pages at the beginning and the end.
			 */

			g_assert(ptr_diff(u, p) >= XHEADER_SIZE);

			q = ptr_add_offset(u, -XHEADER_SIZE);	/* Physical block start */

			if (q != p) {
				size_t before = ptr_diff(q, p);

				/* Because alignment is large enough, this must hold */
				g_assert(before >= XMALLOC_SPLIT_MIN);

				/* Beginning of block, in excess */
				xmalloc_freelist_insert(p, before, XM_COALESCE_BEFORE);
				truncation |= TRUNCATION_BEFORE;
			}

			uend = ptr_add_offset(q, blen);

			if (uend != end) {
				size_t after = ptr_diff(end, uend);

				if (after >= XMALLOC_SPLIT_MIN) {
					/* End of block, in excess */
					xmalloc_freelist_insert(uend, after, XM_COALESCE_AFTER);
					truncation |= TRUNCATION_AFTER;
				} else {
					blen += after;	/* Not truncated */
				}
			}

			p = xmalloc_block_setup(q, blen);	/* User pointer */
		}

		xstats.user_memory += blen;
		xstats.user_blocks++;
		memusage_add(xstats.user_mem, blen);
	}

done:
	*memptr = p;

	if (xmalloc_debugging(1)) {
		t_debug(NULL, "XM aligned %p (%zu bytes) on 0x%lx / %zu via %s%s",
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
	return memalign(compat_pagesize(), size);
}

#endif	/* XMALLOC_IS_MALLOC */

/**
 * In case of crash, dump statistics and make some sanity checks.
 */
static G_GNUC_COLD void
xmalloc_crash_hook(void)
{
	unsigned i;

	/*
	 * When crashing log handlers will not use stdio nor allocate memory.
	 * Therefore it's OK to be using s_xxx() logging routines here.
	 */

	s_debug("XM heap is [%p, %p[", initial_break, current_break);
	s_debug("XM xfreelist_maxidx = %zu", xfreelist_maxidx);
#ifdef XMALLOC_IS_MALLOC
	s_debug("XM xzones_capacity = %zu", xzones_capacity);
#endif
	s_debug("XM dumping virtual memory page map:");
	vmm_dump_pmap();
	xmalloc_dump_stats();

	/*
	 * Now verify that all freelist buckets are not part of the freelist
	 * and that addresses in the freelist are correctly sorted and valid!
	 */

	s_debug("XM verifying freelist...");

	for (i = 0; i < G_N_ELEMENTS(xfreelist); i++) {
		struct xfreelist *fl = &xfreelist[i];
		unsigned j;
		const void *prev;
		gboolean bad = FALSE;

		if (NULL == fl->pointers)
			continue;

		if (fl->capacity < fl->count) {
			s_warning("XM freelist #%zu has corrupted count %zu (capacity %zu)",
				i, fl->count, fl->capacity);
			bad = TRUE;
		}

		for (j = 0; j < G_N_ELEMENTS(xfreelist); j++) {
			if ((size_t) -1 != xfl_lookup(&xfreelist[j], fl->pointers, NULL)) {
				s_warning("XM freelist #%zu bucket %p listed in freelist #%zu!",
					i, (void *) fl->pointers, j);
				goto next;
			}
		}

		for (j = 0, prev = NULL; j < fl->count; j++) {
			const void *p = fl->pointers[j];
			size_t len;

			if (ptr_cmp(p, prev) <= 0) {
				s_warning("XM item #%zu p=%p in freelist #%zu <= prev %p",
					j, p, i, prev);
				bad = TRUE;
			}

			prev = p;

			if (!xmalloc_is_valid_pointer(p)) {
				s_warning("XM item #%zu p=%p in freelist #%zu is invalid",
					j, p, i);
				bad = TRUE;
				continue;
			}

			len = *(size_t *) p;
			if (len != fl->blocksize) {
				s_warning("XM item #%zu p=%p in freelist #%zu (%zu bytes) "
					"has improper length %zu", j, p, i, fl->blocksize, len);
				bad = TRUE;
			}
		}

		if (i > xfreelist_maxidx && fl->count != 0) {
			s_warning("XM freelist #%zu has %zu items and is above maxidx=%zu",
				i, fl->count, xfreelist_maxidx);
			bad = TRUE;
		}

		s_debug("XM freelist #%zu %s", i, bad ? "** CORRUPTED **" : "OK");

		next:
			continue;
	}
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
#endif	/* XMALLOC_IS_MALLOC */

/* vi: set ts=4 sw=4 cindent:  */
