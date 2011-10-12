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
#include "log.h"
#include "misc.h"
#include "pow2.h"
#include "unsigned.h"
#include "vmm.h"
#include "glib-missing.h"

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
 */
#define XMALLOC_ALIGNBYTES	MEM_ALIGNBYTES
#define XMALLOC_MASK		(XMALLOC_ALIGNBYTES - 1)
#define xmalloc_round(s) \
	((unsigned long) (((unsigned long) (s) + XMALLOC_MASK) & ~XMALLOC_MASK))

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
 * multiple of a single XMALLOC_BLOCK_SIZE constant.  For a block size of
 * 1024, the first bucket would be 1024-byte blocks, the fourth 4*1024-byte
 * blocks, etc...
 *
 * When XMALLOC_FACTOR_MAXSIZE equals XMALLOC_BLOCK_SIZE, and in order to
 * avoid having two buckets of XMALLOC_FACTOR_MAXSIZE bytes, the first bucket
 * of the second sizing strategy is 2 * XMALLOC_BLOCK_SIZE.
 *
 * The index in the bucket array where the switch between the first and second
 * sizing strategy operates is called the "cut-over" index.
 */
#define XMALLOC_FACTOR_MAXSIZE	1024
#define XMALLOC_BUCKET_FACTOR	MAX(MEM_ALIGNBYTES, XHEADER_SIZE)
#define XMALLOC_BLOCK_SIZE		XMALLOC_FACTOR_MAXSIZE
#define XMALLOC_MAXSIZE			32768	/**< Largest block size in free list */

/**
 * This contant defines the total number of buckets in the free list.
 */
#define XMALLOC_FREELIST_COUNT	\
	((XMALLOC_FACTOR_MAXSIZE / XMALLOC_BUCKET_FACTOR) + \
	((XMALLOC_MAXSIZE - XMALLOC_FACTOR_MAXSIZE) / XMALLOC_BLOCK_SIZE))

/**
 * The cut-over index is the index of the first bucket using multiples of
 * XMALLOC_BLOCK_SIZE, and it is also the last index using the first sizing
 * strategy since XMALLOC_FACTOR_MAXSIZE == XMALLOC_BLOCK_SIZE.
 */
#define XMALLOC_BUCKET_CUTOVER	\
	((XMALLOC_FACTOR_MAXSIZE / XMALLOC_BUCKET_FACTOR) - 1)

/**
 * Masks for rounding a given size to one of the supported allocation lengths.
 */
#define XMALLOC_FACTOR_MASK	(XMALLOC_BUCKET_FACTOR - 1)
#define XMALLOC_BLOCK_MASK	(XMALLOC_BLOCK_SIZE - 1)

/**
 * Minimum size for a block split: the size of blocks in bucket #0.
 */
#define XMALLOC_SPLIT_MIN	XMALLOC_BUCKET_FACTOR

/**
 * Block coalescing options.
 */
#define XM_COALESCE_NONE	0			/**< No coalescing */
#define XM_COALESCE_BEFORE	(1 << 0)	/**< Coalesce with blocks before */
#define XM_COALESCE_AFTER	(1 << 1)	/**< Coalesce with blocks after */
#define XM_COALESCE_ALL		(XM_COALESCE_BEFORE | XM_COALESCE_AFTER)

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
 *  - if i <= XMALLOC_BUCKET_CUTOVER, size = (i+1) * XMALLOC_BUCKET_FACTOR
 *  - otherwise size = (i - XMALLOC_BUCKET_CUTOVER + 1) * XMALLOC_BLOCK_SIZE
 *
 * The above function is linear by chunk and continuous.
 */
static struct xfreelist {
	void **pointers;		/**< Sorted array of pointers */
	size_t count;			/**< Amount of pointers held */
	size_t capacity;		/**< Maximum amount of pointers that can be held */
	size_t blocksize;		/**< Block size handled by this list */
} xfreelist[XMALLOC_FREELIST_COUNT];

static size_t xfreelist_maxidx;		/**< Highest bucket with blocks */
static guint32 xmalloc_debug;		/**< Debug level */
static gboolean safe_to_log;		/**< True when we can log */
static gboolean xmalloc_vmm_is_up;	/**< True when the VMM layer is up */
static size_t sbrk_allocated;		/**< Bytes allocated with sbrk() */
static gboolean xmalloc_grows_up = TRUE;	/**< Is the VM space growing up? */
static gboolean xmalloc_no_freeing;	/**< No longer release memory */

static void *initial_break;			/**< Initial heap break */
static void *current_break;			/**< Current known heap break */

static void xmalloc_freelist_add(void *p, size_t len, guint32 coalesce);
static void *xmalloc_freelist_alloc(size_t len);
static void xmalloc_freelist_setup(void);
static void *xmalloc_freelist_lookup(size_t len, struct xfreelist **flp);
static void xmalloc_freelist_insert(void *p, size_t len, guint32 coalesce);
static void *xfl_bucket_alloc(const struct xfreelist *flb,
	size_t size, gboolean core, size_t *allocated);

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

	xmalloc_vmm_is_up = TRUE;
	safe_to_log = TRUE;
	xmalloc_grows_up = vmm_grows_upwards();
	xmalloc_freelist_setup();
#ifdef XMALLOC_IS_MALLOC
	vmm_malloc_inited();
#endif
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

	if (len > XMALLOC_MAXSIZE)
		return round_pagesize(len);

	/*
	 * Blocks smaller than XMALLOC_FACTOR_MAXSIZE are allocated using the
	 * first sizing strategy: multiples of XMALLOC_BUCKET_FACTOR bytes.
	 */

	if (len <= XMALLOC_FACTOR_MAXSIZE)
		return (len + XMALLOC_FACTOR_MASK) & ~XMALLOC_FACTOR_MASK;

	/*
	 * Blocks smaller than XMALLOC_MAXSIZE are allocated using the second
	 * sizing strategy: multiples of XMALLOC_BLOCK_SIZE bytes.
	 */

	return (len + XMALLOC_BLOCK_MASK) & ~XMALLOC_BLOCK_MASK;
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
			t_error(NULL, "cannot get initial heap break address: %s (%s)",
				g_strerror(errno), symbolic_errno(errno));
		}
		xmalloc_freelist_setup();
	}

	/*
	 * The VMM layer has not been initialized yet: allocate from the heap.
	 */

#ifdef HAS_SBRK
	p = sbrk(len);
#else
	t_error(NULL, "cannot allocate core on this platform (%lu bytes)",
		(unsigned long) len);
	return p = NULL;
#endif

	if ((void *) -1 == p) {
		t_error(NULL, "cannot allocate more core (%lu bytes): %s (%s)",
			(unsigned long) len,
			g_strerror(errno), symbolic_errno(errno));
	}

	/*
	 * Don't assume we're the only caller of sbrk(): move the current
	 * break pointer relatively to the allocated space rather than
	 * simply increasing our old break pointer by ``len''.
	 */

	current_break = ptr_add_offset(p, len);
	sbrk_allocated += len;

	if (xmalloc_debugging(1)) {
		t_debug(NULL, "XM added %lu bytes of heap core at %p",
			(unsigned long) len, p);
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

		if G_UNLIKELY(end == current_break) {
			void *old_break;
			gboolean success = FALSE;

			if (xmalloc_debugging(0)) {
				t_debug(NULL, "XM releasing %lu bytes of trailing heap",
					(unsigned long) len);
			}

#ifdef HAS_SBRK
			old_break = sbrk(-len);
			if ((void *) -1 == old_break) {
				t_warning(NULL,
					"XM cannot decrease break by %lu bytes: %s (%s)",
					(unsigned long) len, g_strerror(errno),
					symbolic_errno(errno));
			} else {
				current_break = ptr_add_offset(old_break, -len);
				success = !is_running_on_mingw();	/* no sbrk(-x) on Windows */
			}
#endif	/* HAS_SBRK */
			g_assert(ptr_cmp(current_break, initial_break) >= 0);
			return success;
		} else {
			if (xmalloc_debugging(0)) {
				t_debug(NULL, "XM releasing %lu bytes in middle of heap",
					(unsigned long) len);
			}
			return FALSE;		/* Memory not freed */
		}
	}

	if (xmalloc_debugging(1))
		t_debug(NULL, "XM releasing %lu bytes of core", (unsigned long) len);

	vmm_free(ptr, len);
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

	if G_LIKELY(xmalloc_vmm_is_up) {
		return vmm_is_native_pointer(p) || xmalloc_isheap(p, sizeof p);
	} else {
		return xmalloc_isheap(p, sizeof p);
	}
}

/**
 * When pointer is invalid or mis-aligned, return the reason.
 * Also dump the VMM and heap info when facing an invalid pointer.
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
				vmm_dump_pmap();
				s_debug("heap is [%p, %p[", initial_break, current_break);
				return "neither VMM nor heap pointer";
			}
		}
	} else {
		if (xmalloc_isheap(p, sizeof p)) {
			return "valid heap pointer!";		/* Should never happen */
		} else {
			s_debug("heap is [%p, %p[", initial_break, current_break);
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

	if (!size_is_positive(len))
		return FALSE;

	rounded = xmalloc_round_blocksize(len);

	if G_LIKELY(rounded == len || round_pagesize(rounded) == len)
		return TRUE;

	/*
	 * Have to cope with early heap allocations which are done by the libc
	 * before we enter our main(), making it impossible to initialize
	 * proper page size rounding.
	 */

	return xmalloc_isheap(p, len);
}

/***
 *** TODO
 *** Add heap-management to mingw32.c.  Make sure to implement
 *** mingw_addcore() to handle core allocation and mingw_freecore() to free
 *** memory, with mingw_isheap() to check for heap memory.
 ***/

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
		XMALLOC_BUCKET_FACTOR * (idx + 1) :
		XMALLOC_BLOCK_SIZE * (idx + 1 - XMALLOC_BUCKET_CUTOVER);
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

	return (len <= XMALLOC_FACTOR_MAXSIZE) ? 
		len / XMALLOC_BUCKET_FACTOR - 1 :
		XMALLOC_BUCKET_CUTOVER - 1 + len / XMALLOC_BLOCK_SIZE;
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

	if (new_size >= old_size)
		return;

	new_ptr = xfl_bucket_alloc(fl, new_size, new_size >= compat_pagesize(),
		&allocated_size);

	/*
	 * If the new requested size is less than a VM page size and there's
	 * nothing in the freelist, don't bother shrinking: we would need to
	 * get more core, leading to a larger arena.
	 */

	if G_UNLIKELY(NULL == new_ptr)
		return;

	/*
	 * Detect possible recursion.
	 */

	if G_UNLIKELY(fl->pointers != old_ptr) {
		if (xmalloc_debugging(0)) {
			t_debug(NULL, "XM recursion during shrinking of freelist #%lu "
					"(%lu-byte block): already has new bucket at %p "
					"(count = %lu, capacity = %lu)",
					(unsigned long) xfl_index(fl),
					(unsigned long) fl->blocksize, (void *) fl->pointers,
					(unsigned long) fl->count, (unsigned long) fl->capacity);
		}

		g_assert(fl->capacity >= fl->count);	/* Shrinking was OK */

		/*
		 * The freelist structure is coherent, we can release the bucket
		 * we had allocated.
		 */

		if (xmalloc_debugging(1)) {
			t_debug(NULL, "XM discarding allocated bucket %p (%lu bytes) for "
				"freelist #%lu", new_ptr, (unsigned long) allocated_size,
				(unsigned long) xfl_index(fl));
		}

		xmalloc_freelist_add(new_ptr, allocated_size, XM_COALESCE_ALL);
		return;
	}

	g_assert(allocated_size >= new_size);
	g_assert(new_ptr != old_ptr);

	memcpy(new_ptr, old_ptr, old_used);

	fl->pointers = new_ptr;
	fl->capacity = allocated_size / sizeof(void *);

	g_assert(fl->capacity >= fl->count);	/* Still has room for all items */

	if (xmalloc_debugging(1)) {
		t_debug(NULL, "XM shrunk freelist #%lu (%lu-byte block) to %lu items"
			" (holds %lu): old size was %lu bytes, new is %lu, requested %lu,"
			" bucket at %p",
			(unsigned long) xfl_index(fl), (unsigned long) fl->blocksize,
			(unsigned long) fl->capacity, (unsigned long) fl->count,
			(unsigned long) old_size, (unsigned long) allocated_size,
			(unsigned long) new_size, new_ptr);
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
	 * Make sure we resize the pointers[] array when we had enough removals.
	 */

	if (may_shrink && (fl->capacity - fl->count) >= XM_BUCKET_INCREMENT) {
		xfl_shrink(fl);
	}

	/*
	 * Update maximum bucket index.
	 */

	if (0 == fl->count && xfl_index(fl) == xfreelist_maxidx) {
		size_t i;

		xfreelist_maxidx = 0;

		for (i = xfl_index(fl); i > 0; i--) {
			if (xfreelist[i - 1].count != 0) {
				xfreelist_maxidx = i - 1;
				break;
			}
		}

		g_assert(size_is_non_negative(xfreelist_maxidx));
		g_assert(xfreelist_maxidx < G_N_ELEMENTS(xfreelist));

		if (xmalloc_debugging(2)) {
			t_debug(NULL, "XM max frelist index decreased to %lu",
				(unsigned long) xfreelist_maxidx);
		}
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

		if (multiple != len) {
			if (xfl_find_freelist(multiple) == flb)
				return TRUE;

			len -= multiple;
		}
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
		t_error(NULL, "invalid pointer %p in %lu-byte malloc freelist: %s",
			p, (unsigned long) fl->blocksize, xmalloc_invalid_ptrstr(p));
	}

	if (*(size_t *) p != fl->blocksize) {
		size_t len = *(size_t *) p;
		if (!size_is_positive(len)) {
			t_error(NULL, "detected free block corruption at %p: "
				"block in a bucket handling %lu bytes has corrupted length %ld",
				p, (unsigned long) fl->blocksize, (long) len);
		} else {
			t_error(NULL, "detected free block corruption at %p: "
				"%lu-byte long block in a bucket handling %lu bytes", p,
				(unsigned long) len, (unsigned long) fl->blocksize);
		}
	}
}

/**
 * Remove from the free list the block selected by xmalloc_freelist_lookup().
 */
static void
xfl_remove_selected(struct xfreelist *fl)
{
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
			fl->count * sizeof(fl->pointers[0]));
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

		if (xmalloc_debugging(1) && fl == flb) {
			t_debug(NULL, "XM allocated %lu-byte long block at %p "
				"for freelist #%lu from itself (count down to %lu)",
				(unsigned long) fl->blocksize, p, (unsigned long) xfl_index(fl),
				(unsigned long) fl->count);
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

			if G_LIKELY(!xfl_block_falls_in(flb, split_len)) {
				if (xmalloc_grows_up) {
					/* Split the end of the block */
					split = ptr_add_offset(p, len);
				} else {
					/* Split the head of the block */
					split = p;
					p = ptr_add_offset(p, split_len);
				}

				if (xmalloc_debugging(3)) {
					t_debug(NULL, "XM splitting large %lu-byte block at %p"
						" (need only %lu bytes: returning %lu bytes at %p)",
						(unsigned long) blksize, p, (unsigned long) len,
						(unsigned long) split_len, split);
				}

				g_assert(split_len <= XMALLOC_MAXSIZE);

				xmalloc_freelist_insert(split, split_len, XM_COALESCE_NONE);
				blksize = len;		/* We shrank the allocted block */
			} else {
				if (xmalloc_debugging(3)) {
					t_debug(NULL, "XM not splitting large %lu-byte block at %p"
						" (need only %lu bytes but split %lu bytes would fall"
						" in freelist #%lu)",
						(unsigned long) blksize, p, (unsigned long) len,
						(unsigned long) split_len,
						(unsigned long) xfl_index(flb));
				}
			}
		}

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
		p = vmm_alloc(len);
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

	if (0 == old_size) {
		g_assert(NULL == fl->pointers);
		new_size = XM_BUCKET_MINSIZE * sizeof(void *);
	} else if (old_size < XM_BUCKET_THRESHOLD * sizeof(void *)) {
		new_size = old_size * 2;
	} else {
		new_size = old_size + XM_BUCKET_INCREMENT * sizeof(void *);
	}

	g_assert(new_size > old_size);

	if (xmalloc_debugging(1)) {
		t_debug(NULL, "XM extending freelist #%lu (%lu-byte block) "
			"to %lu items, count = %lu, current bucket at %p -- "
			"requesting %lu bytes",
			(unsigned long) xfl_index(fl), (unsigned long) fl->blocksize,
			(unsigned long) (new_size / sizeof(void *)),
			(unsigned long) fl->count, old_ptr, (unsigned long) new_size);
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
			t_debug(NULL, "XM recursion during extension of freelist #%lu "
					"(%lu-byte block): already has new bucket at %p "
					"(count = %lu, capacity = %lu)",
					(unsigned long) xfl_index(fl),
					(unsigned long) fl->blocksize, (void *) fl->pointers,
					(unsigned long) fl->count, (unsigned long) fl->capacity);
		}

		g_assert(fl->capacity >= fl->count);	/* Extending was OK */

		/*
		 * The freelist structure is coherent, we can release the bucket
		 * we had allocated and if it causes it to be put back in this
		 * freelist, we may still safely recurse here since.
		 */

		if (xmalloc_debugging(1)) {
			t_debug(NULL, "XM discarding allocated bucket %p (%lu bytes) for "
				"freelist #%lu", new_ptr, (unsigned long) allocated_size,
				(unsigned long) xfl_index(fl));
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
		t_error(NULL, "XM self-increase during extension of freelist #%lu "
				"(%lu-byte block): has more items than initial %lu "
				"(count = %lu, capacity = %lu)",
				(unsigned long) xfl_index(fl), (unsigned long) fl->blocksize,
				(unsigned long) (old_used / sizeof(void *)),
				(unsigned long) fl->count, (unsigned long) fl->capacity);
	}

	g_assert(new_ptr != old_ptr);

	memcpy(new_ptr, old_ptr, old_used);
	fl->pointers = new_ptr;
	fl->capacity = allocated_size / sizeof(void *);

	g_assert(fl->capacity > fl->count);		/* Extending was OK */

	if (xmalloc_debugging(1)) {
		t_debug(NULL, "XM extended freelist #%lu (%lu-byte block) to %lu items"
			" (holds %lu): new size is %lu bytes, requested %lu, bucket at %p",
			(unsigned long) xfl_index(fl), (unsigned long) fl->blocksize,
			(unsigned long) fl->capacity, (unsigned long) fl->count,
			(unsigned long) allocated_size, (unsigned long) new_size, new_ptr);
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
 * Quick test to avoid costly xfl_lookup() call when we can determine that
 * the block is nowhere to be found.
 */
static inline G_GNUC_HOT ALWAYS_INLINE gboolean
xfl_could_contain(const struct xfreelist *fl, const void *p)
{
	if (0 == fl->count)
		return FALSE;

	return
		ptr_cmp(p, fl->pointers[0]) >= 0 &&
		ptr_cmp(p, fl->pointers[fl->count - 1]) <= 0;
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
	size_t low = 0, high = fl->count - 1;
	size_t mid;

	g_assert(fl->count <= fl->capacity);

	/* Binary search */

	for (;;) {
		const void *item;

		if G_UNLIKELY(low > high || high > SIZE_MAX / 2) {
			mid = -1;		/* Not found */
			break;
		}

		mid = low + (high - low) / 2;
		item = fl->pointers[mid];

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
		t_error(NULL, "block %p already in free list #%lu (%lu bytes)",
			p, (unsigned long) xfl_index(fl),
			(unsigned long) fl->blocksize);
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

	fl->count++;
	fl->pointers[idx] = p;

	/*
	 * To detect freelist corruptions, write the size of the block at the
	 * beginning of the block itself.
	 */

	*(size_t *) p = fl->blocksize;

	if (xmalloc_debugging(2)) {
		t_debug(NULL, "XM inserted block %p in free list #%lu (%lu bytes)",
			p, (unsigned long) xfl_index(fl),
			(unsigned long) fl->blocksize);
	}

	/*
	 * Update maximum bucket index.
	 */

	if (1 == fl->count && xfreelist_maxidx < xfl_index(fl)) {
		xfreelist_maxidx = xfl_index(fl);
		g_assert(xfreelist_maxidx < G_N_ELEMENTS(xfreelist));

		if (xmalloc_debugging(1)) {
			t_debug(NULL, "XM max frelist index increased to %lu",
				(unsigned long) xfreelist_maxidx);
		}
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
	size_t i, j;
	void *base = *base_ptr;
	size_t len = *len_ptr;
	void *end;
	gboolean coalesced = FALSE;

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

			if (!xfl_could_contain(fl, before))
				continue;

			idx = xfl_lookup(fl, before, NULL);

			if G_UNLIKELY((size_t) -1 != idx) {
				if (xmalloc_debugging(6)) {
					t_debug(NULL, "XM iter #%lu, "
						"coalescing previous %lu-byte [%p, %p[ "
						"from list #%lu with %lu-byte [%p, %p[",
						(unsigned long) i,
						(unsigned long) blksize, before,
						ptr_add_offset(before, blksize), (unsigned long) j,
						(unsigned long) ptr_diff(end, base),
						base, end);
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

			/*
			 * Avoid costly lookup if the pointer cannot be found.
			 */

			if (!xfl_could_contain(fl, end))
				continue;

			idx = xfl_lookup(fl, end, NULL);

			if G_UNLIKELY((size_t) -1 != idx) {
				size_t blksize = fl->blocksize;

				if (xmalloc_debugging(6)) {
					t_debug(NULL, "XM iter #%lu, "
						"coalescing next %lu-byte [%p, %p[ "
						"from list #%lu with %lu-byte [%p, %p[",
						(unsigned long) i,
						(unsigned long) blksize, end,
						ptr_add_offset(end, blksize), (unsigned long) j,
						(unsigned long) ptr_diff(end, base),
						base, end);
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

	if (coalesced) {
		*base_ptr = base;
		*len_ptr = ptr_diff(end, base);
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
	 * We can free the zone [page, vend[.
	 */

	if (xmalloc_debugging(1)) {
		t_debug(NULL,
			"XM releasing VMM [%p, %p[ (%lu bytes) within [%p, %p[ (%lu bytes)",
			page, vend, (unsigned long) ptr_diff(vend, page),
			p, end, (unsigned long) len);
	}

	vmm_free(page, ptr_diff(vend, page));

	*head = deconstify_gpointer(p);
	*head_len = ptr_diff(page, p);
	*tail = deconstify_gpointer(vend);
	*tail_len = ptr_diff(end, vend);

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

	if (coalesce)
		xmalloc_freelist_coalesce(&p, &len, coalesce);

	/*
	 * Chunks of memory larger than XMALLOC_MAXSIZE need to be broken up
	 * into smaller blocks.  This can happen when we're putting heap memory
	 * back into the free list, or when a block larger than a page size is
	 * actually spread over two distinct VM pages..
	 */

	if G_UNLIKELY(len > XMALLOC_MAXSIZE) {
		if (xmalloc_debugging(3)) {
			t_debug(NULL, "XM breaking up %s block %p (%lu bytes)",
				xmalloc_isheap(p, len) ? "heap" : "VMM",
				p, (unsigned long) len);
		}

		fl = xfl_find_freelist(XMALLOC_MAXSIZE);

		while (len > XMALLOC_MAXSIZE) {
			xfl_insert(fl, p);
			p = ptr_add_offset(p, XMALLOC_MAXSIZE);
			len -= XMALLOC_MAXSIZE;
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

		if (multiple != len) {
			if (xmalloc_debugging(3)) {
				t_debug(NULL, "XM breaking up %s block %p (%lu bytes)",
					xmalloc_isheap(p, len) ? "heap" : "VMM",
					p, (unsigned long) len);
			}

			fl = xfl_find_freelist(multiple);
			xfl_insert(fl, p);
			p = ptr_add_offset(p, multiple);
			len -= multiple;
		}

		/* FALL THROUGH */
	}

	fl = xfl_find_freelist(len);
	xfl_insert(fl, p);
}

/**
 * Add memory chunk to free list.
 */
static void
xmalloc_freelist_add(void *p, size_t len, guint32 coalesce)
{
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
			xmalloc_freelist_coalesce(&p, &len, coalesce);
		} else if (xmalloc_debugging(4)) {
			t_debug(NULL,
				"XM not attempting coalescing of %lu-byte VMM region at %p",
				(unsigned long) len, p);
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
				t_debug(NULL, "XM %lu bytes of heap released at %p, "
					"not adding to free list", (unsigned long) len, p);
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
					t_debug(NULL, "XM freeed embedded pages, %s head, %s tail",
						head_len != 0 ? "has" : "no",
						tail_len != 0 ? "has" : "no");
				} else {
					t_debug(NULL, "XM freeed whole %lu-byte region at %p",
						(unsigned long) len, p);
				}
			}

			/*
			 * Head and tail are smaller than a page size but could still be
			 * larger than XMALLOC_MAXSIZE.
			 */

			if (head_len != 0) {
				g_assert(head == p);
				if (xmalloc_debugging(4)) {
					t_debug(NULL, "XM freeing head of %p at %p (%lu bytes)",
						p, head, (unsigned long) head_len);
				}
				xmalloc_freelist_add(head, head_len,
					(coalesce & XM_COALESCE_BEFORE) ?
						XM_COALESCE_NONE : XM_COALESCE_BEFORE);
			}
			if (tail_len != 0) {
				g_assert(
					ptr_add_offset(tail, tail_len) == ptr_add_offset(p, len));
				if (xmalloc_debugging(4)) {
					t_debug(NULL, "XM freeing tail of %p at %p (%lu bytes)",
						p, tail, (unsigned long) tail_len);
				}
				xmalloc_freelist_add(tail, tail_len,
					(coalesce & XM_COALESCE_AFTER) ?
						XM_COALESCE_NONE : XM_COALESCE_AFTER);
			}
			return;
		}
	}

	xmalloc_freelist_insert(p, len, XM_COALESCE_NONE);
}

/**
 * Allocate a block from the freelist, of given physical length.
 *
 * @param len		the desired block length (including our overhead)
 *
 * @return the block address we found, NULL if nothing was found.
 * The returned block is removed from the freelist.
 */
static void *
xmalloc_freelist_alloc(size_t len)
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

			if (xmalloc_grows_up) {
				/* Split the end of the block */
				split = ptr_add_offset(p, len);
			} else {
				/* Split the head of the block */
				split = p;
				p = ptr_add_offset(p, split_len);
			}

			if (xmalloc_debugging(3)) {
				t_debug(NULL, "XM splitting large %lu-byte block at %p"
					" (need only %lu bytes: returning %lu bytes at %p)",
					(unsigned long) blksize, p, (unsigned long) len,
					(unsigned long) split_len, split);
			}

			g_assert(split_len <= XMALLOC_MAXSIZE);

			xmalloc_freelist_insert(split, split_len, XM_COALESCE_NONE);
		}
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
		t_debug(NULL, "XM setup allocated %lu-byte block at %p (user %p)",
			(unsigned long) len, p, ptr_add_offset(p, XHEADER_SIZE));
	}

	xh->length = len;
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

static gboolean xalign_free(const void *p);

#else	/* !XMALLOC_IS_MALLOC */
#define is_trapping_malloc()	0
#define xalign_free(p)			FALSE
#endif	/* XMALLOC_IS_MALLOC */

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

	/*
	 * First try to allocate from the freelist when the length is less than
	 * the maximum we handle there.
	 */

	if (len <= XMALLOC_MAXSIZE) {
		p = xmalloc_freelist_alloc(len);
		if (p != NULL)
			return xmalloc_block_setup(p, len);
	}

	/*
	 * Need to allocate more core.
	 */

	if G_LIKELY(xmalloc_vmm_is_up) {
		size_t pagesize = compat_pagesize();

		/*
		 * As soon as the VMM layer is up, use it for all core allocations.
		 */

		if (len >= pagesize) {
			size_t vlen = round_pagesize(len);
			p = vmm_alloc(vlen);

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM added %lu bytes of VMM core at %p",
					(unsigned long) vlen, p);
			}

			return xmalloc_block_setup(p, vlen);
		} else {
			p = vmm_alloc(pagesize);

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM added %lu bytes of VMM core at %p",
					(unsigned long) pagesize, p);
			}

			if (pagesize - len >= XMALLOC_SPLIT_MIN) {
				void * split = ptr_add_offset(p, len);
				xmalloc_freelist_insert(split,
					pagesize - len, XM_COALESCE_AFTER);
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

		if (xmalloc_debugging(0)) {
			t_debug(NULL, "XM added %lu bytes of heap core at %p",
				(unsigned long) len, p);
		}

		return xmalloc_block_setup(p, len);
	}

	g_assert_not_reached();
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
	memset(p, 0 ,size);

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
 * Free memory block allocated via xmalloc() or xrealloc().
 */
void
xfree(void *p)
{
	struct xheader *xh;

	if G_UNLIKELY(xmalloc_no_freeing)
		return;

	/*
	 * Some parts of the libc can call free() with a NULL pointer.
	 * So we explicitly allow this to be able to replace free() correctly.
	 */

	if (NULL == p)
		return;

	xh = ptr_add_offset(p, -XHEADER_SIZE);

	/*
	 * Handle pointers returned by posix_memalign() and friends that
	 * would be page-aligned and therefore directly allocated by VMM.
	 */

	if (is_trapping_malloc() && xalign_free(p))
		return;

	if (!xmalloc_is_valid_pointer(xh)) {
		t_error(NULL, "attempt to free invalid pointer %p: %s",
			p, xmalloc_invalid_ptrstr(p));
	}

	if (!xmalloc_is_valid_length(xh, xh->length))
		t_error(NULL, "corrupted malloc header for pointer %p", p);

	xmalloc_freelist_add(xh, xh->length, XM_COALESCE_ALL);
}

/**
 * Reallocate a block allocated via xmalloc().
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
	struct xheader *xh = ptr_add_offset(p, -XHEADER_SIZE);
	size_t newlen;
	void *np;

	if (NULL == p)
		return xmalloc(size);

	if (0 == size) {
		xfree(p);
		return NULL;
	}

	if (!xmalloc_is_valid_pointer(xh)) {
		t_error(NULL, "attempt to realloc invalid pointer %p: %s",
			p, xmalloc_invalid_ptrstr(p));
	}

	if (!xmalloc_is_valid_length(xh, xh->length))
		t_error(NULL, "corrupted malloc header for pointer %p", p);

	newlen = xmalloc_round_blocksize(xmalloc_round(size) + XHEADER_SIZE);

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
			void *q;

			q = vmm_alloc(newlen);
			np = xmalloc_block_setup(q, newlen);

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM relocated %lu-byte VMM region at %p to %p"
					" (new pysical size is %lu bytes, user size is %lu)",
					(unsigned long) xh->length, (void *) xh, q,
					(unsigned long) newlen, (unsigned long) size);
			}

			goto relocate;
		}

		/*
		 * If the new size is smaller than the original, yet remains larger
		 * than a page size, we can call vmm_shrink() to shrink the block
		 * inplace.
		 */

		if (newlen < xh->length) {
			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM using vmm_shrink() on %lu-byte block at %p"
					" (new size is %lu bytes)",
					(unsigned long) xh->length, (void *) xh,
					(unsigned long) newlen);
			}

			vmm_shrink(xh, xh->length, newlen);
			goto inplace;
		}

		/*
		 * If we have to extend the VMM region, we can skip all the coalescing
		 * logic since we have to allocate a new region.
		 */

		if (newlen > xh->length)
			goto skip_coalescing;

		if (xmalloc_debugging(2)) {
			t_debug(NULL, "XM realloc of %p to %lu bytes can be a noop "
				"(already %lu-byte long VMM region)",
				p, (unsigned long) size, (unsigned long) xh->length);
		}

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
			if (
				q != NULL && newlen == fl->blocksize &&
				(xmalloc_grows_up ? +1 : -1) * ptr_cmp(q, xh) < 0
			) {
				np = xmalloc_block_setup(q, newlen);
				xfl_remove_selected(fl);

				if (xmalloc_debugging(1)) {
					t_debug(NULL, "XM relocated %lu-byte block at %p to %p"
						" (pysical size is still %lu bytes, user size is %lu)",
						(unsigned long) xh->length, (void *) xh, q,
						(unsigned long) newlen, (unsigned long) size);
				}

				goto relocate;
			}
		}

		if (xmalloc_debugging(2)) {
			t_debug(NULL, "XM realloc of %p to %lu bytes can be a noop "
				"(already %lu-byte long from %s)",
				p, (unsigned long) size, (unsigned long) xh->length,
				xmalloc_isheap(p, size) ? "heap" : "VMM");
		}

		return p;
	}

	/*
	 * If the block is shrinked and its old size is less than XMALLOC_MAXSIZE,
	 * put the remainder back in the freelist.
	 */

	if (xh->length <= XMALLOC_MAXSIZE && newlen < xh->length) {
		void *end;

		end = ptr_add_offset(xh, newlen);

		if (xmalloc_debugging(1)) {
			t_debug(NULL, "XM using inplace shrink on %lu-byte block at %p"
				" (new size is %lu bytes, splitting at %p)",
				(unsigned long) xh->length, (void *) xh,
				(unsigned long) newlen, end);
		}

		xmalloc_freelist_insert(end, xh->length - newlen, XM_COALESCE_AFTER);
		goto inplace;
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

			if (!xfl_could_contain(fl, end))
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
						t_debug(NULL, "XM realloc NOT coalescing next %lu-byte "
							"[%p, %p[ from list #%lu with [%p, %p[: invalid "
							"resulting size of %lu bytes",
							(unsigned long) blksize, end,
							ptr_add_offset(end, blksize), (unsigned long) i,
							(void *) xh, end, (unsigned long) csize);
					}
					break;
				}

				if (xmalloc_debugging(6)) {
					t_debug(NULL, "XM realloc coalescing next %lu-byte "
						"[%p, %p[ from list #%lu with [%p, %p[ yielding "
						"%lu-byte block",
						(unsigned long) blksize, end,
						ptr_add_offset(end, blksize), (unsigned long) i,
						(void *) xh, end, (unsigned long) csize);
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
						"XM realloc splitting large %lu-byte block at %p"
						" (need only %lu bytes: returning %lu bytes at %p)",
						(unsigned long) ptr_diff(end, xh), (void *) xh,
						(unsigned long) newlen,
						(unsigned long) split_len, split);
				}

				g_assert(split_len <= XMALLOC_MAXSIZE);

				xmalloc_freelist_insert(split, split_len, XM_COALESCE_AFTER);
			} else {
				/* Actual size ends up being larger than requested */
				newlen = ptr_diff(end, xh);
			}

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM realloc used inplace coalescing on "
					"%lu-byte block at %p (new size is %lu bytes)",
					(unsigned long) xh->length, (void *) xh,
					(unsigned long) newlen);
			}

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

			/*
			 * Avoid costly lookup if the pointer cannot be found.
			 */

			if (!xfl_could_contain(fl, before))
				continue;

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
							"%lu-byte [%p, %p[ from list #%lu with [%p, %p[: "
							"invalid resulting size of %lu bytes",
							(unsigned long) blksize, before,
							ptr_add_offset(before, blksize), (unsigned long) i,
							(void *) xh, end, (unsigned long) csize);
					}
					break;
				}

				if (xmalloc_debugging(6)) {
					t_debug(NULL, "XM realloc coalescing previous %lu-byte "
						"[%p, %p[ from list #%lu with [%p, %p[",
						(unsigned long) blksize, before,
						ptr_add_offset(before, blksize), (unsigned long) i,
						(void *) xh, end);
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
						"XM realloc splitting large %lu-byte block at %p"
						" (need only %lu bytes: returning %lu bytes at %p)",
						(unsigned long) ptr_diff(end, xh), (void *) xh,
						(unsigned long) newlen,
						(unsigned long) split_len, split);
				}

				g_assert(split_len <= XMALLOC_MAXSIZE);

				xmalloc_freelist_insert(split, split_len, XM_COALESCE_AFTER);
			} else {
				/* Actual size ends up being larger than requested */
				newlen = ptr_diff(end, xh);
			}

			if (xmalloc_debugging(1)) {
				t_debug(NULL, "XM realloc used coalescing with block preceding "
					"%lu-byte block at %p "
					"(new size is %lu bytes, new address is %p)",
					(unsigned long) (old_len + XHEADER_SIZE),
					ptr_add_offset(p, -XHEADER_SIZE),
					(unsigned long) newlen, (void *) xh);
			}

			return xmalloc_block_setup(xh, newlen);
		}

		/* FALL THROUGH */
	}

skip_coalescing:

	/*
	 * Regular case: allocate a new block, move data around, free old block.
	 */

	np = xmalloc(size);

	if (xmalloc_debugging(1)) {
		t_debug(NULL, "XM realloc used regular strategy: "
			"%lu-byte block at %p moved to %lu-byte block at %p",
			(unsigned long) xh->length, (void *) xh,
			(unsigned long) (size + XHEADER_SIZE),
			ptr_add_offset(np, -XHEADER_SIZE));
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
		t_info(NULL, "malloc() allocated %lu bytes of heap (%lu remain)",
			(unsigned long) sbrk_allocated,
			(unsigned long) ptr_diff(current_break, initial_break));
	}

	t_info(NULL, "will use %s", xmalloc_is_malloc() ?
		"our own malloc() replacement" : "native malloc()");

	if (xmalloc_debugging(0)) {
		t_info(NULL, "XM using %ld freelist buckets",
			(long) XMALLOC_FREELIST_COUNT);
	}
}

/**
 * Signal that we should stop freeing memory.
 *
 * This is mostly useful during final cleanup when xmalloc() replaces malloc().
 */
G_GNUC_COLD void
xmalloc_stop_freeing(void)
{
	xmalloc_no_freeing = TRUE;
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

#define XALIGN_MINSIZE	64	/**< Minimum alignment for xzalloc() */
#define XALIGN_SHIFT	6	/* 2**6 */

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
	if (xmalloc_debugging(2)) {
		struct xdesc_type *xt = pdesc;
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
		t_debug(NULL, "XM forgot aligned %s %p (%lu bytes)",
			xdesc_type_str(xt->type), p, (unsigned long) len);
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

	aligned = xrealloc(aligned, new_capacity * sizeof(aligned[0]));
	aligned_capacity = new_capacity;

	if (xmalloc_debugging(1)) {
		t_debug(NULL,
			"XM aligned array capacity now %lu, starts at %p (%lu bytes)",
			(unsigned long) aligned_capacity, (void *) aligned,
			(unsigned long) (new_capacity * sizeof(aligned[0])));
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
		t_error(NULL, "page %p already in aligned list (as page %s)",
			p, xalign_type_str(&aligned[idx]));
	}

	g_assert(size_is_non_negative(idx) && idx <= aligned_count);

	/*
	 * Shift items if we're not inserting at the last position in the array.
	 */

	g_assert(aligned != NULL);

	if G_LIKELY(idx < aligned_count) {
		memmove(&aligned[idx + 1], &aligned[idx],
			(aligned_count - idx) * sizeof(aligned[0]));
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

	if (xmalloc_debugging(2)) {
		t_debug(NULL, "XM recorded aligned %p (%lu bytes)",
			p, (unsigned long) size);
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

	arena = vmm_alloc(pagesize);
	nblocks = pagesize / alignment;

	g_assert(nblocks >= 2);		/* Because alignment < pagesize */

	xz = xmalloc0(sizeof *xz);
	xz->type = XPAGE_ZONE;
	xz->alignment = alignment;
	xz->arena = arena;
	xz->bitmap = xmalloc0(BIT_ARRAY_BYTE_SIZE(nblocks));
	xz->nblocks = nblocks;

	xa_insert(arena, xz);

	if (xmalloc_debugging(2)) {
		t_debug(NULL, "XM recorded aligned %p (%lu bytes) as %lu-byte zone",
			arena, (unsigned long) pagesize, (unsigned long) alignment);
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
		t_debug(NULL, "XM discarding %szone for %lu-byte blocks at %p",
			(NULL == xz->next && NULL == xz->prev) ? "last " : "",
			(unsigned long) xz->alignment, xz->arena);
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
	vmm_free(xz->arena, compat_pagesize());
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
		t_debug(NULL, "XM allocated %lu-byte aligned block #%lu at %p from %p",
			(unsigned long) xzf->alignment, (unsigned long) bn, p, xzf->arena);
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
			t_debug(NULL, "XM moving %lu-byte zone %p to head of zone list",
				(unsigned long) xzf->alignment, xzf->arena);
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

	if G_LIKELY((size_t) -1 == idx)
		return FALSE;

	xt = aligned[idx].pdesc;

	switch (xt->type) {
	case XPAGE_SET:
		{
			struct xdesc_set *xs = (struct xdesc_set *) xt;
			size_t len = xs->len;

			g_assert(0 != len);
			xa_delete_slot(idx);
			vmm_free(deconstify_gpointer(p), len);
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

	if G_UNLIKELY(alignment <= MEM_ALIGNBYTES) {
		p = xmalloc(size);
		goto done;
	}

	if G_UNLIKELY(!xmalloc_vmm_is_up)
		return ENOMEM;		/* Cannot allocate without the VMM layer */

	/*
	 * If they want to align on some boundary, they better be allocating
	 * a block large enough to minimize waste.  Warn if that is not
	 * the case.
	 */

	if G_UNLIKELY(size <= alignment / 2 && xmalloc_debugging(0)) {
		t_carp(NULL,
			"XM requested to allocate only %lu bytes with %lu-byte alignment",
			(unsigned long) size, (unsigned long) alignment);
	}

	/*
	 * If they're requesting a block aligned to more than a system page size,
	 * allocate enough pages to get a proper alignment and free the rest.
	 */

	pagesize = compat_pagesize();

	if G_UNLIKELY(alignment == pagesize) {
		p = vmm_alloc(size);	/* More than we need */
		method = "VMM";

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

		p = vmm_alloc(nalloc);	/* More than we need */
		method = "VMM";

		/*
		 * Is the address already properly aligned?
		 * If so, we just need to remove the excess pages at the end.
		 */

		addr = pointer_to_ulong(p);

		if ((addr & ~mask) == addr) {
			end = ptr_add_offset(p, rsize);
			vmm_free(end, size_saturate_sub(nalloc, rsize));
			truncation = TRUNCATION_AFTER;
		} else {
			void *q, *qend;

			/*
			 * Find next aligned address.
			 */

			addr = size_saturate_add(addr, mask) & ~mask;
			q = ulong_to_pointer(addr);
			end = ptr_add_offset(p, nalloc);

			g_assert(ptr_cmp(q, end) <= 0);
			g_assert(ptr_cmp(ptr_add_offset(q, rsize), end) <= 0);

			/*
			 * Remove excess pages at the beginning and the end.
			 */

			g_assert(ptr_cmp(q, p) > 0);

			vmm_free(p, ptr_diff(q, p));		/* Beginning */
			qend = ptr_add_offset(q, rsize);
			if (qend != end) {
				vmm_free(qend, ptr_diff(end, qend));	/* End */
				truncation = TRUNCATION_BOTH;
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

		p = vmm_alloc(rsize);		/* Necessarily aligned */

		/*
		 * There is no xmalloc() header for this block, hence we need to
		 * record the address to be able to free() the pointer.
		 * Unfortunately, we cannot trim anything since free() will require
		 * the total size of the allocated VMM block to be in-use.
		 */

		xa_insert_set(p, rsize);
		method = "plain VMM";
		goto done;
	} else if (size > alignment / 2 && size <= alignment) {
		/*
		 * Blocks of a size close to their alignment get allocated from
		 * a dedicated zone to limit fragmentation within the freelist.
		 */

		p = xzalloc(alignment);
		method = "zone";
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
			p = xmalloc_freelist_alloc(len);

		if (p != NULL) {
			end = ptr_add_offset(p, len);
			method = "freelist";
		} else {
			if (len >= pagesize) {
				size_t vlen = round_pagesize(len);

				p = vmm_alloc(vlen);
				end = ptr_add_offset(p, vlen);
				method = "freelist, then large VMM";

				if (xmalloc_debugging(1)) {
					t_debug(NULL, "XM added %lu bytes of VMM core at %p",
						(unsigned long) vlen, p);
				}
			} else {
				p = vmm_alloc(pagesize);
				end = ptr_add_offset(p, pagesize);
				method = "freelist, then plain VMM";

				if (xmalloc_debugging(1)) {
					t_debug(NULL, "XM added %lu bytes of VMM core at %p",
						(unsigned long) pagesize, p);
				}
			}
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
				/* Beginning of block, in excess */
				xmalloc_freelist_insert(p, ptr_diff(q, p), XM_COALESCE_BEFORE);
				truncation |= TRUNCATION_BEFORE;
			}

			uend = ptr_add_offset(q, blen);

			if (uend != end) {
				/* End of block, in excess */
				xmalloc_freelist_insert(uend, ptr_diff(end, uend),
					XM_COALESCE_AFTER);
				truncation |= TRUNCATION_AFTER;
			}

			p = xmalloc_block_setup(q, blen);	/* User pointer */
		}
	}

done:
	*memptr = p;

	if (xmalloc_debugging(1)) {
		t_debug(NULL, "XM aligned %p (%lu bytes) on 0x%lx / %lu via %s%s",
			p, (unsigned long) size, (unsigned long) alignment,
			(unsigned long) alignment, method, xa_truncation_str(truncation));
	}

	/*
	 * Ensure memory is aligned properly.
	 */

	g_assert_log(
		pointer_to_ulong(p) == (pointer_to_ulong(p) & ~(alignment - 1)),
		"p=%p, alignment=%lu, aligned=%p",
		p, (unsigned long) alignment,
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

/* vi: set ts=4 sw=4 cindent:  */
