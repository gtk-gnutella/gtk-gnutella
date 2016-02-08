/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * Memory allocator for objects that are allocated once and never resized
 * nor freed.
 *
 * Allocation is based on the VMM layer, no usage of g_malloc() or even the
 * system's malloc() is used so that it can be used everywhere, even in the
 * low-level malloc tracking layer.
 *
 * This allocator is very fast (comparable to zone allocators) and imposes
 * no overhead whatsoever on allocated memory, compared to malloc() style
 * allocation.  Its runtime data structures auto-dissolve as needed, leaving
 * no trail.
 *
 * Handling "one time allocation" is rather straightforward since we do not
 * have to bother with freeing memory: hence neither free list management nor
 * bookkeeping of allocated objects are required.
 *
 * The only work required is to avoid wasting too much memory.
 *
 * The algorithm retained is to allocate memory out of a "big chunk", putting
 * objects one after the other until we can no longer fit any object, at which
 * point we allocate a new chunk.
 *
 * Waste is kept at a minimum by not discarding completely chunks in which
 * we cannot allocate an object but in which there is still room.  These
 * chunks are kept in a list organized by buckets, whose size are powers of 2.
 * Whenever we are asked for memory, we look in the buckets whether there
 * are chunks with enough memory left and we allocate from there.
 *
 * Objects larger than our typical memory chunk size are allocated directly
 * from the VMM layer.  However, given the relatively high granularity of
 * allocation there (1 page size, typically 4 KiB), we cram a small chunk
 * at the tail of the allocated arena if there is enough space to do it, so
 * that we can use this space for other smaller allocations.
 *
 * Therefore, the optimial size for our "big chunk" is one page size because
 * this is the lowest granularity we have when allocating pages and it does not
 * prevent us from efficiently allocating smaller objects out of remaining
 * fragments.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"		/* For RCSID */

#include "omalloc.h"

#include "atomic.h"
#include "dump_options.h"
#include "glib-missing.h"
#include "log.h"
#include "misc.h"
#include "pow2.h"
#include "signal.h"
#include "spinlock.h"
#include "stringify.h"
#include "unsigned.h"
#include "vmm.h"
#include "xmalloc.h"

#include "override.h"	/* Must be the last header included */

/**
 * Memory alignment constraints.
 */
#define OMALLOC_ALIGNBYTES	MEM_ALIGNBYTES
#define OMALLOC_MASK		(OMALLOC_ALIGNBYTES - 1)
#define omalloc_round(s) \
	((ulong) (((ulong) (s) + OMALLOC_MASK) & ~OMALLOC_MASK))

/**
 * Maximum chunk size.
 *
 * We can't know for sure what the page size is going to be, statically.
 * What we need here is an upper boundary, so that chunks[] is properly
 * sized and prepared to handle fragments of at most one page size.
 * Given the exponential progression in chunks[], we can greatly over-estimate
 * the real page size and still suffer a negligeable space overhead in chunks[].
 */
#define OMALLOC_CHUNK_BITS	16
#define OMALLOC_CHUNK_SIZE	(1 << OMALLOC_BITS)

/**
 * Chunk header to govern allocation.
 *
 * The header marks the tail of the free space in the chunk.
 *
 * As objects are allocated, the header is updated until everything before
 * the header has been allocated, at which time it will probably dissolve
 * itself to provide room for one last allocation of a small object.
 */
struct ochunk {
	struct ochunk *next;	/* Linking in chunk "free list" */
	struct ochunk *prev;
	void *first;			/* First free location (up to struct's address) */
};

#define OMALLOC_HEADER_SIZE	(sizeof(struct ochunk))

static uint32 omalloc_debug;
static size_t omalloc_pagesize;

#define OMALLOC_CHUNK_COUNT	(OMALLOC_CHUNK_BITS + 1)

/**
 * Array of chunks with free space.
 *
 * An entry at index ``i'' guarantees at least 2^i free bytes in the chunk,
 * including the chunk header.
 */
static struct ochunk *chunks_rw[OMALLOC_CHUNK_COUNT];	/* Read & Write */
static struct ochunk *chunks_ro[OMALLOC_CHUNK_COUNT];	/* Read-Only */

enum omalloc_mode {
	OMALLOC_RW,			/* Read & Write */
	OMALLOC_RO			/* Read-Only */
};

/**
 * Internal statistics.
 */
static struct ostats {
	size_t pages_rw;		/**< Total amount of rw pages allocated */
	size_t objects_rw;		/**< Total amount of rw objects allocated */
	size_t memory_rw;		/**< Total amount of rw memory allocated */
	size_t chunks_rw;		/**< Total amount of rw chunks still present */
	size_t align_rw;		/**< Space wasted in rw chunks for alignment */
	size_t wasted_rw;		/**< Space wasted at tail of rw chunks */
	size_t pages_ro;		/**< Total amount of ro pages allocated */
	size_t objects_ro;		/**< Total amount of ro objects allocated */
	size_t memory_ro;		/**< Total amount of ro memory allocated */
	size_t chunks_ro;		/**< Total amount of ro chunks still present */
	size_t align_ro;		/**< Space wasted in ro chunks for alignment */
	size_t wasted_ro;		/**< Space wasted at tail of ro chunks */
	size_t zeroed;			/**< Zeroed objects at allocation time */
	size_t in_handler;		/**< Allocations from signal handler */
} ostats;
static spinlock_t ostats_slk = SPINLOCK_INIT;

#define OSTATS_LOCK			spinlock_hidden(&ostats_slk)
#define OSTATS_UNLOCK		spinunlock_hidden(&ostats_slk)

/**
 * First byte beyond a chunk page (following trailing chunk header).
 */
static inline const void * G_CONST
omalloc_chunk_end(const struct ochunk *ck)
{
	return const_ptr_add_offset(ck, OMALLOC_HEADER_SIZE);
}

/**
 * Remaining free space in the chunk (including header).
 */
static inline size_t G_PURE
omalloc_chunk_size(const struct ochunk *ck)
{
	g_assert(ck != NULL);
	g_assert(ptr_cmp(ck->first, ck) <= 0);

	return ptr_diff(omalloc_chunk_end(ck), ck->first);
}

/**
 * Remaining free space in the chunk (including header) after starting
 * pointer has been adjusted for specified alignment.
 */
static inline size_t G_PURE
omalloc_chunk_size_aligned(const struct ochunk *ck, size_t align)
{
	void *first;
	size_t mask, size;

	g_assert(ck != NULL);
	g_assert(ptr_cmp(ck->first, ck) <= 0);
	g_assert(is_pow2(align));

	/*
	 * The system's alignment constraints must be at most as large as the
	 * size of the chunk header we're putting at the end of the page.
	 *
	 * Otherwise, when computing the aligned address at which we need to
	 * allocate, we would run the risk of going beyond the page itself.
	 */

	STATIC_ASSERT(OMALLOC_ALIGNBYTES <= OMALLOC_HEADER_SIZE);

	mask = MIN(align, OMALLOC_ALIGNBYTES) - 1;
	first = ulong_to_pointer((pointer_to_ulong(ck->first) + mask) & ~mask);

	size = ptr_diff(omalloc_chunk_end(ck), first);

	g_assert_log(size_is_non_negative(size),
		"%s(): size=%'zu, ck->first=%p, mask=0x%x, first=%p, end(ck)=%p",
		G_STRFUNC, size, ck->first, (uint) mask, first, omalloc_chunk_end(ck));

	return size;
}

/**
 * Compute index in chunks[] where a chunk of given size needs to be linked.
 */
static size_t G_CONST
omalloc_size_index(size_t size)
{
	size_t r = size;
	size_t i = 0;

	while (r >>= 1)
		i++;

	return i;
}

/**
 * Computes index in chunks[] where a given chunk needs to be linked.
 */
static size_t G_PURE
omalloc_chunk_index(const struct ochunk *ck)
{
	return omalloc_size_index(omalloc_chunk_size(ck));
}

/**
 * Ensure the chunk structure is completely held within the page and is
 * consistent with the page boundaries.
 */
static void
assert_ochunk_valid(const struct ochunk *ck, const void *page,
	const char *caller)
{
	const void *end = const_ptr_add_offset(page, omalloc_pagesize);

	g_assert_log(0 == ptr_cmp(&ck[1], end),
		"%s(): chunk at %p (%zu bytes) not at the tail of page [%p, %p[",
		caller, ck, sizeof *ck, page, end);
	g_assert_log(ptr_cmp(ck->first, page) >= 0 && ptr_cmp(ck->first, end) < 0,
		"%s(): chunk at %p lists first free byte at %p, not on page [%p, %p[",
		caller, ck, ck->first, page, end);
}

/**
 * Make read-only chunk read-write.
 */
static void
omalloc_chunk_unprotect(const struct ochunk *p, enum omalloc_mode mode)
{
	if (OMALLOC_RO == mode) {
		void *start = deconstify_pointer(vmm_page_start(p));

		assert_ochunk_valid(p, start, G_STRFUNC);

		if (-1 == mprotect(start, omalloc_pagesize, PROT_READ | PROT_WRITE)) {
			s_error("mprotect(%p, %zu, PROT_READ | PROT_WRITE) failed: %m",
				start, omalloc_pagesize);
		}
	}
}

/**
 * Make read-only chunk read-only.
 */
static void
omalloc_chunk_protect(const struct ochunk *p, enum omalloc_mode mode)
{
	if (OMALLOC_RO == mode) {
		void *start = deconstify_pointer(vmm_page_start(p));

		assert_ochunk_valid(p, start, G_STRFUNC);

		if (-1 == mprotect(start, omalloc_pagesize, PROT_READ)) {
			s_error("mprotect(%p, %zu, PROT_READ) failed: %m",
				start, omalloc_pagesize);
		}
	}
}

/**
 * Make read-only range read-only.
 */
static void
omalloc_range_protect(const void *p, enum omalloc_mode mode, size_t len)
{
	if (OMALLOC_RO == mode) {
		size_t size = round_pagesize(len);
		void *start = deconstify_pointer(vmm_page_start(p));

		if (-1 == mprotect(start, size, PROT_READ)) {
			s_error("mprotect(%p, %zu, PROT_READ) failed: %m", start, size);
		}
	}
}

/**
 * Follow chunk list and stop as soon as we find a chunk capable of
 * allocating ``size'' bytes aligned on ``align'' bytes boundary.
 *
 * @return chunk address if found, NULL if none.
 */
static struct ochunk *
omalloc_chunk_list_find(struct ochunk *head, size_t size, size_t align)
{
	struct ochunk *ck;

	for (ck = head; ck != NULL; ck = ck->next) {
		if (omalloc_chunk_size_aligned(ck, align) >= size)
			return ck;
	}

	return NULL;
}

/**
 * Get chunk array of corresponding type.
 */
static inline struct ochunk ** G_CONST
omalloc_chunk_array(enum omalloc_mode mode)
{
	switch (mode) {
	case OMALLOC_RW:
		return chunks_rw;
	case OMALLOC_RO:
		return chunks_ro;
	}

	g_assert_not_reached();
}

/**
 * Adjust starting address to make sure we can satisfy the alignment
 * requirements.
 *
 * @return the new chunk size.
 */
static size_t
omalloc_chunk_align(struct ochunk *ck, size_t align, enum omalloc_mode mode)
{
	void *first;
	size_t mask;

	g_assert(ck != NULL);
	g_assert(is_pow2(align));

	mask = MIN(align, OMALLOC_ALIGNBYTES) - 1;
	first = ulong_to_pointer((pointer_to_ulong(ck->first) + mask) & ~mask);

	if (first != ck->first) {
		OSTATS_LOCK;
		if (OMALLOC_RW == mode)
			ostats.align_rw += ptr_diff(first, ck->first);
		else
			ostats.align_ro += ptr_diff(first, ck->first);
		OSTATS_UNLOCK;
		ck->first = first;
	}

	/*
	 * Caller can no longer call omalloc_chunk_size() because ck->first
	 * could be gone past the value of `ck' due to the above possible
	 * adjustment.  Hence we return the new chunk size as a convenience.
	 */

	return ptr_diff(omalloc_chunk_end(ck), ck->first);
}

/**
 * Find a chunk capable of allocating ``size'' bytes (rounded up to fit
 * memory alignment concerns), using ``mode'' type memory.
 *
 * @return chunk address if found, NULL if none.
 */
static struct ochunk *
omalloc_chunk_find(size_t size, size_t align, enum omalloc_mode mode)
{
	struct ochunk **chunks;
	size_t i;

	/*
	 * Chunk fragments are, by design, smaller than a page size, hence
	 * we can't find anything larger in them.
	 */

	if (size >= omalloc_pagesize)
		return NULL;

	/*
	 * Say we try to allocate 14 bytes, we'll get i = 3.
	 *
	 * In the chunks[] array, chunks[i] defines a list of chunks capable of
	 * holding at least 2^i bytes.
	 *
	 * In chunks[3] we have therefore chunks capable of holding between 8
	 * and 15 bytes (at 16 bytes, the chunk will be listed in chunks[4]).
	 * There is no guarantee we'll find a suitable chunk in chunks[3].
	 *
	 * However, as soon as we move to bigger entries in the array, the first
	 * chunk listed will be a match.
	 */

	chunks = omalloc_chunk_array(mode);

	for (i = omalloc_size_index(size); i < OMALLOC_CHUNK_COUNT; i++) {
		struct ochunk *ck;

		if (NULL != (ck = omalloc_chunk_list_find(chunks[i], size, align)))
			return ck;
	}

	return NULL;
}

/**
 * Link back chunk into the chunks[] array.
 */
static void
omalloc_chunk_link(struct ochunk *ck, enum omalloc_mode mode)
{
	struct ochunk **chunks;
	size_t i;

	g_assert(ck != NULL);
	g_assert(ptr_cmp(ck->first, ck) <= 0);	/* Or page would be exhausted */

	/*
	 * Contrary to omalloc_chunk_unlink(), the chunk structure is up-to-date
	 * and ck->first really points to the next free location.  As such, we
	 * can use omalloc_chunk_index() which will compute the size of the chunk
	 * by itself.
	 */

	i = omalloc_chunk_index(ck);
	chunks = omalloc_chunk_array(mode);

	/*
	 * Insert as new head.
	 */

	g_assert(i < OMALLOC_CHUNK_COUNT);

	if (NULL == chunks[i]) {
		chunks[i] = ck;
		ck->prev = ck->next = NULL;
	} else {
		struct ochunk *oldhead = chunks[i];

		g_assert(NULL == oldhead->prev);

		chunks[i] = ck;
		ck->prev = NULL;
		ck->next = oldhead;
		omalloc_chunk_unprotect(oldhead, mode);
		oldhead->prev = ck;
		omalloc_chunk_protect(oldhead, mode);
	}
}

/**
 * Unlink chunk from the proper chunks[] array.
 */
static void
omalloc_chunk_unlink(struct ochunk *ck, enum omalloc_mode mode, size_t size)
{
	struct ochunk **chunks;

	g_assert(ck != NULL);

	chunks = omalloc_chunk_array(mode);

	/*
	 * The chunk size is given as argument and cannot be computed through
	 * omalloc_chunk_size() at this point because the allocation routine
	 * may have already adjusted ck->first for alignment purposes.
	 *		--RAM, 2015-10-06
	 */

	if (NULL == ck->prev) {
		/* Was head of list */
		size_t i = omalloc_size_index(size);

		g_assert(i < OMALLOC_CHUNK_COUNT);
		g_assert(chunks[i] == ck);

		chunks[i] = ck->next;
	} else {
		omalloc_chunk_unprotect(ck->prev, mode);
		ck->prev->next = ck->next;
		omalloc_chunk_protect(ck->prev, mode);
	}

	if (ck->next != NULL) {
		omalloc_chunk_unprotect(ck->next, mode);
		ck->next->prev = ck->prev;
		omalloc_chunk_protect(ck->next, mode);
	}

	ck->prev = NULL;
	ck->next = NULL;
}

/**
 * Allocate ``size'' bytes (already rounded up to fit memory alignment
 * constraints) from the specified chunk.
 *
 * If chunk was read-only, it is made read-write upon return (so that any
 * initialization of the allocated block can be made).
 *
 * @return pointer to allocated memory.
 */
static void *
omalloc_chunk_allocate_from(struct ochunk *ck,
	size_t size, size_t align, enum omalloc_mode mode)
{
	size_t used, osize, csize;
	void *first = ck->first;
	void *p;

	/*
	 * Make sure that the size of the chunk header is a multiple of the
	 * memory alignment requirements for the platform.  Otherwise, the
	 * Configure script computed an invalid value for MEM_ALIGNBYTES.
	 */

	STATIC_ASSERT(IS_POWER_OF_2(MEM_ALIGNBYTES)); /* redundant */

	g_assert(ck != NULL);
	g_assert(size_is_positive(size));
	g_assert(omalloc_chunk_size(ck) >= size);

	osize = omalloc_chunk_size(ck);				/* Before possible alignment */
	omalloc_chunk_unprotect(ck, mode);			/* Chunk now read-write */
	csize = omalloc_chunk_align(ck, align, mode);
	p = ck->first;

	/*
	 * This has to hold or we would not have selected that chunk for allocation.
	 */

	g_assert(csize >= size);	/* After possible alignment */

	/*
	 * See whether this is going to be the last block allocated from
	 * this chunk of memory.
	 */

	if (csize - size >= OMALLOC_HEADER_SIZE) {
		struct ochunk **chunks;
		size_t i, j;

		/*
		 * We have enough space in the chunk to allocate more memory.
		 * Move the chunk free pointer ahead and relink with any next/prev.
		 */

		i = omalloc_size_index(osize);	/* Old chunk index, before alignment */
		ck->first = ptr_add_offset(ck->first, size);
		used = ptr_diff(ck->first, first);

		g_assert(ptr_cmp(ck->first, ck) <= 0);
		g_assert(omalloc_chunk_size(ck) >= OMALLOC_HEADER_SIZE);

		j = omalloc_chunk_index(ck);	/* New chunk index */

		g_assert(i < OMALLOC_CHUNK_COUNT);
		g_assert(j < OMALLOC_CHUNK_COUNT);
		g_assert(j <= i);

		chunks = omalloc_chunk_array(mode);

		if (i != j) {
			/*
			 * Chunk moving lists, needs to be unlinked from previous list
			 * and inserted into its new one.
			 */

			if (NULL == ck->prev) {
				/* Was head of list */
				g_assert(chunks[i] == ck);
				chunks[i] = ck->next;
			} else {
				omalloc_chunk_unprotect(ck->prev, mode);
				ck->prev->next = ck->next;
				omalloc_chunk_protect(ck->prev, mode);
			}
			if (ck->next != NULL) {
				omalloc_chunk_unprotect(ck->next, mode);
				ck->next->prev = ck->prev;
				omalloc_chunk_protect(ck->next, mode);
			}
			omalloc_chunk_link(ck, mode);
		}
	} else {
		/*
		 * This is the last block we'll allocate from this chunk.
		 * Once we return, this chunk will no longer be listed in chunks[].
		 */

		omalloc_chunk_unlink(ck, mode, osize);
		used = ptr_diff(omalloc_chunk_end(ck), first);

		OSTATS_LOCK;
		if (OMALLOC_RW == mode) {
			ostats.chunks_rw--;
		} else {
			ostats.chunks_ro--;
		}
		OSTATS_UNLOCK;

		if (omalloc_debug > 2) {
			s_debug("OMALLOC dissolving chunk header on %zu-byte allocation",
				size);
			if (csize != size) {
				s_debug("OMALLOC %zu trailing bytes lost", csize - size);
				OSTATS_LOCK;
				if (OMALLOC_RW == mode) {
					ostats.wasted_rw += csize - size;
				} else {
					ostats.wasted_ro += csize - size;
				}
				OSTATS_UNLOCK;
			}
		}
	}

	OSTATS_LOCK;
	if (OMALLOC_RW == mode) {
		ostats.memory_rw += used;
	} else {
		ostats.memory_ro += used;
	}
	OSTATS_UNLOCK;

	return p;
}

/**
 * Allocate ``size'' bytes of memory that will never be freed.
 * If memory cannot be allocated, it is a fatal error.
 *
 * @param size		amount of memory to allocate
 * @param align		alignment required for memory being allocated
 * @param mode		whether memory is read-only or read-write
 * @param init		if non-NULL, initialization data to copy (size bytes)
 *
 * @return pointer to allocated memory.
 */
static void *
omalloc_allocate(size_t size, size_t align, enum omalloc_mode mode,
	const void *init)
{
	struct ochunk *ck;
	void *p;
	size_t allocated;
	static spinlock_t omalloc_slk = SPINLOCK_INIT;

	g_assert(size_is_positive(size));

	if G_UNLIKELY(0 == omalloc_pagesize) {
		omalloc_pagesize = compat_pagesize();
		g_assert(0 != omalloc_pagesize);
	}

	/*
	 * Loudly warn if called from a signal handler.
	 */

	if (signal_in_unsafe_handler()) {
		ATOMIC_INC(&ostats.in_handler);
		s_minicarp_once("%s(): %s allocating %zu bytes (%s) "
			"from signal handler",
			G_STRFUNC, thread_safe_name(),
			size, OMALLOC_RW == mode ? "rw" : "ro");
	}

	/*
	 * This routine is fast and used infrequently enough to justify a
	 * coarse-grained multi-threading protection via a global spinlock.
	 *
	 * Since the memory is allocated once and never freed, it is also important
	 * to funnel all the core allocation decisions to avoid extra allocations.
	 *
	 * This is the sole entry point for all omalloc()-based operations since
	 * there is no reallocation nor freeing.
	 */

	spinlock(&omalloc_slk);

	OSTATS_LOCK;
	if (OMALLOC_RW == mode) {
		ostats.objects_rw++;
	} else {
		ostats.objects_ro++;
	}
	OSTATS_UNLOCK;

	/*
	 * First try to allocate memory from fragments held in chunks[].
	 */

	ck = omalloc_chunk_find(size, align, mode);
	if (ck != NULL) {
		p = omalloc_chunk_allocate_from(ck, size, align, mode);
		goto done;
	}

	/*
	 * Request new "core" memory.
	 *
	 * We need to relinquish the spinlock because the VMM layer can recurse
	 * to omalloc() through lock recording in the thread-private structures.
	 * It's OK since we're not in a critical section at this stage and do not
	 * need to hold the lock.
	 */

	spinunlock(&omalloc_slk);

	p = vmm_core_alloc(size);
	allocated = round_pagesize(size);

	if (omalloc_debug > 2) {
		size_t pages = allocated / omalloc_pagesize;
		size_t count = OMALLOC_RW == mode ?
			ostats.objects_rw : ostats.objects_ro;
		s_debug("OMALLOC allocated %zu page%s (%zu total for %zu %s object%s)",
			pages, plural(pages),
			OMALLOC_RW == mode ? ostats.pages_rw : ostats.pages_ro,
			count, OMALLOC_RW == mode ? "read-write" : "read-only",
			plural(count));
	}

	OSTATS_LOCK;
	if (OMALLOC_RW == mode) {
		ostats.pages_rw += allocated / omalloc_pagesize;
	} else {
		ostats.pages_ro += allocated / omalloc_pagesize;
	}
	OSTATS_UNLOCK;

	/*
	 * Now that we need to possibly manipulate omalloc() internal chunk list,
	 * re-grab the lock.
	 */

	spinlock(&omalloc_slk);

	/*
	 * If we have enough memory at the tail to create a new chunk, do so.
	 *
	 * We may be able later to allocate other objects in that page fragment,
	 * and even if we can't, we do not lose any memory since this is allocated
	 * space already.
	 */

	if (allocated - size >= OMALLOC_HEADER_SIZE) {
		void *end = ptr_add_offset(p, allocated);
		ck = ptr_add_offset(end, -OMALLOC_HEADER_SIZE);
		ck->first = ptr_add_offset(p, size);
		omalloc_chunk_link(ck, mode);

		OSTATS_LOCK;
		if (OMALLOC_RW == mode) {
			ostats.chunks_rw++;
			ostats.memory_rw += size;
		} else {
			ostats.chunks_ro++;
			ostats.memory_ro += size;
		}
		OSTATS_UNLOCK;

		if (omalloc_debug > 2) {
			size_t count = OMALLOC_RW == mode ?
				ostats.chunks_rw : ostats.chunks_ro;
			s_debug("OMALLOC adding %zu byte-long chunk (%zu %s chunk%s total)",
				omalloc_chunk_size(ck),
				count, OMALLOC_RW == mode ? "read-write" : "read-only",
				plural(count));
		}
	} else {
		/*
		 * There is not enough room at the tail of the allocated memory
		 * to create a chunk.
		 */

		OSTATS_LOCK;
		if (OMALLOC_RW == mode) {
			ostats.memory_rw += allocated;
		} else {
			ostats.memory_ro += allocated;
		}
		OSTATS_UNLOCK;

		if (allocated != size) {
			if (omalloc_debug > 2) {
				s_debug("OMALLOC %zu trailing bytes lost on "
					"%zu-byte allocation", allocated - size, size);
			}
			OSTATS_LOCK;
			if (OMALLOC_RW == mode) {
				ostats.wasted_rw += allocated - size;
			} else {
				ostats.wasted_ro += allocated - size;
			}
			OSTATS_UNLOCK;
		}
	}

done:
	/*
	 * Must initialize the object from a read-only chunk before releasing
	 * the spinlock, since we must make sure no other thread is going to
	 * change the protection of the chunk: we need it writable at this stage,
	 * and a concurrent allocation from another thread could have time to reset
	 * it read-only before the memcpy() below can be done, causing a fault.
	 */

	if (OMALLOC_RW == mode)
		spinunlock(&omalloc_slk);

	if (init != NULL)
		memcpy(p, init, size);

	/*
	 * The following protects back to read-only the whole chunk in which the
	 * pointer was taken from, or the whole region allocated above if the
	 * requested size was larger than a page size.
	 */

	omalloc_range_protect(p, mode, size);

	if (OMALLOC_RO == mode)
		spinunlock(&omalloc_slk);

	return p;
}

/**
 * Allocate ``size'' bytes of memory that will never be freed.
 * If memory cannot be allocated, it is a fatal error.
 *
 * @return pointer to allocated memory.
 */
void *
omalloc(size_t size)
{
	return omalloc_allocate(size, MEM_ALIGNBYTES, OMALLOC_RW, NULL);
}

/**
 * Allocate ``size'' bytes of memory that will never be freed.
 * If memory cannot be allocated, it is a fatal error.
 * Allocated memory is zero'ed before being returned.
 *
 * @return pointer to allocated zero-ed memory.
 */
void *
omalloc0(size_t size)
{
	void *p;

	p = omalloc_allocate(size, MEM_ALIGNBYTES, OMALLOC_RW, NULL);
	memset(p, 0, size);

	OSTATS_LOCK;
	ostats.zeroed++;
	OSTATS_UNLOCK;

	return p;
}

/**
 * Allocate a permanent copy of supplied string (which may be NULL).
 *
 * @return a pointer to the new string, or NULL if argument was NULL.
 */
char *
ostrdup(const char *str)
{
	if (NULL == str)
		return NULL;

	return omalloc_allocate(1 + strlen(str), 1, OMALLOC_RW, str);
}

/**
 * Allocate a permanent copy of supplied string (which may be NULL) or
 * the first 'n' characters, whichever is smaller.
 *
 * @return a pointer to the new string, or NULL if argument was NULL.
 */
char *
ostrndup(const char *str, size_t n)
{
	size_t len;
	char *res;

	if (NULL == str)
		return NULL;

	len = clamp_strlen(str, n);
	res = omalloc_allocate(1 + len, 1, OMALLOC_RW, str);
	res[len] = '\0';

	return res;
}

/**
 * Allocate a permanent read-only copy of the data pointed at.
 *
 * @return pointer to allocated copy.
 */
const void *
ocopy_readonly(const void *p, size_t size)
{
	g_assert(p != NULL);
	g_assert(size_is_non_negative(size));

	return omalloc_allocate(size, MEM_ALIGNBYTES, OMALLOC_RO, p);
}

/**
 * Allocate a permanent read-only copy of supplied string (which may be NULL).
 *
 * @return a pointer to the new string, or NULL if argument was NULL.
 */
const char *
ostrdup_readonly(const char *str)
{
	if (NULL == str)
		return NULL;

	return omalloc_allocate(1 + strlen(str), 1, OMALLOC_RO, str);
}

/**
 * Allocate a permanent read-only copy of supplied string (which may be NULL)
 * or the first 'n' characters, whichever is smaller.
 *
 * @return a pointer to the new string, or NULL if argument was NULL.
 */
const char *
ostrndup_readonly(const char *str, size_t n)
{
	size_t len;

	if (NULL == str)
		return NULL;

	len = clamp_strlen(str, n);

	if ('\0' == str[len]) {
		return ostrdup_readonly(str);
	} else {
		char *tmp;
		const char *res;

		tmp = xcopy(str, len + 1);
		tmp[len] = '\0';
		res = omalloc_allocate(1 + len, 1, OMALLOC_RO, tmp);
		xfree(tmp);

		return res;
	}
}

/**
 * Report on the number of pages allocated.
 * Since the memory allocated here is never freed, these pages are not leaks.
 */
size_t
omalloc_page_count(void)
{
	size_t n;

	OSTATS_LOCK;
	n = ostats.pages_rw + ostats.pages_ro;
	OSTATS_UNLOCK;

	return n;
}

/**
 * Set debug level.
 */
void
set_omalloc_debug(uint32 level)
{
	omalloc_debug = level;
}

/**
 * Final shutdown.
 */
void G_COLD
omalloc_close(void)
{
	/*
	 * We can't free anything since we don't track allocated memory.
	 * Just log what we did during this run.
	 */

	if (omalloc_debug) {
		s_debug("omalloc() allocated %zu read-write object%s "
			"spread on %zu page%s",
			ostats.objects_rw, plural(ostats.objects_rw),
			ostats.pages_rw, plural(ostats.pages_rw));
		s_debug("omalloc() allocated %s read-write, "
			"%zu partial page%s remain%s",
			short_size(ostats.memory_rw, FALSE),
			ostats.chunks_rw, plural(ostats.chunks_rw),
			plural(ostats.chunks_rw));
		s_debug("omalloc() allocated %zu read-only object%s "
			"spread on %zu page%s",
			ostats.objects_ro, plural(ostats.objects_ro),
			ostats.pages_ro, plural(ostats.pages_ro));
		s_debug("omalloc() allocated %s read-only, "
			"%zu partial page%s remain%s",
			short_size(ostats.memory_ro, FALSE),
			ostats.chunks_ro, plural(ostats.chunks_ro),
			plural(ostats.chunks_ro));
	}
}

/**
 * Dump omalloc() statistics for run-time inspection.
 */
void G_COLD
omalloc_dump_stats_log(logagent_t *la, unsigned options)
{
	struct ostats stats;
	size_t pages, objects, memory, chunks, align, wasted;
	bool groupped = booleanize(options & DUMP_OPT_PRETTY);

#define DUMP(x) log_info(la, "OMALLOC %s = %s", #x,	\
	size_t_to_string_grp(stats.x, groupped))

#define DUMP_VAR(x) log_info(la, "OMALLOC %s = %s", #x,	\
	size_t_to_string_grp(x, groupped))

#define CONSOLIDATE(x)		x = stats.x##_rw + stats.x##_ro

	OSTATS_LOCK;
	stats = ostats;			/* struct copy under lock protection */
	OSTATS_UNLOCK;

	CONSOLIDATE(pages);
	CONSOLIDATE(objects);
	CONSOLIDATE(memory);
	CONSOLIDATE(chunks);
	CONSOLIDATE(align);
	CONSOLIDATE(wasted);

	DUMP(pages_rw);
	DUMP(objects_rw);
	DUMP(memory_rw);
	DUMP(chunks_rw);
	DUMP(align_rw);
	DUMP(wasted_rw);
	DUMP(pages_ro);
	DUMP(objects_ro);
	DUMP(memory_ro);
	DUMP(chunks_ro);
	DUMP(align_ro);
	DUMP(wasted_ro);
	DUMP_VAR(pages);
	DUMP_VAR(objects);
	DUMP_VAR(memory);
	DUMP_VAR(chunks);
	DUMP_VAR(align);
	DUMP_VAR(wasted);
	DUMP(zeroed);
	DUMP(in_handler);

#undef DUMP
#undef DUMP_VAR
#undef CONSOLIDATE
}

/* vi: set ts=4 sw=4 cindent:  */
