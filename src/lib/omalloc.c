/*
 * $Id$
 *
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
 * objects one after the other until we can no longer fit an object, at which
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
 * this is the lowest granularity we have when allocating pages and it does
 * prevent us from efficiently allocating smaller objects out of remaining
 * fragments.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"		/* For RCSID */

RCSID("$Id$")

#include "omalloc.h"
#include "misc.h"
#include "pow2.h"
#include "unsigned.h"
#include "vmm.h"

#include "override.h"	/* Must be the last header included */

/**
 * Memory alignment constraints.
 */
#define OMALLOC_ALIGNBYTES	MEM_ALIGNBYTES
#define OMALLOC_MASK		(OMALLOC_ALIGNBYTES - 1)
#define omalloc_round(s) \
	((gulong) (((gulong) (s) + OMALLOC_MASK) & ~OMALLOC_MASK))

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
 * The header marks the beginning of the free space in the chunk.
 *
 * As more objects are allocated, the header slides down until it reaches
 * the tail of the allocated chunk, at which time it will probably dissolve
 * itself to provide room for one last allocation of a small object.
 */
struct ochunk {
	struct ochunk *next;	/* Linking in chunk "free list" */
	struct ochunk *prev;
	void *end;				/* End of physical chunk (first byte beyond) */
};

#define OMALLOC_HEADER_SIZE	(sizeof(struct ochunk))

static guint32 omalloc_debug;

/**
 * Array of chunks with free space.
 *
 * An entry at index ``i'' guarantees at least 2^i free bytes in the chunk,
 * including the chunk header.
 */
static struct ochunk *chunks[OMALLOC_CHUNK_BITS + 1];

/**
 * Internal statistics.
 */
static struct {
	size_t pages;			/**< Total amount of pages allocated */
	size_t objects;			/**< Total amount of objects allocated */
	size_t memory;			/**< Total amount of memory allocated */
	size_t chunks;			/**< Total amount of chunks still present */
} stats;

/**
 * Remaining free space in the chunk (including header).
 */
static inline size_t
omalloc_chunk_size(const struct ochunk *ck)
{
	g_assert(ck != NULL);
	return ptr_diff(ck->end, ck);
}

/**
 * Compute index in chunks[] where a chunk of given size needs to be linked.
 */
static size_t
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
static size_t
omalloc_chunk_index(const struct ochunk *ck)
{
	return omalloc_size_index(omalloc_chunk_size(ck));
}

/**
 * Follow chunk list and stop as soon as we find a chunk capable of
 * allocating ``size'' bytes.
 *
 * @return chunk address if found, NULL if none.
 */
static struct ochunk *
omalloc_chunk_list_find(struct ochunk *head, size_t size)
{
	struct ochunk *ck;

	for (ck = head; ck != NULL; ck = ck->next) {
		if (omalloc_chunk_size(ck) >= size)
			return ck;
	}

	return NULL;
}

/**
 * Find a chunk capable of allocating ``size'' bytes (rounded up to fit
 * memory alignment concerns).
 *
 * @return chunk address if found, NULL if none.
 */
static struct ochunk *
omalloc_chunk_find(size_t size)
{
	size_t i;

	g_assert(size == omalloc_round(size));		/* Already rounded */

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

	for (i = omalloc_size_index(size); i < G_N_ELEMENTS(chunks); i++) {
		struct ochunk *ck;

		if (NULL != (ck = omalloc_chunk_list_find(chunks[i], size)))
			return ck;
	}

	return NULL;
}

/**
 * Link back chunk into the chunks[] array.
 */
static void
omalloc_chunk_link(struct ochunk *ck)
{
	size_t i;

	g_assert(ck != NULL);

	i = omalloc_chunk_index(ck);

	/*
	 * Insert as new head.
	 */

	g_assert(i < G_N_ELEMENTS(chunks));

	if (NULL == chunks[i]) {
		chunks[i] = ck;
		ck->prev = ck->next = NULL;
	} else {
		struct ochunk *oldhead = chunks[i];

		g_assert(NULL == oldhead->prev);

		chunks[i] = ck;
		ck->prev = NULL;
		ck->next = oldhead;
		oldhead->prev = ck;
	}
}

/**
 * Unlink chunk from the chunks[] array.
 */
static void
omalloc_chunk_unlink(struct ochunk *ck)
{
	g_assert(ck != NULL);

	if (NULL == ck->prev) {
		/* Was head of list */
		size_t i = omalloc_chunk_index(ck);

		g_assert(i < G_N_ELEMENTS(chunks));
		g_assert(chunks[i] == ck);

		chunks[i] = ck->next;
	} else {
		ck->prev->next = ck->next;
		ck->prev = NULL;
	}

	if (ck->next != NULL) {
		ck->next->prev = ck->prev;
		ck->next = NULL;
	}
}

/**
 * Allocate ``size'' bytes (already rounded up to fit memory alignment
 * constraints) from the specified chunk.
 *
 * @return pointer to allocated memory.
 */
static void *
omalloc_chunk_allocate_from(struct ochunk *ck, size_t size)
{
	size_t csize;
	void *p = ck;

	/*
	 * Make sure that the size of the chunk header is a multiple of the
	 * memory alignment requirements for the platform.  Otherwise, the
	 * Configure script computed an invalid value for MEM_ALIGNBYTES.
	 */

	STATIC_ASSERT(IS_POWER_OF_2(MEM_ALIGNBYTES)); /* redundant */
	/** FIXME: BUG, does not compile on common 64-bit machines */
	//STATIC_ASSERT(omalloc_round(OMALLOC_HEADER_SIZE) == OMALLOC_HEADER_SIZE);

	g_assert(ck != NULL);
	g_assert(size_is_positive(size));
	g_assert(omalloc_chunk_size(ck) >= size);
	g_assert(size == omalloc_round(size));		/* Already rounded */

	csize = omalloc_chunk_size(ck);

	/*
	 * See whether this is going to be the last block allocated from
	 * this chunk of memory.
	 */

	if (csize - size >= OMALLOC_HEADER_SIZE) {
		struct ochunk *nck;
		size_t i;
		size_t j;

		/*
		 * We have enough space in the chunk to allocate more memory.
		 * Move the chunk pointer ahead and relink with any next/prev.
		 */

		nck = ptr_add_offset(ck, size);

		g_assert(ptr_diff(ck->end, nck) >= OMALLOC_HEADER_SIZE);

		i = omalloc_chunk_index(ck);	/* Old chunk index */
		memmove(nck, ck, sizeof *ck);	/* Move ahead */
		j = omalloc_chunk_index(nck);	/* New chunk index */

		g_assert(i < G_N_ELEMENTS(chunks));
		g_assert(j < G_N_ELEMENTS(chunks));
		g_assert(j <= i);

		if (i != j) {
			/*
			 * Chunk moving lists, needs to be unlinked from previous list
			 * and inserted in its new one.
			 */

			if (NULL == nck->prev) {
				/* Was head of list */
				g_assert(chunks[i] == ck);	/* ``ck'' is old chunk's start */
				chunks[i] = nck->next;
			} else {
				nck->prev->next = nck->next;
			}
			if (nck->next != NULL) {
				nck->next->prev = nck->prev;
			}
			omalloc_chunk_link(nck);
		} else {
			/*
			 * Chunk stays in same list, update pointers from neighbours.
			 */

			if (NULL == nck->prev) {
				/* Was head of list */
				g_assert(chunks[i] == ck);
				chunks[i] = nck;			/* Chunk's start was moved */
			} else {
				nck->prev->next = nck;
			}

			if (nck->next != NULL) {
				nck->next->prev = nck;
			}
		}
	} else {
		/*
		 * This is the last block we'll allocate from this chunk.
		 * Once we return, this chunk will no longer be listed in chunks[].
		 */

		omalloc_chunk_unlink(ck);
		stats.chunks--;

		if (omalloc_debug > 2) {
			g_message("OMALLOC dissolving chunk header on %lu-byte allocation",
				(unsigned long) size);
			if (csize != size) {
				g_message("OMALLOC %lu trailing bytes lost",
					(unsigned long) (csize - size));
			}
		}
	}

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
	size_t rounded;
	struct ochunk *ck;
	void *result;
	size_t allocated;

	g_assert(size_is_positive(size));

	rounded = omalloc_round(size);		/* Alignment requirements */
	stats.memory += rounded;
	stats.objects++;
	g_assert(rounded >= size);

	/*
	 * First try to allocate memory from fragments held in chunks[].
	 */

	ck = omalloc_chunk_find(rounded);
	if (ck != NULL)
		return omalloc_chunk_allocate_from(ck, rounded);

	/*
	 * Request new memory.
	 */

	result = vmm_alloc(rounded);
	allocated = round_pagesize(rounded);

	if (omalloc_debug > 2) {
		size_t pages = allocated / compat_pagesize();
		g_message("OMALLOC allocated %lu page%s (%lu total for %lu object%s)",
			(unsigned long) pages, 1 == pages ? "" : "s",
			(unsigned long) stats.pages, (unsigned long) stats.objects,
			1 == stats.objects ? "" : "s");
	}

	stats.pages += allocated / compat_pagesize();

	/*
	 * If we have enough memory at the tail to create a new chunk, do so.
	 *
	 * We may be able later to allocate other objects in that page fragment,
	 * and even if we can't, we do not lose any memory since this is allocated
	 * space already.
	 */

	if (allocated - rounded >= OMALLOC_HEADER_SIZE) {
		ck = ptr_add_offset(result, rounded);
		ck->end = ptr_add_offset(result, allocated);
		omalloc_chunk_link(ck);
		stats.chunks++;

		if (omalloc_debug > 2) {
			g_message("OMALLOC adding %lu byte-long chunk (%lu chunk%s total)",
				(unsigned long) omalloc_chunk_size(ck),
				(unsigned long) stats.chunks, 1 == stats.chunks ? "" : "s");
		}
	} else if (allocated != rounded) {
		if (omalloc_debug > 2) {
			g_message("OMALLOC %lu trailing bytes lost on %lu-byte allocation",
				(unsigned long) (allocated - rounded),
				(unsigned long) rounded);
		}
	}

	return result;
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

	p = omalloc(size);
	memset(p, 0, size);

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
	size_t len;
	char *p;

	if (NULL == str)
		return NULL;

	len = strlen(str);
	p = omalloc(len + 1);
	memcpy(p, str, len + 1);	/* Include trailing NUL in copy */

	return p;
}

/**
 * Report on the number of pages allocated.
 * Since the memory allocated here is never freed, these pages are not leaks.
 */
size_t
omalloc_page_count(void)
{
	return stats.pages;
}

/**
 * Set debug level.
 */
void
set_omalloc_debug(guint32 level)
{
	omalloc_debug = level;
}

/**
 * Final shutdown.
 */
void
omalloc_close(void)
{
	/*
	 * We can't free anything since we don't track allocated memory.
	 * Just log what we did during this run.
	 */

	if (omalloc_debug) {
		g_message("omalloc() allocated %lu object%s spread on %lu page%s",
			(unsigned long) stats.objects, 1 == stats.objects ? "" : "s",
			(unsigned long) stats.pages, 1 == stats.pages ? "" : "s");
		g_message("omalloc() allocated %s, %lu partial page%s remain%s",
			short_size(stats.memory, FALSE),
			(unsigned long) stats.chunks, 1 == stats.chunks ? "" : "s",
			1 == stats.chunks ? "s" : "");
	}
}

/* vi: set ts=4 sw=4 cindent:  */
