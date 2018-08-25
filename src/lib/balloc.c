/*
 * Copyright (c) 2016 Raphael Manfredi
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
 * Buffer-based allocator.
 *
 * This is a thread-safe buffer-based allocator that will allocate blocks
 * of equal size from a fixed pre-allocated buffer that cannot be extended.
 * The maximum size of items that can be allocated is 2^32 bytes.
 *
 * We use a zone allocator alogorithm to allocate the fix sized blocks within
 * the arena at our disposal.
 *
 * It is meant to be used in low-level routines where one cannot assume that
 * we have any properly initialized general-purpose allocator available, and
 * yet there is a need to dynamically allocate and free memory.
 *
 * It uses its own low-level locks to be completely independent and minimize
 * the memory footprint of the allocator descriptor.
 *
 * @author Raphael Manfredi
 * @date 2016
 */

#include "common.h"

#include "balloc.h"

#include "atomic.h"

#include "override.h"		/* Must be the last header included */

#define BALLOC_ALIGNBYTES	MEM_ALIGNBYTES
#define BALLOC_MASK			(BALLOC_ALIGNBYTES - 1)

#define balloc_round(x) 	(((ulong) (x) + BALLOC_MASK) & ~BALLOC_MASK)

enum balloc_magic { BALLOC_MAGIC = 0x4b6a2215 };

/**
 * The buffer-based allocator descriptor.
 *
 * This structure lies at the beginning of the buffer we're allocating from
 * and is therefore stolen from the available memory.  It is therefore kept
 * to a minimum size.
 */
typedef struct balloc {
	enum balloc_magic magic;		/**< Magic number */
	atomic_lock_t lock;				/**< Concurrency lock */
	void *avail;					/**< Next available block, NULL if full */
} balloc_t;

static inline void
balloc_check(const balloc_t * const b)
{
	g_assert(b != NULL);
	g_assert(BALLOC_MAGIC == b->magic);
}

/**
 * Cram a new zone in chunk.
 *
 * @param b			the buffer allocator descriptor
 * @param size		the size of each block we allocate
 * @param buflen	the total size of the buffer
 */
static void
balloc_cram(balloc_t *b, size_t size, size_t buflen)
{
	void *start = ulong_to_pointer(balloc_round(ptr_add_offset(b, sizeof *b)));
	void *end = ptr_add_offset(b, buflen);
	void *next = NULL;

	balloc_check(b);
	g_assert_log((ulong) end == balloc_round(end),
		"%s(): buffer length %zu is not properly aligned or base %p is weird",
		G_STRFUNC, buflen, b);

	/*
	 * We can't assume we have enough room between "start" and "end" to
	 * cram an even amount blocks of "size" bytes each.  Hence we start from
	 * the end of the zone and stop as soon as the beginning of the block
	 * would lie before "start".
	 */

	for (;;) {
		void *block = ptr_add_offset(end, -size);

		if G_UNLIKELY(ptr_cmp(block, start) < 0)
			break;

		*(void **) block = next;	/* Free block points to next free one */
		next = end = block;
	}

	b->avail = next;		/* First free block in zone */
}

/**
 * Initialize buffer to be suitable for allocating blocks of "size" bytes.
 *
 * @param size		size of blocks to allocate
 * @param base		buffer base
 * @param length	buffer length
 */
void
balloc_init(uint32 size, void *base, size_t length)
{
	balloc_t *b = base;

	ZERO(b);
	b->magic = BALLOC_MAGIC;

	balloc_cram(b, balloc_round(size), length);

	if (NULL == b->avail) {
		s_error("%s(): buffer %p of %zu bytes too small for %u-byte blocks",
			G_STRFUNC, base, length, size);
	}
}

/**
 * Lock buffer allocator descriptor.
 */
static void
balloc_lock(balloc_t *b)
{
	balloc_check(b);

	while (!atomic_acquire(&b->lock))
		/* empty */;
}

/**
 * Unlock buffer allocator descriptor.
 */
static void
balloc_unlock(balloc_t *b)
{
	balloc_check(b);
	g_assert(0 != b->lock);		/* Must be locked already */

	atomic_release(&b->lock);
}

/**
 * Check whether buffer appears to be initialized for allocations.
 */
bool
balloc_is_initialized(const void *base)
{
	const balloc_t *b = base;

	g_assert(base != NULL);

	return BALLOC_MAGIC == b->magic;
}

/**
 * Allocate a new block from an initialized buffer.
 *
 * @param base		buffer base
 *
 * @return newly allocated block address.
 */
void *
balloc_alloc(void *base)
{
	balloc_t *b = base;
	void *blk;

	balloc_check(b);

	balloc_lock(b);

	/* Allocated block is the head of free list */

	blk = b->avail;
	if G_LIKELY(blk != NULL)
		b->avail = *(void **) blk;

	balloc_unlock(b);

	if G_UNLIKELY(NULL == blk)
		s_error("%s(): no more free blocks in buffer %p", G_STRFUNC, base);

	return blk;
}

/**
 * Free block allocated via balloc_alloc().
 *
 * @param base		buffer base
 * @param p			allocated block address
 */
void
balloc_free(void *base, void *p)
{
	balloc_t *b = base;

	balloc_check(b);

	balloc_lock(b);

	/* Put back free block at head of free list */

	*(void **) p = b->avail;
	b->avail = p;

	balloc_unlock(b);
}

/* vi: set ts=4 sw=4 cindent: */
