/*
 * $Id$
 *
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
 * Memory allocator for objects that are allocated once out of an existing
 * chunk and cannot be individually freed, but altogether with every other
 * object allocated in the chunk.
 *
 * This allocator is meant to be used in situations where traditional memory
 * allocation cannot work, and is safe to use in signal handlers.  As a result,
 * its performance is rather low and it will return NULL if allocation fails,
 * since it will never extend its data structures.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"		/* For RCSID */

RCSID("$Id$")

#include "ckalloc.h"
#include "signal.h"
#include "unsigned.h"
#include "vmm.h"

#include "override.h"	/* Must be the last header included */

/**
 * Memory alignment constraints.
 */
#define CKALLOC_ALIGNBYTES	MEM_ALIGNBYTES
#define CKALLOC_MASK		(CKALLOC_ALIGNBYTES - 1)
#define ckalloc_round(s) \
	((gulong) (((gulong) (s) + CKALLOC_MASK) & ~CKALLOC_MASK))

enum ckhunk_magic { CKHUNK_MAGIC = 0x09b1f3c2 };

/**
 * The chunk object (header of arena).
 */
struct ckhunk {
	enum ckhunk_magic magic;
	size_t size;				/**< Total arena size (including header) */
	size_t reserved;			/**< Reserved memory size */
	char *arena;				/**< Start of allocated arena */
	char *end;					/**< First byte past the arena */
	char *avail;				/**< Beginning of free space for allocation */
};

static inline void
ckhunk_check(const struct ckhunk * const ck)
{
	/* A NULL `ck' argument is allowed in the interface, for robustness */
	g_assert(NULL == ck || CKHUNK_MAGIC == ck->magic);
}

/**
 * Initialize a new chunk allocator.
 *
 * @param size		total arena size (including management overhead)
 * @param reserved	amount of memory to reserve for critical allocations
 *
 * @return a new chunk allocator object.
 */
ckhunk_t *
ckinit(size_t size, size_t reserved)
{
	void *arena;
	ckhunk_t *ck;

	g_assert(size_is_positive(size));
	g_assert(size_is_non_negative(reserved));
	g_assert(size >=
		size_saturate_add(reserved, ckalloc_round(sizeof(struct ckhunk))));

	arena = vmm_alloc(size);
	ck = arena;
	ck->magic = CKHUNK_MAGIC;
	ck->size = size;
	ck->reserved = reserved;
	ck->arena = arena;
	ck->end = ck->arena + size;
	ck->avail = ck->arena + ckalloc_round(sizeof(struct ckhunk));

	g_assert(ptr_cmp(ck->end, ck->avail) > 0);

	return ck;
}

/**
 * Destroy a chunk allocator.
 */
static void
ckdestroy(ckhunk_t *ck)
{
	ckhunk_check(ck);
	g_assert(ck != NULL);

	ck->magic = 0;
	vmm_free(ck->arena, ck->size);
}

/**
 * Destroy a chunk allocator, nullify its pointer.
 */
void
ckdestroy_null(ckhunk_t **ck_ptr)
{
	ckhunk_t *ck = *ck_ptr;

	if (ck != NULL) {
		ckdestroy(ck);
		*ck_ptr = NULL;
	}
}

/**
 * @return whether someething has been allocated.
 */
gboolean
ckused(const ckhunk_t *ck)
{
	ckhunk_check(ck);

	if (NULL == ck)
		return FALSE;
	
	return ck->avail != ck->arena + ckalloc_round(sizeof(struct ckhunk));
}

/**
 * Free all the objects allocated in the chunk.
 */
void
ckfree_all(ckhunk_t *ck)
{
	sigset_t set;

	ckhunk_check(ck);

	if (NULL == ck)
		return;

	if (!signal_enter_critical(&set))
		return;

	ck->avail = ck->arena + ckalloc_round(sizeof(struct ckhunk));

	signal_leave_critical(&set);
}

/**
 * Allocate `len' bytes from chunk.
 *
 * This routine may be safely called from a signal handler.
 *
 * The allocated memory cannot be freed individually.  However, all the
 * memory allocated in the chunk can be freed using ckfree_all().
 *
 * @param ck		an initialized chunk memory allocator
 * @param len		amount of memory to allocate
 * @param critical	whether we can use the reserved chunk space
 *
 * @return pointer to allocated memory, NULL if memory cannot be allocated.
 */
static void *
ckalloc_internal(ckhunk_t *ck, size_t len, gboolean critical)
{
	void *p = NULL;
	sigset_t set;
	char *new_avail;

	ckhunk_check(ck);
	g_assert(size_is_positive(len));

	if (NULL == ck)
		return NULL;

	if (!signal_enter_critical(&set))
		return NULL;

	/*
	 * Make sure we have enough room, leaving the reserved memory intact
	 * unless ``critical'' is TRUE.
	 */

	new_avail = ptr_add_offset(ck->avail, len);
	if (ptr_cmp(ck->end, new_avail) < 0)
		goto done;

	if (!critical && ptr_diff(ck->end, new_avail) < ck->reserved)
		goto done;

	/*
	 * Allocation succeeded.
	 */

	p = ck->avail;
	ck->avail = new_avail;

	/* FALL THROUGH */

done:
	signal_leave_critical(&set);
	return p;
}

/**
 * Allocate `len' bytes from chunk.
 *
 * This routine may be safely called from a signal handler.
 *
 * The allocated memory cannot be freed individually.  However, all the
 * memory allocated in the chunk can be freed using ckfree_all().
 *
 * @param ck		an initialized chunk memory allocator
 * @param len		amount of memory to allocate
 *
 * @return pointer to allocated memory, NULL if memory cannot be allocated.
 */
void *
ckalloc(ckhunk_t *ck, size_t len)
{
	return ckalloc_internal(ck, len, FALSE);
}

/**
 * Allocate `len' bytes from chunk, using the reserved memory space if needed.
 *
 * This routine may be safely called from a signal handler.
 *
 * The allocated memory cannot be freed individually.  However, all the
 * memory allocated in the chunk can be freed using ckfree_all().
 *
 * @param ck		an initialized chunk memory allocator
 * @param len		amount of memory to allocate
 *
 * @return pointer to allocated memory, NULL if memory cannot be allocated.
 */
void *
ckalloc_critical(ckhunk_t *ck, size_t len)
{
	return ckalloc_internal(ck, len, TRUE);
}

/**
 * Copy memory into new buffer.
 *
 * @return new buffer with copied data, NULL if memory could not be allocated.
 */
void *
ckcopy(ckhunk_t *ck, const void *p, size_t size)
{
	void *cp;

	ckhunk_check(ck);

	if (NULL == ck)
		return NULL;

	cp = ckalloc(ck, size);
	if (cp != NULL)
		memcpy(cp, p, size);

	return cp;
}

/**
 * Convenience routine to duplicate a string.
 *
 * @return duplicated string, NULL if allocation failed or str was NULL.
 */
char *
ckstrdup(ckhunk_t *ck, const char *str)
{
	ckhunk_check(ck);

	return str ? ckcopy(ck, str, 1 + strlen(str)) : NULL;
}

/* vi: set ts=4 sw=4 cindent:  */
