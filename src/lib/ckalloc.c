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
 * Memory allocator for objects that are allocated once out of an existing
 * chunk and cannot be individually freed, but altogether with every other
 * object allocated in the chunk or via checkpoint / restore of the chunk
 * allocation state to "free" memory allocated since the checkpoint.
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

#include "ckalloc.h"
#include "log.h"
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
	((ulong) (((ulong) (s) + CKALLOC_MASK) & ~CKALLOC_MASK))

enum ckhunk_magic { CKHUNK_MAGIC = 0x09b1f3c2 };

/**
 * The chunk object (header of arena).
 */
struct ckhunk {
	enum ckhunk_magic magic;
	size_t size;				/**< Total arena size (excluding header) */
	size_t reserved;			/**< Reserved memory size */
	char *arena;				/**< Start of allocated arena */
	char *end;					/**< First byte past the arena */
	char *avail;				/**< Beginning of free space for allocation */
	unsigned read_only:1;		/**< Chunk marked read-only */
};

static inline void
ckhunk_check(const struct ckhunk * const ck)
{
	/* A NULL `ck' argument is allowed in the interface, for robustness */
	g_assert(NULL == ck || CKHUNK_MAGIC == ck->magic);
}

/**
 * Is chunk read-only?
 */
bool
ck_is_readonly(ckhunk_t *ck)
{
	ckhunk_check(ck);

	return NULL == ck ? FALSE : ck->read_only;
}

/**
 * Initialize a new chunk allocator.
 *
 * @param size		usable arena size (excluding management overhead)
 * @param reserved	amount of memory to reserve for critical allocations
 * @param leaking	whether not freeing this object would create a leak
 *
 * @return a new chunk allocator object.
 */
static ckhunk_t *
ckinit(size_t size, size_t reserved, bool leaking)
{
	void *arena;
	ckhunk_t *ck;

	g_assert(size >= reserved);
	size = size_saturate_add(size, ckalloc_round(sizeof(struct ckhunk)));

	g_assert(size_is_positive(size));
	g_assert(size_is_non_negative(reserved));

	arena = leaking ? vmm_core_alloc(size) : vmm_core_alloc_not_leaking(size);
	ck = arena;
	ZERO(ck);
	ck->magic = CKHUNK_MAGIC;
	ck->size = round_pagesize(size);	/* Size allocated by the VMM layer */
	ck->reserved = reserved;
	ck->arena = arena;
	ck->end = ck->arena + ck->size;
	ck->avail = ck->arena + ckalloc_round(sizeof(struct ckhunk));

	g_assert(ptr_cmp(ck->end, ck->avail) > 0);

	return ck;
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
ck_init(size_t size, size_t reserved)
{
	return ckinit(size, reserved, TRUE);
}

/**
 * Initialize a new non-leaking chunk allocator.
 *
 * @param size		total arena size (including management overhead)
 * @param reserved	amount of memory to reserve for critical allocations
 *
 * @return a new chunk allocator object.
 */
ckhunk_t *
ck_init_not_leaking(size_t size, size_t reserved)
{
	return ckinit(size, reserved, FALSE);
}

/**
 * Destroy a chunk allocator.
 */
void
ck_destroy(ckhunk_t *ck)
{
	ckhunk_check(ck);
	g_assert(ck != NULL);
	g_assert(!ck->read_only);

	ck->magic = 0;
	vmm_free(ck->arena, ck->size);
}

/**
 * Destroy a chunk allocator, nullify its pointer.
 */
void
ck_destroy_null(ckhunk_t **ck_ptr)
{
	ckhunk_t *ck = *ck_ptr;

	if (ck != NULL) {
		ck_destroy(ck);
		*ck_ptr = NULL;
	}
}

/**
 * @return whether someething has been allocated.
 */
bool
ck_used(const ckhunk_t *ck)
{
	ckhunk_check(ck);

	if (NULL == ck)
		return FALSE;

	return ck->avail != ck->arena + ckalloc_round(sizeof(struct ckhunk));
}

/**
 * Checkpoint current allocation context.
 *
 * @return current allocation pointer, to "save" the allocation context.
 */
void *
ck_save(const ckhunk_t *ck)
{
	ckhunk_check(ck);

	if (NULL == ck)
		return NULL;

	return ck->avail;
}

/**
 * Restore allocation context to the saved pointer.
 */
void
ck_restore(ckhunk_t *ck, void *saved)
{
	sigset_t set;
	char *start;
	size_t d;

	ckhunk_check(ck);

	if (NULL == ck)
		return;

	g_assert(!ck->read_only);

	/*
	 * Make sure the saved context lies within the chunk boundaries
	 * and is properly aligned.
	 */

	start = ck->arena + ckalloc_round(sizeof(struct ckhunk));

	g_assert(ptr_cmp(start, saved) <= 0);
	g_assert(ptr_cmp(ck->end, saved) >= 0);

	d = ptr_diff(saved, start);
	g_assert(d == ckalloc_round(d));

	/*
	 * No need to enter a critical section if there was no change
	 * since the checkpoint.
	 */

	if (0 == ptr_cmp(saved, ck->avail))
		return;

	/*
	 * Restore the allocation context, in essence freeing all the memory
	 * allocated since the cksave() checkpoint.
	 */

	if (!signal_enter_critical(&set))
		return;

	ck->avail = saved;

	signal_leave_critical(&set);
}

/**
 * Free all the objects allocated in the chunk.
 */
void
ck_free_all(ckhunk_t *ck)
{
	sigset_t set;

	ckhunk_check(ck);

	if (NULL == ck)
		return;

	g_assert(!ck->read_only);

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
ckalloc(ckhunk_t *ck, size_t len, bool critical)
{
	void *p = NULL;
	sigset_t set;
	char *new_avail;
	size_t allocated;

	ckhunk_check(ck);
	g_assert(size_is_positive(len));

	if (NULL == ck)
		return NULL;

	g_assert(!ck->read_only);

	/*
	 * FIXME: Don't increase the alignment, a single byte allocation
	 *		  does not have be aligned by MEM_ALIGN_BYTES.
	 */
	allocated = ckalloc_round(len);		/* Keep allocations aligned */

	if (!signal_enter_critical(&set))
		return NULL;

	/*
	 * Make sure we have enough room, leaving the reserved memory intact
	 * unless ``critical'' is TRUE.
	 */

	new_avail = ptr_add_offset(ck->avail, allocated);
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
ck_alloc(ckhunk_t *ck, size_t len)
{
	return ckalloc(ck, len, FALSE);
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
ck_alloc_critical(ckhunk_t *ck, size_t len)
{
	return ckalloc(ck, len, TRUE);
}

/**
 * Copy memory into new buffer.
 *
 * @return new buffer with copied data, NULL if memory could not be allocated.
 */
void *
ck_copy(ckhunk_t *ck, const void *p, size_t size)
{
	void *cp;

	ckhunk_check(ck);

	if (NULL == ck)
		return NULL;

	/* FIXME: Don't increase alignment of p */
	cp = ck_alloc(ck, size);
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
ck_strdup(ckhunk_t *ck, const char *str)
{
	ckhunk_check(ck);

	return str ? ck_copy(ck, str, 1 + vstrlen(str)) : NULL;
}

/**
 * Change chunk memory protections.
 */
static void
ck_protect(ckhunk_t *ck, int prot)
{
	ckhunk_check(ck);
	g_assert(ck != NULL);

	if (-1 == mprotect(ck, ck->size, prot)) {
		s_error("mprotect(%p, %zu, %s) failed: %m",
			(void *) ck, ck->size,
			(PROT_WRITE & prot) ? "PROT_READ | PROT_WRITE" :
			(PROT_READ & prot) ? "PROT_READ" : "PROT_NONE");
	}
}

/**
 * Turn chunk into a read-only memory area.
 */
void
ck_readonly(ckhunk_t *ck)
{
	ckhunk_check(ck);

	if (NULL == ck)
		return;

	/*
	 * The chunk is allocated with vmm_alloc() so its start is page-aligned.
	 * To make sure we call mprotect() on an integer amount of pages, also
	 * check that the chunk size is a multiple of the kernel page size.
	 */

	g_assert(round_pagesize(ck->size) == ck->size);

	if (!ck->read_only) {
		ck->read_only = TRUE;
		ck_protect(ck, PROT_READ);
	}
}

/**
 * Turn chunk into a writable memory area.
 */
void
ck_writable(ckhunk_t *ck)
{
	ckhunk_check(ck);

	if (NULL == ck)
		return;

	/*
	 * The chunk is allocated with vmm_alloc() so its start is page-aligned.
	 * To make sure we call mprotect() on an integer amount of pages, also
	 * check that the chunk size is a multiple of the kernel page size.
	 */

	if (ck->read_only) {
		ck_protect(ck, PROT_READ | PROT_WRITE);
		ck->read_only = FALSE;
	}
}

/**
 * Allocate memory from a read-only chunk.
 */
void *
ck_alloc_readonly(ckhunk_t *ck, size_t len)
{
	void *p;
	sigset_t set;

	ckhunk_check(ck);

	if (NULL == ck)
		return NULL;

	g_assert(ck->read_only);

	if (!signal_enter_critical(&set))
		return NULL;

	ck_protect(ck, PROT_READ | PROT_WRITE);
	ck->read_only = FALSE;
	p = ckalloc(ck, len, FALSE);
	ck->read_only = TRUE;
	ck_protect(ck, PROT_READ);

	signal_leave_critical(&set);
	return p;
}

/**
 * Copy memory into new read-only buffer.
 *
 * @return new buffer with copied data, NULL if memory could not be allocated.
 */
void *
ck_copy_readonly(ckhunk_t *ck, const void *p, size_t size)
{
	void *cp;
	sigset_t set;

	ckhunk_check(ck);

	if (NULL == ck)
		return NULL;

	g_assert(ck->read_only);

	if (!signal_enter_critical(&set))
		return NULL;

	ck_protect(ck, PROT_READ | PROT_WRITE);
	ck->read_only = FALSE;
	/* FIXME: Don't increase alignment of p */
	cp = ckalloc(ck, size, FALSE);
	if (cp != NULL)
		memcpy(cp, p, size);
	ck->read_only = TRUE;
	ck_protect(ck, PROT_READ);

	signal_leave_critical(&set);
	return cp;
}

/**
 * Convenience routine to duplicate a string into a read-only chunk.
 *
 * @return duplicated string, NULL if allocation failed or str was NULL.
 */
char *
ck_strdup_readonly(ckhunk_t *ck, const char *str)
{
	ckhunk_check(ck);

	return str ? ck_copy_readonly(ck, str, 1 + vstrlen(str)) : NULL;
}

/**
 * Shrink chunk to be at least the specified size.
 *
 * @return TRUE if we were able to shrink the chunk, FALSE if it was not
 * possible to shrink it or if the specified size was larger than the
 * actual size.
 */
bool
ck_shrink(ckhunk_t *ck, size_t size)
{
	size_t nsize, used;
	sigset_t set;

	ckhunk_check(ck);

	if (NULL == ck)
		return FALSE;

	size = MAX(1, size);	/* round_pagesize(0) returns 0 */
	nsize = round_pagesize(size);	/* VMM rounds up to the next page size */

	if (ck->size <= nsize)
		return FALSE;

	used = round_pagesize(ptr_diff(ck->avail, ck->arena));
	nsize = used > nsize ? used : nsize;

	/*
	 * We're going to shrink the arena down to nsize bytes only.
	 */

	g_assert(ck->size > nsize);

	if (!signal_enter_critical(&set))
		return FALSE;

	if (ck->read_only)
		ck_protect(ck, PROT_READ | PROT_WRITE);

	vmm_shrink(ck->arena, ck->size, nsize);
	ck->size = nsize;
	ck->end = ck->arena + ck->size;

	if (ck->read_only)
		ck_protect(ck, PROT_READ);

	g_assert(ptr_cmp(ck->end, ck->avail) >= 0);

	signal_leave_critical(&set);
	return TRUE;
}

/**
 * Copy data into a memory area within a chunk which may be read-only.
 *
 * The copy operation is atomic with respect to signals, so the whole
 * data is updated or none of it when a signal hits.
 *
 * @return TRUE of OK, FALSE on error.
 */
bool
ck_memcpy(ckhunk_t *ck, void *dest, const void *src, size_t size)
{
	void *chunk_start;
	sigset_t set;

	g_assert(ck != NULL);
	g_assert(src != NULL);
	g_assert(size_is_non_negative(size));
	ckhunk_check(ck);

	chunk_start = ck->arena + ckalloc_round(sizeof(struct ckhunk));
	g_assert(ptr_cmp(dest, chunk_start) >= 0);
	g_assert(ptr_cmp(dest, ck->end) < 0);
	g_assert(ptr_diff(ck->end, dest) >= size);

	if (0 == size)
		return TRUE;

	if (!signal_enter_critical(&set))
		return FALSE;

	if (ck->read_only)
		ck_protect(ck, PROT_READ | PROT_WRITE);

	memcpy(dest, src, size);		/* The copy operation */

	if (ck->read_only)
		ck_protect(ck, PROT_READ);

	signal_leave_critical(&set);
	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
