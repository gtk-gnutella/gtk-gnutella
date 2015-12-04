/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Virtual Memory Emergency Allocator (VMEA).
 *
 * The VMEA layer is the last resort allocator for the VMM layer when it
 * reaches an out-of-memory condition and has no way to allocate the
 * requested amount of memory.
 *
 * It works by pre-allocating, at startup time, a memory region that can then
 * be used to serve memory requests that are necessary during shutdown or
 * to be able to decompile stack traces into symbolic forms at crash time.
 *
 * To limit the need for dynamic structures here, all the require memory
 * is preallocated.  The memory region is handled via a bitmap, each set bit
 * in the bitmap representing an allocated page in the reserved memory region.
 *
 * To be able to determine the places that required emergency allocations,
 * a page is allocated to hold up raw stack traces that led to the need for
 * memory.  These stack traces are then formatted at shutdown time.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "vmea.h"

#include "bit_array.h"
#include "log.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "unsigned.h"
#include "vmm.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#define VMEA_STACKTRACE_DEPTH	16

/**
 * The stacktrace we capture during emergency allocations.
 */
struct vmea_stacktrace {
	void *stack[VMEA_STACKTRACE_DEPTH];		/* PC of callers */
	size_t count;							/* Number of valid entries */
	size_t requested;						/* Requested memory size */
	bool success;							/* Whether allocation succeeded */
};

/**
 * Data structure which keeps track of emergency stack traces.
 */
static struct vmea_stack {
	struct vmea_stacktrace *page;		/* Base page */
	size_t count;						/* Amount of entries */
	size_t capacity;					/* Max amount of entries on page */
	bool enabled;						/* Set when we can get a stacktrace */
	spinlock_t lock;					/* Multi-thread protection */
} vmea_stacks;

/**
 * Data structure containing emergency memory.
 */
static struct vmea_region {
	bit_array_t *bitmap;				/* Bitmap flagging allocated pages */
	void *memory;						/* Allocated emergency region */
	size_t capacity;					/* Total size of the region */
	size_t allocated;					/* Total allocated amount */
	size_t pages;						/* Amount of pages in region */
	size_t pagesize;					/* System page size */
	spinlock_t lock;					/* Multi-thread protection */
} vmea_region;

/**
 * Reserve the initial amount of emergency memory.
 *
 * Once reserved, calls to vmea_alloc() and vmea_free() are possible.
 *
 * @param size		amount of bytes in the emergency region
 */
void
vmea_reserve(size_t size)
{
	struct vmea_region *vr = &vmea_region;
	struct vmea_stack  *vs = &vmea_stacks;

	g_assert_log(NULL == vr->memory,
		"%s(): already has a reserved region of %'zu bytes",
		G_STRFUNC, vr->capacity);

	vr->capacity = round_pagesize(size);
	vr->memory   = vmm_core_alloc(vr->capacity);
	vr->pages    = vmm_page_count(vr->capacity);
	vr->bitmap   = xmalloc0(BIT_ARRAY_BYTE_SIZE(vr->pages));
	vr->pagesize = compat_pagesize();

	vs->page     = vmm_core_alloc(vr->pagesize);
	vs->capacity = vr->pagesize / sizeof vs->page[0];
	vs->enabled  = TRUE;

	spinlock_init(&vr->lock);
	spinlock_init(&vs->lock);
}

/**
 * Close the emergency layer.
 */
void
vmea_close(void)
{
	struct vmea_region *vr = &vmea_region;
	struct vmea_stack  *vs = &vmea_stacks;
	size_t count = vs->count;
	struct vmea_stacktrace *st = vs->page;

	vs->enabled = FALSE;		/* Disable further stacktrace collection */

	/*
	 * If there were collected stacktraces, dump them.
	 */

	while (count-- != 0) {
		s_message("%s(): emergency allocation stack of %'zu bytes (%s):",
			G_STRFUNC, st->requested, st->success ? "OK" : "FAILED");
		stacktrace_stack_print_decorated(STDERR_FILENO,
			st->stack, st->count, STACKTRACE_F_ORIGIN | STACKTRACE_F_SOURCE);
		st++;
	}

	if (vs->page != NULL)
		vmm_core_free(vs->page, vr->pagesize);

	XFREE_NULL(vr->bitmap);
	if (0 == vr->allocated && vr->memory != NULL)
		vmm_core_free(vr->memory, vr->capacity);
}

/**
 * Capture a stacktrace of the allocation attempt if possible.
 *
 * @param size		the amount of requested bytes
 * @param success	whether allocation was successful
 */
static void
vmea_stacktrace(size_t size, bool success)
{
	struct vmea_stack  *vs = &vmea_stacks;
	struct vmea_stacktrace *st = NULL;

	if G_UNLIKELY(!vs->enabled)
		return;

	spinlock(&vs->lock);

	if (vs->enabled && vs->count < vs->capacity) {
		st = &vs->page[vs->count++];
		vs->enabled = FALSE;
	}

	spinunlock(&vs->lock);

	if (NULL == st)
		return;

	st->count = stacktrace_unwind(st->stack, G_N_ELEMENTS(st->stack), 2);
	st->requested = size;
	st->success = success;

	spinlock_hidden(&vs->lock);
	vs->enabled = TRUE;
	spinunlock_hidden(&vs->lock);
}

/**
 * Attempt to allocate emergency memory.
 *
 * The allocated memory is not zeroed, this must be handled by the caller
 * when necessary.
 *
 * @param size		the size of the region we want, in bytes
 *
 * @return pointer to allocated memory on success, NULL on failure.
 */
void *
vmea_alloc(size_t size)
{
	struct vmea_region *vr = &vmea_region;
	size_t rounded, n, first, last;
	void *p = NULL;

	if G_UNLIKELY(NULL == vr->bitmap)
		return NULL;

	spinlock(&vr->lock);

	/*
	 * If we know the requested size exceeds the remaining space we have,
	 * it is certain that we will not be able to allocate.
	 */

	rounded = round_pagesize(size);
	n = vmm_page_count(rounded);

	if (rounded > vr->capacity - vr->allocated)
		goto failed;

	/*
	 * Use the page bitmap to locate a location where we have ``n''
	 * consecutive pages available.
	 */

	for (first = 0; first < vr->pages; first = last + 1) {
		first = bit_array_first_clear(vr->bitmap, first, vr->pages - 1);
		if ((size_t) -1 == first)
			goto failed;

		if (first + n > vr->pages)
			goto failed;				/* No room within region */

		if (first + n != vr->pages) {
			g_assert(first + n < vr->pages);
			last = bit_array_first_set(vr->bitmap, first + 1, first + n);
			if ((size_t) -1 == last)
				last = vr->pages;		/* First bit beyond the bitmap */
		} else {
			last = vr->pages;			/* First bit beyond the bitmap */
		}

		if (n <= last - first) {
			bit_array_set_range(vr->bitmap, first, first + n - 1);
			p = ptr_add_offset(vr->memory, first * vr->pagesize);
			goto allocated;
		}
	}

	/* FALL THROUGH */

failed:
	spinunlock(&vr->lock);
	vmea_stacktrace(size, FALSE);
	/* We don't want a stacktrace, use s_minilog() directly */
	s_minilog(G_LOG_LEVEL_CRITICAL,
		"%s(): cannot allocate %'zu bytes", G_STRFUNC, size);
	return NULL;

allocated:
	vr->allocated += rounded;
	spinunlock(&vr->lock);
	vmea_stacktrace(size, TRUE);
	return p;
}

/**
 * Free memory if it falls within the emergency region.
 *
 * @param p			start of the allocated region
 * @param size		the size of the allocated region
 *
 * @return TRUE if memory was emergency memory and it was freed.
 */
bool
vmea_free(void *p, size_t size)
{
	struct vmea_region *vr = &vmea_region;

	g_assert(0 == size || p != NULL);
	g_assert_log(vmm_page_start(p) == p, "%s(): p=%p", G_STRFUNC, p);

	if G_UNLIKELY(NULL == vr->bitmap)
		return FALSE;

	if G_LIKELY(p != NULL) {
		void *end = ptr_add_offset(vr->memory, vr->capacity);
		size_t first, n;

		/*
		 * Check whether region to free falls within the emergency region.
		 */

		if (ptr_cmp(p, vr->memory) < 0) {
			g_assert_log(ptr_cmp(ptr_add_offset(p, size), vr->memory) <= 0,
				"%s(): p=%p, size=%'zu, vr->memory=%p",
				G_STRFUNC, p, size, vr->memory);
			return FALSE;
		}

		if (ptr_cmp(p, end) >= 0)
			return FALSE;

		/*
		 * Ensure the whole region to free falls within the emergency region.
		 */

		g_assert_log(ptr_cmp(ptr_add_offset(p, size), end) <= 0,
			"%s(): p=%p, size=%'zu, end=%p",
			G_STRFUNC, p, size, end);

		/*
		 * We found memory that falls within the emergency region.  Free it!
		 */

		n = vmm_page_count(size);
		first = vmm_page_count(ptr_diff(p, vr->memory));

		g_assert(first < vr->pages);
		g_assert(bit_array_get(vr->bitmap, first));

		spinlock(&vr->lock);

		bit_array_clear_range(vr->bitmap, first, first + n - 1);
		vr->allocated -= round_pagesize(size);

		spinunlock(&vr->lock);
	}

	return TRUE;	/* Emergency memory released */
}

/* vi: set ts=4 sw=4 cindent: */
