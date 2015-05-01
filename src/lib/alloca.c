/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * An emulation of alloca() based on the chunk allocation layer, itself
 * based on the VMM layer.
 *
 * This code does not (and MUST NOT) rely on xmalloc() or zalloc().
 *
 * Allocation is thread-safe but cannot be used from signal handlers in
 * case they would be executed on a separate signal stack.
 *
 * When compiling with gcc, the __builtin_alloca() implementation is used,
 * hence the emulation is not required.
 *
 * The alloca_stack_direction() routine is always made available for everyone
 * to determine the stack growing direction.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "alloca.h"
#include "spinlock.h"

/**
 * Determine whether stack is growing upwards or backwards.
 *
 * @return +1 if stack is growing in the virtual address space, -1 otherwise.
 */
static int
alloca_stack_direction_compute(void)
{
	static void *old_sp;
	int sp;

	if (NULL == old_sp) {
		old_sp = &sp;
		return alloca_stack_direction_compute();
	} else {
		return ptr_cmp(&sp, old_sp);
	}
}

/**
 * Determine whether stack is growing upwards or backwards.
 *
 * @return +1 if stack is growing in the virtual address space, -1 otherwise.
 */
int
alloca_stack_direction(void)
{
	static int direction;
	static spinlock_t alloca_slk = SPINLOCK_INIT;

	if G_LIKELY(direction != 0)
		return direction;

	spinlock_hidden(&alloca_slk);

	if (0 == direction)
		direction = alloca_stack_direction_compute();

	spinunlock_hidden(&alloca_slk);

	return direction;
}

#ifdef EMULATE_ALLOCA

#include "ckalloc.h"
#include "log.h"
#include "thread.h"
#include "unsigned.h"

#include "override.h"			/* Must be the last header included */

#define ALLOCA_STACK	32768	/* Upper boundary of allocation space */
#define ALLOCA_FUNCMAX	65536	/* Largest function size */
#define ALLOCA_WARNSIZE	4096	/* Above this size, warn about large alloca() */

/**
 * Memory alignment constraints.
 */
#define ALLOCA_ALIGNBYTES	MEM_ALIGNBYTES
#define ALLOCA_MASK			(ALLOCA_ALIGNBYTES - 1)
#define alloca_round(s) \
	((unsigned long) (((unsigned long) (s) + ALLOCA_MASK) & ~ALLOCA_MASK))

/**
 * Allocation header.
 */
union alloca_header {
	char align[ALLOCA_ALIGNBYTES];
	struct {
		const void *sp;				/**< Stack pointer at allocation time */
		const void *pc;				/**< PC of caller at allocation time */
		union alloca_header *prev;	/**< Previous header */
	} header;
};

enum alloca_magic { ALLOCA_MAGIC = 0x018886c7 };

/**
 * Allocation stack structure.
 */
struct alloca_stack {
	enum alloca_magic magic;
	ckhunk_t *stack;	/**< Stack chunk from which we're allocating */
	void *base;			/**< Stack base */
	union alloca_header *last;	/**< Last allocation (NULL if none) */
};

static inline void
alloca_stack_check(const struct alloca_stack * const as)
{
	g_assert(as != NULL);
	g_assert(ALLOCA_MAGIC == as->magic);
}

/**
 * Compare two pointers according to the stack growing direction.
 * A pointer is larger than another if it is further up in the stack, i.e.
 * it was allocated afterwards (deeper in the stack).
 */
static inline int
alloca_ptr_cmp(const void *a, const void *b)
{
	static int direction;

	if G_UNLIKELY(0 == direction) {
		direction = alloca_stack_direction();
		g_assert(direction != 0);
	}

	return CMP(direction, 0) * ptr_cmp(a, b);
}

/**
 * Allocate a new alloca() stack.
 */
static struct alloca_stack *
alloca_new_stack(void)
{
	struct alloca_stack *as;
	ckhunk_t *ck;

	ck = ck_init_not_leaking(ALLOCA_STACK, 0);
	as = ck_alloc(ck, sizeof *as);

	g_assert(as != NULL);

	ZERO(as);
	as->magic = ALLOCA_MAGIC;
	as->stack = ck;
	as->base = ck_save(ck);

	return as;
}

/**
 * Get the thread-private alloca() stack.
 */
static struct alloca_stack *
alloca_get_stack(void)
{
	static bool warned;
	struct alloca_stack *as;

	/*
	 * Warn them that we're using an emulated alloca() in case we enter
	 * one of the pathological cases where we can't cleanup the allocated
	 * blocks even though the routines which allocated them have long returned.
	 */

	if G_UNLIKELY(!warned) {
		s_warning("using emulated alloca() with a %d-byte stack", ALLOCA_STACK);
		warned = TRUE;
	}

	as = thread_private_get(func_to_pointer(alloca_get_stack));

	if G_UNLIKELY(NULL == as) {
		as = alloca_new_stack();
		thread_private_add(func_to_pointer(alloca_get_stack), as);
	}

	return as;
}

/**
 * Check whether alloca() block has expired.
 *
 * @param ah		the header of the allocated block
 * @param sp		current alloca() stack pointer
 * @param pc		current program counter of the alloca() caller
 *
 * @return TRUE if block has expired.
 */
static bool
alloca_expired(const union alloca_header *ah, const void *sp, const void *pc)
{
	int c;

	/*
	 * Don't simply look at the current stack pointer because if a routine
	 * calls f() iteratively and f() calls alloca(), we will always enter
	 * here with the same top stack pointer and we will not be able to cleanup
	 * previous allocations from f().
	 *
	 * Instead we also look at the PC of the caller, and if the stack pointer
	 * is the same but the PC is lower, we know we left the routine.
	 * When the PC is greater, we assume that functions using alloca() are
	 * not bigger than ALLOCA_FUNCMAX bytes.  Therefore, any distance between
	 * the caller's PC and the allocation PC greater than that indicates that
	 * we have left the routine, even though the stack pointer is at the
	 * same level.
	 *
	 * Still, we don't detect cases where f() is called first from a stack
	 * depth=1, then through another chain from a stack depth=2, etc... Its
	 * allocated blocks will be flagged "alive" because they appear to be
	 * in the same stack frame, as if some recursion occurred, whereas the
	 * frames are different.
	 */

	c = alloca_ptr_cmp(ah->header.sp, sp);

	if (c < 0)
		return FALSE;		/* Block was allocated before on the stack */

	if (c > 0)
		return TRUE;		/* Block was allocated after on the stack */

	/*
	 * Stack pointers are identical.
	 */

	if (ptr_cmp(pc, ah->header.pc) <= 0)
		return TRUE;		/* Allocated by code coming afterwards */

	if (ptr_diff(pc, ah->header.pc) > ALLOCA_FUNCMAX)
		return TRUE;		/* We must be in another routine */

	return FALSE;		/* Can't determine for sure, assume still alive! */
}

/**
 * Compute size of alloca() block.
 *
 * @attention
 * This is inefficient but is only used when dumping the blocks, so it is
 * not worth making it faster at the expense of tracking the block size.
 */
static size_t
alloca_block_size(const struct alloca_stack *as, const union alloca_header *ah)
{
	union alloca_header *h;

	if (ah == as->last)
		return ptr_diff(ck_save(as->stack), ah);

	for (h = as->last; h != NULL; h = h->header.prev) {
		if (ah == h->header.prev)
			return ptr_diff(h, ah);
	}

	return 0;	/* Cannot happen, must be found */
}

/**
 * Dump allocated blocks.
 */
static void
alloca_dump_used(void)
{
	struct alloca_stack *as;
	union alloca_header *ah;

	as = alloca_get_stack();

	alloca_stack_check(as);

	for (ah = as->last; ah != NULL; ah = ah->header.prev) {
		s_info("alloca() block %p (%zu bytes) from %s()", (void *) ah,
			alloca_block_size(as, ah),
			stacktrace_routine_name(ah->header.pc, FALSE));
	}
}

/**
 * Allocate memory on the current thread's alloca() stack.
 */
void *
alloca_emulate(size_t len)
{
	struct alloca_stack *as;
	const void *sp = &as;
	const void *pc = stacktrace_caller(1);
	union alloca_header *ah, *last_expired = NULL;

	g_assert(size_is_non_negative(len));

	as = alloca_get_stack();

	alloca_stack_check(as);

	if G_UNLIKELY(len > ALLOCA_WARNSIZE)
		s_carp("large alloca() of %zu bytes", len);

	/*
	 * Look whether we have to garbage collect something.
	 */

	for (ah = as->last; ah != NULL; ah = ah->header.prev) {
		if (!alloca_expired(ah, sp, pc))
			break;
		last_expired = ah;
	}

	if (ah != as->last) {
		g_assert(last_expired != NULL);
		if (NULL == ah)
			ck_restore(as->stack, as->base);
		else
			ck_restore(as->stack, last_expired);
		as->last = ah;
	}

	/*
	 * Calling with a length of 0 has no effect.
	 *
	 * The real alloca() will do nothing, we just garbage collect and
	 * return NULL.
	 */

	if (0 == len)
		return NULL;

	ah = ck_alloc(as->stack, alloca_round(len + sizeof *ah));

	if (NULL == ah) {
		s_critical("cannot alloca() %zu bytes", len);
		alloca_dump_used();
		s_error("out of stack memory");
	}

	ah->header.sp = sp;
	ah->header.pc = pc;
	ah->header.prev = as->last;
	as->last = ah;

	return ptr_add_offset(ah, sizeof *ah);
}

#endif	/* EMULATE_ALLOCA */

/* vi: set ts=4 sw=4 cindent: */
