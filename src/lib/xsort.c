/*
 * Copyright (c) 1988 Mike Haertel
 * Copyright (c) 1991 Douglas C. Schmidt
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
 * Sorting routines that do not call zalloc() or xmalloc().
 *
 * Most of this code comes from the GNU C library and was adapted by Raphael
 * Manfredi for inclusion into this library, mostly to remove all malloc()
 * dependency, strip libc internal dependencies, and reformat to our coding
 * standards.
 *
 * @author Mike Haertel
 * @date 1988
 * @author Douglas C. Schmidt
 * @date 1991
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "xsort.h"
#include "getphysmemsize.h"
#include "mempcpy.h"
#include "unsigned.h"
#include "vmm.h"

#include "override.h"			/* Must be the last header included */

/*
 * Quicksort algorithm.
 * Written by Douglas C. Schmidt (schmidt@ics.uci.edu).
 */

/*
 * If you consider tuning this algorithm, you should consult first:
 * Engineering a sort function; Jon Bentley and M. Douglas McIlroy;
 * Software - Practice and Experience; Vol. 23 (11), 1249-1265, 1993.
 */

/* Byte-wise swap two items of size SIZE. */
#define SWAP(a, b, size) G_STMT_START {		\
	register size_t __size = (size);		\
	register char *__a = (a), *__b = (b);	\
											\
	do {									\
	  char __tmp = *__a;					\
	  *__a++ = *__b;						\
	  *__b++ = __tmp;						\
	} while (--__size > 0);					\
} G_STMT_END

/*
 * Discontinue quicksort algorithm when partition gets below this size.
 * This particular magic number was chosen to work best on a Sun 4/260.
 */
#define MAX_THRESH 4

/* Stack node declarations used to store unfulfilled partition obligations. */
typedef struct {
	char *lo;
	char *hi;
} stack_node;

/*
 * The next 4 #defines implement a very fast in-line stack abstraction.
 *
 * The stack needs log (total_elements) entries (we could even subtract
 * log(MAX_THRESH)).  Since total_elements has type size_t, we get as
 * upper bound for log (total_elements):
 * bits per byte (CHAR_BIT) * sizeof(size_t).
 */
#define STACK_SIZE	(CHAR_BIT * sizeof(size_t))
#define PUSH(low, high)	((void) ((top->lo = (low)), (top->hi = (high)), ++top))
#define	POP(low, high)	((void) (--top, (low = top->lo), (high = top->hi)))
#define	STACK_NOT_EMPTY	(stack < top)


/*
 * Order size using quicksort.  This implementation incorporates
 * four optimizations discussed in Sedgewick:
 *
 * 1. Non-recursive, using an explicit stack of pointer that store the
 *    next array partition to sort.  To save time, this maximum amount
 *    of space required to store an array of SIZE_MAX is allocated on the
 *    stack.  Assuming a 32-bit (64 bit) integer for size_t, this needs
 *    only 32 * sizeof(stack_node) == 256 bytes (for 64 bit: 1024 bytes).
 *    Pretty cheap, actually.
 *
 * 2. Chose the pivot element using a median-of-three decision tree.
 *    This reduces the probability of selecting a bad pivot value and
 *    eliminates certain extraneous comparisons.
 *
 * 3. Only quicksorts TOTAL_ELEMS / MAX_THRESH partitions, leaving
 *    insertion sort to order the MAX_THRESH items within each partition.
 *    This is a big win, since insertion sort is faster for small, mostly
 *    sorted array segments.
 *
 * 4. The larger of the two sub-partitions is always pushed onto the
 *    stack first, with the algorithm then concentrating on the
 *    smaller partition.  This *guarantees* no more than log (total_elems)
 *    stack size is needed (actually O(1) in this case)!
 */

static void
quicksort(void *const pbase, size_t total_elems, size_t size, xsort_cmp_t cmp)
{
	register char *base_ptr = pbase;
	const size_t max_thresh = MAX_THRESH * size;
	char *pivot_buffer;

	/*
	 * Allocating SIZE bytes for a pivot buffer facilitates a better
	 * algorithm below since we can do comparisons directly on the pivot.
	 */

	pivot_buffer = alloca(size);

	if (total_elems == 0)
		return;	/* Avoid lossage with unsigned arithmetic below.  */

	if (total_elems > MAX_THRESH) {
		char *lo = base_ptr;
		char *hi = &lo[size * (total_elems - 1)];
		stack_node stack[STACK_SIZE];
		stack_node *top = stack + 1;

		while (STACK_NOT_EMPTY) {
			char *left_ptr;
			char *right_ptr;

			char *pivot = pivot_buffer;

			/*
			 * Select median value from among LO, MID, and HI. Rearrange
			 * LO and HI so the three values are sorted. This lowers the
			 * probability of picking a pathological pivot value and
			 * skips a comparison for both the LEFT_PTR and RIGHT_PTR in
			 * the while loops.
			 */

			char *mid = lo + size * ((hi - lo) / size >> 1);

			if ((*cmp)(mid, lo) < 0)
				SWAP(mid, lo, size);
			if ((*cmp)(hi, mid) < 0)
				SWAP(mid, hi, size);
			else
				goto jump_over;
			if ((*cmp)(mid, lo) < 0)
				SWAP(mid, lo, size);
		jump_over:
			memcpy(pivot, mid, size);
			pivot = pivot_buffer;

			left_ptr  = lo + size;
			right_ptr = hi - size;

			/*
			 * Here's the famous ``collapse the walls'' section of quicksort.
			 * Gotta like those tight inner loops!  They are the main reason
			 * that this algorithm runs much faster than others.
			 */

			do {
				while ((*cmp)(left_ptr, pivot) < 0)
					left_ptr += size;

				while ((*cmp)(pivot, right_ptr) < 0)
					right_ptr -= size;

				if (left_ptr < right_ptr) {
					SWAP(left_ptr, right_ptr, size);
					left_ptr += size;
					right_ptr -= size;
				} else if (left_ptr == right_ptr) {
					left_ptr += size;
					right_ptr -= size;
					break;
				}
			} while (left_ptr <= right_ptr);

			/*
			 * Set up pointers for next iteration.  First determine whether
			 * left and right partitions are below the threshold size.  If so,
			 * ignore one or both.  Otherwise, push the larger partition's
			 * bounds on the stack and continue sorting the smaller one.
			 */

			if (ptr_diff(right_ptr, lo) <= max_thresh) {
				if (ptr_diff(hi, left_ptr) <= max_thresh)
					POP(lo, hi);	/* Ignore both small partitions. */
				else
					lo = left_ptr;	/* Ignore small left partition. */
			} else if (ptr_diff(hi, left_ptr) <= max_thresh) {
				hi = right_ptr;		/* Ignore small right partition. */
			} else if (ptr_diff(right_ptr, lo) > ptr_diff(hi, left_ptr)) {
				/* Push larger left partition indices. */
				PUSH(lo, right_ptr);
				lo = left_ptr;
			} else {
				/* Push larger right partition indices. */
				PUSH (left_ptr, hi);
				hi = right_ptr;
			}
		}
	}

	/* Once the BASE_PTR array is partially sorted by quicksort the rest
	 * is completely sorted using insertion sort, since this is efficient
	 * for partitions below MAX_THRESH size. BASE_PTR points to the beginning
	 * of the array to sort, and END_PTR points at the very last element in
	 * the array (*not* one beyond it!).
	 */

	{
		char *const end_ptr = &base_ptr[size * (total_elems - 1)];
		char *tmp_ptr = base_ptr;
		char *thresh = MIN(end_ptr, base_ptr + max_thresh);
		register char *run_ptr;

		/*
		 * Find smallest element in first threshold and place it at the
		 * array's beginning.  This is the smallest array element,
		 * and the operation speeds up insertion sort's inner loop.
		 */

		for (run_ptr = tmp_ptr + size; run_ptr <= thresh; run_ptr += size) {
			if ((*cmp)(run_ptr, tmp_ptr) < 0)
				tmp_ptr = run_ptr;
		}

		if (tmp_ptr != base_ptr)
		  SWAP(tmp_ptr, base_ptr, size);

		/* Insertion sort, running from left-hand-side up to right-hand-side */

		run_ptr = base_ptr + size;

		while ((run_ptr += size) <= end_ptr) {
			tmp_ptr = run_ptr - size;
			while ((*cmp)(run_ptr, tmp_ptr) < 0) {
				tmp_ptr -= size;
			}

			tmp_ptr += size;
			if (tmp_ptr != run_ptr) {
				char *trav;

				trav = run_ptr + size;
				while (--trav >= run_ptr) {
					char c = *trav;
					char *hi, *lo;

					for (hi = lo = trav; (lo -= size) >= tmp_ptr; hi = lo) {
						*hi = *lo;
					}
					*hi = c;
				}
			}
		}
	}
}

/*
 * An alternative to qsort(), with an identical interface.
 * Written by Mike Haertel, September 1988.
 */

#define op_t	unsigned long int
#define OPSIZ	(sizeof(op_t))

static void
msort_with_tmp(void *b, size_t n, size_t s, xsort_cmp_t cmp, char *t)
{
	char *tmp;
	char *b1, *b2;
	size_t n1, n2;

	if (n <= 1)
		return;

	n1 = n / 2;
	n2 = n - n1;
	b1 = b;
	b2 = ptr_add_offset(b, n1 * s);

	msort_with_tmp(b1, n1, s, cmp, t);
	msort_with_tmp(b2, n2, s, cmp, t);

	tmp = t;

	if (s == OPSIZ && (b1 - (char *) 0) % OPSIZ == 0) {
		op_t *otmp = (op_t *) tmp;
		op_t *ob1 = (op_t *) b1;
		op_t *ob2 = (op_t *) b2;

		/* We are operating on aligned words.  Use direct word stores. */

		while (n1 > 0 && n2 > 0) {
			if ((*cmp)(ob1, ob2) <= 0) {
				--n1;
				*otmp++ = *ob1++;
			} else {
				--n2;
				*otmp++ = *ob2++;
			}
		}

		tmp = (char *) otmp;
		b1 = (char *) ob1;
		b2 = (char *) ob2;
	} else {
		while (n1 > 0 && n2 > 0) {
			if ((*cmp) (b1, b2) <= 0) {
				tmp = mempcpy(tmp, b1, s);
				b1 += s;
				--n1;
			} else {
				tmp = mempcpy(tmp, b2, s);
				b2 += s;
				--n2;
			}
		}
	}

	if (n1 > 0)
		memcpy(tmp, b1, n1 * s);

	memcpy(b, t, (n - n2) * s);
}

/**
 * Sort array with ``n'' elements of size ``s''.  The base ``b'' points to
 * the start of the array.
 *
 * The contents are sorted in ascending order, as defined by the comparison
 * function ``cmp''.
 */
void
xsort(void *b, size_t n, size_t s, xsort_cmp_t cmp)
{
	const size_t size = size_saturate_mult(n, s);

	if (size < 1024) {
		/* The temporary array is small, so put it on the stack */
		void *buf = alloca(size);

		msort_with_tmp(b, n, s, cmp, buf);
	} else {
		static uint64 memsize;

		/*
		 * We should avoid allocating too much memory since this might
		 * have to be backed up by swap space.
		 */

		if G_UNLIKELY(0 == memsize) {
			memsize = getphysmemsize();
			if (0 == memsize)
				memsize = (uint64) -1;
		}

		/* If the memory requirements are too high don't allocate memory */
		if ((uint64) size > memsize / 4) {
			quicksort(b, n, s, cmp);
		} else {
			char *tmp;

			/* It's somewhat large, so alloc it through VMM */

			tmp = vmm_alloc(size);
			msort_with_tmp(b, n, s, cmp, tmp);
			vmm_free(tmp, size);
		}
	}
}

/* vi: set ts=4 sw=4 cindent: */
