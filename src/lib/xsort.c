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
 * The excellent quicksort() implementation from Douglas C. Schmidt was further
 * optimized: maximize the chances of picking a good pivot when the partition
 * is large, optimize insertsort() when dealing with aligned items that are
 * multiples of words, detect an already sorted partition or one that is
 * almost-sorted to discontinue quicksort() and switch to insertsort() instead,
 * and better handle pathological inputs (all items equal).
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
#include "op.h"
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

/* Conditional item swap */
#define CSWAP(a, b, s) G_STMT_START {	\
	if G_LIKELY((a) != (b))				\
		SWAP((a), (b), (s));			\
} G_STMT_END


/*
 * Discontinue quicksort algorithm when partition gets below this size.
 * 4 was a particular magic number chosen to work best on a Sun 4/260.
 * 7 seems to be working well on Intel CPUs.
 */
#define MAX_THRESH 7

/*
 * Use carefully-chosen median insted of median-of-3 when there are more
 * items in the partition than this minimum.
 */
#define MIN_MEDIAN	64

/*
 * Threshold on the amount of items we swap in a partition to guide us in
 * deciding whether it is almost sorted and insersort would be more efficient
 * than quicksort to complete the sorting.
 */
#define SWAP_THRESH 1

/**
 * Threshold for insertsort() to bail out when it is about to move more than
 * that many times the amount of bytes in the partition being sorted, for
 * ones larger than MAX_THRESH items.
 */
#define INSERT_THRESH 2		/* Experiments showed 2 is a good compromise */

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

/**
 * Insertion sort for small partions or ones that are believed already sorted.
 *
 * When the partition is larger than MAX_THRESH items, detect that we are
 * facing pathological input and bail out in the middle if needed.
 *
 * @return TRUE if OK, FALSE when we decide to bail-out.
 */
static G_GNUC_HOT bool
insertsort(void *const pbase, size_t lastoff, size_t size, cmp_fn_t cmp)
{
	char *base = pbase;
	char *const end = &base[lastoff];	/* Last item */
	char *tmp = base;
	char *thresh;
	register char *run;
	size_t n;
	size_t moved = 0;

	/*
	 * We're called with a supposedly almost-sorted array.
	 *
	 * Find smallest element in the first few locations and place it at the
	 * array's beginning.  This is likely the smallest array element, and the
	 * operation speeds up insertion sort's inner loop.
	 *
	 * However, when we do not scan the whole array, we have no guarantee
	 * that we're placing the absolute lower item, which means we have
	 * to guard the main insertion loop with a pointer comparison at each
	 * step to make sure we do not go before the bottom of the array.
	 */

	thresh = ptr_add_offset(pbase, MAX_THRESH * size);
	thresh = MIN(thresh, end);

	for (run = tmp + size; run <= thresh; run += size) {
		if ((*cmp)(run, tmp) < 0)
			tmp = run;
	}

	if G_LIKELY(tmp != base) {
		SWAP(tmp, base, size);
		moved = size;
	}

	/*
	 * When we scanned the whole array, we have the lowest item at index 0
	 * and we can start iterating at the next item.  Otherwise, we have to
	 * start at the base.
	 */

	run = base + (thresh == end ? size : 0);
	n = (op_aligned(size) && op_aligned(base)) ? size / OPSIZ : 0;

	/* Insertion sort, running from left-hand-side up to right-hand-side */

	while ((run += size) <= end) {
		tmp = run - size;
		while (tmp >= base && (*cmp)(run, tmp) < 0) {
			tmp -= size;
		}

		tmp += size;
		if (tmp != run) {
			/*
			 * If the partition is larger than MAX_THRESH items, then attempt
			 * to detect when we're not facing sorted input and we run the
			 * risk of approaching O(n^2) complexity.
			 *
			 * In that case, bail out and quicksort() will pick up where
			 * we left.
			 *
			 * The criteria is that we must not move around more than about
			 * INSERT_THRESH time the size of the arena.  This is only checked
			 * past the size threshold to prevent any value checking from
			 * quicksort() when we are called with a small enough partition,
			 * where complexity is not deemed an issue.
			 *
			 * Exception when we reach the last item: regardless of where it
			 * will land, the cost now should be less than bailing out and
			 * resuming quicksort() on the partition, so finish off the sort.
			 */

			if G_UNLIKELY(run > thresh && run != end) {
				if (moved > INSERT_THRESH * lastoff)
					return FALSE;	/* We bailed out */
			}

			moved += ptr_diff(run, tmp) + size;

			if G_LIKELY(n != 0) {
				/* Operates on words */
				op_t *trav = (op_t *) (run + size);
				op_t *r = (op_t *) run;
				op_t *t = (op_t *) tmp;

				while (--trav >= r) {
					op_t c = *trav;
					register op_t *hi, *lo;

					for (hi = lo = trav; (lo -= n) >= t; hi = lo) {
						*hi = *lo;
					}
					*hi = c;
				}
			} else {
				/* Operates on bytes */
				char *trav = run + size;

				while (--trav >= run) {
					char c = *trav;
					register char *hi, *lo;

					for (hi = lo = trav; (lo -= size) >= tmp; hi = lo) {
						*hi = *lo;
					}
					*hi = c;
				}
			}
		}
	}

	return TRUE;	/* OK, fully sorted */
}

/**
 * Return position of median among 3 items without re-arranging items.
 */
static inline void *
median_three(void *a, void *b, void *c, cmp_fn_t cmp)
{
	return (*cmp)(a, b) < 0 ?
		((*cmp)(b, c) < 0 ? b : ((*cmp)(a, c) < 0 ? c : a )) :
		((*cmp)(b, c) > 0 ? b : ((*cmp)(a, c) < 0 ? a : c ));
}

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

static G_GNUC_HOT void
quicksort(void *const pbase, size_t total_elems, size_t size, cmp_fn_t cmp)
{
	char *base = pbase;
	const size_t max_thresh = MAX_THRESH * size;
	bool careful = FALSE;

	if G_UNLIKELY(total_elems == 0)
		return;	/* Avoid lossage with unsigned arithmetic below.  */

	if (total_elems > MAX_THRESH) {
		char *lo = base;
		char *hi = &lo[size * (total_elems - 1)];
		stack_node stack[STACK_SIZE];
		stack_node *top = stack + 1;

		while (STACK_NOT_EMPTY) {
			register char *left;
			register char *right;
			size_t items = (hi - lo) / size;
			char *mid = lo + size * (items >> 1);
			size_t swapped;
			char *xlo;
			char *xhi;
			size_t lsize, rsize;

			/*
			 * If there are more than MIN_MEDIAN items, it pays to spend
			 * more time selecting a good pivot by doing a median over
			 * several items.
			 *		--RAM, 2012-03-02
			 */

			if (careful && items > MIN_MEDIAN) {
				size_t d = size * (items >> 3);
				char *plo, *phi;

				plo = median_three(lo, lo + d, lo + 2*d, cmp);
				mid = median_three(mid - d, mid, mid + d, cmp);
				phi = median_three(hi - 2*d, hi - d, hi, cmp);
				mid = median_three(plo, mid, phi, cmp);
			} else {
				mid = median_three(lo, mid, hi, cmp);
			}

			CSWAP(mid, lo, size);		/* Put pivot at the base */
			left  = xlo = lo + size;	/* Since pivot is at the base now */
			right = xhi = hi;

			swapped = 0;	/* Detect almost-sorted partition --RAM */

			/*
			 * Here's the famous ``collapse the walls'' section of quicksort.
			 * Gotta like those tight inner loops!  They are the main reason
			 * that this algorithm runs much faster than others.
			 */

			for (;;) {
				int c;

				/*
				 * Changes by Raphael Manfredi to avoid O(n^2) behaviour
				 * when all items are identical.
				 *
				 * This also protects code that asserts no two compared items
				 * can be identical when we have meta-knowledge that all the
				 * items in the sorted array are different.
				 *		--RAM, 2012-03-01.
				 */

				while (left <= right && (c = (*cmp)(left, lo)) <= 0) {
					if G_UNLIKELY(0 == c) {
						CSWAP(left, xlo, size);
						xlo += size;
					}
					left += size;
				}

				while (left <= right && (c = (*cmp)(lo, right)) <= 0) {
					if G_UNLIKELY(0 == c) {
						CSWAP(right, xhi, size);
						xhi -= size;
					}
					right -= size;
				}

				if G_UNLIKELY(left >= right)
					break;

				SWAP(left, right, size);
				swapped++;
				left += size;
				right -= size;
			}

			/*
			 * Move back items equal to the pivot at the middle of the
			 * partition.
			 */

			lsize = ptr_diff(left, xlo);
			rsize = ptr_diff(xhi, right);

			if (!careful && ((lsize >> 2) > rsize || (rsize >> 2) > lsize))
				careful = TRUE;

			{
				size_t equal = ptr_diff(xlo, lo);	/* Equal to pivot */
				size_t n = MIN(equal, lsize);
				if (n != 0)
					SWAP(lo, left - n, n);
			}

			{
				size_t equal = ptr_diff(hi, xhi);	/* Equal to pivot */
				size_t n = MIN(equal, rsize);
				if (n != 0)
					CSWAP(left, hi - n + size, n);
			}

			/*
			 * Optimization by Raphael Manfredi: if we only swapped a few
			 * items in the partition, use insertsort() on it and do not
			 * recurse.  This greatly accelerates quicksort() on already
			 * sorted arrays.
			 *
			 * However, because we may have guessed wrong, intersort() monitors
			 * pathological cases and can bail out (when we hand out more than
			 * MAX_THRESH items). Hence we must monitor the result and continue
			 * as if we hadn't call insertsort() when it returns a non-NULL
			 * pointer.
			 *
			 * This works because insertsort() processes its input from left
			 * to right and therefore will not disrupt the "left/right"
			 * partitionning with respect to the pivot value and the already
			 * computed left and right boundaries.
			 */

			if G_UNLIKELY(swapped <= SWAP_THRESH) {
				bool ok;

				/*
				 * Switch to insertsort() to completely sort this partition.
				 *
				 * Although we could call insertsort() on the whole partition,
				 * we want to limit the size in case it has to bail out.
				 * This also limits the amount of data to move around, at
				 * the cost of extra setup.
				 */

				ok = lsize > size ?
					insertsort(lo, lsize - size, size, cmp) : TRUE;

				if (ok) {
					ok = rsize != 0 ?
						insertsort(hi - rsize, rsize, size, cmp) : TRUE;
					if (ok) {
						POP(lo, hi);	/* Done with partition */
						continue;
					}
					lsize = size;		/* Mark left as fully sorted */
				}

				/* Continue as if we hadn't called insertsort() */
			}

			/*
			 * Set up pointers for next iteration.  First determine whether
			 * left and right partitions are below the threshold size.  If so,
			 * insertsort one or both.  Otherwise, push the larger partition's
			 * bounds on the stack and continue quicksorting the smaller one.
			 *
			 * Change by Raphael Manfredi: immediately do the insertsort of
			 * the small partitions instead of waiting for the end of quicksort
			 * to benefit from the locality of reference, at the expense of
			 * more setup costs.
			 */

			if G_UNLIKELY(lsize - size <= max_thresh) {
				if (lsize > size)
					insertsort(lo, lsize - size, size, cmp);
				if G_UNLIKELY(rsize <= max_thresh) {
					if (rsize != 0)
						insertsort(hi - rsize, rsize, size, cmp);
					POP(lo, hi);	/* Ignore both small partitions. */
				} else
					lo = hi - rsize;	/* Ignore small left partition. */
			} else if G_UNLIKELY(rsize <= max_thresh) {
				if (rsize != 0)
					insertsort(hi - rsize, rsize, size, cmp);
				hi = &lo[lsize - size];	/* Ignore small right partition. */
			} else if (lsize > rsize) {
				/* Push larger left partition indices. */
				PUSH(lo, &lo[lsize - size]);
				lo = hi - rsize;
			} else {
				/* Push larger right partition indices. */
				PUSH (hi - rsize, hi);
				hi = &lo[lsize - size];
			}
		}
	} else {
		insertsort(pbase, (total_elems - 1) * size, size, cmp);
	}
}

/*
 * An alternative to qsort(), with an identical interface.
 * Written by Mike Haertel, September 1988.
 */

static void
msort_with_tmp(void *b, size_t n, size_t s, cmp_fn_t cmp, char *t)
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

	if (s == OPSIZ && op_aligned(b1)) {
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
 * This routine allocates memory on the stack or through the VMM layer and
 * prefers to use mergesort, reserving quicksort to cases where there would
 * be too much memory required for the mergesort.
 *
 * The contents are sorted in ascending order, as defined by the comparison
 * function ``cmp''.
 */
void
xsort(void *b, size_t n, size_t s, cmp_fn_t cmp)
{
	const size_t size = size_saturate_mult(n, s);

	g_assert(b != NULL);
	g_assert(cmp != NULL);
	g_assert(size_is_non_negative(n));
	g_assert(size_is_positive(s));


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
				memsize = (uint64) -1;		/* Assume plenty! */
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

/**
 * Sort array in-place (no memory allocated) with ``n'' elements of size ``s''.
 * The base ``b'' points to the start of the array.
 *
 * The contents are sorted in ascending order, as defined by the comparison
 * function ``cmp''.
 */
void
xqsort(void *b, size_t n, size_t s, cmp_fn_t cmp)
{
	quicksort(b, n, s, cmp);
}

/* vi: set ts=4 sw=4 cindent: */
