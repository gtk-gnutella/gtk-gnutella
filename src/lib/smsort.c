/*
 * Copyright (C) 2005 Nokia Corporation.
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
 * Smoothsort is an in-situ sorting algorithm invented by E.D. Dijkstra to
 * allow O(N) complexity when facing an already sorted array, and gradually
 * incresing its complexity as the array is more randomly shuffled up to
 * its maximal complexity of O(N.log N).  Hence the "smooth" qualificative.
 *
 * This implementation is remarkable in that it is clean and almost litterally
 * follows the original Dijkstra paper.  Congratulations to Pekka for such a
 * great work.
 *
 * Inclusion in this library and minor editings were made by Raphael Manfredi
 * in order to adapt the code to the local coding style and benefit from
 * the other services available in the library, such as assertions, and to
 * make the interface more "qsort-like".
 *
 * This qsort()-like implementation is only optimized for aligned arrays of
 * pointers or longs, because the offset computations done in swap_items() and
 * cmp_items() are performance killers.
 *
 * To be able to efficiently sort other arrays, the original interface
 * available as smsort_ext() may be preferred, but it requires two callback
 * routines:
 *
 *		bool less(void *m, size_t i, size_t j);
 *		void swap(void *m, size_t i, size_t j);
 *
 * The less() routine returns TRUE is m[i] < m[j].
 * The swap() routine swaps items m[i] and m[j].
 *
 * Timing benchmarks show that smsort() is about twice slower as xsort()
 * on randomly shuffled arrays of pointers but, of course, is always
 * more efficient when the array of pointers is initially sorted.
 *
 * So smsort() should be used only when there is meta-knowledge that a
 * significant portion of the array is already sorted.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @date 2005
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "op.h"
#include "smsort.h"
#include "unsigned.h"

#include "override.h"			/* Must be the last header included */

/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
 *
 * Contact: Pekka Pessi <pekka.pessi@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

/**
 * @file smoothsort.c
 * @brief Smoothsort implementation
 *
 * Smoothsort is a in-place sorting algorithm with performance of O(N.log N)
 * in worst case and O(N) in best case.
 *
 * @sa <a href="http://www.enterag.ch/hartwig/order/smoothsort.pdf">
 * "Smoothsort, an alternative for sorting in-situ", E.D. Dijkstra, EWD796a</a>,
 * &lt;http://www.enterag.ch/hartwig/order/smoothsort.pdf&gt;.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 */

/** Description of current stretch */
typedef struct {
	size_t b, c;			/** Leonardo numbers */
	uint64 p;				/** Concatenation codification */
} stretch;

/** Description of sorted array */
typedef struct {
	char *m;
	size_t s;
	cmp_fn_t cmp;
	smsort_less_t less;
	smsort_swap_t swap;
	uint8 aligned;
} array;

/*
 * Leonardo numbers are defined by the following recurrence.
 *
 * L[0] = L[1] = 1
 * L[n] = L[n-1] + L[n-2] + 1
 *
 * Hence stretch_up() and stretch_down() need to keep "b" and "c" to compute
 * the next number or revert to the previous one.
 */

static inline size_t
stretch_up(stretch s[1])
{
	size_t next;
	s->p >>= 1;
	next = s->b + s->c + 1, s->c = s->b, s->b = next;
	return next;
}

static inline size_t
stretch_down(stretch s[1], unsigned bit)
{
	size_t next;
	s->p <<= 1, s->p |= bit;
	next = s->c, s->c = s->b - s->c - 1, s->b = next;
	return next;
}

#if DEBUG_SMOOTHSORT
static char const *
binary(uint64 p)
{
	static char binary[65];
	int i;
	if (p == 0)
		return "0";
	binary[64] = 0;
	for (i = 64; p; p >>= 1)
		binary[--i] = "01"[p & 1];
	return binary + i;
}
#else
#undef DEBUG
#define DEBUG(x) ((void)0)
#endif

/**
 * Swap two items from array.
 */
static void G_HOT
swap_items(array const *ary, size_t a, size_t b)
{
	if (ary->aligned) {
		op_t tmp;
		op_t *om = (op_t *) ary->m;

		tmp = om[b];
		om[b] = om[a];
		om[a] = tmp;
	} else if (NULL == ary->swap) {
		char *x = cast_to_char_ptr(&ary->m[a * ary->s]);
		char *y = cast_to_char_ptr(&ary->m[b * ary->s]);

		/*
		 * Using SWAP() ends-up generating way faster code than 3 successive
		 * memcpy() calls, by a factor 2 at least.
		 *		--RAM, 2012-02-28
		 */

		SWAP(x, y, ary->s);
	} else {
		ary->swap(ary->m, a, b);
	}
}

/**
 * Compare two items in the array.
 */
static int G_HOT
cmp_items(array const *ary, size_t a, size_t b)
{
	if (ary->aligned) {
		op_t *om = (op_t *) ary->m;

		return ary->cmp(&om[a], &om[b]);
	} else if (ary->cmp != NULL) {
		size_t i = a * ary->s;
		size_t j = b * ary->s;

		return ary->cmp(&ary->m[i], &ary->m[j]);
	} else {
		return ary->less(ary->m, a, b) ? -1 : 0;
	}
}

/**
 * Sift the root of the stretch.
 *
 * The low values are sifted up (towards index 0) from root.
 *
 * @param ary		description of array to sort
 * @param r			root of the stretch
 * @param s			description of current stretch
 */
static void G_HOT
sift(array const *ary, size_t r, stretch s)
{
	while (s.b >= 3) {
		size_t r2 = r - s.b + s.c;
		if (cmp_items(ary, r - 1, r2) >= 0) {
			r2 = r - 1;
			stretch_down(&s, 0);
		}
		if (cmp_items(ary, r2, r) < 0)
			break;
		DEBUG(("\tswap(%p @%zu <=> @%zu)\n", ary, r, r2));
		swap_items(ary, r, r2); r = r2;
		stretch_down(&s, 0);
	}
}

/**
 * Trinkle the roots of the given stretches
 *
 * @param ary		description of array to sort
 * @param r			root of the stretch
 * @param s			description of stretches to concatenate
 */
static void G_HOT
trinkle(array const *ary, size_t r, stretch s)
{
	DEBUG(("trinkle(%p, %zu, (%u, %s))\n", ary, r, s.b, binary(s.p)));
	while (s.p != 0) {
		size_t r2, r3;
		while ((s.p & 1) == 0)
			stretch_up(&s);
		if (s.p == 1)
			break;
		r3 = r - s.b;
		if (cmp_items(ary, r3, r) < 0)
			break;
		s.p--;
		if (s.b < 3) {
			DEBUG(("\tswap(%p @%zu <=> @%zu b=%u)\n", ary, r, r3, s.b));
			swap_items(ary, r, r3); r = r3;
			continue;
		}
		r2 = r - s.b + s.c;
		if (cmp_items(ary, r2, r - 1) < 0) {
			r2 = r - 1;
			stretch_down(&s, 0);
		}
		if (cmp_items(ary, r2, r3) < 0) {
			DEBUG(("swap(%p [%zu]=[%zu])\n", ary, r, r3));
			swap_items(ary, r, r3); r = r3;
			continue;
		}
		DEBUG(("\tswap(%p @%zu <=> @%zu b=%u)\n", ary, r, r2, s.b));
		swap_items(ary, r, r2); r = r2;
		stretch_down(&s, 0);
		break;
	}
	sift(ary, r, s);
}

/**
 * Trinkles the stretches when the adjacent stretches are already trusty.
 *
 * @param ary		description of array to sort
 * @param r			root of the stretch
 * @param stretch	description of stretches to trinkle
 */
static void G_HOT
semitrinkle(array const *ary, size_t r, stretch s)
{
	size_t r1 = r - s.c;

	DEBUG(("semitrinkle(%p, %zu, (%u, %s))\n", ary, r, s.b, binary(s.p)));

	if (cmp_items(ary, r, r1) < 0) {
		DEBUG(("\tswap(%p @%zu <=> @%zu b=%u)\n", ary, r, r1, s.b));
		swap_items(ary, r, r1);
		trinkle(ary, r1, s);
	}
}

/**
 * Sort array using smoothsort.
 *
 * @param ary		the array being sorted
 * @param first		first index to sort
 * @param N			amount ot items to sort
 */
static void
smoothsort(array const *ary, size_t first, size_t N)
{
	stretch s = { 1, 1, 1 };
	size_t r = first;
	size_t q;

	if G_UNLIKELY(N <= 1)
		return;

	DEBUG(("\nsmoothsort(%p, %zu)\n", ary, N));

	for (q = 1; q != N; q++, r++, s.p++) {
		DEBUG(("loop0 q=%zu, b=%u, p=%s \n", q, s.b, binary(s.p)));
		if ((s.p & 7) == 3) {
			sift(ary, r, s), stretch_up(&s), stretch_up(&s);
		}
		else /* if ((s.p & 3) == 1) */ {
			if (q + s.c < N)
				sift(ary, r, s);
			else
				trinkle(ary, r, s);
			while (stretch_down(&s, 0) > 1)
				/* noop */;
		}
	}
	trinkle(ary, r, s);
	for (; q > 1; q--) {
		s.p--;
		DEBUG(("loop1 q=%zu: b=%u p=%s\n", q, s.b, binary(s.p)));
		if (s.b <= 1) {
			while ((s.p & 1) == 0)
				stretch_up(&s);
			--r;
		}
		else /* if b >= 3 */ {
			if (s.p) semitrinkle(ary, r - (s.b - s.c), s);
			stretch_down(&s, 1);
			semitrinkle(ary, --r, s);
			stretch_down(&s, 1);
		}
	}
}

/**
 * Sort array using smoothsort, via a qsort()-like interface.
 *
 * Sort @a N elements from array @a base whose items are @a S byte long
 * with smoothsort.
 *
 * The interface was made identical to that of qsort() by Raphael Manfredi,
 * for easier drop-in replacement.
 *
 * @param base		starting point of array to sort
 * @param N			number of elements to sort
 * @param S			size of each item in array
 * @param cmp		sort comparison returning -1, 0, +1 for m[a] <=> m[b]
 */
void
smsort(void *base, size_t N, size_t S, cmp_fn_t cmp)
{
	array const ary[1] = {
		{ base, S, cmp, NULL, NULL, OPSIZ == S && op_aligned(base) }
	};

	g_assert(base != NULL);
	g_assert(cmp != NULL);
	g_assert(size_is_non_negative(N));
	g_assert(size_is_positive(S));

	smoothsort(ary, 0, N);
}

/**
 * Sort array using smoothsort, via an extended interface.
 *
 * Sort @a N elements from array @a base starting with index @a r
 * with smoothsort.
 *
 * The interface was made identical to that of qsort() by Raphael Manfredi,
 * for easier drop-in replacement.
 *
 * @param base		starting point of array to sort
 * @param r			lowest index to sort
 * @param N			number of elements to sort
 * @param less		comparison function returning TRUE if m[a] < m[b]
 * @param swap		swapper function exchanging elements m[a] and m[b]
 */
void
smsort_ext(void *base, size_t r, size_t N,
	smsort_less_t less, smsort_swap_t swap)
{
	array const ary[1] = {
		{ base, 0, NULL, less, swap, FALSE }
	};

	g_assert(base != NULL);
	g_assert(size_is_non_negative(r));
	g_assert(size_is_non_negative(N));
	g_assert(less != NULL);
	g_assert(swap != NULL);

	smoothsort(ary, r, N);
}

/* vi: set ts=4 sw=4 cindent:  */
