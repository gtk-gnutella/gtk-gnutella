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
 * Virtual sorting entry points to dynamically select the best sorting routine
 * based on local benchmarking.
 *
 * We measure several algorithms with four different scenarios: large and small
 * arrays on one dimension, random or almost-sorted arrays on another dimension.
 * The drawback is that to get meaningful results we need to do enough
 * iterations, which is of course slowing down the process for a few seconds.
 *
 * The vsort() entry point can then be used to sort arrays for which we cannot
 * have a priori knowledge that they are almost sorted.
 *
 * The vsort_almost() entry point should be used when the array is almost
 * sorted, since the algorithm used in that case could be different than the
 * one selected for vsort().
 *
 * These routines work even when vsort_init() was not called: the hardwired
 * default sorting routine is set to our xqsort(), which is a reasonably fast
 * quicksort implementation with no memory allocation.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#ifdef I_MATH
#include <math.h>		/* For log() */
#endif

#include "vsort.h"

#include "log.h"
#include "op.h"
#include "random.h"
#include "smsort.h"
#include "tm.h"
#include "tqsort.h"
#include "unsigned.h"
#include "vmm.h"
#include "xsort.h"

#include "override.h"			/* Must be the last header included */

#define VSORT_LOOPS			16		/* Targeted amount of benchmarking loops */
#define VSORT_ATTEMPTS		5		/* Max retry attempts made when doubling */
#define VSORT_ITEMS			8192	/* A rather large amount of items */
#define VSORT_SMALL_ITEMS	128		/* Upper limit for small arrays */
#define VSORT_HUGE_ITEMS	TQSORT_ITEMS	/* Huge item amount */
#define VSORT_MIN_SECS		0.05	/* Lowest CPU time we want to spend */

struct vsort_timing {
	void *data;				/* The data to sort */
	void *copy;				/* The arena where we sort copied data */
	size_t items;			/* Amount of items to sort */
	size_t isize;			/* Item size */
	size_t len;				/* Bytes used by `data' and `copy' VMM chunks */
};

typedef void (*vsort_timer_t)(struct vsort_timing *vt, size_t loops);
typedef void (*vsort_t)(void *b, size_t n, size_t s, cmp_fn_t cmp);

#define VSORT_SMALL		0U	/* Index in vsort_table[] for small arrays */
#define VSORT_LARGE		1U	/* Index in vsort_table[] for large arrays */
#define VSORT_HUGE		2U	/* Index in vsort_table[] for huge arrays */

static struct {
	vsort_t v_sort;			/* Sort routine to use for general arrays */
	vsort_t v_sort_almost;	/* Sort routine to use for almost-sorted arrays */
} vsort_table[] = {
	{ xqsort, xqsort },		/* Default if they do not call vsort_init() */
	{ xqsort, xqsort },		/* Default if they do not call vsort_init() */
	{ tqsort, xqsort },		/* Default if they do not call vsort_init() */
};

static int
vsort_long_cmp(const void *a, const void *b)
{
	const long * const la = a, * const lb = b;

	return CMP(*la, *lb);
}

static void
vsort_qsort(struct vsort_timing *vt, size_t loops)
{
	size_t n = loops;

	while (n-- > 0) {
		memcpy(vt->copy, vt->data, vt->len);
		qsort(vt->copy, vt->items, vt->isize, vsort_long_cmp);
	}
}

static void
vsort_xsort(struct vsort_timing *vt, size_t loops)
{
	size_t n = loops;

	while (n-- > 0) {
		memcpy(vt->copy, vt->data, vt->len);
		xsort(vt->copy, vt->items, vt->isize, vsort_long_cmp);
	}
}

static void
vsort_xqsort(struct vsort_timing *vt, size_t loops)
{
	size_t n = loops;

	while (n-- > 0) {
		memcpy(vt->copy, vt->data, vt->len);
		xqsort(vt->copy, vt->items, vt->isize, vsort_long_cmp);
	}
}

static void
vsort_tqsort(struct vsort_timing *vt, size_t loops)
{
	size_t n = loops;

	while (n-- > 0) {
		memcpy(vt->copy, vt->data, vt->len);
		tqsort(vt->copy, vt->items, vt->isize, vsort_long_cmp);
	}
}

static void
vsort_smsort(struct vsort_timing *vt, size_t loops)
{
	size_t n = loops;

	while (n-- > 0) {
		memcpy(vt->copy, vt->data, vt->len);
		smsort(vt->copy, vt->items, vt->isize, vsort_long_cmp);
	}
}

/**
 * Computes amount of timing loops to run depending on the amount of items
 * to sort, to keep the time reasonable.
 */
static size_t
vsort_loops(size_t items)
{
	double target, used;

	/*
	 * Assume VSORT_LOOPS loops for VSORT_HUGE_ITEMS items will take about the
	 * time we want to spend for a single test.  If we have less items, we
	 * can do more loops.
	 *
	 * We know the running time is O(n * log n) where n is the amount of items.
	 */

	target = VSORT_HUGE_ITEMS * log(VSORT_HUGE_ITEMS);
	used = items * log(items);

	return MAX(target / used * VSORT_LOOPS, 1);
}

/**
 * Time sorting routine.
 *
 * @param f		the function we call and compute the average execution time for
 * @param vt	describes the data we're sorting, given as input to ``f''
 * @param loops	amount of loops to perform, possibly updated (increased)
 *
 * @return real clock-time in seconds for one single iteration.
 */
static double
vsort_timeit(vsort_timer_t f, struct vsort_timing *vt, size_t *loops)
{
	double start, end;
	size_t n = *loops;
	double elapsed = 0.0, telapsed = 0.0;
	uint attempts = 0;
	tm_t tstart, tend;

retry:
	/*
	 * Safety against broken clocks which would stall the process forever if
	 * we were to continue.
	 */

	if (attempts++ >= VSORT_ATTEMPTS) {
		s_critical("%s(): "
			"either CPU is too fast or kernel clock resultion too low: "
			"elapsed time is %F secs after %zu loops",
			G_STRFUNC, elapsed, n);
		goto done;
	}

	/*
	 * This is a pure CPU grinding algorithm, hence we monitor the amount of
	 * CPU used and not the wall clock: if the process gets suspended in the
	 * middle of the test, that would completely taint the results.
	 *
	 * However, in multi-threaded processes, the accounted CPU time is for
	 * the whole process, and this is not fair for tqsort() which uses multiple
	 * threads in order to minimize the overall elapsed time.
	 *
	 * Hence we measure both the CPU time and the wall-clock time and pick
	 * the lowest figure.
	 */

	(*f)(vt, 1);		/* Blank run to offset effect of memory caching */

	tm_now_exact(&tstart);
	tm_cputime(&start, NULL);
	(*f)(vt, n);
	tm_cputime(&end, NULL);
	tm_now_exact(&tend);

	elapsed = end - start;
	telapsed = tm_elapsed_f(&tend, &tstart);

	/*
	 * If the machine is too powerful (or the clock granularity too low),
	 * double the amount of items and retry.
	 */

	if (elapsed < VSORT_MIN_SECS) {
		*loops = n = n * 2;
		goto retry;
	}

	elapsed = MIN(elapsed, telapsed);

done:
	return elapsed / n;
}

/**
 * Sort array in-place with ``n'' elements of size ``s'' using fastest routine.
 * The base ``b'' points to the start of the array.
 *
 * The contents are sorted in ascending order, as defined by the comparison
 * function ``cmp''.
 */
void
vsort(void *b, size_t n, size_t s, cmp_fn_t cmp)
{
	uint idx = n <= VSORT_SMALL_ITEMS ? VSORT_SMALL :
		n >= VSORT_HUGE_ITEMS ? VSORT_HUGE : VSORT_LARGE;
	vsort_t f = vsort_table[idx].v_sort;

	(*f)(b, n, s, cmp);
}

/**
 * Sort almost-sorted array in-place with ``n'' elements of size ``s'' using
 * the fastest routine.
 * The base ``b'' points to the start of the array.
 *
 * The contents are sorted in ascending order, as defined by the comparison
 * function ``cmp''.
 */
void
vsort_almost(void *b, size_t n, size_t s, cmp_fn_t cmp)
{
	uint idx = n <= VSORT_SMALL_ITEMS ? VSORT_SMALL :
		n >= VSORT_HUGE_ITEMS ? VSORT_HUGE : VSORT_LARGE;
	vsort_t f = vsort_table[idx].v_sort_almost;

	(*f)(b, n, s, cmp);
}

/**
 * Randomly swap 1/128 of the array items.
 */
static void
vsort_perturb_sorted_array(void *array, size_t cnt, size_t isize)
{
	size_t n;
	size_t i;

	n = cnt / 128;

	for (i = 0; i < n; i++) {
		size_t a = random_value(cnt - 1);
		size_t b = random_value(cnt - 1);
		void *x = ptr_add_offset(array, a * isize);
		void *y = ptr_add_offset(array, b * isize);

		SWAP(x, y, isize);
	}
}

struct vsort_testing {
	vsort_timer_t v_timer;
	vsort_t v_routine;
	double v_elapsed;
	int v_weight;
	char *v_name;
};

static int
vsort_testing_cmp(const void *a, const void *b)
{
	int c;
	const struct vsort_testing * const va = a, * const vb = b;

	/*
	 * If the two items being compared have the same execution time,
	 * prefer the one with the highest weight.
	 */

	c = CMP(va->v_elapsed, vb->v_elapsed);
	return 0 == c ? CMP(vb->v_weight, va->v_weight) : c;
}

/*
 * Always substitute xqsort() for tqsort() if handling less than
 * TQSORT_ITEMS at a time since tqsort() will always remap to xqsort()
 * in that case.
 */
static vsort_t
vsort_routine(const vsort_t routine, size_t items)
{
	if (items < TQSORT_ITEMS && routine == tqsort)
		return xqsort;

	return routine;
}

static const char *
vsort_routine_name(const char *name, size_t items)
{
	if (items < TQSORT_ITEMS && 0 == strcmp(name, "tqsort"))
		return "xqsort";

	return name;
}

/**
 * Check which of qsort(), xqsort(), xsort() or smsort() is best for sorting
 * aligned arrays with a native item size of OPSIZ.  At identical performance
 * level, we prefer our own sorting algorithms instead of libc's qsort() for
 * memory allocation purposes.
 *
 * @param items		amount of items to use in the sorted array
 * @param idx		index of the virtual routine to update
 * @param verbose	whether to be verbose
 * @param which		either "large" or "small", for logging
 */
static void
vsort_init_items(size_t items, unsigned idx, int verbose, const char *which)
{
	struct vsort_testing tests[] = {
		{ vsort_qsort,	qsort,	0.0, 0, "qsort" },
		{ vsort_xqsort,	xqsort,	0.0, 2, "xqsort" },
		{ vsort_xsort,	xsort,	0.0, 1, "xsort" },
		{ vsort_tqsort,	tqsort,	0.0, 1, "tqsort" },
		{ vsort_smsort,	smsort,	0.0, 1, "smsort" },	/* Only for almost sorted */
	};
	size_t len = items * OPSIZ;
	struct vsort_timing vt;
	size_t loops, highest_loops;
	unsigned i;

	g_assert(uint_is_non_negative(idx));
	g_assert(idx < G_N_ELEMENTS(vsort_table));

	vt.data = vmm_alloc(len);
	vt.copy = vmm_alloc(len);
	vt.items = items;
	vt.isize = OPSIZ;
	vt.len = len;
	random_bytes(vt.data, len);

	highest_loops = loops = vsort_loops(items);

	/* The -1 below is to avoid benchmarking smsort() for the general case */

retry_random:
	for (i = 0; i < G_N_ELEMENTS(tests) - 1; i++) {
		tests[i].v_elapsed = vsort_timeit(tests[i].v_timer, &vt, &loops);

		if (verbose > 1) {
			s_debug("%s() took %.4f secs for %s array (%zu loops)",
				tests[i].v_name, tests[i].v_elapsed * loops, which, loops);
		}

		if (loops != highest_loops) {
			highest_loops = loops;
			/* Redo all the tests if the number of timing loops changes */
			if (i != 0)
				goto retry_random;
		}
	}

	/*
	 * When dealing with a large amount of items, redo the tests twice with
	 * another set of random bytes to make sure we're not hitting a special
	 * ordering case.
	 */

	if (items >= VSORT_ITEMS) {
		unsigned j;

		for (j = 0; j < 2; j++) {
			random_bytes(vt.data, len);

			for (i = 0; i < G_N_ELEMENTS(tests) - 1; i++) {
				tests[i].v_elapsed +=
					vsort_timeit(tests[i].v_timer, &vt, &loops);

				if (verbose > 1) {
					s_debug("%s() spent %.6f secs total for %s array",
						tests[i].v_name, tests[i].v_elapsed, which);
				}

				if (loops != highest_loops) {
					highest_loops = loops;
					/* Redo all the tests if the number of loops changes */
					s_info("%s(): restarting %s array tests with %zu loops",
						G_STRFUNC, which, loops);
					goto retry_random;
				}
			}
		}
	}

	xqsort(tests, G_N_ELEMENTS(tests) - 1, sizeof tests[0], vsort_testing_cmp);

	vsort_table[idx].v_sort = vsort_routine(tests[0].v_routine, items);

	if (verbose) {
		s_info("vsort() will use %s() for %s arrays",
			vsort_routine_name(tests[0].v_name, items), which);
	}

	/*
	 * Now sort the data, then randomly perturb them by swapping a few items
	 * so that the array is almost sorted.
	 */

	xqsort(vt.data, vt.items, vt.isize, vsort_long_cmp);
	vsort_perturb_sorted_array(vt.data, vt.items, vt.isize);

retry_sorted:
	for (i = 0; i < G_N_ELEMENTS(tests); i++) {
		tests[i].v_elapsed = vsort_timeit(tests[i].v_timer, &vt, &loops);

		if (verbose > 1) {
			s_debug("%s() on almost-sorted took %.4f secs "
				"for %s array (%zu loops)",
				tests[i].v_name, tests[i].v_elapsed * loops, which, loops);
		}

		if (loops != highest_loops) {
			highest_loops = loops;
			/* Redo all the tests if the number of timing loops changes */
			if (i != 0)
				goto retry_sorted;
		}
	}

	xqsort(tests, G_N_ELEMENTS(tests), sizeof tests[0], vsort_testing_cmp);

	vsort_table[idx].v_sort_almost = vsort_routine(tests[0].v_routine, items);

	if (verbose) {
		s_info("vsort_almost() will use %s() for %s arrays",
			vsort_routine_name(tests[0].v_name, items), which);
	}

	vmm_free(vt.data, len);
	vmm_free(vt.copy, len);
}

/**
 * Check which of qsort() or xqsort() is best for sorting aligned arrays with
 * a native item size of OPSIZ.
 */
void
vsort_init(int verbose)
{
	tm_t start, end;
	bool blockable = TRUE;

	STATIC_ASSERT(VSORT_HUGE_ITEMS > VSORT_ITEMS);
	STATIC_ASSERT(VSORT_ITEMS > VSORT_SMALL_ITEMS);

	if (verbose)
		s_info("benchmarking sort routines to select the best one...");

	/*
	 * Allow main thread to block during the duration of our tests.
	 * This is needed since tqsort() can create threads and block.
	 */

	if (thread_is_main() && !thread_main_is_blockable()) {
		thread_set_main(TRUE);
		blockable = FALSE;
	}

	tm_now_exact(&start);
	vsort_init_items(VSORT_HUGE_ITEMS, VSORT_HUGE, verbose, "huge");
	vsort_init_items(VSORT_ITEMS, VSORT_LARGE, verbose, "large");
	vsort_init_items(VSORT_SMALL_ITEMS, VSORT_SMALL, verbose, "small");
	tm_now_exact(&end);

	if (verbose)
		s_info("vsort() benchmarking took %F secs", tm_elapsed_f(&end, &start));

	/*
	 * Restore non-blockable main thread if needed.
	 */

	if (!blockable)
		thread_set_main(FALSE);
}

/* vi: set ts=4 sw=4 cindent: */
