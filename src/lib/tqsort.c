/*
 * Copyright (C) 1995 Sun Microsystems, Inc.
 * Copyright (c) 2013 Raphael Manfredi
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
 * Multi-threaded quicksort algorithm to speed-up sorting of large arrays.
 *
 * @author Richard Pettit <Richard.Pettit@West.Sun.COM>
 * @date 1995
 * @author Raphael Manfredi
 * @date 2013
 */

/*
 *  Multithreaded Demo Source
 * 
 *  Copyright (C) 1995 by Sun Microsystems, Inc.
 *  All rights reserved.
 * 
 *  This file is a product of SunSoft, Inc. and is provided for
 *  unrestricted use provided that this legend is included on all
 *  media and as a part of the software program in whole or part.
 *  Users may copy, modify or distribute this file at will.
 * 
 *  THIS FILE IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING
 *  THE WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 *  This file is provided with no support and without any obligation on the
 *  part of SunSoft, Inc. to assist in its use, correction, modification or
 *  enhancement.
 * 
 *  SUNSOFT AND SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT
 *  TO THE INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY THIS
 *  FILE OR ANY PART THEREOF.
 * 
 *  IN NO EVENT WILL SUNSOFT OR SUN MICROSYSTEMS, INC. BE LIABLE FOR ANY
 *  LOST REVENUE OR PROFITS OR OTHER SPECIAL, INDIRECT AND CONSEQUENTIAL
 *  DAMAGES, EVEN IF THEY HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGES.
 * 
 *  SunSoft, Inc.
 *  2550 Garcia Avenue
 *  Mountain View, California  94043
 *
 * Adaptation to gtk-gnutella made by Raphael Manfredi, to adjust the thread
 * creation interface to our thread run-time, to fix a bug (a 'i' was used
 * in place of 'j') and to re-route to xqsort() when we're recursing too deeply
 * or when there is not enough items to sort.
 */

/*
 * multiple-thread quick-sort.	See man page for qsort(3c) for info.
 * Works fine on uniprocessor machines as well.
 *
 * Written by: Richard Pettit (Richard.Pettit@West.Sun.COM)
 */

#include "common.h"

#include "tqsort.h"

#include "atomic.h"
#include "getcpucount.h"
#include "log.h"
#include "once.h"
#include "thread.h"
#include "xsort.h"

/* don't create more threads for less than this */
#define TQSORT_THRESH		4096

/* how many threads per CPU */
#define TQSORT_THR_PER_CPU	4

/* stack size requested for each thread */
#define TQSORT_STACK		THREAD_STACK_MIN

/*
 * Maximum stack depth we allow before switching to xqsort().
 *
 * This multi-threaded algorithm is going to be efficient if the threads are
 * created early in the sorting processing, when we're not too deep in the
 * recursion already,
 *		--RAM
 */
#define TQSORT_DEPTH		24		/* Keep it small */

static bool tqsort_trace = FALSE;

typedef struct {
	void *sa_base;
	int sa_nel;
	size_t sa_width;
	cmp_fn_t sa_compar;
	int sa_depth;
} sort_args_t;

/* for all instances of quicksort (hence using atomic ops on it -- RAM) */
static int threads_avail;

/* cast the void to a one byte quanitity and compute the offset */
#define TSUB(a, n)	  ((void *) (((uint8 *) (a)) + ((n) * width)))

#define TSWAP(a, i, j, width) \
{ \
	register void *p = TSUB(a, i), *q; \
	if (p == pivot) \
		pivot = TSUB(a, j); \
	else if (TSUB(a, j) == pivot) \
		pivot = p; \
	\
	/* one of the more convoluted swaps I've done */ \
	switch(width) { \
	case 1: {\
		register uint8 x = *((uint8 *) p); \
		*((uint8 *) p) = *((uint8 *) (q = TSUB(a, j))); \
		*((uint8 *) q) = x; \
		} break; \
	case 2: {\
		register uint16 x = *((uint16 *) p); \
		*((uint16 *) p) = *((uint16 *) (q = TSUB(a, j))); \
		*((uint16 *) q) = x; \
		} break; \
	case 4: {\
		register uint32 x = *((uint32 *) p); \
		*((uint32 *) p) = *((uint32 *) (q = TSUB(a, j))); \
		*((uint32 *) q) = x; \
		} break; \
	case 8: {\
		register uint64 x = *((uint64 *) p); \
		*((uint64 *) p) = *((uint64 *) (q = TSUB(a,j))); \
		*((uint64 *) q) = x; \
		} break; \
	default: \
		q = TSUB(a, j); \
		SWAP(p, q, width); \
		break; \
	} \
}

enum tqstate {
	TQ_STATE_XQSORT,		/* Handle first partition with xqsort() */
	TQ_STATE_THREAD,		/* Handle first partition with a thread */
	TQ_STATE_RECURSE,		/* Handle first partition via recursion */
	TQ_STATE_DONE			/* First partition fully sorted */
};

/**
 * Threaded quicksort().
 *
 * This is only called when sorting at least TQSORT_THRESH items.
 */
static void * G_HOT
tquicksort(void *arg)
{
	sort_args_t *sargs = (sort_args_t *) arg;
	register void *a = sargs->sa_base;
	int n = sargs->sa_nel;
	int width = sargs->sa_width;
	int depth = sargs->sa_depth + 1;
	cmp_fn_t compar = sargs->sa_compar;
	register int i;
	register int j;
	void *t;
	void *b[3];
	void *pivot = NULL;
	sort_args_t sort_args[2];
	uint tid = THREAD_INVALID_ID;
	enum tqstate first = TQ_STATE_DONE;

	/*
	 * Modifications by Raphael Manfredi.
	 *
	 * If we're too deep in the stack, reroute to our mono-threaded xqsort().
	 * This allows us to use a small stack in sorting threads, and also avoids
	 * problems when this simple quicksort algorithm does not manage to find
	 * a good pivot, resulting in many recursions.
	 */

	if G_UNLIKELY(depth > TQSORT_DEPTH) {
		xqsort(a, n, width, compar);
		return NULL;
	}

	/* find the pivot */
	b[0] = TSUB(a, 0);
	b[1] = TSUB(a, n / 2);
	b[2] = TSUB(a, n - 1);
	/* three sort */
	if ((*compar) (b[0], b[1]) > 0) {
		t = b[0];
		b[0] = b[1];
		b[1] = t;
	}
	/* the first two are now ordered, now order the second two */
	if ((*compar) (b[2], b[1]) < 0) {
		t = b[1];
		b[1] = b[2];
		b[2] = t;
	}
	/* should the second be moved to the first? */
	if ((*compar) (b[1], b[0]) < 0) {
		t = b[0];
		b[0] = b[1];
		b[1] = t;
	}
	if ((*compar) (b[0], b[2]) != 0) {
		if ((*compar) (b[0], b[1]) < 0)
			pivot = b[1];
		else
			pivot = b[2];
	}

	if G_UNLIKELY(pivot == NULL) {
		for (i = 1; i < n; i++) {
			void *p = TSUB(a, i);
			int z;
			if ((z = (*compar) (a, p))) {
				pivot = (z > 0) ? a : p;
				break;
			}
		}
		if (pivot == NULL)
			return NULL;	/* All elements are equal, hence sorted */
	}

	/* sort */
	i = 0;
	j = n - 1;
	while (i <= j) {
		while ((*compar) (TSUB(a, i), pivot) < 0)
			++i;
		while ((*compar) (TSUB(a, j), pivot) >= 0)
			--j;
		if (i < j) {
			TSWAP(a, i, j, width);
			++i;
			--j;
		}
	}

	/*
	 * Handle the first partition.
	 *
	 * Improvement from Raphael Manfredi:
	 *
	 * If we end up not spawning a thread for the first partition, we'll
	 * handle the second partition (which may in turn spawn a thread) and
	 * then we'll come back to the first partition, in order to maximize
	 * concurrency.
	 *		--RAM
	 */

	/* sort the sides judiciously */
	switch (i) {
	case 0:
	case 1:
		break;
	case 2:
		if ((*compar) (TSUB(a, 0), TSUB(a, 1)) > 0) {
			TSWAP(a, 0, 1, width);
		}
		break;
	case 3:
		/* three sort */
		if ((*compar) (TSUB(a, 0), TSUB(a, 1)) > 0) {
			TSWAP(a, 0, 1, width);
		}
		/* the first two are now ordered, now order the second two */
		if ((*compar) (TSUB(a, 2), TSUB(a, 1)) < 0) {
			TSWAP(a, 2, 1, width);
		}
		/* should the second be moved to the first? */
		if ((*compar) (TSUB(a, 1), TSUB(a, 0)) < 0) {
			TSWAP(a, 1, 0, width);
		}
		break;
	default:
		sort_args[0].sa_base = a;
		sort_args[0].sa_nel = i;
		sort_args[0].sa_width = width;
		sort_args[0].sa_compar = compar;
		sort_args[0].sa_depth = depth;

		/*
		 * Do not create a thread if the pivot was chosen poorly and we
		 * did not create a first partition of at least 1/8th of the items.
		 */

		if (i < (n >> 3) || i <= TQSORT_THRESH) {
			first = TQ_STATE_XQSORT;
		} else if (atomic_int_dec(&threads_avail) > 0) {
			tid = thread_create(tquicksort, &sort_args[0], 0, TQSORT_STACK);
			if G_UNLIKELY(THREAD_INVALID_ID == tid) {
				s_warning_once_per(LOG_PERIOD_SECOND,
					"%s(): cannot create new thread: %m", G_STRFUNC);
				atomic_int_inc(&threads_avail);
				first = TQ_STATE_XQSORT;
			} else {
				if G_UNLIKELY(tqsort_trace) {
					s_debug("%s(): created thread #%d, i=%d, depth=%d",
						G_STRFUNC, tid, i, depth);
				}
				first = TQ_STATE_THREAD;
			}
		} else {
			atomic_int_inc(&threads_avail);
			first = TQ_STATE_RECURSE;
		}
		break;
	}

	/*
	 * Handle the second partition.
	 */

	j = n - i;
	switch (j) {
	case 1:
		break;
	case 2:
		if ((*compar) (TSUB(a, i), TSUB(a, i + 1)) > 0) {
			TSWAP(a, i, i + 1, width);
		}
		break;
	case 3:
		/* three sort */
		if ((*compar) (TSUB(a, i), TSUB(a, i + 1)) > 0) {
			TSWAP(a, i, i + 1, width);
		}
		/* the first two are now ordered, now order the second two */
		if ((*compar) (TSUB(a, i + 2), TSUB(a, i + 1)) < 0) {
			TSWAP(a, i + 2, i + 1, width);
		}
		/* should the second be moved to the first? */
		if ((*compar) (TSUB(a, i + 1), TSUB(a, i)) < 0) {
			TSWAP(a, i + 1, i, width);
		}
		break;
	default:
		sort_args[1].sa_base = TSUB(a, i);
		sort_args[1].sa_nel = j;
		sort_args[1].sa_width = width;
		sort_args[1].sa_compar = compar;
		sort_args[1].sa_depth = depth;

		if (j < (n >> 3) || j <= TQSORT_THRESH) {
			xqsort(sort_args[1].sa_base, j, width, compar);
		} else if (
			THREAD_INVALID_ID == tid &&		/* No thread for other partition */
			atomic_int_dec(&threads_avail) > 0
		) {
			tid = thread_create(tquicksort, &sort_args[1], 0, TQSORT_STACK);
			if G_UNLIKELY(THREAD_INVALID_ID == tid) {
				s_warning_once_per(LOG_PERIOD_SECOND,
					"%s(): cannot create new thread: %m", G_STRFUNC);
				atomic_int_inc(&threads_avail);
				xqsort(sort_args[1].sa_base, j, width, compar);
			} else {
				if G_UNLIKELY(tqsort_trace) {
					s_debug("%s(): created thread #%d, j=%d, depth=%d",
						G_STRFUNC, tid, j, depth);
				}
			}
		} else {
			if G_LIKELY(THREAD_INVALID_ID == tid)
				atomic_int_inc(&threads_avail);
			tquicksort(&sort_args[1]);
		}
		break;
	}

	/*
	 * Process the first partition now.
	 */

	switch (first) {
	case TQ_STATE_XQSORT:
		xqsort(a, i, width, compar);
		goto done;
	case TQ_STATE_RECURSE:
		tquicksort(&sort_args[0]);
		goto done;
	case TQ_STATE_THREAD:
	case TQ_STATE_DONE:
		goto done;
	}

	g_assert_not_reached();

done:

	if (THREAD_INVALID_ID != tid) {
		if (-1 == thread_join(tid, NULL)) {
			s_critical("%s(): cannot join with %s: %m",
				G_STRFUNC, thread_id_name(tid));
		}
		atomic_int_inc(&threads_avail);
	}

	return NULL;
}

/**
 * Initialize the maximum amount of threads we can dedicate to tqsort().
 */
static void
tqsort_threads_init(void)
{
	long ncpus = getcpucount();

	/* thread count not to exceed TQSORT_THR_PER_CPU per CPU */
	threads_avail = (ncpus == 1) ? 0 : (ncpus * TQSORT_THR_PER_CPU);
	threads_avail = MIN(threads_avail, THREAD_MAX - 16);

	if G_UNLIKELY(tqsort_trace)
		s_debug("%s(): available threads: %d", G_STRFUNC, threads_avail);
}

/**
 * Sort array with ``n'' elements of size ``s''.  The base ``b'' points to
 * the start of the array.
 *
 * When there are more than TQSORT_ITEMS items to sort, this routine will
 * create threads to accelerate the sorting process.
 */
void
tqsort(void *b, size_t n, size_t s, cmp_fn_t cmp)
{
	static once_flag_t inited;
	sort_args_t sort_args;

	/*
	 * If we have less than TQSORT_ITEMS to sort, chances are that the
	 * overhead of setting up and launching threads will be large enough
	 * to completely offset the gains we'll achieve through concurrency.
	 *		--RAM, 2013-11-16
	 */

	if (n < TQSORT_ITEMS) {
		xqsort(b, n, s, cmp);
	} else {
		ONCE_FLAG_RUN(inited, tqsort_threads_init);

		sort_args.sa_base = b;
		sort_args.sa_nel = n;
		sort_args.sa_width = s;
		sort_args.sa_compar = cmp;
		sort_args.sa_depth = 0;

		(void) tquicksort(&sort_args);
	}
}

/* vi: set ts=4 sw=4 cindent: */
