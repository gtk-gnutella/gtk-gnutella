/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * HTTP range handling.
 *
 * This organizes HTTP ranges into a data structure that can be easily iterated
 * over as a sorted list of http_range_t items.
 *
 * But it also manages the set of HTTP ranges to be able to quickly determine
 * whether a particular range is covered, how many bytes the known ranges
 * cover, etc...  One can efficiently add new HTTP ranges in the set, merging
 * them with the existing ranges.
 *
 * Internally, the HTTP ranges are part of a red-black tree and also held into
 * a one-way list.  This makes it trivial to iterate over the list of ranges
 * and efficient to query for presence of a given range.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "http_range.h"

#include "ascii.h"
#include "buf.h"
#include "erbtree.h"
#include "eslist.h"
#include "misc.h"
#include "parse.h"
#include "str.h"
#include "stringify.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

#if 0
#define HTTP_RANGE_SAFETY_ASSERT	/**< Turn on costly assertion checks */
#endif

#if 0
#define HTTP_RANGE_TESTING			/**< Perform unit testing at startup */
#endif

#if 0
#define HTTP_RANGE_DEBUGGING		/**< Extra debugging */
#endif

#ifdef HTTP_RANGE_SAFETY_ASSERT
#define safety_assert(x)	g_assert(x)
#else
#define safety_assert(x)
#endif

#define http_range_debugging(x)	G_UNLIKELY(http_range_debug > (x))

#ifdef HTTP_RANGE_DEBUGGING
#define HTTP_RANGE_DEBUG(l, msg, ...) G_STMT_START {	\
	if (http_range_debugging(l)) {						\
		g_debug("%s(): " msg, G_STRFUNC, __VA_ARGS__);	\
	}													\
} G_STMT_END

#define HTTP_RANGE_PRINT(l, msg) G_STMT_START {	\
	if (http_range_debugging(l)) {				\
		g_debug("%s(): " msg, G_STRFUNC);		\
	}											\
} G_STMT_END
#else
#define HTTP_RANGE_DEBUG(l, msg, ...)
#define HTTP_RANGE_PRINT(l, msg)
#endif	/* HTTP_RANGE_DEBUGGING */

enum http_range_magic { HTTP_RANGE_MAGIC = 0x6e8d7dfd };

/**
 * Internal representation of an HTTP range in our set.
 *
 * The first two fields MUST be the same as http_range_t so as to let our
 * data structure pass for an http_range_t thanks to structural equivalence.
 */
struct http_range_item {
	/* Leading fields MUST match those in http_range_t */
	filesize_t start;			/**< First byte of range */
	filesize_t end;				/**< Last byte, HTTP_OFFSET_MAX if unbounded */
	rbnode_t node;				/**< Embedded red-black node */
	slink_t lk;					/**< Embedded one-way list */
	enum http_range_magic magic;/**< Magic number, cannot be at the start */
};

static inline void
http_range_item_check(const struct http_range_item * const hri)
{
	g_assert(hri != NULL);
	g_assert(HTTP_RANGE_MAGIC == hri->magic);
	g_assert(hri->start <= hri->end);
}

enum http_rangeset_magic { HTTP_RANGESET_MAGIC = 0x640a1e25 };

/**
 * HTTP range set.
 */
struct http_rangeset {
	enum http_rangeset_magic magic;	/**< Magic number */
	erbtree_t tree;					/**< Tree of HTTP range items */
	eslist_t list;					/**< List of HTTP range items */
	filesize_t length;				/**< Total length of held HTTP ranges */
};

static inline void
http_rangeset_check(const struct http_rangeset * const hrs)
{
	g_assert(hrs != NULL);
	g_assert(HTTP_RANGESET_MAGIC == hrs->magic);
}

static inline bool
http_rangeset_invariant(const struct http_rangeset * const hrs)
{
	g_assert(eslist_count(&hrs->list) == erbtree_count(&hrs->tree));

	return TRUE;		/* So that we can safety_assert() this routine */
}

/**
 * Cast an http_range_item to an http_range structure, thanks to equivalence.
 */
static const http_range_t *
HTTP_RANGE(const struct http_range_item *x)
{
	/* Assert structural equivalence, which guarantees cast safety */

	STATIC_ASSERT(offsetof(http_range_t, start) ==
		offsetof(struct http_range_item, start));
	STATIC_ASSERT(offsetof(http_range_t, end) ==
		offsetof(struct http_range_item, end));

	if G_LIKELY(x != NULL)
		http_range_item_check(x);

	return (const http_range_t *) x;
}

static uint32 http_range_debug;

/**
 * Set debug level.
 */
void
set_http_range_debug(uint32 level)
{
	http_range_debug = level;
}

/**
 * Compares two HTTP ranges so that ranges are equal only when they overlap.
 */
int
http_range_overlap_cmp(const void *a, const void *b)
{
	const http_range_t *ra = a, *rb = b;

	if (ra->end < rb->start)		/* `end' is part of the HTTP range */
		return -1;

	if (rb->end < ra->start)
		return +1;

	return 0;		/* Overlapping ranges are equal */
}

/**
 * Allocate a new HTTP range item.
 */
static struct http_range_item *
http_range_item_alloc(filesize_t start, filesize_t end)
{
	struct http_range_item *hri;

	g_assert(start <= end);

	WALLOC0(hri);
	hri->magic = HTTP_RANGE_MAGIC;
	hri->start = start;
	hri->end = end;

	return hri;
}

/**
 * Free HTTP range item (as generic callback for tree).
 */
static void
http_range_item_free(struct http_range_item *hri)
{
	http_range_item_check(hri);

	hri->magic = 0;
	WFREE(hri);
}

/**
 * @returns the length of the HTTP range.
 */
static inline filesize_t
http_range_item_length(const struct http_range_item * const hri)
{
	http_range_item_check(hri);

	return hri->end - hri->start + 1;
}

/**
 * @return string representation for HTTP range (pointer to static data).
 */
static const char *
http_range_item_to_string(const struct http_range_item * const hri)
{
	buf_t *b = buf_private(G_STRFUNC, FILESIZE_DEC_BUFLEN * 2 + 1);

	if (NULL == hri)
		return "null";

	http_range_item_check(hri);

	buf_printf(b, "%s-%s",
		filesize_to_string(hri->start), filesize_to_string2(hri->end));

	return buf_data(b);
}

/**
 * @return string representation for HTTP range (pointer to static data).
 */
static const char *
http_range_item_to_string2(const struct http_range_item * const hri)
{
	buf_t *b = buf_private(G_STRFUNC, FILESIZE_DEC_BUFLEN * 2 + 1);

	if (NULL == hri)
		return "null";

	http_range_item_check(hri);

	buf_printf(b, "%s-%s",
		filesize_to_string(hri->start), filesize_to_string2(hri->end));

	return buf_data(b);
}

/**
 * Computes the HTTP range length, for assertions.
 *
 * As a side effect, also validates that the list of ranges is sorted and
 * that there are no adjacent ranges (they should always be coalesced).
 */
static inline filesize_t G_UNUSED
http_rangeset_compute_length(const http_rangeset_t *hrs)
{
	slink_t *sl;
	filesize_t length = 0;
	const struct http_range_item *prev = NULL;

	http_rangeset_check(hrs);

	ESLIST_FOREACH(&hrs->list, sl) {
		const struct http_range_item *hri = eslist_data(&hrs->list, sl);
		length += http_range_item_length(hri);
		if (prev != NULL) {
			g_assert(prev->end + 1 < hri->start);
		}
		prev = hri;
	}

	return length;
}

/**
 * Allocate a new empty HTTP range set.
 */
http_rangeset_t *
http_rangeset_create(void)
{
	http_rangeset_t *hrs;

	WALLOC0(hrs);
	hrs->magic = HTTP_RANGESET_MAGIC;
	erbtree_init(&hrs->tree, http_range_overlap_cmp,
		offsetof(struct http_range_item, node));
	eslist_init(&hrs->list, offsetof(struct http_range_item, lk));

	return hrs;
}

/**
 * Clear the HTTP range set, discarding all the ranges.
 */
void
http_rangeset_clear(http_rangeset_t *hrs)
{
	http_rangeset_check(hrs);
	http_rangeset_invariant(hrs);

	eslist_wfree(&hrs->list, sizeof(struct http_range_item));
	erbtree_clear(&hrs->tree);
}

/**
 * Free HTTP range set.
 */
static void
http_rangeset_free(http_rangeset_t *hrs)
{
	http_rangeset_check(hrs);

	http_rangeset_clear(hrs);
	hrs->magic = 0;
	WFREE(hrs);
}

/**
 * Free HTTP range set and nullify its pointer.
 */
void
http_rangeset_free_null(http_rangeset_t **hrs_ptr)
{
	http_rangeset_t *hrs = *hrs_ptr;

	if (hrs != NULL) {
		http_rangeset_free(hrs);
		*hrs_ptr = NULL;
	}
}

/**
 * @return the length covered by the HTTP ranges.
 */
filesize_t
http_rangeset_length(const http_rangeset_t *hrs)
{
	http_rangeset_check(hrs);

	return hrs->length;
}

/**
 * @return the amount of distinct HTTP ranges held.
 */
size_t
http_rangeset_count(const http_rangeset_t *hrs)
{
	http_rangeset_check(hrs);
	safety_assert(http_rangeset_invariant(hrs));

	return eslist_count(&hrs->list);
}

/**
 * Does HTTP range set contain a set overlapping with the specified boundaries.
 *
 * @param hrs		the HTTP range set
 * @param start		start of HTTP range
 * @param end		end (last byte) of HTTP range
 *
 * @return TRUE if one of the held ranges overlaps with the given range.
 */
bool
http_rangeset_contains(const http_rangeset_t *hrs,
	filesize_t start, filesize_t end)
{
	http_range_t range;

	http_rangeset_check(hrs);
	g_assert(start <= end);

	range.start = start;
	range.end = end;

	return erbtree_contains(&hrs->tree, &range);
}

/**
 * Lookup any range overlapping with the specified boundaries.
 *
 * @param hrs		the HTTP range set
 * @param start		start of HTTP range
 * @param end		end (last byte) of HTTP range
 *
 * @return an HTTP range if a match is found, NULL if no overlapping range.
 */
const http_range_t *
http_rangeset_lookup(const http_rangeset_t *hrs,
	filesize_t start, filesize_t end)
{
	http_range_t range;
	const struct http_range_item *hri;

	http_rangeset_check(hrs);
	g_assert(start <= end);

	range.start = start;
	range.end = end;

	hri = erbtree_lookup(&hrs->tree, &range);

	return HTTP_RANGE(hri);
}

/**
 * Lookup the first range (with the smallest starting point) overlapping with
 * the specified boundaries.
 *
 * @param hrs		the HTTP range set
 * @param start		start of HTTP range
 * @param end		end (last byte) of HTTP range
 *
 * @return first HTTP range if a match is found, NULL if no overlapping range.
 */
const http_range_t *
http_rangeset_lookup_first(const http_rangeset_t *hrs,
	filesize_t start, filesize_t end)
{
	http_range_t range;
	const struct http_range_item *hri;

	http_rangeset_check(hrs);
	g_assert(start <= end);

	range.start = start;
	range.end = end;

	hri = erbtree_lookup(&hrs->tree, &range);

	if (NULL == hri)
		return NULL;

	/*
	 * Move to the earliest overlapping range.
	 */

	for (;;) {
		rbnode_t *prev;
		struct http_range_item *prange;

		prev = erbtree_prev(&hri->node);
		if (NULL == prev)
			break;			/* We are already at the first known range */

		prange = erbtree_data(&hrs->tree, prev);
		http_range_item_check(prange);

		if (prange->end < start)
			break;			/* Not overlapping */

		hri = prange;		/* Update earliest overlapping range */
	}

	return HTTP_RANGE(hri);
}

/**
 * Insert a new standalone HTTP range in the set, which does not overlap with
 * any previous or next range nor is adjacent to them.
 *
 * @param hrs		the HTTP range set
 * @param start		start of HTTP range
 * @param end		end (last byte) of HTTP range
 */
static void
http_rangeset_insert_standalone(http_rangeset_t *hrs,
	filesize_t start, filesize_t end)
{
	struct http_range_item *hrnew;
	void *old;
	rbnode_t *prev;

	safety_assert(http_rangeset_invariant(hrs));
	safety_assert(http_rangeset_compute_length(hrs) == hrs->length);

	hrnew = http_range_item_alloc(start, end);

	old = erbtree_insert(&hrs->tree, &hrnew->node);
	g_assert(NULL == old);		/* It's a standalone chunk */

	prev = erbtree_prev(&hrnew->node);
	if (NULL == prev) {
		eslist_prepend(&hrs->list, hrnew);
	} else {
		struct http_range_item *hri = erbtree_data(&hrs->tree, prev);
		eslist_insert_after(&hrs->list, hri, hrnew);
		g_assert(hri->end + 1 < hrnew->start);		/* Not adjacent */
	}

	/*
	 * Ensure we're not adjacent to the next range, if any, otherwise this
	 * routine should not have been called.
	 */

	{
		slink_t *next;

		next = eslist_next(&hrnew->lk);
		if (next != NULL) {
			const struct http_range_item *hri = eslist_data(&hrs->list, next);
			g_assert(hrnew->end + 1 < hri->start);	/* Not adjacent */
		}
	}

	hrs->length += end - start + 1;

	safety_assert(http_rangeset_invariant(hrs));
	safety_assert(http_rangeset_compute_length(hrs) == hrs->length);
}

/**
 * Append a new standalone HTTP range in the set, which does not overlap with
 * any previous range nor is adjacent to it.
 *
 * @param hrs		the HTTP range set
 * @param start		start of HTTP range
 * @param end		end (last byte) of HTTP range
 */
static void
http_rangeset_append(http_rangeset_t *hrs, filesize_t start, filesize_t end)
{
	struct http_range_item *hrnew;
	void *old;

	safety_assert(http_rangeset_invariant(hrs));
	safety_assert(http_rangeset_compute_length(hrs) == hrs->length);

	hrnew = http_range_item_alloc(start, end);
	old = erbtree_insert(&hrs->tree, &hrnew->node);
	g_assert(NULL == old);

	eslist_append(&hrs->list, hrnew);
	hrs->length += http_range_item_length(hrnew);

	safety_assert(http_rangeset_invariant(hrs));
	safety_assert(http_rangeset_compute_length(hrs) == hrs->length);
}

/**
 * Coalesce all the HTTP ranges between ``start'' and ``end'' which overlap
 * or can be coalesced with ranges from ``left'' to ``right''.
 *
 * Upon return, ``left'' is the coalesced range and all HTTP ranges afterwards
 * and up to ``right'' have been removed, provided ``right'' is different from
 * ``left''.
 */
static void
http_rangeset_coalesce_ranges(http_rangeset_t *hrs,
	struct http_range_item *left, struct http_range_item *right,
	filesize_t start, filesize_t end)
{
	filesize_t length, lower, upper, newlen;

	http_rangeset_check(hrs);
	http_range_item_check(left);
	http_range_item_check(right);
	g_assert(start <= end);
	g_assert(left->start <= right->start);
	g_assert(left->end <= right->end);
	g_assert(right->start <= end + 1);
	g_assert(left->end + 1 >= start);
	safety_assert(http_rangeset_invariant(hrs));
	safety_assert(http_rangeset_compute_length(hrs) == hrs->length);

	HTTP_RANGE_DEBUG(5, "coalescing for %s-%s",
		filesize_to_string(start), filesize_to_string2(end));
	HTTP_RANGE_DEBUG(5, "left=%s, right=%s",
		http_range_item_to_string(left), http_range_item_to_string2(right));

	lower = MIN(left->start, start);
	upper = MAX(right->end, end);

	length = http_range_item_length(left);
	left->start = lower;

	if (left == right)
		goto coalesce;

	/*
	 * Remove all the ranges after ``left'', updating the running length.
	 */

	for (;;) {
		struct http_range_item *nrange;
		slink_t *next;
		void *removed;

		/*
		 * We use the one-way list to move from one range to the next, but
		 * we need to remove ranges from both the list and the tree.
		 */

		next = eslist_next(&left->lk);
		g_assert(next != NULL);

		nrange = eslist_data(&hrs->list, next);
		length += http_range_item_length(nrange);
		removed = eslist_remove_after(&hrs->list, left);
		g_assert(nrange == removed);

		HTTP_RANGE_DEBUG(5, "removing %s-%s",
			filesize_to_string(nrange->start),
			filesize_to_string2(nrange->end));

		erbtree_remove(&hrs->tree, &nrange->node);
		http_range_item_free(nrange);

		if (nrange == right)
			break;
	}

coalesce:

	/*
	 * Coalesce the whole range in the left-most range item.
	 */

	left->end = upper;
	newlen = http_range_item_length(left);		/* New spanned length */

	g_assert(newlen >= length);

	hrs->length += newlen - length;

	HTTP_RANGE_DEBUG(5, "final range is %s-%s, added %s byte%s",
		filesize_to_string(left->start),
		filesize_to_string2(left->end),
		filesize_to_string3(newlen - length), plural(newlen - length));

	safety_assert(http_rangeset_invariant(hrs));
	safety_assert(http_rangeset_compute_length(hrs) == hrs->length);
}

/*
 * Find the lowest overlapping or right-adjacent range given lower boundary.
 *
 * @param hrs		the HTTP range set
 * @param first		lookup starting position
 * @param lower		lower boundary (right-adjacent position)
 * @param upper		upper boundary for determining overlapping condition
 * @param last		last looked-up range
 *
 * @return first (left-most) range overlapping or right-adjacent with lower,
 * NULL if there is none.
 */
static struct http_range_item *
http_rangeset_lowest_lookup(const http_rangeset_t *hrs,
	const struct http_range_item *first, filesize_t lower, filesize_t upper,
	struct http_range_item **last)
{
	const struct http_range_item *hrlast = first;

	http_range_item_check(first);
	g_assert(lower <= upper);
	g_assert(last != NULL);

	for (;;) {
		slink_t *next;

		*last = deconstify_pointer(hrlast);

		if (hrlast->start > upper)
			break;			/* No overlap possible, we're past upper point */

		if (hrlast->end + 1 >= lower)
			return deconstify_pointer(hrlast);	/* Found match */

		next = eslist_next(&hrlast->lk);
		if (NULL == next) {
			*last = NULL;	/* Tell caller that no range is suitable */
			break;			/* Reached the tail of the list */
		}

		hrlast = eslist_data(&hrs->list, next);
		http_range_item_check(hrlast);
	}

	/*
	 * Even though we do not return a match, we leave in ``last'' the last
	 * chunk we visited, or NULL if we reached the end of the list with no
	 * possible overlap and with all the ranges well before the ``lower''
	 * point, i.e. with no adjacent merging possible.
	 */

	return NULL;		/* No match found */
}

/*
 * Find the highest overlapping or left-adjacent range given upper boundary
 * and first overlapping or right-adjacent range.
 *
 * @param hrs		the HTTP range set
 * @param first		lookup starting position, overlapping or right-adjacent
 * @param upper		upper boundary (target for left-adjacent position)
 *
 * @return last (right-most) range overlapping or left-adjacent with upper.
 */
static struct http_range_item *
http_rangeset_highest_lookup(const http_rangeset_t *hrs,
	struct http_range_item *first, filesize_t upper)
{
	struct http_range_item *hrlast = first;

	http_range_item_check(first);

	for (;;) {
		slink_t *next;
		struct http_range_item *nrange;

		next = eslist_next(&hrlast->lk);
		if (NULL == next)
			break;			/* Reached the tail of the list */

		nrange = eslist_data(&hrs->list, next);
		http_range_item_check(nrange);

		if (upper + 1 < nrange->start)
			break;			/* No overlap and not adjacent */

		hrlast = nrange;
	}

	return hrlast;
}

/**
 * Insert a new HTTP range in the set, merging with any existing range that
 * it would overlap with or with which it would become adjacent.
 *
 * Because of coalescing, this routine can perform in O(n).  However, when
 * inserting without coalescing, or when the inserted range already exists,
 * it will perform in O(log n).
 *
 * @param hrs		the HTTP range set
 * @param start		start of HTTP range
 * @param end		end (last byte) of HTTP range
 */
void
http_rangeset_insert(http_rangeset_t *hrs, filesize_t start, filesize_t end)
{
	struct http_range_item *hri, *hrlast;
	http_range_t range;

	http_rangeset_check(hrs);
	g_assert(start <= end);
	http_rangeset_invariant(hrs);
	safety_assert(http_rangeset_compute_length(hrs) == hrs->length);

	range.start = start;
	range.end = end;

	HTTP_RANGE_DEBUG(5, "adding %s-%s to existing %s",
		filesize_to_string(start), filesize_to_string2(end),
		http_rangeset_to_string(hrs));

	hri = erbtree_lookup(&hrs->tree, &range);

	if (NULL == hri) {
		/*
		 * Range overlaps with nothing.
		 *
		 * See whether we can coalesce it with the previous range, and
		 * if not, with the next range.
		 */

		if (start != 0) {
			range.start = range.end = start - 1;
			hri = erbtree_lookup(&hrs->tree, &range);
		}

		if (NULL == hri) {
			/* No coalescing possible with previous range */

			HTTP_RANGE_PRINT(5, "cannot coalesce with previous");

			range.start = range.end = end + 1;
			hri = erbtree_lookup(&hrs->tree, &range);

			if (NULL == hri) {
				/* No coalescing possible with next range either */

				HTTP_RANGE_PRINT(5, "cannot coalesce with next");

				http_rangeset_insert_standalone(hrs, start, end);
				goto done;
			}

			/*
			 * Can coalesce with the next range but not with the previous.
			 */

			HTTP_RANGE_PRINT(5, "can coalesce with next only");

			http_range_item_check(hri);
			g_assert(end + 1 == hri->start);

			hrs->length += end - start + 1;
			hri->start = start;
			goto done;
		} else {
			struct http_range_item *hrnext;
			slink_t *sln;
			void *next;

			http_range_item_check(hri);

			HTTP_RANGE_PRINT(5, "can coalesce with previous");

			/*
			 * Can coalesce with the previous rnage, see whether we can also
			 * coalesce with the next range.
			 */

			g_assert(hri->end + 1 == start);

			sln = eslist_next(&hri->lk);
			hrnext = eslist_data(&hrs->list, sln);

			if (NULL == hrnext || hrnext->start > end + 1) {
				/* No coalescing possible with the next range */

				HTTP_RANGE_DEBUG(5, "cannot coalesce with next%s",
					NULL == hrnext ? " (nothing there)" : "");

				hrs->length += end - start + 1;
				hri->end = end;
				goto done;
			}

			/*
			 * The new chunk fits exactly between the previous and the next
			 * range, hence we can remove the next range and merge it
			 * with the previous one.
			 */

			HTTP_RANGE_DEBUG(5, "exact in-between fit with %s and %s",
				http_range_item_to_string(hri),
				http_range_item_to_string2(hrnext));

			http_range_item_check(hrnext);
			g_assert(end + 1 == hrnext->start);

			erbtree_remove(&hrs->tree, &hrnext->node);
			next = eslist_remove_after(&hrs->list, hri);

			g_assert_log(next == hrnext,
				"next: %s, hrnext: %s",
				http_range_item_to_string(next),
				http_range_item_to_string2(hrnext));

			hri->end = hrnext->end;
			hrs->length += end - start + 1;
			http_range_item_free(hrnext);
			goto done;
		}
		g_assert_not_reached();
	}

	/*
	 * If range is already contained, do nothing.
	 */

	if (start >= hri->start && end <= hri->end) {
		HTTP_RANGE_PRINT(5, "range already contained");
		goto done;
	}

	/*
	 * Look for the earliest overlapping or right-adjacent range.
	 */

	for (;;) {
		rbnode_t *prev;
		struct http_range_item *prange;

		prev = erbtree_prev(&hri->node);
		if (NULL == prev)
			break;			/* We are already at the first known range */

		prange = erbtree_data(&hrs->tree, prev);
		http_range_item_check(prange);

		if (prange->end + 1 < start)
			break;			/* No overlap and not adjacent */

		hri = prange;		/* Update earliest overlapping range */
	}

	HTTP_RANGE_DEBUG(5, "earliest overalaping/adjacent is %s",
		http_range_item_to_string(hri));

	/*
	 * Find the highest overlapping or left-adjacent range after the
	 * earliest overlapping or right-adjacent range `hri'.
	 */

	hrlast = http_rangeset_highest_lookup(hrs, hri, end);

	HTTP_RANGE_DEBUG(5, "last overalaping/adjacent is %s",
		http_range_item_to_string(hrlast));

	/*
	 * We can now compute the union between the range we're adding and
	 * all the chunks between ``hri'' and ``hrlast'' (both included).
	 */

	http_rangeset_coalesce_ranges(hrs, hri, hrlast, start, end);

	/* FALL THROUGH */

done:
	http_rangeset_invariant(hrs);
	safety_assert(http_rangeset_compute_length(hrs) == hrs->length);
}

/**
 * Start iteration over the list of HTTP ranges.
 *
 * @param hrs		the HTTP range set
 *
 * @return NULL if the set is empty, or the first HTTP range.
 */
const http_range_t *
http_range_first(const http_rangeset_t *hrs)
{
	struct http_range_item *hri;
	slink_t *first;

	/*
	 * This is a convenience routine for HTTP_RANGE_FOREACH() hence it must
	 * accept a NULL argument, in which case of course there is nothing
	 * to iterate over.
	 */

	if (NULL == hrs)
		return NULL;

	http_rangeset_check(hrs);

	first = eslist_first(&hrs->list);
	if (NULL == first)
		return NULL;

	hri = eslist_data(&hrs->list, first);

	return HTTP_RANGE(hri);
}

/**
 * Continue iteration over the list of HTTP ranges.
 *
 * @param hrs		the HTTP range set
 * @param r			the previous HTTP range iterated over
 *
 * @return NULL if the item was the last one, or the next HTTP range.
 */
const http_range_t *
http_range_next(const http_rangeset_t *hrs, const http_range_t *r)
{
	struct http_range_item *hri;
	const struct http_range_item *hitem;
	slink_t *next;

	http_rangeset_check(hrs);

	hitem = (const struct http_range_item *) r;
	http_range_item_check(hitem);

	next = eslist_next(&hitem->lk);
	if (NULL == next)
		return NULL;

	hri = eslist_data(&hrs->list, next);

	return HTTP_RANGE(hri);
}

/**
 * Possible returned values from parsing callback.
 */
enum http_range_parser_status {
	HTTP_RANGE_PARSER_OK = 0,	/* OK, range accepted */
	HTTP_RANGE_PARSER_STOP,		/* OK, range accepted, stop parsing */
	HTTP_RANGE_OVERLAP,			/* Partial overlapping with another range */
	HTTP_RANGE_DUPLICATE,		/* Range was already fully known */
};

/**
 * Callback invoked for each valid range found by http_range_parser().
 *
 * @param start		the first byte of the range
 * @param end		the last byte included in the range
 * @param data		user-supplied extra argument
 *
 * @return TRUE if we can continue the parsing, FALSE if parsing should stop.
 */
typedef enum http_range_parser_status (*http_range_parser_cb_t)(
	filesize_t start, filesize_t end, void *data);

/**
 * Invoke range-adding callback
 *
 * @return TRUE if we need to stop processing.
 */
static bool
http_range_parser_add_range(const char *where,
	filesize_t start, filesize_t end,
	http_range_parser_cb_t cb, void *data,
	size_t count, const char *field, const char *vendor, size_t offset,
	const char *value)
{
	switch ((*cb)(start, end, data)) {
	case HTTP_RANGE_PARSER_OK:
		break;
	case HTTP_RANGE_PARSER_STOP:
		return TRUE;
	case HTTP_RANGE_OVERLAP:
		if (http_range_debugging(0)) {
			g_warning("%s(): weird %s header from <%s>, offset %zu "
				"(overlapping range #%zu %s-%s): %s",
				where, field, vendor, offset, count,
				filesize_to_string(start), filesize_to_string(end),
				value);
		}
		break;
	case HTTP_RANGE_DUPLICATE:
		if (http_range_debugging(0)) {
			g_warning("%s(): weird %s header from <%s>, offset %zu "
				"(duplicate range #%zu %s-%s): %s",
				where, field, vendor, offset, count,
				filesize_to_string(start), filesize_to_string(end),
				value);
		}
		break;
	}
	return FALSE;
}

/**
 * Parse a Range: header from an HTTP request, invoking a callback for each
 * valid range we find.  Invalid ranges are ignored.
 *
 * Only "bytes" ranges are supported.
 *
 * When parsing a "bytes=" style, it means it's a request, so we allow
 * negative ranges.  Otherwise, for "bytes " specifications, it's a reply
 * and we ignore negative ranges.
 *
 * `size' gives the length of the resource, to resolve negative ranges and
 * make sure we don't have ranges that extend past that size.
 *
 * The `field' and `vendor' arguments are only there to log errors, if any.
 *
 * @param field		the name of the HTTP header we're parsing, for logging
 * @param value		the HTTP header value where ranges are expected
 * @param size		the total known size of the resource, or HTTP_OFFSET_MAX
 * @param vendor	the user-agent of the requester/server, for logging
 * @param cb		parsing callback to invoke for each range found
 * @param data		extra callback argument
 *
 * @return TRUE if OK, FALSE if we had to abort due to a syntax error.
 */
static bool
http_range_parser(
	const char *field, const char *value, filesize_t size, const char *vendor,
	http_range_parser_cb_t cb, void *data)
{
	static const char unit[] = "bytes";
	const char *str = value;
	uchar c;
	filesize_t start, end;
	bool request = FALSE;		/* True if 'bytes=' is seen */
	bool has_start, has_end, skipping, minus_seen;
	int count = 0;

	g_assert(size != 0);
	vendor = vendor != NULL ? vendor : "unknown";

	if (NULL != (str = is_strprefix(str, unit))) {
		c = *str;
		if (!is_ascii_space(c) && c != '=') {
			if (http_range_debugging(0)) {
				g_warning("%s(): improper %s header from <%s>: %s",
					G_STRFUNC, field, vendor, value);
			}
			return FALSE;
		}
	} else {
		if (http_range_debugging(0)) {
			g_warning("%s(): improper %s header from <%s> (not bytes?): %s",
				G_STRFUNC, field, vendor, value);
		}
		return FALSE;
	}

	/*
	 * Move to the first non-space char.
	 * Meanwhile, if we see a '=', we know it's a request-type range header.
	 */

	while ((c = *str)) {
		if ('=' == c) {
			if (request) {
				if (http_range_debugging(0)) {
					g_warning("%s(): improper %s header from <%s> "
						"(multiple '='): %s", G_STRFUNC, field, vendor, value);
				}
				return FALSE;
			}
			request = TRUE;
			str++;
			continue;
		}
		if (is_ascii_space(c)) {
			str++;
			continue;
		}
		break;
	}

	start = 0;
	has_start = FALSE;
	has_end = FALSE;
	end = size - 1;
	skipping = FALSE;
	minus_seen = FALSE;

	while ((c = *str++)) {
		if (is_ascii_space(c))
			continue;

		if (',' == c) {
			if (skipping) {
				skipping = FALSE;		/* ',' is a resynch point */
				continue;
			}

			if (!minus_seen) {
				if (http_range_debugging(0)) {
					g_warning("%s(): weird %s header from <%s>, offset %zu "
						"(no range?): %s",
						G_STRFUNC, field, vendor, (str - value) - 1, value);
				}
				goto reset;
			}

			if (HTTP_OFFSET_MAX == start && !has_end) {
				/* Bad negative range */
				if (http_range_debugging(0)) {
					g_warning("%s(): weird %s header from <%s>, offset %zu "
						"(incomplete negative range): %s",
						G_STRFUNC, field, vendor, (str - value) - 1, value);
				}
				goto reset;
			}

			if (start > end) {
				if (http_range_debugging(0)) {
					g_warning("%s(): weird %s header from <%s>, offset %zu "
						"(swapped range?): %s",
						G_STRFUNC, field, vendor, (str - value) - 1, value);
				}
				goto reset;
			}

			/*
			 * Found a valid range, invoke callback for processing it.
			 */

			count++;

			if (
				http_range_parser_add_range(G_STRFUNC,
					start, end, cb, data,
					count, field, vendor, (str - value) - 1, value)
			)
				return TRUE;

			goto reset;
		}

		if (skipping)				/* Waiting for a ',' */
			continue;

		if ('-' == c) {
			if (minus_seen) {
				if (http_range_debugging(0)) {
					g_warning("%s(): weird %s header from <%s>, "
						"offset %zu (spurious '-'): %s",
						G_STRFUNC, field, vendor, (str - value) - 1, value);
				}
				goto resync;
			}
			minus_seen = TRUE;
			if (!has_start) {		/* Negative range */
				if (!request) {
					if (http_range_debugging(0)) {
						g_warning("%s(): weird %s header from <%s>, offset %zu "
							"(negative range in reply): %s",
							G_STRFUNC, field, vendor, (str - value) - 1, value);
					}
					goto resync;
				}
				start = HTTP_OFFSET_MAX;	/* Indicates negative range */
				has_start = TRUE;
			}
			continue;
		}

		if (is_ascii_digit(c)) {
			int error;
			const char *dend;
			uint64 val = parse_uint64(str - 1, &dend, 10, &error);

			/* Started with digit! */
			g_assert(dend != (str - 1));

			str = dend;		/* Skip number */

			if (has_end) {
				if (http_range_debugging(0)) {
					g_warning("%s(): weird %s header from <%s>, offset %zu "
						"(spurious boundary %s): %s",
						G_STRFUNC, field, vendor, (str - value) - 1,
						uint64_to_string(val), value);
				}
				goto resync;
			}

			if (val >= size) {
				/*
				 * ``last-byte-pos'' may extend beyond the actual
				 * filesize. It's more a response limit than an exact
				 * range end specifier.
				 */
				val = size - 1;
			}

			if (has_start) {
				if (!minus_seen) {
					if (http_range_debugging(0)) {
						g_warning("%s(): weird %s header from <%s>, offset %zu "
							"(no '-' before boundary %s): %s",
							G_STRFUNC, field, vendor, (str - value) - 1,
							uint64_to_string(val), value);
					}
					goto resync;
				}
				if (HTTP_OFFSET_MAX == start) {			/* Negative range */
					start = (val > size) ? 0 : size - val;	/* Last bytes */
					end = size - 1;
				} else {
					end = val;
				}
				has_end = TRUE;
			} else {
				start = val;
				has_start = TRUE;
			}
			continue;
		}

		if (http_range_debugging(0)) {
			g_warning("%s(): weird %s header from <%s>, offset %zu "
				"(unexpected char '%c'): %s",
				G_STRFUNC, field, vendor, (str - value) - 1, c, value);
		}

		/* FALL THROUGH */

	resync:
		skipping = TRUE;
	reset:
		start = 0;
		has_start = FALSE;
		has_end = FALSE;
		minus_seen = FALSE;
		end = size - 1;
	}

	/*
	 * Handle trailing range, if needed.
	 */

	if (minus_seen) {
		if (HTTP_OFFSET_MAX == start && !has_end) {	/* Bad negative range */
			if (http_range_debugging(0)) {
				g_warning("%s(): weird %s header from <%s>, offset %zu "
					"(incomplete trailing negative range): %s",
					G_STRFUNC, field, vendor, (str - value) - 1, value);
			}
			goto final;
		}

		if (start > end) {
			if (http_range_debugging(0)) {
				g_warning("%s(): weird %s header from <%s>, offset %zu "
					"(swapped trailing range?): %s",
					G_STRFUNC, field, vendor, (str - value) - 1, value);
			}
			goto final;
		}

		count++;

		if (
			http_range_parser_add_range(G_STRFUNC,
				start, end, cb, data,
				count, field, vendor, (str - value) - 1, value)
		)
			return TRUE;
	}

	/* FALL THROUGH */

final:

	if (http_range_debugging(0) && 0 == count) {
		g_warning("%s(): retained no ranges in %s header from <%s>: %s",
			G_STRFUNC, field, vendor, value);
	}

	return TRUE;
}

/**
 * @returns a pointer to static data, containing the available ranges.
 */
const char *
http_rangeset_to_string(const http_rangeset_t *hrs)
{
	str_t *s = str_private(G_STRFUNC, 80);
	static const char comma[] = ", ";
	slink_t *sl;

	http_rangeset_check(hrs);
	http_rangeset_invariant(hrs);

	str_reset(s);

	ESLIST_FOREACH(&hrs->list, sl) {
		const struct http_range_item *hri = eslist_data(&hrs->list, sl);
		char sbuf[FILESIZE_DEC_BUFLEN], ebuf[FILESIZE_DEC_BUFLEN];
		size_t slen, elen;

		if (0 != str_len(s))
			str_cat_len(s, comma, CONST_STRLEN(comma));

		slen = uint64_to_string_buf(hri->start, sbuf, sizeof sbuf);
		elen = uint64_to_string_buf(hri->end, ebuf, sizeof ebuf);

		str_cat_len(s, sbuf, slen); 
		str_putc(s, '-');
		str_cat_len(s, ebuf, elen); 
	}

	return str_2c(s);
}

/**
 * Merge second rangeset into the first.
 *
 * @param hdest		the destination range set
 * @param hsrc		the source range set, ranges to merge into destination
 *
 * @return new length covered by the merged set.
 */
filesize_t
http_rangeset_merge(http_rangeset_t *hdest, const http_rangeset_t *hsrc)
{
	slink_t *sld, *sls;

	http_rangeset_check(hdest);
	http_rangeset_check(hsrc);
	http_rangeset_invariant(hdest);
	http_rangeset_invariant(hsrc);
	safety_assert(http_rangeset_compute_length(hdest) == hdest->length);

	/*
	 * Use a linear walk with on-the-fly merging, running in O(m + n).
	 *
	 * This is better than looping over the second set and inserting the ranges
	 * into the first because that would be about O(n * log(m + n)), with
	 * n being the count of the second set and m the count of the first set,
	 * assuming no coalescing is done, tending towards O(n * m) in the worst
	 * case.
	 */

	HTTP_RANGE_DEBUG(5, "destination is %s", http_rangeset_to_string(hdest));
	HTTP_RANGE_DEBUG(5, "source is %s", http_rangeset_to_string(hsrc));

	sld = eslist_first(&hdest->list);

	ESLIST_FOREACH(&hsrc->list, sls) {
		const struct http_range_item *hri = eslist_data(&hsrc->list, sls);

		http_range_item_check(hri);

		HTTP_RANGE_DEBUG(5, "dealing with %s", http_range_item_to_string(hri));

		if (NULL == sld) {
			/*
			 * Reached end of destination list, all its ranges come before
			 * the sourced ones, so we can just append all the ranges we see.
			 */

			HTTP_RANGE_PRINT(5, "reached destination end, appending");

			http_rangeset_append(hdest, hri->start, hri->end);
		} else {
			const struct http_range_item *hcur = eslist_data(&hdest->list, sld);
			struct http_range_item *left, *last;

			HTTP_RANGE_DEBUG(5, "current merge point is %s",
				http_range_item_to_string(hcur));

			/*
			 * Look for a chunk in the destination list that is adjacent to
			 * the left of `hri', or which is overlapping with it.
			 */

			left = http_rangeset_lowest_lookup(hdest, hcur,
					hri->start, hri->end, &last);

			if (NULL == left) {
				if (NULL == last) {
					/*
					 * We reached the end of the list without finding a match or
					 * an adjacent range we can merge with, so we're back to the
					 * appending case.
					 */

					HTTP_RANGE_PRINT(5, "will be appending from now on");

					sld = NULL;
					http_rangeset_append(hdest, hri->start, hri->end);
				} else {
					/*
					 * The range we last considered is not overlapping nor is
					 * it adjacent on its right to the range we're attempting
					 * to insert.  And there is no match for an overlapping
					 * or adjacent range on our left.
					 *
					 * If the last range is adjacent on its left to the range
					 * we're adding, then we can merge, otherwise we can
					 * insert a standalone range.
					 */

					HTTP_RANGE_DEBUG(5, "last lowest range was %s",
						http_range_item_to_string(last));

					sld = &last->lk;	/* Next merging starting point */

					g_assert(last->start > hri->end);

					if (hri->end + 1 == last->start) {
						/* Coalesce */

						HTTP_RANGE_PRINT(5, "coalescing last lowest range");

						last->start = hri->start;
						hdest->length += http_range_item_length(hri);
					} else {
						/* No colaescing possible, insert standalone range */

						HTTP_RANGE_DEBUG(5, "cannot coalesce %s with %s",
							http_range_item_to_string(hri),
							http_range_item_to_string(last));

						http_rangeset_insert_standalone(hdest,
							hri->start, hri->end);
					}
				}
			} else {
				struct http_range_item *right;

				HTTP_RANGE_DEBUG(5, "lowest overlapping/adjacent is %s",
					http_range_item_to_string(left));

				right = http_rangeset_highest_lookup(hdest, left, hri->end);

				HTTP_RANGE_DEBUG(5, "highest overlapping/adjacent is %s",
					http_range_item_to_string(right));

				http_rangeset_coalesce_ranges(hdest, left, right,
					hri->start, hri->end);

				HTTP_RANGE_DEBUG(5, "merged item is %s",
					http_range_item_to_string(left));

				sld = &left->lk;		/* Last merging point */
			}
		}
	}

	HTTP_RANGE_DEBUG(5, "result is %s", http_rangeset_to_string(hdest));

	http_rangeset_invariant(hdest);
	safety_assert(http_rangeset_compute_length(hdest) == hdest->length);

	return hdest->length;
}

/**
 * Are two rangesets equal?
 */
bool
http_rangeset_equal(const http_rangeset_t *hrs1, const http_rangeset_t *hrs2)
{
	const slink_t *sl1, *sl2;

	http_rangeset_check(hrs1);
	http_rangeset_check(hrs2);

	if (hrs1->length != hrs2->length)
		return FALSE;

	for (
		sl1 = eslist_first(&hrs1->list), sl2 = eslist_first(&hrs2->list);
		sl1 != NULL && sl2 != NULL;
		sl1 = eslist_next(sl1), sl2 = eslist_next(sl2)
	) {
		const struct http_range_item *r1 = eslist_data(&hrs1->list, sl1);
		const struct http_range_item *r2 = eslist_data(&hrs2->list, sl2);

		if (r1->start != r2->start || r1->end != r2->end)
			return FALSE;
	}

	return NULL == sl1 && NULL == sl2;	/* Same list length, ranges identical */
}

/**
 * Range parsing callback to insert new range to the set.
 */
static enum http_range_parser_status
http_rangeset_fill(filesize_t start, filesize_t end, void *data)
{
	http_rangeset_t *hrs = data;
	filesize_t oldlength, newlength;

	http_rangeset_check(hrs);
	g_assert(start <= end);

	oldlength = hrs->length;
	newlength = oldlength + end - start + 1;

	http_rangeset_insert(hrs, start, end);

	if (newlength == hrs->length)
		return HTTP_RANGE_PARSER_OK;

	return hrs->length == oldlength ? HTTP_RANGE_DUPLICATE : HTTP_RANGE_OVERLAP;
}

/**
 * Parse an HTTP range header to extract all the advertised ranges in a new
 * range set.
 *
 * @param field		the name of the HTTP header we're parsing, for logging
 * @param value		the HTTP header value where ranges are expected
 * @param size		the total known size of the resource, or HTTP_OFFSET_MAX
 * @param vendor	the user-agent of the requester/server, for logging
 *
 * @return a new range set if OK, NULL if we could not parse the header.
 */
http_rangeset_t *
http_rangeset_extract(
	const char *field, const char *value, filesize_t size, const char *vendor)
{
	http_rangeset_t *hrs;
	bool ok;

	hrs = http_rangeset_create();
	ok = http_range_parser(field, value, size, vendor, http_rangeset_fill, hrs);

	if (!ok) {
		http_rangeset_free(hrs);
		return NULL;
	}

	return hrs;
}

struct http_range_extract_ctx {
	filesize_t start;
	filesize_t end;
	uint has_range:1;
	uint has_multi:1;
};

/**
 * Range parsing callback to extract the first range we see.
 */
static enum http_range_parser_status
http_range_got(filesize_t start, filesize_t end, void *data)
{
	struct http_range_extract_ctx *ctx = data;

	g_assert(start <= end);

	if (ctx->has_range) {
		ctx->has_multi = TRUE;
		return HTTP_RANGE_PARSER_STOP;
	}

	ctx->start = start;
	ctx->end = end;
	ctx->has_range = TRUE;

	return HTTP_RANGE_PARSER_OK;
}

/**
 * Parse an HTTP range header and extract the first range.
 *
 * @param field		the name of the HTTP header we're parsing, for logging
 * @param value		the HTTP header value where ranges are expected
 * @param size		the total known size of the resource, or HTTP_OFFSET_MAX
 * @param vendor	the user-agent of the requester/server, for logging
 * @param start		where the start of the extracted range is written
 * @param end		where the end of the extracted range is written
 *
 * @return HTTP_RANGE_NONE on parsing error, HTTP_RANGE_SINGLE if there was
 * only a single range, HTTP_RANGE_MULTI if multiple ranges were present.
 */
enum http_range_extract_status
http_range_extract_first(
	const char *field, const char *value, filesize_t size, const char *vendor,
	filesize_t *start, filesize_t *end)
{
	struct http_range_extract_ctx ctx;
	bool ok;

	ZERO(&ctx);
	ok = http_range_parser(field, value, size, vendor, http_range_got, &ctx);

	if (!ok || !ctx.has_range)
		return HTTP_RANGE_NONE;

	if (start != NULL)	*start = ctx.start;
	if (end != NULL)	*end = ctx.end;

	return ctx.has_multi ? HTTP_RANGE_MULTI : HTTP_RANGE_SINGLE;
}

/***
 *** Unit tests.
 ***/

#ifdef HTTP_RANGE_TESTING

static const http_range_t hrtest_even[] = {
	{ 0, 0 },
	{ 2, 2 },
	{ 4, 4 },
	{ 6, 6 },
	{ 8, 8 },
};

static const http_range_t hrtest_odd[] = {
	{ 1, 1 },
	{ 3, 3 },
	{ 5, 5 },
	{ 7, 7 },
	{ 9, 9 },
};

static const http_range_t hrtest_overlap[] = {
	{ 0, 1 },
	{ 3, 9 },
};

static const http_range_t hrtest_partial[] = {
	{ 1, 2 },
	{ 4, 5 },
	{ 9, 10 },
	{ 15, 19 },
	{ 21, 24 },
	{ 26, 29 },
	{ 31, 32 },
	{ 37, 41 },
	{ 43, 43 },
	{ 45, 47 },
	{ 50, 50 },
	{ 58, 58 },
};

static const http_range_t hrtest_added[] = {
	{ 0, 4 },
	{ 7, 11 },
	{ 17, 18 },
	{ 22, 27 },
	{ 34, 49 },
	{ 51, 53 },
	{ 51, 53 },
	{ 55, 60 },
};

static const http_range_t hrtest_result[] = {
	{ 0, 5 },
	{ 7, 11 },
	{ 15, 19 },
	{ 21, 29 },
	{ 31, 32 },
	{ 34, 53 },
	{ 55, 60 },
};

/**
 * Test utility to create a rangeset from an array of ranges.
 */
static http_rangeset_t *
http_range_test_load(const http_range_t ranges[], size_t cnt)
{
	http_rangeset_t *hrs;
	size_t i;

	hrs = http_rangeset_create();
	for (i = 0; i < cnt; i++) {
		http_rangeset_insert(hrs, ranges[i].start, ranges[i].end);
	}

	return hrs;
}

#define HTTP_RANGE_TEST_LOAD(x)	http_range_test_load((x), G_N_ELEMENTS(x))

/**
 * Perform unit tests for HTTP ranges.
 */
void G_COLD
http_range_test(void)
{
	http_rangeset_t *hrs_even, *hrs_odd, *hrs_over;
	http_rangeset_t *hrs_partial, *hrs_added, *hrs_result;
	const http_range_t *hr;
	uint test = 0;
	str_t *s;

	hrs_even = http_range_test_load(hrtest_even, G_N_ELEMENTS(hrtest_even));
	hrs_odd = http_range_test_load(hrtest_odd, G_N_ELEMENTS(hrtest_odd));

	g_assert(G_N_ELEMENTS(hrtest_even) == http_rangeset_length(hrs_even));
	g_assert(G_N_ELEMENTS(hrtest_even) == http_rangeset_count(hrs_even));
	g_assert(G_N_ELEMENTS(hrtest_odd) == http_rangeset_length(hrs_odd));
	g_assert(G_N_ELEMENTS(hrtest_odd) == http_rangeset_count(hrs_odd));

	HTTP_RANGE_FOREACH(hrs_odd, hr) {
		http_rangeset_insert(hrs_even, hr->start, hr->end);
	}

	g_assert(http_rangeset_length(hrs_even) ==
		G_N_ELEMENTS(hrtest_even) + G_N_ELEMENTS(hrtest_odd));
	g_assert(1 == http_rangeset_count(hrs_even));

	http_rangeset_free_null(&hrs_even);
	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);

	hrs_even = HTTP_RANGE_TEST_LOAD(hrtest_even);
	http_rangeset_merge(hrs_even, hrs_odd);

	g_assert(http_rangeset_length(hrs_even) ==
		G_N_ELEMENTS(hrtest_even) + G_N_ELEMENTS(hrtest_odd));
	g_assert(1 == http_rangeset_count(hrs_even));

	http_rangeset_free_null(&hrs_even);
	http_rangeset_free_null(&hrs_odd);
	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);

	hrs_even = HTTP_RANGE_TEST_LOAD(hrtest_even);
	hrs_odd = HTTP_RANGE_TEST_LOAD(hrtest_odd);

	HTTP_RANGE_FOREACH(hrs_even, hr) {
		http_rangeset_insert(hrs_odd, hr->start, hr->end);
	}

	g_assert(http_rangeset_length(hrs_odd) ==
		G_N_ELEMENTS(hrtest_even) + G_N_ELEMENTS(hrtest_odd));
	g_assert(1 == http_rangeset_count(hrs_odd));

	http_rangeset_free_null(&hrs_odd);
	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);

	hrs_odd = HTTP_RANGE_TEST_LOAD(hrtest_odd);
	http_rangeset_merge(hrs_odd, hrs_even);

	g_assert(http_rangeset_length(hrs_odd) ==
		G_N_ELEMENTS(hrtest_even) + G_N_ELEMENTS(hrtest_odd));
	g_assert(1 == http_rangeset_count(hrs_odd));

	http_rangeset_free_null(&hrs_even);
	http_rangeset_free_null(&hrs_odd);
	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);

	hrs_even = HTTP_RANGE_TEST_LOAD(hrtest_even);
	hrs_over = HTTP_RANGE_TEST_LOAD(hrtest_overlap);

	HTTP_RANGE_FOREACH(hrs_even, hr) {
		http_rangeset_insert(hrs_over, hr->start, hr->end);
	}

	g_assert(http_rangeset_length(hrs_over) ==
		G_N_ELEMENTS(hrtest_even) + G_N_ELEMENTS(hrtest_odd));
	g_assert(1 == http_rangeset_count(hrs_over));

	http_rangeset_free_null(&hrs_over);
	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);

	hrs_over = HTTP_RANGE_TEST_LOAD(hrtest_overlap);

	HTTP_RANGE_FOREACH(hrs_over, hr) {
		http_rangeset_insert(hrs_even, hr->start, hr->end);
	}

	g_assert(http_rangeset_length(hrs_even) ==
		G_N_ELEMENTS(hrtest_even) + G_N_ELEMENTS(hrtest_odd));
	g_assert(1 == http_rangeset_count(hrs_even));

	http_rangeset_free_null(&hrs_even);
	http_rangeset_free_null(&hrs_over);
	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);

	hrs_even = HTTP_RANGE_TEST_LOAD(hrtest_even);
	hrs_odd = HTTP_RANGE_TEST_LOAD(hrtest_odd);
	hrs_over = HTTP_RANGE_TEST_LOAD(hrtest_overlap);

	http_rangeset_merge(hrs_odd, hrs_over);
	http_rangeset_merge(hrs_even, hrs_over);

	g_assert(http_rangeset_length(hrs_even) ==
		G_N_ELEMENTS(hrtest_even) + G_N_ELEMENTS(hrtest_odd));
	g_assert(1 == http_rangeset_count(hrs_even));

	g_assert(http_rangeset_length(hrs_odd) ==
		G_N_ELEMENTS(hrtest_even) + G_N_ELEMENTS(hrtest_odd) - 1);
	g_assert(2 == http_rangeset_count(hrs_odd));	/* 0-1, 3-9 */

	http_rangeset_free_null(&hrs_even);
	http_rangeset_free_null(&hrs_odd);
	http_rangeset_free_null(&hrs_over);
	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);

	hrs_partial = HTTP_RANGE_TEST_LOAD(hrtest_partial);
	hrs_added = HTTP_RANGE_TEST_LOAD(hrtest_added);
	hrs_result = HTTP_RANGE_TEST_LOAD(hrtest_result);

	g_assert(!http_rangeset_equal(hrs_partial, hrs_added));
	g_assert(!http_rangeset_equal(hrs_partial, hrs_result));
	g_assert(http_rangeset_equal(hrs_partial, hrs_partial));

	http_rangeset_merge(hrs_partial, hrs_added);

	g_assert(http_rangeset_equal(hrs_partial, hrs_result));

	http_rangeset_free_null(&hrs_partial);
	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);

	hrs_partial = HTTP_RANGE_TEST_LOAD(hrtest_partial);

	http_rangeset_merge(hrs_added, hrs_partial);

	g_assert(http_rangeset_equal(hrs_added, hrs_result));

	http_rangeset_free_null(&hrs_partial);
	http_rangeset_free_null(&hrs_added);
	http_rangeset_free_null(&hrs_result);
	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);

	hrs_result = HTTP_RANGE_TEST_LOAD(hrtest_result);
	s = str_new(0);

	str_printf(s, "bytes %s", http_rangeset_to_string(hrs_result));

	{
		enum http_range_extract_status status;
		filesize_t start, end;

		status = http_range_extract_first("Test", str_2c(s), 70, "test",
			&start, &end);

		g_assert(HTTP_RANGE_MULTI == status);
		g_assert(hrtest_result[0].start == start);
		g_assert(hrtest_result[0].end == end);
	}

	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);

	{
		http_rangeset_t *hrs;

		hrs = http_rangeset_extract("Test", str_2c(s), 70, "test");

		g_assert(hrs != NULL);
		g_assert(http_rangeset_equal(hrs, hrs_result));

		http_rangeset_free_null(&hrs);
	}

	str_destroy_null(&s);
	http_rangeset_free_null(&hrs_result);
	g_info("%s(): test #%-2u OK at %s", G_STRFUNC, test++, G_STRLOC);
}
#else	/* !HTTP_RANGE_TESTING */
void G_COLD
http_range_test(void)
{
	/* Empty */
}
#endif	/* HTTP_RANGE_TESTING */

/* vi: set ts=4 sw=4 cindent: */
