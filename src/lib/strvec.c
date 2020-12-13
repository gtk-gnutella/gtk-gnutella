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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Manages string vector arrays.
 *
 * A string vector array is an array like argv[] where each entry holds a
 * string (NUL-terminated set of bytes) and whose last entry is identified
 * by a NULL pointer.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "strvec.h"

#include "mempcpy.h"
#include "misc.h"				/* For strsize() */
#include "unsigned.h"			/* For size_is_non_negative() */

#include "override.h"			/* Must be the last header included */

/**
 * Count amount of entries in the string vector array.
 *
 * @param strv	the string vector array base
 *
 * @return the amount of entries, i.e. the number n such that NULL == strv[n].
 */
size_t
strvec_count(char * const *strv)
{
	size_t i = 0;

	while (strv[i] != NULL)
		i++;

	return i;
}

/**
 * Compute length in bytes of all the strings held in the string vector array.
 *
 * @param strv	the string vector array base
 *
 * @return the total byte length of all the strings, including their NUL bytes.
 */
size_t
strvec_size(char * const *strv)
{
	size_t i = 0, bytes = 0;

	while (strv[i] != NULL) {
		bytes += strsize(strv[i]);	/* Include trailing NUL */
		i++;
	}

	return bytes;
}

/**
 * Free string vector content (not the array itself) with given free routine.
 *
 * The routine stops at the first NULL pointer in the vector and each entry
 * is NULL-ified after being freed.
 *
 * @param fn		the free routine (xfree, hfree, etc...)
 * @param strv		the string vector whose strings need to be freed
 *
 * @return the amount of entries up to the final NULL.
 */
size_t
strvec_free_with(free_fn_t fn, char **strv)
{
	size_t i;

	g_assert(fn != NULL);
	g_assert(strv != NULL);

	for (i = 0; strv[i] != NULL; i++) {
		(*fn)(strv[i]);
		strv[i] = NULL;
	}

	return i;
}

/**
 * Expand existing vector array and append items from the other vector into it.
 *
 * The strings are NOT duplicated, their pointer is simply copied.
 *
 * Upon return, "oldn" is updated to hold the new vector count.
 *
 * @param fn		the reallocation routine (xrealloc, hrealloc, etc...)
 * @param oldv		the string vector we want to expand
 * @param oldn		contains current known amount of items in oldv, or 0
 * @param copyv		the string vector we want to copy at the tail of oldv
 * @param copyn		if not-zero, the current known amount of items in copyv
 *
 * @return the address of the (possibly re-allocated) new vector
 */
char **
strvec_append_with(
	realloc_fn_t fn,
	char **oldv, size_t *oldn,
	char * const *copyv, size_t copyn)
{
	size_t n, m = copyn, i, j;
	char **newv;

	g_assert(fn != NULL);
	g_assert(oldv != NULL);
	g_assert(copyv != NULL);
	g_assert(oldn != NULL);
	g_assert(size_is_non_negative(*oldn));
	g_assert(size_is_non_negative(copyn));

	n = *oldn;
	if (0 == n)
		n = strvec_count(oldv);

	g_assert_log(NULL == oldv[n],
		"%s(): corrupted vector oldv=%p; given count %zu, %s count n=%zu",
		G_STRFUNC, oldv, *oldn, 0 == *oldn ? "computed" : "used", n);

	if (0 == m)
		m = strvec_count(copyv);

	g_assert_log(NULL == copyv[m],
		"%s(): corrupted vector copyv=%p; given count %zu, %s count m=%zu",
		G_STRFUNC, copyv, copyn, 0 == copyn ? "computed" : "used", m);

	newv = (*fn)(oldv, (m + n + 1) * sizeof oldv[0]);

	for (i = n, j = 0; j <= m; /* empty */)
		newv[i++] = copyv[j++];		/* Will copy trailing NULL when j == m */

	*oldn = n + m;

	return newv;
}

/**
 * Copy string vector array by allocating items from a supplied memory buffer
 * and filling given destination vector with pointers.
 *
 * The dstv[] vector must be adequately size to be able to hold "cnt + 1"
 * entries (to include the trailing NULL).
 *
 * Each string entry in strv[i] is duplicated at dstv[i] using memory that
 * is linearily taken from the supplied memory buffer.  All the strings are
 * therefore contiguous in memory, separated by their trailing NUL byte.
 *
 * The "len" parameter initially holds the amount of space available in the
 * memory buffer.  Upon return, it is updated to reflect the amount of space
 * remaining, to account for the allocated strings made during the duplication.
 *
 * @param dstv		pre-allocated vector capable of holding cnt + 1 entries
 * @param strv		the base of the original string vector array to copy
 * @param cnt		the amount of entries to duplicate
 * @param mem		base of memory buffer where strings are to be duplicated
 * @param len		contains initial length of mem buffer, updated upon return
 *
 * @return the first free location in the memory buffer, with "len" updated,
 * or NULL if we exhausted all the space without being able to fully duplicate
 * the original array.
 */
void *
strvec_cpy(char **dstv, char *const *strv, size_t cnt, void *mem, size_t *len)
{
	size_t i, avail;
	void *p = mem;				/* Linearily increased allocation pointer */

	g_assert(size_is_non_negative(cnt));
	g_assert(mem != NULL);
	g_assert(len != NULL);
	g_assert(size_is_non_negative(*len));

	avail = *len;

	for (i = 0; i < cnt; i++) {
		size_t n = strsize(strv[i]);

		if G_UNLIKELY(avail < n) {
			*len -= ptr_diff(p, mem);	/* Account for what we used so far */
			return NULL;				/* Could not duplicate all of strv[] */
		}

		dstv[i] = p;
		p = mempcpy(p, strv[i], n);
		avail -= n;
	}

	dstv[cnt] = NULL;
	*len -= ptr_diff(p, mem);	/* Account for what we used so far */

	return p;		/* First byte in "mem" beyond last string we copied */
}

/* vi: set ts=4 sw=4 cindent: */
