/*
 * Copyright (c) 2023 Raphael Manfredi
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
 * String substitution using string patterns.
 *
 * @author Raphael Manfredi
 * @date 2023
 */

#include "common.h"

#include "str_subst_str.h"

#include "pattern.h"

#include "override.h"		/* Must be the last header included */

/**
 * Replace `needle' string with `replacement', inplace, either the first
 * occurrence or all of them, as governed by `all'.
 *
 * @param s				the string we are modifying
 * @param needle		the element to replace
 * @param replacement	the replacement string
 * @param icase			whether needle is case-insensitive
 * @param all			whether all `needle' instances need to be replaced
 *
 * @return the amount of replacements done.
 */
static size_t
str_subst_str_internal(
	str_t *s, const char *needle, const char *replacement, bool icase, bool all)
{
	cpattern_t *cp;
	size_t offset = 0;
	size_t matches = 0;
	size_t nlen = vstrlen(needle);
	size_t rlen = vstrlen(replacement);

	cp = pattern_compile_fast(needle, nlen, icase);

	for (;;) {
		const char *r = pattern_search(cp, s->s_data, s->s_len, offset, qs_any);
		size_t idx;

		if (NULL == r)
			goto done;

		matches++;
		idx = ptr_diff(r, s->s_data);
		str_replace_len(s, idx, nlen, replacement, rlen);

		if (!all)
			goto done;

		offset = idx + rlen;		/* Move past last replacement */
	}

done:
	pattern_free(cp);

	return matches;
}

/**
 * Replace first instance of `needle' string with `replacement', inplace.
 *
 * @param s				the string we are modifying
 * @param needle		the element to replace
 * @param replacement	the replacement string
 *
 * @return the amount of replacements done.
 */
size_t
str_subst_first_str(str_t *s, const char *needle, const char *replacement)
{
	str_check(s);
	g_assert(needle != NULL);
	g_assert(replacement != NULL);

	return str_subst_str_internal(s, needle, replacement, FALSE, FALSE);
}

/**
 * Replace all instances of `needle' string with `replacement', inplace.
 *
 * @param s				the string we are modifying
 * @param needle		the element to replace
 * @param replacement	the replacement string
 *
 * @return the amount of replacements done.
 */
size_t
str_subst_all_str(str_t *s, const char *needle, const char *replacement)
{
	str_check(s);
	g_assert(needle != NULL);
	g_assert(replacement != NULL);

	return str_subst_str_internal(s, needle, replacement, FALSE, TRUE);
}

/**
 * Replace first instance of `needle' string (case-insensitive) with
 * `replacement', inplace.
 *
 * @param s				the string we are modifying
 * @param needle		the element to replace
 * @param replacement	the replacement string
 *
 * @return the amount of replacements done.
 */
size_t
str_case_subst_first_str(str_t *s, const char *needle, const char *replacement)
{
	str_check(s);
	g_assert(needle != NULL);
	g_assert(replacement != NULL);

	return str_subst_str_internal(s, needle, replacement, TRUE, FALSE);
}

/**
 * Replace all instances of `needle' string (case-insensitive) with
 * `replacement', inplace.
 *
 * @param s				the string we are modifying
 * @param needle		the element to replace
 * @param replacement	the replacement string
 *
 * @return the amount of replacements done.
 */
size_t
str_case_subst_all_str(str_t *s, const char *needle, const char *replacement)
{
	str_check(s);
	g_assert(needle != NULL);
	g_assert(replacement != NULL);

	return str_subst_str_internal(s, needle, replacement, TRUE, TRUE);
}

/* vi: set ts=4 sw=4 cindent: */
