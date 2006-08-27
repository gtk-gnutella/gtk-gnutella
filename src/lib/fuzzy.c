/*
 * $Id$
 *
 * Copyright (c) 2002, Vidar Madsen
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
 * Functions to compute likelihood of two file names being the same file.
 *
 * @author Vidar Madsen
 * @date 2002
 */

#include "common.h"

RCSID("$Id$")

#include "fuzzy.h"
#include "misc.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

typedef struct word_entry {
	size_t len;	/**< length of the whole struct, used for wfree() */
	gchar s[1];	/**< dynamically resized */
} word_entry_t;


static GSList *
fuzzy_make_word_list(const char *str)
{
	GSList *sl = NULL;

	while (*str) {
		const char *p;
		size_t size;

		while (*str && !is_ascii_alnum((guchar) *str)) {
			str++;
		}
		p = str;
		while (is_ascii_alnum((guchar) *str)) {
			str++;
		}
		size = (str - p) + 1; /* Include space for the NUL-byte */
		if (*p) {
			size_t n = G_STRUCT_OFFSET(word_entry_t, s) + size;
			word_entry_t *w = walloc(n);

			w->len = n;
			g_strlcpy(w->s, p, size);
			ascii_strlower(w->s, w->s);
			sl = g_slist_prepend(sl, w);
		}
	}
	return g_slist_reverse(sl);
}

static gulong
fuzzy_word_similarity(const char *a, const char *b)
{
	gulong score = 0;
	size_t len;

	for (len = 0; *a && *b; len++) {
		if (*a == *b) score += 1 << FUZZY_SHIFT;
		else if (*a == b[1]) { score += 1 << (FUZZY_SHIFT-2); b++; }
		else if (a[1] == *b) { score += 1 << (FUZZY_SHIFT-2); a++; len++; }
		a++;
		b++;
	}
	if ('\0' != *a) {
		len += strlen(a);
	}
	return score / len;
}

static gulong
fuzzy_cmp_word_list(const char *s, const GSList *words)
{
	const GSList *sl;
	gulong score = 0;
	gulong n = 0;

	for (sl = words; sl; sl = g_slist_next(sl), n++) {
		const word_entry_t *w = sl->data;

		if (0 == strcmp(s, w->s))
			return 1 << FUZZY_SHIFT;
		else
			score += fuzzy_word_similarity(s, w->s);
	}

	return n > 0 ? score / n : 0;
}

static gulong
fuzzy_find_score(const GSList *a, const GSList *b)
{
	const GSList *sl;
	gulong score = 0;
	gulong n = 0;

	for (sl = a; sl; sl = g_slist_next(sl), n++) {
		const word_entry_t *w = sl->data;
		score += fuzzy_cmp_word_list(w->s, b);
	}

	return n > 0 ? score / n : 0;
}

static void
word_list_free(GSList **sl_ptr)
{
	g_assert(sl_ptr);

	if (*sl_ptr) {
		GSList *sl;

		for (sl = *sl_ptr; sl; sl = g_slist_next(sl)) {
			word_entry_t *w = sl->data;
			wfree(w, w->len);
		}
		g_slist_free(*sl_ptr);
		*sl_ptr = NULL;
	}
}

/**
 * @return the similarity of both strings as a value
 * between 0 and (1 << FUZZY_SHIFT).
 *
 * @attention
 * NB: The result will be bogus for strings larger than
 *     1 << (BIT_LENGTH_OF_GULONG - (FUZZY_SHIFT + 2)) chars.
 */
gulong
fuzzy_compare(const char *str1, const char *str2)
{
	GSList *a, *b;
	gulong score;

	a = fuzzy_make_word_list(str1);
	b = fuzzy_make_word_list(str2);

	score = (fuzzy_find_score(a, b) + fuzzy_find_score(b, a)) / 2;

	word_list_free(&a);
	word_list_free(&b);

	return score;
}

/* vi: set ts=4 sw=4 cindent: */
