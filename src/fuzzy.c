/*
 * $Id$
 *
 * Copyright (c) 2002, Vidar Madsen
 *
 * Functions to compute likelihood of two file names being the same file.
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

#include "common.h"

#include <ctype.h>

#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

typedef struct word_entry {
	size_t len;  /* length of the whole struct, used for wfree() */
	gchar s[1]; /* dynamically resized */
} word_entry_t;

static char *fuzzy_strlower(char *dst, const char *src, size_t len)
{
	guchar *p = (guchar *) dst;
	size_t i = len;

	g_assert(len > 0);
	g_assert(NULL != dst);

	while ('\0' != (*p = tolower((guchar) *src)) && --i > 0)
		src++, p++;

	g_assert((gchar *) p < dst + len);
	*p = '\0'; /* The ``dst'' buffer could be smaller than src is long. */
	return dst;
}

static GSList *fuzzy_make_word_list(const char *str)
{
	GSList *l = NULL;
	const char *p;
	size_t size;

	while (*str) {
		while (*str && !isalnum((guchar) *str)) str++;
		p = str;
		size = 1;
		while (isalnum((guchar) *str)) {
			str++;
			size++;
		}
		if (*p) {
			size_t n = G_STRUCT_OFFSET(word_entry_t, s) + size;
			word_entry_t *w = walloc(n);
		
			w->len = n;
			fuzzy_strlower(w->s, p, size);
			l = g_slist_append(l, w);
		}
	}
	return l;
}

static gulong fuzzy_word_similarity(const char *a, const char *b)
{
	gulong score = 0;
	size_t l = 0;	

	while (*a && *b) {
		if (*a == *b) score += 1 << FUZZY_SHIFT;
		else if (*a == b[1]) { score += 1 << (FUZZY_SHIFT-2); b++; }
		else if (a[1] == *b) { score += 1 << (FUZZY_SHIFT-2); a++; l++; }
		a++;
		b++;
		l++;
	}
	if ('\0' != *a)
		l += strlen(a);
	return score / l;
}

static gulong fuzzy_cmp_word_list(const char *s, GSList *words)
{
	GSList *l;
	gulong score = 0;
	gulong n = 0;
	
	for (l = words; l; l = g_slist_next(l), n++) {
		if (0 == strcmp(s, ((word_entry_t *) l->data)->s))
			return 1 << FUZZY_SHIFT;
		else
			score += fuzzy_word_similarity(s, ((word_entry_t *) l->data)->s);
	}

	return n > 0 ? score / n : 0;
}

static gulong fuzzy_find_score(GSList *a, GSList *b)
{
	GSList *l;
	gulong score = 0;
	gulong n = 0;
	
	for (l = a; l; l = g_slist_next(l), n++)
		score += fuzzy_cmp_word_list(((word_entry_t *) l->data)->s, b);
   
	return n > 0 ? score / n : 0;
}

/*
 * fuzzy_compare
 *
 * Returns the similarity of both strings as a value 
 * between 0 and (1 << FUZZY_SHIFT).
 *
 * NB: The result will be bogus for strings larger than
 *     1 << (BIT_LENGTH_OF_GULONG - (FUZZY_SHIFT + 2)) chars.
 */
gulong fuzzy_compare(const char *str1, const char *str2)
{
	GSList *a, *b, *l;
	gulong score;
	
	a = fuzzy_make_word_list(str1);
	b = fuzzy_make_word_list(str2);

	score = (fuzzy_find_score(a, b) + fuzzy_find_score(b, a)) / 2;

	for (l = a; l; l = g_slist_next(l))
		wfree(l->data, ((word_entry_t *) l->data)->len);
	g_slist_free(a);

	for (l = b; l; l = g_slist_next(l))
		wfree(l->data, ((word_entry_t *) l->data)->len);
	g_slist_free(b);
	
	return score;
}

