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

RCSID("$Id$");

static char *fuzzy_strlower(char *a)
{
	unsigned char *p;
	
	for (p = a; '\0' != *p; p++)
		*p = tolower(*p);

	return a;
}

static GSList *fuzzy_make_word_list(char *n)
{
	GSList *l = NULL;
	char *p;

	while (*n) {
		while (!isalnum((unsigned char)*n)) n++;
		p = n;
		while (isalnum((unsigned char)*n)) n++;
		if(*n) { 
			*n = '\0';
			n++;
		}
		if (*p)
			l = g_slist_append(l, fuzzy_strlower(g_strdup(p)));
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

static gulong fuzzy_cmp_word_list(const char *w, GSList *words)
{
	GSList *l;
	gulong score = 0;
	gulong n = 0;
	
	for (l = words; l; l = g_slist_next(l), n++)
		if (0 == strcmp(w, l->data))
			return 1 << FUZZY_SHIFT;
		else
			score += fuzzy_word_similarity(w, l->data);

	return n > 0 ? score / n : 0;
}

static gulong fuzzy_find_score(GSList *a, GSList *b)
{
	GSList *l;
	gulong score = 0;
	gulong n = 0;
	
	for (l = a; l; l = g_slist_next(l), n++)
		score += fuzzy_cmp_word_list(l->data, b);
   
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
	char *n1, *n2;
	GSList *a, *b, *l;
	gulong score;
	
	n1 = g_strdup(str1);
	n2 = g_strdup(str2);
	
	a = fuzzy_make_word_list(n1);
	b = fuzzy_make_word_list(n2);

	score = (fuzzy_find_score(a, b) + fuzzy_find_score(b, a)) / 2;

	for (l = a; l; l = g_slist_next(l))
		G_FREE_NULL(l->data);
	g_slist_free(a);

	for (l = b; l; l = g_slist_next(l))
		G_FREE_NULL(l->data);
	g_slist_free(b);
	
	g_free(n1);
	g_free(n2);

	return score;
}

