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
	unsigned char *p = a;
	while (*p) {
		*p = tolower(*p);
		p++;
	}
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

static float fuzzy_word_similarity(char *a, char *b)
{
	float score = 0.0;
	int l = strlen(a);	

	if(!l) return 0.0;

	while (*a && *b) {
		if (*a == *b) score += 1.0;
		else if (*a == b[1]) { score += 0.25; b++; }
		else if (a[1] == *b) { score += 0.25; a++; }
		a++;
		b++;
	}
	score /= l;

	return score;
}

static float fuzzy_cmp_word_list(char *w, GSList *l)
{
	GSList *p;
	float score = 0.0, maxscore = 0.0;
	
	for (p = l; p; p = p->next)
		if (!strcmp(w, p->data))
			return 1.0;

	for (p = l; p; p = p->next) {
		maxscore += 1.0;
		score += fuzzy_word_similarity(w, p->data);
	}

	if (maxscore > 0.0)
		return score / maxscore;
	
	return 0.0;
}

static float fuzzy_find_score(GSList *a, GSList *b)
{
	GSList *l;
	float score = 0.0, maxscore = 0.0;
	
	for (l = a; l; l = l->next) {
		maxscore += 1.0;
		score += fuzzy_cmp_word_list(l->data, b);
	}
   
	if (maxscore > 0.0)
		return score / maxscore;
	
	return 0.0;
}

float fuzzy_compare(char *str1, char *str2)
{
	char *n1, *n2;
	GSList *a, *b, *l;
	float score;
	
	n1 = g_strdup(str1);
	n2 = g_strdup(str2);
	
	a = fuzzy_make_word_list(n1);
	b = fuzzy_make_word_list(n2);

	score = fuzzy_find_score(a, b);
	score += fuzzy_find_score(b, a);
	score /= 2.0;

	for (l = a; l; l = l->next)
		g_free(l->data);
	g_slist_free(a);

	for (l = b; l; l = l->next)
		g_free(l->data);
	g_slist_free(b);
	
	g_free(n1);
	g_free(n2);
	
	return score;
}

