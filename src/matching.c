/*
 * Copyright (c) 2001, Raphael Manfredi
 */

#include <ctype.h>
#include "gnutella.h"
#include "matching.h"

/*
 * Search query word splitting.
 *
 * When facing a query like "this file.jpg", we want to be able to
 * split that down to ("this", "file", "jpg"), and look for each word
 * at a time.
 *
 * However, with a query like "the file is the one", then the word
 * "the" must match twice, exactly.  We must not only collect the words,
 * but also their wanted frequency.
 */

/*
 * query_make_word_vec
 *
 * Given a query string, return a dynamically built word vector, along
 * with the amount of items held into that vector.
 * Words are broken on non-alphanumeric boundaries.
 *
 * Returns the amount of valid items in the built vector, and fill `wovec'
 * with the pointer to the allocated vector.  If there are no items, there
 * is no vector returned.
 */
guint query_make_word_vec(guchar *query, word_vec_t **wovec)
{
	guint n = 0;
	GHashTable *seen_word = g_hash_table_new(g_str_hash, g_str_equal);
	guint nv = 10;
	word_vec_t *wv = g_malloc(nv * sizeof(word_vec_t));
	guchar c;
	gchar *start = NULL;

	g_assert(wovec != NULL);

	for (;; query++) {
		gboolean is_alpha;
		c = *query;
		is_alpha = c ? isalnum(c) : FALSE;
		if (start == NULL) {				/* Not in a word yet */
			if (is_alpha) start = query;
		} else {
			guint np1;
			if (is_alpha) continue;
			*query = '\0';
			/*
			 * If word already seen in query, it's in the seen_word table.
			 * The associated value is the index in the vector plus 1.
			 */
			np1 = (guint) g_hash_table_lookup(seen_word, (gconstpointer) start);
			if (np1) wv[np1-1].amount++;
			else {
				word_vec_t *entry;
				if (n == nv) {				/* Filled all the slots */
					nv *= 2;
					wv = g_realloc(wv, nv * sizeof(word_vec_t));
				}
				entry = &wv[n++];
				entry->word = g_strdup(start);
				entry->amount = 1;
				g_hash_table_insert(seen_word, entry->word, (gpointer) n);
			}
			*query = c;
			start = NULL;
		}
		if (!c) break;
	}

	g_hash_table_destroy(seen_word);	/* Key pointers belong to vector */
	if (n)
		*wovec = wv;
	else
		g_free(wv);

	return n;
}

/*
 * query_word_vec_free
 *
 * Relase a word vector, containing `n' items.
 */
void query_word_vec_free(word_vec_t *wovec, guint n)
{
	guint i;

	for (i = 0; i < n; i++)
		g_free(wovec[i].word);

	g_free(wovec);
}

/*
 * Pattern matching (substrings, not regular expressions)
 *
 * The algorithm used below is the one described in Communications
 * of the ACM, volume 33, number 8, August 1990, by Daniel M. Sunday
 * It's a variant of the classical Boyer-Moore search, but with a small
 * enhancement that can make a difference.
 */

/*
 * pattern_compile
 *
 * Compile given string pattern by computing the delta shift table.
 * The pattern string given is duplicated.
 *
 * Returns a compiled pattern structure.
 */
cpattern_t *pattern_compile(guchar *pattern)
{
	cpattern_t *p = (cpattern_t *) g_malloc0(sizeof(cpattern_t));
	guint32 plen = strlen(pattern);
	guint32 *pd = p->delta;
	gint i;
	guchar *c;

	p->pattern = g_strdup(pattern);
	p->len = plen;

	plen++;			/* Avoid increasing within the loop */

	for (i = 0; i < ALPHA_SIZE; i++)
		*pd++ = plen;

	plen--;			/* Restore original pattern length */

	for (pd = p->delta, c = pattern, i = 0; i < plen; c++, i++)
		pd[(guint) *c] = plen - i;

	return p;
}

/*
 * pattern_free
 *
 * Dispose of compiled pattern.
 */
void pattern_free(cpattern_t *cpat)
{
	g_free(cpat->pattern);
	g_free(cpat);
}

/*
 * pattern_qsearch
 *
 * Quick substring search algorithm.  It looks for the compiled pattern
 * with `text', from left to right.  The `tlen' argument is the length
 * of the text, and can left to 0, in which case it will be computed.
 *
 * Return pointer to beginning of matching substring, NULL if not found.
 */
gchar *pattern_qsearch(
	cpattern_t *cpat,		/* Compiled pattern */
	guchar *text,			/* Text we're scanning */
	guint32 tlen,			/* Text length, 0 = compute strlen(text) */
	guint32 toffset,		/* Offset within text for search start */
	qsearch_mode_t word)	/* Beginning/whole word matching? */
{
	guchar *p;			/* Pointer within string pattern */
	guchar *t;			/* Pointer within text */
	guchar *tp;			/* Initial local search text pointer */
	guint32 i;			/* Position within pattern string */
	guchar *start;		/* Start of matching */
	guchar *end;		/* End of text (first byte after physical end) */
	guint32 plen;

	if (!tlen)
		tlen = strlen(text);
	start = text + toffset;
	end = text + tlen;
	tp = start;
	plen = cpat->len;

	while (tp + plen <= end) {		/* Enough text left for matching */

		for (p = cpat->pattern, t = tp, i = 0; i < plen; p++, t++, i++)
			if (*p != *t)
				break;				/* Mismatch, stop looking here */

		if (i == plen) {			/* OK, we got a pattern match */
			gboolean at_begin = FALSE;

			if (word == qs_any)
				return tp;			/* Start of substring */

			/*
			 * They set `word', so we must look whether we are at the start
			 * of a word, i.e. if it is either the beginning of the text,
			 * or if the character before is a non-alphanumeric character.
			 */

			g_assert(word == qs_begin || word == qs_whole);

			if (tp == text) {					/* At beginning of text */
				if (word == qs_begin) return tp;
				else at_begin = TRUE;
			} else if (!isalnum(*(tp-1))) {		/* At word boundary */
				if (word == qs_begin) return tp;
				else at_begin = TRUE;
			}

			if (at_begin && word == qs_whole) {
				if (tp + plen == end)			/* At end of string */
					return tp;
				else if (!isalnum(*(tp+plen)))	/* At word boundary after */
					return tp;
			}

			/* Fall through */
		}

		tp += cpat->delta[(guint) *(tp + plen)]; /* Continue search there */
	}

	return (char *) 0;		/* Not found */
}

/* vi: set ts=4: */

