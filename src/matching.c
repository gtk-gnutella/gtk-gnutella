/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 *
 * Search bins are Copyright (c) 2001-2003, Kenn Brooks Hamm & Raphael Manfredi
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
#include "qrp.h"			/* For qhvec_add() */

#include <ctype.h>

RCSID("$Id$");

/* FIXME: remove this dependency */
extern guint32 dbg;

#define WOVEC_DFLT	10				/* Default size of word-vectors */

/*
 * Masks for mask_hash().
 */

#define MASK_LETTER(x)		(1 << (x))		/* bits 0 to 25 */
#define MASK_DIGIT			0x80000000

static zone_t *pat_zone = NULL;		/* Compiled patterns */
static zone_t *wovec_zone = NULL;	/* Word-vectors of WOVEC_DFLT entries */



/*
 * matching_init
 *
 * Initialize matching data structures.
 */
void matching_init(void)
{
	/*
	 * We don't expect much word vectors to be created.  They are normally
	 * created and destroyed in the same routine, without any threading
	 * taking place.
	 *
	 * We only allocate word vectors of WOVEC_DFLT entries in the zone.
	 * If we need to expand that, it will be done through regular malloc().
	 */

	wovec_zone = zget(WOVEC_DFLT * sizeof(word_vec_t), 2);

	/*
	 * Patterns are not only used for query matching but also for filters,
	 * therefore we can expect quite a few to be created at the same time.
	 */

	pat_zone = zget(sizeof(cpattern_t), 64);
}

/*
 * matching_close
 *
 * Terminate matching data structures.
 */
void matching_close(void)
{
	zdestroy(wovec_zone);
	zdestroy(pat_zone);
}

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
 * word_vec_zrealloc
 *
 * Reallocate a word-vector from the zone into heap memory, to hold `ncount'.
 */
static word_vec_t *word_vec_zrealloc(word_vec_t *wv, gint ncount)
{
	word_vec_t *nwv = g_malloc(ncount * sizeof(word_vec_t));

	g_assert(ncount > WOVEC_DFLT);

	memcpy(nwv, wv, WOVEC_DFLT * sizeof(word_vec_t));
	zfree(wovec_zone, wv);

	return nwv;
}

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
guint query_make_word_vec(const gchar *query_str, word_vec_t **wovec)
{
	guint n = 0;
	GHashTable *seen_word = NULL;
	guint nv = WOVEC_DFLT;
	word_vec_t *wv = zalloc(wovec_zone);
	const gchar *start = NULL;
	gchar * const query_dup = g_strdup(query_str);
	gchar *query;
	gchar first = TRUE;
	guchar c;

	g_assert(wovec != NULL);

	for (query = query_dup; /* empty */; query++) {
		gboolean is_alpha;

		c = *(guchar *) query;
		is_alpha = isalnum(c);

		if (start == NULL) {				/* Not in a word yet */
			if (is_alpha) start = query;
		} else {
			guint np1;
			if (is_alpha) continue;
			*query = '\0';

			/* Only create a hash table if there is more than one word. */
			if (first) 
				np1 = 0;
			else {
				if (seen_word == NULL) {
					seen_word = g_hash_table_new(g_str_hash, g_str_equal);
					g_hash_table_insert(seen_word, wv[0].word,
						GUINT_TO_POINTER(1));
				}

				/*
			 	 * If word already seen in query, it's in the seen_word table.
		 	 	 * The associated value is the index in the vector plus 1.
		 	 	 */

				np1 = GPOINTER_TO_UINT(
					g_hash_table_lookup(seen_word, (gconstpointer) start));
			}

			if (np1--) {
				wv[np1].amount++;
				wv[np1].len = query - start;
			} else {
				word_vec_t *entry;
				if (n == nv) {				/* Filled all the slots */
					nv *= 2;
					if (n > WOVEC_DFLT)
						wv = g_realloc(wv, nv * sizeof(word_vec_t));
					else
						wv = word_vec_zrealloc(wv, nv);
				}
				entry = &wv[n++];
				entry->len = query - start;
				entry->word = walloc(entry->len + 1);	/* For trailing NUL */
				memcpy(entry->word, start, entry->len + 1); /* Includes NUL */
				
				entry->amount = 1;

				/*
				 * Delay insertion of first word until we find another one.
				 * The hash table storing duplicates is not created for
				 * the first word.  The word entry is saved into `first_word'
				 * for later insertion, if needed.
				 */

				if (first)
					first = FALSE;
				else { 
					g_hash_table_insert(seen_word, entry->word,
						GUINT_TO_POINTER(n));
				}
			}
			start = NULL;
		}

		if (c == '\0') break;
	}

	if (NULL != seen_word)
		g_hash_table_destroy(seen_word);	/* Key pointers belong to vector */
	if (n)
		*wovec = wv;
	else
		zfree(wovec_zone, wv);
	g_free(query_dup);
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
		wfree(wovec[i].word, wovec[i].len + 1);

	if (n > WOVEC_DFLT)
		g_free(wovec);
	else
		zfree(wovec_zone, wovec);
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
cpattern_t *pattern_compile(gchar *pattern)
{
	cpattern_t *p = (cpattern_t *) zalloc(pat_zone);
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

	for (pd = p->delta, c = (guchar *) pattern, i = 0; i < plen; c++, i++)
		pd[*c] = plen - i;

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
	zfree(pat_zone, cpat);
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
	gchar *text,			/* Text we're scanning */
	guint32 tlen,			/* Text length, 0 = compute strlen(text) */
	guint32 toffset,		/* Offset within text for search start */
	qsearch_mode_t word)	/* Beginning/whole word matching? */
{
	gchar *p;			/* Pointer within string pattern */
	gchar *t;			/* Pointer within text */
	gchar *tp;			/* Initial local search text pointer */
	guint32 i;			/* Position within pattern string */
	gchar *start;		/* Start of matching */
	gchar *end;			/* End of text (first byte after physical end) */
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
			} else if (!isalnum((guchar) *(tp-1))) {	/* At word boundary */
				if (word == qs_begin) return tp;
				else at_begin = TRUE;
			}

			if (at_begin && word == qs_whole) {
				if (tp + plen == end)			/* At end of string */
					return tp;
				else if (!isalnum((guchar) *(tp+plen)))
					return tp; /* At word boundary after */
			}

			/* Fall through */
		}

		tp += cpat->delta[(guchar) *(tp + plen)]; /* Continue search there */
	}

	return NULL;		/* Not found */
}

/*
 * Search table searching routines.
 *
 * We're building an inverted index of all the file names by linking
 * together all the names having in common sequences of two chars.
 *
 * For instance, given the filenames "foo", "bar", "ar" and "arc", we'll
 * have the following bins:
 *
 *    bin["fo"] = { "foo" };
 *    bin["oo"] = { "foo" };
 *    bin["ba"] = { "bar" };
 *    bin["ar"] = { "bar", "ar", "arc" };
 *    bin["rc"] = { "arc" };
 *
 * Now assume we're looking for "arc". We're scanning the pattern to find
 * the bin which has the less amount of files listed insided.  The patterns
 * gives us the bins "ar" and "rc", and:
 *
 *    bin["ar"] has 3 items
 *    bin["rc"] has 1
 *
 * Therefore we'll look for "arc" in the bin["rc"] list.
 */

#define ST_MIN_BIN_SIZE		4


static void destroy_entry(struct st_entry *entry)
{
	g_free(entry->string);
}

/* initialize a bin */
static void bin_initialize(struct st_bin *bin, gint size)
{
	gint i;
	
	bin->nvals = 0;
	bin->nslots = size;

	bin->vals = g_malloc(size * sizeof(bin->vals[0]));
	for (i = 0; i < size; i++)
		bin->vals[i] = NULL;
}

/* allocate a bin */
static struct st_bin *bin_allocate(void)
{
	struct st_bin *bin = (struct st_bin *) g_malloc(sizeof(struct st_bin));

	bin_initialize(bin, ST_MIN_BIN_SIZE);
	return bin;
}

/* destroy a bin
 * NOTE: does NOT destroy the st_entry's, since they may be shared */
static void bin_destroy(struct st_bin *bin)
{
	g_free(bin->vals);
	bin->vals = 0;
}

/* inserts an item into a bin */
static void bin_insert_item(struct st_bin *bin, struct st_entry *entry)
{
	if (bin->nvals == bin->nslots) {
		bin->nslots *= 2;
		bin->vals = g_realloc(bin->vals, bin->nslots * sizeof(bin->vals[0]));
	}
	bin->vals[bin->nvals++] = entry;
}

/* makes a bin take as little memory as needed */
static void bin_compact(struct st_bin *bin)
{
	g_assert(bin->vals != NULL);	/* Or it would not have been allocated */
	bin->vals = g_realloc(bin->vals, bin->nvals * sizeof(bin->vals[0]));
	bin->nslots = bin->nvals;
}

/*
 * match_map_string
 *
 * Apply a char map to a string, inplace.
 * Returns length of string.
 */
guint match_map_string(char_map_t map, gchar *string)
{
	gchar *ptr = string;
	guchar c;

	while ((c = (guchar) *ptr))
		*ptr++ = map[c];

	return ptr - string;
}

/* initialize permanent data in search table */
void st_initialize(search_table_t *table, char_map_t map)
{
	gint i;
	guchar cur_char = '\0', map_char;

	table->nentries = table->nchars = 0;
	
	for (i = 0; i < 256; i++)
		table->fold_map[i] = 0;

	/*
	 * The indexing map is used to avoid having 256*256 bins.
	 */
	
	for (i = 0; i < 256; i++) {
		map_char = map[i];
		if (!table->fold_map[map_char]) {
			table->fold_map[map_char] = cur_char;
			table->index_map[i] = cur_char;
			cur_char++;
		} else {
			table->index_map[i] = table->fold_map[map_char];
		}
	}

	for (i = 0; i < 256; i++)
		table->fold_map[i] = map[i];

	table->nchars = cur_char;
	table->nbins = table->nchars * table->nchars;
	table->bins = 0;
	table->all_entries.vals = 0;

	if (dbg > 3)
		printf("search table will use max of %d bins (%d indexing chars)\n",
			table->nbins, table->nchars);
}
	
/* recreate variable parts of the search table */
void st_create(search_table_t *table)
{
	gint i;

	table->bins = g_malloc(table->nbins * sizeof(struct st_bin));
	for (i = 0; i < table->nbins; i++)
		table->bins[i] = 0;

    bin_initialize(&table->all_entries, ST_MIN_BIN_SIZE);
}

/* destroy a search table */
void st_destroy(search_table_t *table)
{
	gint i;

	if (table->bins) {
		for (i = 0; i < table->nbins; i++) {
			if (table->bins[i]) {
				bin_destroy(table->bins[i]);
				g_free(table->bins[i]);
			}
		}
		g_free(table->bins);
		table->bins = 0;
	}

	if (table->all_entries.vals) {
		for (i = 0; i < table->all_entries.nvals; i++) {
			destroy_entry(table->all_entries.vals[i]);
			g_free(table->all_entries.vals[i]);
		}
		bin_destroy(&table->all_entries);
	}
}

/*
 * mask_hash
 *
 * Compute character mask "hash", using one bit per letter of the alphabet,
 * plus one for any digit.
 */
static guint32 mask_hash(gchar *s) {
	guchar c;
	guint32 mask = 0;

	while ((c = (guchar) *s++)) {
		if (isspace(c))
			continue;
		else if (isdigit(c))
			mask |= MASK_DIGIT;
		else {
			gint idx = tolower(c) - 'a';
			if (idx >= 0 && idx < 26)
				mask |= MASK_LETTER(idx);
		}
	}

	return mask;
}

/* get key of two-char pair */
inline gint st_key(search_table_t *table, gchar k[2])
{
	return table->index_map[(guchar) k[0]] * table->nchars +
		table->index_map[(guchar) k[1]];
}

/* insert an item into the search_table
 * one-char strings are silently ignored */
void st_insert_item(search_table_t *table, gchar *string, void *data)
{
	gint i;
	guint len;
	struct st_entry *entry;
	GHashTable *seen_keys;

	string = g_strdup(string);

	len = match_map_string(table->fold_map, string);
	if (len < 2) {
		g_free(string);
		return;
	}

	seen_keys = g_hash_table_new(g_direct_hash, 0);
	
	entry = g_malloc(sizeof(struct st_entry));
	entry->string = string;
	entry->data = data;
	entry->mask = mask_hash(string);
	
	for (i = 0; i < len-1; i++) {
		gint key = st_key(table, string + i);

		/* don't insert item into same bin twice */
		if (g_hash_table_lookup(seen_keys, (gconstpointer)GINT_TO_POINTER(key)))
			continue;

		g_hash_table_insert(seen_keys, GINT_TO_POINTER(key),
			GINT_TO_POINTER(1));

		g_assert(key < table->nbins);
		if (table->bins[key] == NULL)
			table->bins[key] = bin_allocate();

		bin_insert_item(table->bins[key], entry);
	}
	bin_insert_item(&table->all_entries, entry);
	table->nentries++;

	g_hash_table_destroy(seen_keys);
}

/* minimize space consumption */
void st_compact(search_table_t *table)
{
	gint i;

	if (!table->all_entries.nvals)
		return;			/* Nothing in table */

	bin_compact(&table->all_entries);
	for (i = 0; i < table->nbins; i++)
		if (table->bins[i])
			bin_compact(table->bins[i]);
}

/*
 * pattern_compile_fast
 *
 * Same as pattern_compile(), but the pattern string is NOT duplicated,
 * and its length is known upon entry.
 *
 * NB: there is no pattern_free_fast(), just call zfree() on the result.
 */
static cpattern_t *pattern_compile_fast(gchar *pattern, guint32 plen)
{
	cpattern_t *p = (cpattern_t *) zalloc(pat_zone);
	guint32 *pd = p->delta;
	gint i;
	guchar *c;

	p->pattern = pattern;
	p->len = plen;

	plen++;			/* Avoid increasing within the memset() inlined macro */

	for (i = 0; i < ALPHA_SIZE; i++)
		*pd++ = plen;

	plen--;			/* Restore original pattern length */

	for (pd = p->delta, c = (guchar *) pattern, i = 0; i < plen; c++, i++)
		pd[*c] = plen - i;

	return p;
}

/*
 * entry_match
 *
 * Apply pattern matching on text, matching at the *beginning* of words.
 * Patterns are lazily compiled as needed, using pattern_compile_fast().
 */
static gboolean entry_match(
	gchar *text, gint tlen,
	cpattern_t **pw, word_vec_t *wovec, gint wn)
{
	gint i;

	for (i = 0; i < wn; i++) {
		gint amount = wovec[i].amount;
		gint j;
		guint32 offset = 0;

		if (pw[i] == NULL)
			pw[i] = pattern_compile_fast(wovec[i].word, wovec[i].len);

		for (j = 0; j < amount; j++) {
			char *pos =
				pattern_qsearch(pw[i], text, tlen, offset, qs_begin);
			if (pos)
				offset = (pos - text) + pw[i]->len;
			else
				break;
		}
		if (j != amount)		/* Word does not occur as many time as we want */
			return FALSE;
	}

	return TRUE;
}

/* do an actual search */
gint st_search(
	search_table_t *table,
	gchar *search,
	gboolean (*callback)(shared_file_t *),
	gint max_res,
	query_hashvec_t *qhv)
{
	gint i, key, nres = 0;
	guint len;
	struct st_bin *best_bin = NULL;
	gint best_bin_size = INT_MAX;
	word_vec_t *wovec;
	guint wocnt;
	cpattern_t **pattern;
	struct st_entry **vals;
	gint vcnt;
	gint scanned = 0;		/* measure search mask efficiency */
	guint32 search_mask;
	gint minlen;

	len = match_map_string(table->fold_map, search);

	/*
	 * Find smallest bin
	 */

	for (i = 0; i < len-1; i++) {
		struct st_bin *bin;
		if (isspace((guchar) search[i]) || isspace((guchar) search[i+1]))
			continue;
		key = st_key(table, search + i);
		if ((bin = table->bins[key]) == NULL) {
			best_bin = NULL;
			break;
		}
		if (bin->nvals < best_bin_size) {
			best_bin = bin;
			best_bin_size = bin->nvals;
		}
	}

	if (dbg > 6)
		printf("st_search(): str=\"%s\", len=%d, best_bin_size=%d\n",
			search, len, best_bin_size);

	/*
	 * If the best_bin is NULL, we did not find a matching bin, and we're
	 * sure we won't be able to find the search string.
	 *
	 * Note that on search strings like "r e m ", we always have a letter
	 * followed by spaces, so we won't search that.
	 *		--RAM, 06/10/2001
	 */

	if (best_bin == NULL) {
		/*
		 * If we have a `qhv', we need to compute the word vector anway,
		 * for query routing...
		 */

		if (qhv == NULL)
			return 0;
	}

	/*
	 * Prepare matching patterns
	 */

	wocnt = query_make_word_vec(search, &wovec);

	/*
	 * Compute the query hashing information for query routing, if needed.
	 */

	if (qhv != NULL) {
		for (i = 0; i < wocnt; i++) {
			if (wovec[i].len >= QRP_MIN_WORD_LENGTH)
				qhvec_add(qhv, wovec[i].word, QUERY_H_WORD);
		}
	}

	if (wocnt == 0 || best_bin == NULL) {
		if (wocnt > 0)
			query_word_vec_free(wovec, wocnt);
		return 0;
	}

	g_assert(best_bin_size > 0);	/* Allocated bin, it must hold something */


	pattern = (cpattern_t **) g_malloc0(wocnt * sizeof(cpattern_t *));

	/*
	 * Prepare matching optimization, an idea from Mike Green.
	 *
	 * At library building time, we computed a mask hash, made from the
	 * lowercased file name, using one bit per different letter, roughly
	 * (see mask_hash() for the exact algorigthm).
	 *
	 * We're now going to compute the same mask on the query, and compare
	 * it bitwise with the mask for each file.  If the file does not hold
	 * at least all the chars present in the query, it's no use applying
	 * the pattern matching algorithm, it won't match at all.
	 *
	 *		--RAM, 01/10/2001
	 */

	search_mask = mask_hash(search);

	/*
	 * Prepare second matching optimization: since all words in the query
	 * must match the exact amount of time, we can compute the minimum length
	 * the searched file must have.  We add one character after each word
	 * but the last, to account for space between words.
	 *		--RAM, 11/07/2002
	 */

	for (minlen = 0, i = 0; i < wocnt; i++)
		minlen += wovec[i].len + 1;
	minlen--;

	/*
	 * Search through the smallest bin
	 */

	vcnt = best_bin->nvals;
	vals = best_bin->vals;

	while (nres < max_res && vcnt-- > 0) {
		struct st_entry *e = *vals++;
		struct shared_file *sf = (struct shared_file *)  e->data;

		if ((e->mask & search_mask) != search_mask)
			continue;		/* Can't match */

		if (sf->file_name_len < minlen)
			continue;		/* Can't match */

		scanned++;

		if (entry_match(e->string, sf->file_name_len, pattern, wovec, wocnt)) {
			if (dbg > 5)
				printf("MATCH: %s\n", sf->file_name);
			if (!(*callback)(sf)) {
				g_warning("stopping matching at %d entr%s, packet too large",
					nres, nres == 1 ? "y" : "ies");
				break;
			}
			nres++;
		}
	}

	if (dbg > 6)
		printf("st_search(): scanned %d entry from the %d in bin, %d matches\n",
			scanned, best_bin_size, nres);

	for (i = 0; i < wocnt; i++)
		if (pattern[i])					/* Lazily compiled by entry_match() */
			zfree(pat_zone, pattern[i]);

	g_free(pattern);
	query_word_vec_free(wovec, wocnt);

	return nres;
}

/* vi: set ts=4: */

