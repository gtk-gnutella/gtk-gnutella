/*
 * Copyright (c) 2001, Raphael Manfredi
 *
 * Search bins are Copyright (c) 2001, Kenn Brooks Hamm & Raphael Manfredi
 */

#include <ctype.h>
#include "gnutella.h"
#include "matching.h"
#include "search_stats.h"

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

/*
 * Masks for mask_hash().
 */

#define MASK_LETTER(x)		(1 << (x))		/* bits 0 to 25 */
#define MASK_DIGIT			0x80000000

/*
 * mask_hash
 *
 * Compute character mask "hash", using one bit per letter of the alphabet,
 * plus one for any digit.
 */
static guint32 mask_hash(guchar *str) {
	guchar *s = str;
	guchar c;
	guint32 mask = 0;

	while ((c = *s++)) {
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
__inline__ static gint st_key(search_table_t *table, guchar k[2])
{
	return table->index_map[k[0]] * table->nchars +
		table->index_map[k[1]];
}

static void destroy_entry(struct st_entry *entry)
{
	/* FIXME: make sure this frees everything */
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
	g_assert(bin->vals > 0);	/* Or it would not have been allocated */
	bin->vals = g_realloc(bin->vals, bin->nvals * sizeof(bin->vals[0]));
	bin->nslots = bin->nvals;
}

/* apply a char map to a string -- returns length of sting */
static guint map_string(char_map_t map, guchar *string)
{
	guchar *ptr = string;
	guchar c;

	while ((c = *ptr))
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

/* insert an item into the search_table
 * one-char strings are silently ignored */
void st_insert_item(search_table_t *table, guchar *string, void *data)
{
	gint i;
	guint len;
	struct st_entry *entry;
	GHashTable *seen_keys;

	string = g_strdup(string);

	len = map_string(table->fold_map, string);
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
		if (g_hash_table_lookup(seen_keys, (gconstpointer) key))
			continue;

		g_hash_table_insert(seen_keys, (gpointer) key, (gpointer) 1);

		g_assert(key < table->nbins);
		if (table->bins[key] == NULL)
			table->bins[key] = bin_allocate();

		bin_insert_item(table->bins[key], entry);
	}
	bin_insert_item(&table->all_entries, entry);
	table->nentries++;

	g_hash_table_destroy(seen_keys);
}

/*
 * Apply pattern matching on text, matching at the *beginning* of words.
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
	guchar *search,
	gboolean (*callback)(struct shared_file *),
	gint max_res)
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

	len = map_string(table->fold_map, search);

	/*
	 * Find smallest bin
	 */

	for (i = 0; i < len-1; i++) {
		struct st_bin *bin;
		if (isspace(search[i]) || isspace(search[i+1]))
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

	if (best_bin == NULL)
		return 0;

	g_assert(best_bin_size > 0);	/* Allocated bin, it must hold something */

	/*
	 * Prepare matching patterns
	 */

	wocnt = query_make_word_vec(search, &wovec);
	if (wocnt == 0)
		return 0;

	/*
	 * If search statistics are being gathered, count each word
	 */
	if (search_stats_enabled)
	    for (i = 0; i < wocnt; i++)
		tally_search_stats(&wovec[i]);

	pattern = (cpattern_t **) g_malloc(wocnt * sizeof(cpattern_t *));

	for (i = 0; i < wocnt; i++)
		pattern[i] = pattern_compile(wovec[i].word);

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
	 * Search through the smallest bin
	 */

	vcnt = best_bin->nvals;
	vals = best_bin->vals;

	while (nres < max_res && vcnt-- > 0) {
		struct st_entry *e = *vals++;
		struct shared_file *sf = (struct shared_file *)  e->data;

		if ((e->mask & search_mask) != search_mask)
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
		pattern_free(pattern[i]);
	g_free(pattern);
	query_word_vec_free(wovec, wocnt);

	return nres;
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


/* vi: set ts=4: */

