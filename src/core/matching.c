/*
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

#include "matching.h"
#include "qrp.h"				/* For qhvec_add() */
#include "share.h"
#include "search.h"				/* For lazy_safe_search() */

#include "lib/ascii.h"
#include "lib/atomic.h"
#include "lib/atoms.h"
#include "lib/halloc.h"
#include "lib/hset.h"
#include "lib/pattern.h"
#include "lib/random.h"
#include "lib/stringify.h"	/* For hex_escape() */
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/wordvec.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

#define WOVEC_DFLT	10			/**< Default size of word-vectors */

/*
 * Masks for mask_hash().
 */

#define MASK_LETTER(x)		(1 << (x))		/**< bits 0 to 25 */
#define MASK_DIGIT			0x80000000

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

struct st_entry {
	const char *string;				/* atom */
	shared_file_t *sf;
	uint32 mask;
};

struct st_bin {
	int nslots, nvals;
	struct st_entry **vals;
};

enum search_table_magic { SEARCH_TABLE_MAGIC = 0x0cf66242 };

struct search_table {
	enum search_table_magic magic;
	int nentries, nchars, nbins;
	struct st_bin **bins;
	struct st_bin all_entries;
	uchar index_map[MAX_INT_VAL(uchar)];
	uchar fold_map[MAX_INT_VAL(uchar)];
	int refcnt;
};

static inline void
search_table_check(const struct search_table * const st)
{
	g_assert(st != NULL);
	g_assert(SEARCH_TABLE_MAGIC == st->magic);
}

static void
destroy_entry(struct st_entry *entry)
{
	g_assert(entry != NULL);

	atom_str_free_null(&entry->string);
	shared_file_unref(&entry->sf);
	WFREE(entry);
}

/**
 * Initialize a bin.
 */
static void
bin_initialize(struct st_bin *bin, int size)
{
	int i;

	bin->nvals = 0;
	bin->nslots = size;

	HALLOC_ARRAY(bin->vals, bin->nslots);
	for (i = 0; i < bin->nslots; i++)
		bin->vals[i] = NULL;
}

/**
 * Allocate a bin.
 */
static struct st_bin *
bin_allocate(void)
{
	struct st_bin *bin;

	WALLOC(bin);
	bin_initialize(bin, ST_MIN_BIN_SIZE);
	return bin;
}

/**
 * Destroy a bin.
 *
 * @note Do NOT destroy the st_entry's, since they may be shared.
 */
static void
bin_destroy(struct st_bin *bin)
{
	HFREE_NULL(bin->vals);
	bin->nslots = 0;
	bin->nvals = 0;
}

/**
 * Inserts an item into a bin.
 */
static void
bin_insert_item(struct st_bin *bin, struct st_entry *entry)
{
	if (bin->nvals == bin->nslots) {
		bin->nslots *= 2;
		HREALLOC_ARRAY(bin->vals, bin->nslots);
	}
	bin->vals[bin->nvals++] = entry;
}

/**
 * Makes a bin take as little memory as needed.
 */
static void
bin_compact(struct st_bin *bin)
{
	g_assert(bin->vals != NULL);	/* Or it would not have been allocated */

	HREALLOC_ARRAY(bin->vals, bin->nvals);
	bin->nslots = bin->nvals;
}

static uchar map[MAX_INT_VAL(uchar)];

static void
setup_map(void)
{
	static bool done;
	uint i;

	if (done)
		return;

	for (i = 0; i < G_N_ELEMENTS(map); i++)	{
		uchar c;

		if (i > 0 && utf8_byte_is_allowed(i)) {
			if (is_ascii_upper(i)) {
				c = ascii_tolower(i);
			} else if (
				is_ascii_punct(i) || is_ascii_cntrl(i) || is_ascii_space(i)
			) {
				c = ' ';
			} else { 
				c = i;
			}
		} else {
			c = 0;
		}
		map[i] = c;
	}

	done = TRUE;
}

/**
 * Initialize permanent data in search table.
 */
static void
st_initialize(search_table_t *table)
{
	uchar cur_char = '\0';
	uint i;

	search_table_check(table);

	table->refcnt = 1;
	table->nentries = table->nchars = 0;
	setup_map();

	/*
	 * The indexing map is used to avoid having 256*256 bins.
	 */

	for (i = 0; i < G_N_ELEMENTS(table->index_map); i++) {
		uchar map_char = map[i];

		if (table->fold_map[map_char]) {
			table->index_map[i] = table->fold_map[map_char];
		} else {
			table->fold_map[map_char] = cur_char;
			table->index_map[i] = cur_char;
			cur_char++;
		}
	}

	table->nchars = cur_char;
	table->nbins = table->nchars * table->nchars;
	table->bins = NULL;
	table->all_entries.vals = 0;

	if (GNET_PROPERTY(matching_debug)) {
		static bool done;

		if (!done) {
			done = TRUE;
			g_debug("MATCH search tables will use %d bins max "
				"(%d indexing chars)", table->nbins, table->nchars);
		}
	}
}

/**
 * Recreate variable parts of the search table.
 */
static void
st_recreate(search_table_t *table)
{
	int i;

	search_table_check(table);
	g_assert(NULL == table->bins);

	HALLOC_ARRAY(table->bins, table->nbins);
	for (i = 0; i < table->nbins; i++)
		table->bins[i] = NULL;

    bin_initialize(&table->all_entries, ST_MIN_BIN_SIZE);
}

/**
 * Destroy a search table, if its reference count dropped to 0.
 *
 * @return TRUE if table was destroyed, FALSE if some reference still remains.
 */
static bool
st_destroy(search_table_t *table)
{
	int i;

	search_table_check(table);

	if (!atomic_int_dec_is_zero(&table->refcnt))
		return FALSE;

	g_assert(0 == table->refcnt);

	if (table->bins) {
		for (i = 0; i < table->nbins; i++) {
			struct st_bin *bin = table->bins[i];

			if (bin) {
				bin_destroy(bin);
				WFREE(bin);
			}
		}
		HFREE_NULL(table->bins);
	}

	if (table->all_entries.vals) {
		for (i = 0; i < table->all_entries.nvals; i++) {
			destroy_entry(table->all_entries.vals[i]);
			table->all_entries.vals[i] = NULL;
		}
		bin_destroy(&table->all_entries);
	}

	return TRUE;
}

/**
 * Allocates a new search_table_t.
 * Use st_free() to free it.
 */
search_table_t *
st_create(void)
{
	search_table_t *table;

	WALLOC0(table);
	table->magic = SEARCH_TABLE_MAGIC;
	st_initialize(table);
	st_recreate(table);
	return table;
}

/**
 * Free search table (if no longer referenced), nullifying its pointer.
 */
void
st_free(search_table_t **ptr)
{
	g_assert(ptr != NULL);

	if (*ptr) {
		search_table_t *table = *ptr;
		if (st_destroy(table)) {
			table->magic = 0;
			WFREE(table);
		}
		*ptr = NULL;
	}
}

/**
 * Add reference to the search table.
 *
 * To remove a reference on the table, call st_free().
 *
 * @return its argument.
 */
search_table_t *
st_refcnt_inc(search_table_t *st)
{
	search_table_check(st);

	atomic_int_inc(&st->refcnt);
	return st;
}

/**
 * @return amount of entries in the table.
 */
int
st_count(const search_table_t *table)
{
	search_table_check(table);

	return table->all_entries.nvals;
}

/**
 * Compute character mask "hash", using one bit per letter of the alphabet,
 * plus one for any digit.
 */
static uint32
mask_hash(const char *s) {
	uchar c;
	uint32 mask = 0;

	while ((c = (uchar) *s++)) {
		if (is_ascii_space(c))
			continue;
		else if (is_ascii_digit(c))
			mask |= MASK_DIGIT;
		else {
			int idx = ascii_tolower(c) - 97;
			if (idx >= 0 && idx < 26)
				mask |= MASK_LETTER(idx);
		}
	}

	return mask;
}

/**
 * Get key of two-char pair.
 */
static inline int
st_key(search_table_t *table, const char k[2])
{
	return table->index_map[(uchar) k[0]] * table->nchars +
		table->index_map[(uchar) k[1]];
}

/**
 * Insert an item into the search_table
 * one-char strings are silently ignored.
 *
 * @return TRUE if the item was inserted; FALSE otherwise.
 */
bool
st_insert_item(search_table_t *table, const char *s, const shared_file_t *sf)
{
	size_t i, len;
	struct st_entry *entry;
	hset_t *seen_keys;

	len = utf8_strlen(s);
	if (len < 2)
		return FALSE;

	seen_keys = hset_create(HASH_KEY_SELF, 0);

	WALLOC(entry);
	entry->string = atom_str_get(s);
	entry->sf = shared_file_ref(sf);
	entry->mask = mask_hash(entry->string);

	len = strlen(entry->string);
	for (i = 0; i < len - 1; i++) {
		int key = st_key(table, &entry->string[i]);

		/* don't insert item into same bin twice */
		if (hset_contains(seen_keys, int_to_pointer(key)))
			continue;

		hset_insert(seen_keys, int_to_pointer(key));

		g_assert(key < table->nbins);
		if (table->bins[key] == NULL)
			table->bins[key] = bin_allocate();

		bin_insert_item(table->bins[key], entry);
	}
	bin_insert_item(&table->all_entries, entry);
	table->nentries++;

	hset_free_null(&seen_keys);
	return TRUE;
}

/**
 * Minimize space consumption.
 */
void
st_compact(search_table_t *table)
{
	int i;

	if (!table->all_entries.nvals)
		return;			/* Nothing in table */

	bin_compact(&table->all_entries);
	for (i = 0; i < table->nbins; i++)
		if (table->bins[i])
			bin_compact(table->bins[i]);
}

/**
 * Apply pattern matching on text, matching at the *beginning* of words.
 * Patterns are lazily compiled as needed, using pattern_compile_fast().
 */
static bool
entry_match(const char *text, size_t tlen,
	cpattern_t **pw, word_vec_t *wovec, size_t wn)
{
	size_t i;

	for (i = 0; i < wn; i++) {
		size_t j, offset = 0, amount = wovec[i].amount;

		if (pw[i] == NULL)
			pw[i] = pattern_compile_fast(wovec[i].word, wovec[i].len);

		for (j = 0; j < amount; j++) {
			const char *pos;

			pos = pattern_qsearch(pw[i], text, tlen, offset, qs_begin);
			if (pos)
				offset = (pos - text) + pattern_len(pw[i]);
			else
				break;
		}
		if (j != amount)	/* Word does not occur as many time as we want */
			return FALSE;
	}

	return TRUE;
}

/**
 * Fill non-NULL query hash vector for query routing.
 *
 * This needs to be called when st_search() is not called when processing
 * a query, otherwise the qhery hash vector won't be properly initialized
 * and the query would be improperly dropped by qrt_build_query_target(),
 * hence never routed.
 */
void
st_fill_qhv(const char *search_term, query_hashvec_t *qhv)
{
	char *search;
	word_vec_t *wovec;
	uint wocnt;
	uint i;

	if (NULL == qhv)
		return;

	search = UNICODE_CANONIZE(search_term);
	wocnt = word_vec_make(search, &wovec);

	for (i = 0; i < wocnt; i++) {
		if (wovec[i].len >= QRP_MIN_WORD_LENGTH)
			qhvec_add(qhv, wovec[i].word, QUERY_H_WORD);
	}

	if (search != search_term)
		HFREE_NULL(search);

	if (wocnt > 0)
		word_vec_free(wovec, wocnt);
}

/**
 * Do an actual search.
 *
 * @param table			table containing organized entries to search from
 * @param search_term	the query string
 * @param callback		routine to invoke for each match
 * @param ctx			user-supplied data to pass on to callback
 * @param max_res		maximum amount of results to return
 * @param qhv			query hash vector built from query string, for routing
 *
 * @return number of hits we produced
 */
G_GNUC_HOT int
st_search(
	search_table_t *table,
	const char *search_term,
	st_search_callback callback,
	void *ctx,
	int max_res,
	query_hashvec_t *qhv)
{
	char *search;
	int key, nres = 0;
	uint i, len;
	struct st_bin *best_bin = NULL;
	int best_bin_size = INT_MAX;
	word_vec_t *wovec;
	uint wocnt;
	cpattern_t **pattern;
	struct st_entry **vals;
	uint vcnt;
	int scanned = 0;		/* measure search mask efficiency */
	uint32 search_mask;
	size_t minlen;
	uint random_offset; 	 /* Randomizer for search returns */

	search = UNICODE_CANONIZE(search_term);

	if (GNET_PROPERTY(query_debug) > 4 && 0 != strcmp(search, search_term)) {
		char *safe_search = hex_escape(search, FALSE);
		char *safe_search_term = hex_escape(search_term, FALSE);
		g_debug("original search term: \"%s\"", safe_search_term);
		g_debug("canonical search term: \"%s\"", safe_search);
		if (safe_search != search)
			HFREE_NULL(safe_search);
		if (safe_search_term != search_term)
			HFREE_NULL(safe_search_term);
	}
	len = strlen(search);

	/*
	 * Find smallest bin
	 */

	if (len >= 2) {
		for (i = 0; i < len - 1; i++) {
			struct st_bin *bin;
			if (is_ascii_space(search[i]) || is_ascii_space(search[i+1]))
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

		if (GNET_PROPERTY(matching_debug) > 4)
			g_debug("MATCH st_search(): str=\"%s\", len=%d, best_bin_size=%d",
				lazy_safe_search(search_term), len, best_bin_size);
	}

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
			goto finish;
	}

	/*
	 * Prepare matching patterns
	 */

	wocnt = word_vec_make(search, &wovec);

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
			word_vec_free(wovec, wocnt);
		goto finish;
	}

	g_assert(best_bin_size > 0);	/* Allocated bin, it must hold something */


	WALLOC0_ARRAY(pattern, wocnt);

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
	g_assert(minlen <= INT_MAX);

	/*
	 * Search through the smallest bin
	 */

	vcnt = best_bin->nvals;
	vals = best_bin->vals;
	random_offset = random_value(vcnt - 1);

	nres = 0;
	for (i = 0; i < vcnt; i++) {
		const struct st_entry *e;
		shared_file_t *sf;
		size_t canonic_len;

		/*
		 * As we only return a limited count of results, pick a random
		 * offset, so that repeated searches will match different items
		 * instead of always the first - with some probability.
		 */
		e = vals[(i + random_offset) % vcnt];
		
		if ((e->mask & search_mask) != search_mask)
			continue;		/* Can't match */

		sf = e->sf;

		if (!shared_file_is_shareable(sf))
			continue;		/* Cannot be shared */

		canonic_len = shared_file_name_canonic_len(sf);
		if (canonic_len < minlen)
			continue;		/* Can't match */

		scanned++;

		if (entry_match(e->string, canonic_len, pattern, wovec, wocnt)) {
			if (GNET_PROPERTY(matching_debug) > 4) {
				g_debug("MATCH \"%s\" matches %s",
					search, shared_file_name_nfc(sf));
			}

			if ((*callback)(ctx, sf)) {
				nres++;
				if (nres >= max_res)
					break;
			}
		}
	}

	if (GNET_PROPERTY(matching_debug) > 3)
		g_debug("MATCH st_search(): scanned %d entr%s from the %d in bin, "
			"got %d match%s",
			scanned, plural_y(scanned), best_bin_size, nres, plural_es(nres));

	for (i = 0; i < wocnt; i++)
		if (pattern[i])					/* Lazily compiled by entry_match() */
			pattern_free(pattern[i]);

	WFREE_ARRAY(pattern, wocnt);
	word_vec_free(wovec, wocnt);

finish:
	if (search != search_term) {
		HFREE_NULL(search);
	}

	return nres;
}

/* vi: set ts=4 sw=4 cindent: */
