/*
 * Copyright (c) 2001-2003, 2016 Raphael Manfredi
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

#include "alias.h"
#include "qrp.h"				/* For qhvec_add() */
#include "search.h"				/* For lazy_safe_search() */
#include "share.h"

#include "lib/ascii.h"
#include "lib/atomic.h"
#include "lib/atoms.h"
#include "lib/halloc.h"
#include "lib/hset.h"
#include "lib/pattern.h"
#include "lib/pslist.h"
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
	uint nslots, nvals;
	struct st_entry **vals;
};

struct st_set {
	uint nentries, nchars, nbins;
	struct st_bin **bins;
	struct st_bin all_entries;
	uchar index_map[MAX_INT_VAL(uchar)];
	uchar fold_map[MAX_INT_VAL(uchar)];
};

enum search_table_magic { SEARCH_TABLE_MAGIC = 0x0cf66242 };

struct search_table {
	enum search_table_magic magic;
	int refcnt;
	struct st_set plain;		/* Plain table, original names */
	struct st_set alias;		/* Normalized names */
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
	uint i;

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
	HREALLOC_ARRAY(bin->vals, bin->nvals);
	bin->nslots = bin->nvals;
}

static uchar map[MAX_INT_VAL(uchar)];

static void
st_setup_map(void)
{
	static bool done;
	uint i;

	if (done)
		return;

	for (i = 0; i < N_ITEMS(map); i++)	{
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
 * Initialize permanent entries in a table set.
 */
static void
st_set_initialize(struct st_set *set)
{
	uint i;
	uchar cur_char = '\0';

	set->nentries = set->nchars = 0;

	/*
	 * The indexing map is used to avoid having 256*256 bins.
	 */

	for (i = 0; i < N_ITEMS(set->index_map); i++) {
		uchar map_char = map[i];

		if (set->fold_map[map_char]) {
			set->index_map[i] = set->fold_map[map_char];
		} else {
			set->fold_map[map_char] = cur_char;
			set->index_map[i] = cur_char;
			cur_char++;
		}
	}

	set->nchars = cur_char;
	set->nbins = set->nchars * set->nchars;
	set->bins = NULL;
	set->all_entries.vals = 0;

	if (GNET_PROPERTY(matching_debug)) {
		static bool done;

		if (!done) {
			done = TRUE;
			g_debug("MATCH search sets will use %d bins max "
				"(%d indexing chars)", set->nbins, set->nchars);
		}
	}
}

/**
 * Initialize permanent data in search table.
 */
static void
st_initialize(search_table_t *table)
{
	search_table_check(table);

	table->refcnt = 1;
	st_setup_map();
	st_set_initialize(&table->plain);
	st_set_initialize(&table->alias);
}

/**
 * Recreate variable parts of the searching sets.
 */
static void
st_set_recreate(struct st_set *set)
{
	uint i;

	g_assert(NULL == set->bins);

	HALLOC_ARRAY(set->bins, set->nbins);
	for (i = 0; i < set->nbins; i++)
		set->bins[i] = NULL;

    bin_initialize(&set->all_entries, ST_MIN_BIN_SIZE);
}

/**
 * Recreate variable parts of the search table.
 */
static void
st_recreate(search_table_t *table)
{
	search_table_check(table);

	st_set_recreate(&table->plain);
	st_set_recreate(&table->alias);
}

/**
 * Destroy a set.
 */
static void
st_set_destroy(struct st_set *set)
{
	uint i;

	if (set->bins) {
		for (i = 0; i < set->nbins; i++) {
			struct st_bin *bin = set->bins[i];

			if (bin) {
				bin_destroy(bin);
				WFREE(bin);
			}
		}
		HFREE_NULL(set->bins);
	}

	if (set->all_entries.vals) {
		for (i = 0; i < set->all_entries.nvals; i++) {
			destroy_entry(set->all_entries.vals[i]);
			set->all_entries.vals[i] = NULL;
		}
		bin_destroy(&set->all_entries);
	}
}

/**
 * Destroy a search table, if its reference count dropped to 0.
 *
 * @return TRUE if table was destroyed, FALSE if some reference still remains.
 */
static bool
st_destroy(search_table_t *table)
{
	search_table_check(table);

	if (!atomic_int_dec_is_zero(&table->refcnt))
		return FALSE;

	g_assert(0 == table->refcnt);

	st_set_destroy(&table->plain);
	st_set_destroy(&table->alias);

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
 * @return amount of entries in the table set.
 */
int
st_count(const search_table_t *table, enum match_set which)
{
	const struct st_set *set = NULL;

	search_table_check(table);

	switch (which) {
	case ST_SET_PLAIN: set = &table->plain; break;
	case ST_SET_ALIAS: set = &table->alias; break;
	}

	g_assert(set != NULL);

	return set->all_entries.nvals;
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
static inline uint
st_key(struct st_set *set, const char k[2])
{
	return set->index_map[(uchar) k[0]] * set->nchars +
		set->index_map[(uchar) k[1]];
}

/**
 * Insert an item into the search_table
 * one-char strings are silently ignored.
 *
 * @return TRUE if the item was inserted; FALSE otherwise.
 */
bool
st_insert_item(search_table_t *table,
	enum match_set which, const char *s, const shared_file_t *sf)
{
	size_t i, len;
	struct st_entry *entry;
	hset_t *seen_keys;
	struct st_set *set = NULL;

	search_table_check(table);

	len = utf8_strlen(s);
	if (len < 2)
		return FALSE;

	switch (which) {
	case ST_SET_PLAIN: set = &table->plain; break;
	case ST_SET_ALIAS: set = &table->alias; break;
	}

	g_assert(set != NULL);

	seen_keys = hset_create(HASH_KEY_SELF, 0);

	WALLOC(entry);
	entry->string = atom_str_get(s);
	entry->sf = shared_file_ref(sf);
	entry->mask = mask_hash(entry->string);

	len = strlen(entry->string);
	for (i = 0; i < len - 1; i++) {
		uint key = st_key(set, &entry->string[i]);

		/* don't insert item into same bin twice */
		if (hset_contains(seen_keys, int_to_pointer(key)))
			continue;

		hset_insert(seen_keys, int_to_pointer(key));

		g_assert(key < set->nbins);
		if (set->bins[key] == NULL)
			set->bins[key] = bin_allocate();

		bin_insert_item(set->bins[key], entry);
	}
	bin_insert_item(&set->all_entries, entry);
	set->nentries++;

	hset_free_null(&seen_keys);
	return TRUE;
}

/**
 * Minimize space consumption in the set.
 */
static void
st_set_compact(struct st_set *set)
{
	uint i;

	if (!set->all_entries.nvals)
		return;			/* Nothing in set */

	bin_compact(&set->all_entries);

	for (i = 0; i < set->nbins; i++) {
		if (set->bins[i])
			bin_compact(set->bins[i]);
	}
}

/**
 * Minimize space consumption.
 */
void
st_compact(search_table_t *table)
{
	search_table_check(table);

	st_set_compact(&table->plain);
	st_set_compact(&table->alias);
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

enum search_mode {
	SEARCH_NORMAL,		/* Original query string */
	SEARCH_ALIAS		/* Query mangled with normalized aliases */
};

typedef size_t (*st_filename_len_fn_t)(const shared_file_t *sf);

/**
 * Perform search.
 *
 * The "qhv" parameter MUST be NULL if the "mode" is SEARCH_ALIAS: the hash
 * vector needs to use the unmangled search terms for query routing.
 *
 * @param mode			search mode
 * @param set			set containing organized entries to search from
 * @param search		the query string (canonized)
 * @param result		list where results are added
 * @param qhv			query hash vector built from query string, for routing
 *
 * @return number of hits added to the list
 */
static uint G_HOT
st_run_search(
	enum search_mode mode,
	struct st_set *set,
	const char *search,
	pslist_t **result,
	query_hashvec_t *qhv)
{
	uint key, nres = 0;
	uint i, len;
	struct st_bin *best_bin = NULL;
	uint best_bin_size = UINT_MAX;
	word_vec_t *wovec;
	uint wocnt;
	cpattern_t **pattern;
	struct st_entry **vals;
	uint vcnt;
	int scanned = 0;		/* measure search mask efficiency */
	pslist_t *local;
	uint32 search_mask;
	size_t minlen;
	hset_t *already_matched = NULL;	/* entries that are already in the list */
	st_filename_len_fn_t flen;

	g_assert(implies(SEARCH_ALIAS == mode, NULL == qhv));

	len = strlen(search);

	/*
	 * Find smallest bin
	 */

	if (len >= 2) {
		for (i = 0; i < len - 1; i++) {
			struct st_bin *bin;
			if (is_ascii_space(search[i]) || is_ascii_space(search[i+1]))
				continue;
			key = st_key(set, search + i);
			if ((bin = set->bins[key]) == NULL) {
				best_bin = NULL;
				break;
			}
			if (bin->nvals < best_bin_size) {
				best_bin = bin;
				best_bin_size = bin->nvals;
			}
		}

		if (GNET_PROPERTY(matching_debug) > 4)
			g_debug("MATCH %s(): mode=%s, str=\"%s\", len=%d, best_bin_size=%d",
				G_STRFUNC, SEARCH_NORMAL == mode ? "normal" : "alias",
				lazy_safe_search(search), len,
				NULL == best_bin ? 0 : best_bin_size);
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
		 * If we have a `qhv', we need to compute the word vector anyway,
		 * for query routing...
		 */

		if (qhv == NULL)
			goto finish;
	}

	/*
	 * If we are not a normal match, it means we may already have some
	 * of the file entries matched in the result and we must make sure we
	 * do not create duplicates in the result list -- we simply need to skip
	 * any matching for files we already have!
	 */

	if (mode != SEARCH_NORMAL) {
		pslist_t *sl;

		already_matched = hset_create(HASH_KEY_SELF, 0);

		PSLIST_FOREACH(*result, sl) {
			hset_insert(already_matched, sl->data);
		}
	}

	/*
	 * Prepare matching patterns
	 */

	wocnt = word_vec_make(search, &wovec);

	/*
	 * Compute the query hashing information for query routing, if needed.
	 *
	 * The hash vector needs to be build only when we are given the normal
	 * search string, not the aliases one.
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
		minlen += wovec[i].len * wovec[i].amount + 1;
	minlen--;
	g_assert(minlen <= INT_MAX);		/* No overflows */

	flen = SEARCH_NORMAL == mode ?
		shared_file_name_canonic_len : shared_file_name_normalized_len;

	/*
	 * Search through the smallest bin
	 */

	vcnt = best_bin->nvals;
	vals = best_bin->vals;

	nres = 0;
	local = *result;
	for (i = 0; i < vcnt; i++) {
		const struct st_entry *e = vals[i];
		const shared_file_t *sf;
		size_t filename_len;

		/*
		 * As we only return a limited amount of results, we insert all the
		 * matching entries in a list, which will then be randomly shuffled.
		 * Only its leading items will be extracted.
		 *
		 * That strategy allows us to possibly return all the matching entries
		 * when they repeat the search over time.
		 */

		if ((e->mask & search_mask) != search_mask)
			continue;		/* Can't match */

		sf = e->sf;

		if (already_matched != NULL && hset_contains(already_matched, sf))
			continue;

		if (!shared_file_is_shareable(sf))
			continue;		/* Cannot be shared */

		filename_len = (*flen)(sf);

		if (filename_len < minlen)
			continue;		/* Can't match */

		scanned++;

		if (entry_match(e->string, filename_len, pattern, wovec, wocnt)) {
			if (GNET_PROPERTY(matching_debug) > 4) {
				g_debug("MATCH \"%s\" matches %s",
					search, shared_file_name_nfc(sf));
			}

			local = pslist_prepend_const(local, sf);
			nres++;
		}
	}

	*result = local;

	if (GNET_PROPERTY(matching_debug) > 3) {
		g_debug("MATCH %s(): "
			"scanned %d entr%s from the %d in bin, got %d match%s",
			G_STRFUNC, scanned, plural_y(scanned),
			best_bin_size, nres, plural_es(nres));
	}

	for (i = 0; i < wocnt; i++) {
		if (pattern[i])					/* Lazily compiled by entry_match() */
			pattern_free(pattern[i]);
	}

	WFREE_ARRAY(pattern, wocnt);
	word_vec_free(wovec, wocnt);

	/* FALL THROUGH */

finish:
	hset_free_null(&already_matched);

	return nres;
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
int G_HOT
st_search(
	search_table_t *table,
	const char *search_term,
	st_search_callback callback,
	void *ctx,
	uint max_res,
	query_hashvec_t *qhv)
{
	uint nres = 0;
	uint i;
	pslist_t *result = NULL;
	char *search, *alias;

	/*
	 * We use a canonic search string, which simplifies matching.
	 *
	 * A canonic string has all letters lower-cased, most non-alphanumeric
	 * replaced by a " ".  However, important non-space marks like "\n"
	 * or japanese kana marks are kept.
	 */

	search = UNICODE_CANONIZE(search_term);

	if (GNET_PROPERTY(query_debug) > 4 && 0 != strcmp(search, search_term)) {
		char *safe_search = hex_escape(search, FALSE);
		char *safe_search_term = hex_escape(search_term, FALSE);
		g_debug("%s(): original=\"%s\", canonic=\"%s\"",
			G_STRFUNC, safe_search_term, safe_search);
		if (safe_search != search)
			HFREE_NULL(safe_search);
		if (safe_search_term != search_term)
			HFREE_NULL(safe_search_term);
	}


	/*
	 * Run the original query, unmangled.
	 */

	nres = st_run_search(SEARCH_NORMAL, &table->plain, search, &result, qhv);

	/*
	 * Handle aliases if needed.
	 *
	 * If the alias set is empty, there is no need to attempt a search through
	 * an aliased query.
	 */

	alias = 0 == table->alias.nentries ? NULL : alias_normalize(search, " ");

	if (alias != NULL) {
		nres += st_run_search(SEARCH_ALIAS, &table->alias, alias, &result, NULL);
		HFREE_NULL(alias);
	}

	/*
	 * Randomly shuffle the results and pick the first max_res items.
	 */

	if (result != NULL) {
		if (nres > max_res)
			result = pslist_shuffle(result);

		for (i = 0; i < max_res; /* empty */) {
			const shared_file_t *sf = pslist_shift(&result);

			if (NULL == sf)
				break;

			if ((*callback)(ctx, sf))
				i++;						/* Entry retained */
		}

		pslist_free_null(&result);
	}

	if (search != search_term)
		HFREE_NULL(search);

	return nres;
}

/* vi: set ts=4 sw=4 cindent: */
