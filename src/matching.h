/*
 * Copyright (c) 2001, Raphael Manfredi
 */

#ifndef __matching_h__
#define __matching_h__

/*
 * Search query splitting.
 */

typedef struct {				/* Query word vector */
	guchar *word;				/* The word to search */
	guint amount;				/* Amount of expected occurrences */
} word_vec_t;

guint query_make_word_vec(guchar *query, word_vec_t **wovec);
void query_word_vec_free(word_vec_t *wovec, guint n);

/*
 * Sunday pattern search data structures.
 */

#define ALPHA_SIZE	256			/* Alphabet size */

typedef struct {				/* Compiled pattern */
	guchar *pattern;			/* The pattern */
	guint32 len;				/* Pattern length */
	guint32 delta[ALPHA_SIZE];	/* Shifting deltas */
} cpattern_t;

typedef enum {
	qs_any = 0,					/* Match anywhere */
	qs_begin,					/* Match beginning of words */
	qs_whole					/* Match whole words only */
} qsearch_mode_t;

cpattern_t *pattern_compile(guchar *pattern);
void pattern_free(cpattern_t *cpat);
gchar *pattern_qsearch(cpattern_t *cpat,
	guchar *text, guint32 tlen, guint32 toffset, qsearch_mode_t word);

/*
 * Basic explanation of how search table works:
 *
 *    A search_table is a global object.  Only one of these is expected to
 *  exist.  It consists of a number of "bins", each bin containing all
 *  entries which have a certain sequence of two characters in a row, plus
 *  some metadata.
 *
 *    Each bin is a simple array, without repetitions, of items.  Each item
 *  consists of a string to which a certain mapping of characters onto
 *  characters has been applied, plus a void * representing the actual data
 *  mapped to.  (I used void * to make this code reasonably generic, so that
 *  in any project I or someone else wants to use code like this for, they
 *  can just use it.)  The same mapping is also applied to each search before
 *  running it.  This maps uppercase and lowercase letters to match one
 *  another, maps all whitespace and punctuation to a simple space, etc.
 *  This mechanism is very flexible and could easily be adapted to match
 *  accented characters, etc.
 *
 *    The actual search builds a regular expression to do the matching.  This
 *  might have a tiny bit higher overhead than a custom implementation of
 *  string matching, but it also allows a great deal of flexibility and ease
 *  of experimentation with different search techniques, both to increase
 *  efficiency and to give the best possible results.  Hopefully the code is
 *  reasonably self-explanatory, but if you find it confusing, email the
 *  gtk-gnutella-devel mailing list and I'll try to respond...
 *
 *    -- KBH, 2001-10-03
 */

struct st_entry {
	guchar *string;
	void *data;
	guint32 mask;
};

typedef	guchar char_map_t[256];		/* Maps one char to another */

struct st_bin {
	gint nslots, nvals;
	struct st_entry **vals;
};

typedef struct _search_table {
	gint nentries, nchars, nbins;
	struct st_bin **bins;
	struct st_bin all_entries;
	char_map_t index_map, fold_map;
} search_table_t;

void st_initialize(search_table_t *, char_map_t);
void st_create(search_table_t *table);
void st_destroy(search_table_t *);
void st_insert_item(search_table_t *, guchar *, void *);
void st_compact(search_table_t *);

gint st_search(
	search_table_t *table,
	guchar *search,
	void (*callback)(struct shared_file *),
	gint max_res);

#endif	/* __matching_h__ */

/* vi: set ts=4: */

