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

#endif	/* __matching_h__ */

/* vi: set ts=4: */

