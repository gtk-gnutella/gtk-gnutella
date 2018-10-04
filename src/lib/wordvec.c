/*
 * Copyright (c) 2001-2003, Raphael Manfredi
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

/**
 * @ingroup lib
 * @file
 *
 * Word vector.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "common.h"

#include "wordvec.h"

#include "halloc.h"
#include "hstrfn.h"
#include "htable.h"
#include "unsigned.h"
#include "utf8.h"
#include "walloc.h"
#include "zalloc.h"

#include "override.h"		/* Must be the last header included */

#define WOVEC_DFLT	10		/**< Default size of word-vectors */

static zone_t *wovec_zone = NULL;	/**< Word-vectors of WOVEC_DFLT entries */

/**
 * Initialize matching data structures.
 */
void
word_vec_init(void)
{
	/*
	 * We don't expect much word vectors to be created.  They are normally
	 * created and destroyed in the same routine.
	 *
	 * We only allocate word vectors of WOVEC_DFLT entries in the zone.
	 * If we need to expand that, it will be done through regular malloc().
	 *
	 * The zone is not private: concurrent allocation can be done.
	 */

	wovec_zone = zget(WOVEC_DFLT * sizeof(word_vec_t), 10, FALSE);
}

/**
 * Terminate matching data structures.
 */
void
word_vec_close(void)
{
	zdestroy(wovec_zone);
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

/**
 * Reallocate a word-vector from the zone into heap memory, to hold `ncount'.
 */
static word_vec_t *
word_vec_zrealloc(word_vec_t *wv, int ncount)
{
	word_vec_t *nwv;

	g_assert(ncount > WOVEC_DFLT);

	HALLOC_ARRAY(nwv, ncount);
	memcpy(nwv, wv, WOVEC_DFLT * sizeof(word_vec_t));
	zfree(wovec_zone, wv);

	return nwv;
}

/**
 * Given a query string, return a dynamically built word vector, along
 * with the amount of items held into that vector.
 * Words are broken on non-alphanumeric boundaries.
 *
 * @returns the amount of valid items in the built vector, and fill `wovec'
 * with the pointer to the allocated vector.  If there are no items, there
 * is no vector returned.
 */
uint
word_vec_make(const char *query_str, word_vec_t **wovec)
{
	uint n = 0;
	htable_t *seen_word = NULL;
	uint nv = WOVEC_DFLT;
	word_vec_t *wv = zalloc(wovec_zone);
	const char *start = NULL;
	char * const query_dup = h_strdup(query_str);
	char *query;
	uchar c;

	g_assert(wovec != NULL);

	for (query = query_dup; /* empty */; query++) {
		bool is_separator;

		c = *(uchar *) query;
		/*
	 	 * We can't meet other separators than space, because the
	 	 * string is normalised.
	 	 */
		is_separator = c == ' ' || c == '\0';

		if (start == NULL) {				/* Not in a word yet */
			if (!is_separator)
				start = query;
		} else {
			uint np1;

			if (!is_separator)
				continue;

			*query = '\0';

			/* Only create a hash table if there is more than one word. */
			if G_UNLIKELY(0 == n)
				np1 = 0;
			else {
				if G_UNLIKELY(NULL == seen_word) {
					seen_word = htable_create(HASH_KEY_STRING, 0);
					htable_insert(seen_word, wv[0].word, uint_to_pointer(1));
				}

				/*
			 	 * If word already seen in query, it's in the seen_word table.
				 * The associated value is the index in the vector plus 1: that
				 * way, we can know a word is not present in the table since
				 * the line below will evaluate to 0.
		 	 	 */

				np1 = pointer_to_uint(htable_lookup(seen_word, start));
			}

			if (np1--) {
				/* Word already seen before */
				g_assert(np1 < n);
				wv[np1].amount++;
			} else {
				/* We are dealing with a new word */
				word_vec_t *entry;

				if G_UNLIKELY(n == nv) {		/* Filled all the slots */
					nv *= 2;
					if (n > WOVEC_DFLT)
						HREALLOC_ARRAY(wv, nv);
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
				 * the first word.
				 */

				if (n > 1)
					htable_insert(seen_word, entry->word, uint_to_pointer(n));
			}
			start = NULL;
		}

		if (c == '\0') break;
	}

	htable_free_null(&seen_word);	/* Key pointers belong to vector */
	if (n)
		*wovec = wv;
	else
		zfree(wovec_zone, wv);
	hfree(query_dup);
	return n;
}

/**
 * Release a word vector, containing `n' items.
 */
void
word_vec_free(word_vec_t *wovec, uint n)
{
	uint i;

	g_assert(uint_is_positive(n));

	for (i = 0; i < n; i++)
		wfree(wovec[i].word, wovec[i].len + 1);

	if (n > WOVEC_DFLT)
		HFREE_NULL(wovec);
	else
		zfree(wovec_zone, wovec);
}

/* vi: set ts=4 sw=4 cindent: */
