/*
 * Copyright (c) 2016 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Managing search word aliases.
 *
 * An alias is defined here as a set of search words that can be used
 * indistinctly without any one being the "right" one.
 *
 * Currently this implementation handles the way different people have
 * of naming series of objects that can be broken into sets.  For instance,
 * the 8th entry of set #4 can be encoded as "s04e08", or "4x08", or "408", or
 * even "04x08".  Because it is unknown which naming convention will be used,
 * we must treat all these as equivalent.
 *
 * So we would define { "s04e08", "4x08", "408", "04x08" } as an alias set.
 *
 * When a word in a shared file matches one of the atrings in an alias set, we
 * must advertise all the words in the set in the QRP table, and when one
 * looks for any of the strings in the set, we must report a match if there
 * is a file bearing one of the other strings in the set.
 *
 * To optimize searching, we normalize the file names bearing one of the words
 * in the alias set, we normalize the query by replacing words by their
 * normalized form and we also search for that, in addition to the original
 * query.
 *
 * @author Raphael Manfredi
 * @date 2016
 */

#include "common.h"

#include "alias.h"

#include "lib/ascii.h"
#include "lib/halloc.h"
#include "lib/hset.h"
#include "lib/hstrfn.h"
#include "lib/parse.h"
#include "lib/strvec.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

enum alias_params_magic { ALIAS_PARAMS_MAGIC = 0x42822a17 };

/**
 * Set generating parameters.
 *
 * This is a generic data structure whose size and interpretation will vary
 * depending on the actual alias set.
 *
 * However, the head of the data structure will always be matching the following
 * fields.
 */
struct alias_params {
	enum alias_params_magic magic;	/* Magic number */
	uint len;						/* Total length of the structure */
	char params[1];					/* Start of parameters */
};

static inline void
alias_params_check(const struct alias_params * const ap)
{
	g_assert(ap != NULL);
	g_assert(ALIAS_PARAMS_MAGIC == ap->magic);
}

/**
 * An alias generator function.
 *
 * Given the set generation parameters, this routine fills a pre-allocated array
 * with all the words in the set.  The array is NULL-terminated for convenience
 * (allowing it to be treated as any other "string vector") and must therefore
 * be correctly sized to hold that extra value by the caller.
 *
 * The interpretation of the "param" argument is left to the generation routine.
 * It will typically be a pointer to a structure providing the actual set
 * generation instructions.
 *
 * The first item in the vector can be considered as the normalized form
 * of the set.
 *
 * @param ap		the alias set generation parameters
 * @param vec		pre-allocated string vector, with cnt entries
 * @param cnt		size of the string vector
 */
typedef void (*alias_wordgen_t)(const alias_params_t *ap,
	char **vec, size_t cnt);

/**
 * Allocates the normalized form of the set with defined generation parameters.
 *
 * @param ap		the alias set generation parameters
 */
typedef char *(*alias_normalized_t)(const alias_params_t *ap);

/**
 * A routine checking whether a word is part of a set.
 *
 * This is typically a pattern-matching routine that will return TRUE if
 * the given word is part of a set.
 *
 * @param word		the word to attempt to match
 * @param params	where address of allocated generation parameters is stored
 */
typedef bool (*alias_match_t)(const char *word, alias_params_t **params);

enum alias_set_magic { ALIAS_SET_MAGIC = 0x6c8cf00f };

/**
 * A description of a known set.
 */
struct alias_set {
	enum alias_set_magic magic;
	const char *name;			/**< set name, for debugging */
	size_t count;				/**< the set count */
	alias_wordgen_t wordgen;	/**< routine generating the set of words */
	alias_match_t match;		/**< routine to check whether word matches */
	alias_normalized_t normal;	/**< routine to generate normalized string */
	size_t params_size;			/**< size of parameter structure */
};

static inline void
alias_set_check(const struct alias_set * const as)
{
	g_assert(as != NULL);
	g_assert(ALIAS_SET_MAGIC == as->magic);
}

/* === The "series" alias set === */

/**
 * Generation parameters for the "series" aliases.
 */
struct alias_params_series {
	/* Mandatory generic fields */
	enum alias_params_magic magic;	/* Magic number */
	uint len;						/* Total length of the structure */
	/* Set-specific fields */
	uint season;					/* Season number */
	uint episode;					/* Episode number */
};

/**
 * Allocates the normalized string for the "series" set.
 *
 * @param ap		the alias set generation parameters
 */
static char *
alias_series_normalized(const alias_params_t *ap)
{
	struct alias_params_series *p = (struct alias_params_series *) ap;

	g_assert(ap->len == sizeof(struct alias_params_series));

	return h_strdup_printf("s%02ue%02u", p->season, p->episode);
}

/**
 * Generator for the "series" set.
 *
 * The first entry in the vector is the normalized form of the set.
 *
 * @param ap		the alias set generation parameters
 * @param vec		pre-allocated string vector, with cnt entries
 * @param cnt		size of the string vector
 */
static void
alias_series_gen(const alias_params_t *ap, char **vec, size_t cnt)
{
	struct alias_params_series *p = (struct alias_params_series *) ap;
	size_t n = 0;

	g_assert(ap->len == sizeof(struct alias_params_series));
	g_assert(5 == cnt);

	vec[n++] = alias_series_normalized(ap);

	vec[n++] = h_strdup_printf("%02u%02u",  p->season, p->episode);
	vec[n++] = h_strdup_printf("%u%02u",    p->season, p->episode);
	vec[n++] = h_strdup_printf("%ux%02u",   p->season, p->episode);
	vec[n++] = h_strdup_printf("%02ux%02u", p->season, p->episode);

	g_assert(n == cnt);
}

/**
 * Extract season and episode from a word composed of "season number",
 * followed by a separator and then the "episode number".
 *
 * @return TRUE if we were able to extract season and episode correctly.
 */
static bool
alias_series_extract(const char *word, int sep, uint *season, uint *episode)
{
	const char *end;
	int error;
	uint value;

	value = parse_uint(word, &end, 10, &error);

	if (error != 0)
		return FALSE;

	if (sep != *end)
		return FALSE;	/* number ended before the separator */

	if (0 == value || value > 18)
		return FALSE;	/* Magic limitations to avoid "years" */

	*season = value;

	value = parse_uint(end + 1, &end, 10, &error);

	if (error != 0)
		return FALSE;

	if (0 != *end)
		return FALSE;	/* trailing character after episode number */

	if (value >= 100)
		return FALSE;

	*episode = value;
	return TRUE;
}

/**
 * Check whether "word" is part of the "series" set.
 *
 * @attention
 * This routine must be reasonably fast, and matching shortcuts are critical
 * to ensure we do not spend time parsing a string that we know cannot match.
 *
 * @param word		the word to attempt to match
 * @param params	where address of allocated generation parameters is stored
 *
 * @return TRUE if the word matches.
 */
static bool G_HOT
alias_series_match(const char *word, alias_params_t **params)
{
	uint season = 0, episode = 0;
	int c = word[0];
	const char *end;
	int error;
	uint value;

	if (is_ascii_digit(c)) {
		c = word[1];
		if (0 == c)
			return FALSE;
		if ('x' == c) {
			/* "4x05" for instance */
			goto x_separator;
		} else if (is_ascii_digit(c)) {
			c = word[2];
			if (0 == c)
				return FALSE;
			if ('x' == c) {
				/* "24x12" for instance */
				goto x_separator;
			}
		}

		/*
		 * Word is long enough to be a valid series number, parse it.
		 */

		value = parse_uint(word, &end, 10, &error);
		if (error != 0)
			return FALSE;

		if (0 != *end)
			return FALSE;	/* "word" was not a whole number */

		/*
		 * Magic... We must start at 101 (season 1, episode 1) and
		 * we do not go above 1899 to avoid "years" like 1996 or 2016.
		 *
		 * We authorize episode = 0 for seasons > 1.
		 */

		if (value < 101 || value > 1899)
			return FALSE;

		season = value / 100;
		episode = value - (100 * season);
	} else if ('s' == c) {
		/* "s03e06" for instance */
		c = word[1];
		if (0 == c)
			return FALSE;
		if (!is_ascii_digit(c))
			return FALSE;		/* Quick shortcut if 's' followed by letter */
		if (!alias_series_extract(word + 1, 'e', &season, &episode))
			return FALSE;
	} else {
		return FALSE;
	}

done:
	/*
	 * Allocate parameters if requested.
	 */

	if (params != NULL) {
		struct alias_params_series *p;

		WALLOC0(p);
		p->magic = ALIAS_PARAMS_MAGIC;
		p->len = sizeof(*p);
		p->season = season;
		p->episode = episode;

		*params = (alias_params_t *) p;
	}

	return TRUE;

x_separator:
	/*
	 * Extract season and episode from "4x03" or "04x03".
	 */

	if (!alias_series_extract(word, 'x', &season, &episode))
		return FALSE;

	goto done;			/* We extracted the season and episode numbers */

}

/* === End of the "series" alias set === */

/**
 * All the known alias sets.
 */
static const struct alias_set alias_known_sets[] = {
	{
		ALIAS_SET_MAGIC, "series", 5,
		alias_series_gen, alias_series_match, alias_series_normalized,
		sizeof(struct alias_params_series)
	},
};

/**
 * Check whether "word" is part of a set we know.
 *
 * If "params" is non-NULL and the word matches a set, its generation
 * parameters will be allocated and returned there.
 *
 * @param word		the word we want to check
 * @param params	if non-NULL, where set generation parameters are filled
 *
 * @return the set descriptor if found, NULL otherwise.
 */
static const alias_set_t *
alias_word_in_set(const char *word, alias_params_t **params)
{
	const struct alias_set *as;
	size_t i;

	g_assert(word != NULL);

	for (
		i = 0, as = &alias_known_sets[0];
		i < N_ITEMS(alias_known_sets);
		i++, as++
	) {
		if (as->match(word, params))
			return as;
	}

	return NULL;		/* Not found! */
}

/**
 * Get normalized string representing the set defined with given parameters.
 *
 * @param as		the alias set
 * @param ap		the alias generation parameters
 *
 * @return a newly allocated string that can be freed with hfree().
 */
static char *
alias_normal_alloc(const alias_set_t *as, const alias_params_t *ap)
{
	alias_set_check(as);
	alias_params_check(ap);

	return (*as->normal)(ap);
}

/**
 * Free allocated set generation parameters and nullify its pointer.
 */
static void
alias_params_free_null(alias_params_t **ap_ptr)
{
	alias_params_t *ap = *ap_ptr;

	if (ap != NULL) {
		alias_params_check(ap);

		wfree(ap, ap->len);
		*ap_ptr = NULL;
	}
}

/**
 * Generate the words corresponding to the set as a string vector.
 *
 * @param as	the set descriptor
 * @param ap	set generation parameters
 * @param cnt	if not NULL, filled with amount of entries in the vector
 *
 * @return a string vector that can be freed with h_strfreev().
 */
static char **
alias_wordvec_alloc(
	const alias_set_t *as, const alias_params_t *ap, size_t *cnt)
{
	char **vec;
	size_t n;

	alias_set_check(as);
	alias_params_check(ap);

	n = as->count;
	HALLOC0_ARRAY(vec, n + 1);

	(*as->wordgen)(ap, vec, n);

	if (cnt != NULL)
		*cnt = n;

	return vec;
}

/**
 * Utility routine to normalize a string, considering all known alias sets.
 *
 * The given string is broken into words, delimited by the bytes in the "delim"
 * string.  Then each word is checked for an alias, and is normalized, with
 * each known alias set being used only once.
 *
 * The expectation from set matching routines is that the string is canonic,
 * that is all ASCII letters are lower-cased.  This speeds up matching.
 *
 * @attention
 * The normalized string returned may be identical to the input, but this
 * indicates that the string contains words belonging to some equivalence
 * class.
 *
 * @param str		the string to normalize (must be canonic)
 * @param delim		the delimiting bytes to use for breaking up into words
 *
 * @return NULL if we were not able to find aliases, the normalized string
 * otherwise, which must be freed with hfree().  Words in the normalized
 * string are spearated by a single space.
 */
char *
alias_normalize(const char *str, const char *delim)
{
	char **vec;
	const char *word;
	size_t i;
	hset_t *seen;
	bool normalized = FALSE;
	char *result = NULL;

	g_assert(str != NULL);
	g_assert(delim != NULL);

	vec = h_strsplit_set(str, delim, 0);
	seen = hset_create(HASH_KEY_SELF, 0);

	for (i = 0, word = vec[0]; word != NULL; word = vec[++i]) {
		alias_params_t *params = NULL;
		const alias_set_t *as = alias_word_in_set(word, &params);

		if (NULL == as)
			continue;

		if (!hset_contains(seen, as)) {
			char *normal = alias_normal_alloc(as, params);

			hset_insert(seen, as);		/* Each set can be used once */
			normalized = TRUE;			/* At least one word in alias sets */

			if (0 != strcmp(normal, word)) {
				hfree(vec[i]);
				vec[i] = normal;		/* "normal" was halloc()'ed as well */
			} else {
				HFREE_NULL(normal);
			}
		}

		alias_params_free_null(&params);
	}

	if (normalized)
		result = h_strjoinv(" ", vec);

	hset_free_null(&seen);
	h_strfreev(vec);

	return result;
}

/**
 * Utility routine to compute all additional words, as an alias expansion.
 *
 * The given string is broken into words, delimited by the bytes in the "delim"
 * string.  Then each word is checked for an alias, and is expanded, with
 * each known alias set being used only once.
 *
 * @param str		the string to normalize
 * @param delim		the delimiting bytes to use for breaking up into words
 *
 * @return a string vector (cannot be empty) that needs to be freed with
 * h_strfreev() and which contains all the additional words expanded from
 * each alias we found, or NULL if we have not found any alias.
 */
char **
alias_expand(const char *str, const char *delim)
{
	char **vec, **result = NULL;
	const char *word;
	size_t i, total = 0;
	hset_t *seen;

	g_assert(str != NULL);
	g_assert(delim != NULL);

	vec = h_strsplit_set(str, delim, 0);
	seen = hset_create(HASH_KEY_SELF, 0);

	for (i = 0, word = vec[0]; word != NULL; word = vec[++i]) {
		alias_params_t *params = NULL;
		const alias_set_t *as = alias_word_in_set(word, &params);

		if (NULL == as)
			continue;

		if (!hset_contains(seen, as)) {
			size_t n;
			char **words = alias_wordvec_alloc(as, params, &n);

			hset_insert(seen, as);		/* Each set can be used once */

			if (NULL == result) {
				g_assert(0 == total);
				result = words;
				total = n;
			} else {
				result = strvec_append_with(hrealloc, result, &total, words, n);
				hfree(words);	/* String pointers copied into result[] */
			}
		}

		alias_params_free_null(&params);
	}

	hset_free_null(&seen);
	h_strfreev(vec);

	g_assert(NULL == result || NULL == result[total]);

	return result;
}

/* vi: set ts=4 sw=4 cindent: */
