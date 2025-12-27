/*
 * Copyright (c) 2023 Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * String substitution and matching using regular expressions.
 *
 * @author Raphael Manfredi
 * @date 2023
 */

#include "common.h"

#include "str_subst_re.h"

#include "ascii.h"
#include "alloca.h"
#include "halloc.h"
#include "hashing.h"
#include "hstrfn.h"
#include "log.h"
#include "lru_cache.h"
#include "once.h"
#include "re.h"
#include "str.h"
#include "stringify.h"
#include "unsigned.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

/*
 * The size of the LRU regex cache is fixed, arbitrarily.
 *
 * If necessary, we will offer a way for client code to customize the
 * size of the LRU cache, and possibly dynamically increase/decrease the
 * value.
 */
#define STR_REGEX_CACHE_SIZE 	64		/* Size of LRU cache for regex */

/*
 * Since compilation of a regular expression is an expensive operation
 * (typically taking 500x more time than actually executing the regex to
 * perform a match), it is worth caching compiled regex in case they
 * happen to be re-used soon.
 */
static lru_cache_t *str_regex_cache;	/* Compiled regex cache */

enum str_match_magic { STR_MATCH_MAGIC = 0x7d7a5f8b };

struct str_match {
	enum str_match_magic magic;	/* Magic number */
	str_t *source;				/* Source string for matching (cloned) */
	re_match_t *pos;			/* Matching positions in source */
	size_t npos;				/* Total amount of entries in `pos' */
};

static void
str_match_check(const struct str_match * const m)
{
	g_assert(m != NULL);
	g_assert(STR_MATCH_MAGIC == m->magic);
}

enum str_re_cached_magic { STR_RE_CACHED_MAGIC = 0x4a007261 };

/*
 * Keys for the cached regex.
 */
struct str_re_cached {
	enum str_re_cached_magic magic;	/* Magic number */
	uint32 cflags;					/* Pattern compilation flags */
	const char *pattern;			/* The pattern string */
};

static void
str_re_cached_check(const struct str_re_cached * const rc)
{
	g_assert(rc != NULL);
	g_assert(STR_RE_CACHED_MAGIC == rc->magic);
}

/* Creates a str_re_cached key */
static struct str_re_cached *
str_re_cached_new(const char *pattern, uint32 cflags)
{
	struct str_re_cached *rc;

	WALLOC0(rc);
	rc->magic = STR_RE_CACHED_MAGIC;
	rc->cflags = cflags;
	rc->pattern = h_strdup(pattern);

	return rc;
}

/* Hashing function for str_re_cached keys */
static unsigned
str_re_cached_hash(const void *p)
{
	const struct str_re_cached *rc = p;

	str_re_cached_check(rc);

	return integer_hash(rc->cflags) + string_mix_hash(rc->pattern);
}

/* Equality function for str_re_cached_hash */
static bool
str_re_cached_eq(const void *a, const void *b)
{
	const struct str_re_cached *rca = a;
	const struct str_re_cached *rcb = b;

	str_re_cached_check(rca);
	str_re_cached_check(rcb);

	return rca->cflags == rcb->cflags && string_eq(rca->pattern, rcb->pattern);
}

/* Free routine for the tuple (str_re_cached, regex) */
static void
str_re_cached_kvfree(void *key, void *val)
{
	struct str_re_cached *rc = key;
	re_regex_t *re = val;

	str_re_cached_check(rc);

	hfree(deconstify_char(rc->pattern));
	rc->magic = 0;
	WFREE(rc);

	re_free(re);
}

/**
 * Initialize LRU cache for regex.
 */
static void
str_re_cache_init(void)
{
	/*
	 * These operations are performed atomically, under the protection
	 * of the "once" mechanism, hence there is no race condition introduced
	 * by setting the str_regex_cache variable before marking the cache
	 * thread-safe.
	 */

	str_regex_cache = lru_cache_make(
		STR_REGEX_CACHE_SIZE,
		str_re_cached_hash, str_re_cached_eq,
		str_re_cached_kvfree);

	lru_cache_thread_safe(str_regex_cache);
}

/**
 * Initialize LRU cache for regex if not done yet.
 */
static void
str_re_cache_init_once(void)
{
	static once_flag_t done;

	once_flag_run(&done, str_re_cache_init);
}

/**
 * Compile pattern, possibly re-using cache and caching compiled form.
 *
 * If `cache_re' is TRUE, then the compiled form returned may be from the cache
 * and therefore it must not be freed by the caller: it will get disposed of
 * when the cached entry expires.
 *
 * @param caller		the calling routine, for error reporting
 * @param pat			the pattern string to compile
 * @param cflags		the compilation flags
 * @param cache_re		if TRUE, makes use of the regex cache
 *
 * @return NULL on error, the compiled regular expression otherwise.
 */
static re_regex_t *
str_re_compile(const char *caller, const char *pat, uint32 cflags, bool cache_re)
{
	re_regex_t *re;

	if (cache_re) {
		struct str_re_cached rc;

		rc.magic = STR_RE_CACHED_MAGIC;
		rc.pattern = pat;
		rc.cflags = cflags;

		str_re_cache_init_once();

		re = lru_cache_lookup(str_regex_cache, &rc);
	} else {
		re = NULL;
	}

	if (NULL == re) {
		re_error_t error;

		re = re_compile(pat, cflags, &error);

		if (NULL == re) {
			s_carp("%s(): error compiling regex \"%s\" at offset %zu: %s",
				caller, pat, error.pos, re_strerror(error.code));
			return NULL;
		}

		if (cache_re)
			lru_cache_insert(str_regex_cache, str_re_cached_new(pat, cflags), re);
	}

	return re;
}

/**
 * Apply offset to all positions in the array that are not -1.
 *
 * This is meant to re-establish offsets from the start of the supplied text
 * when we actually begin matching in the middle of the text.
 */
static void
str_match_offset_pos(re_match_t *pos, size_t npos, ssize_t offset)
{
	size_t i;

	if (0 == offset)
		return;			/* Nothing to offset */

	for (i = 0; i < npos; i++) {
		if (pos[i].re_start != -1) {
			pos[i].re_start += offset;
			pos[i].re_end += offset;
		}
	}
}

/**
 * Attempt a match on `s', at offset `offset', using compiled regex `re'.
 *
 * If `pos' is non-NULL, it is filled with the starting and ending offsets
 * within `s' of the first match.
 *
 * If `offset' is negative, its absolute value stands for the amount of bytes
 * starting from the end of the string (hence -1 is the last byte).
 *
 * When `keep_pos' is TRUE, we ignore `offset' and instead use the
 * ending position in pos[0] to continue matching further.  This means that
 * on the first invocation, pos[0].re_end must be 0.
 *
 * @param caller	name of calling routine, for logging
 * @param s			the string over which matching is attempted
 * @param offset	the string offset at which matching must start
 * @param re		the compiled regular expression pattern to use
 * @param pos		if non-NULL, filled with matching position
 * @param npos		how many items in the `pos' array (for getting group matches)
 * @param keep_pos	whether we need to restart where we left off at previous match
 * @param eflags	regex execution flags
 *
 * @return TRUE if a match occurred, with `pos' filled if supplied, otherwise
 * FALSE with `pos' left untouched.
 *
 * If there are groups, pos[0] will indicate the overall match and pos[i],
 * for i > 0, will refer to the text matched by group #i in the pattern.
 */
static bool
str_match_rec_internal(const char *caller, const str_t *s, ssize_t offset,
	const re_regex_t *re, re_match_t *pos, size_t npos,
	bool keep_pos, uint32 eflags)
{
	int match;
	const char *str;
	size_t len;
	ssize_t idx = offset;

	str = str_2c(deconstify_pointer(s));
	len = str_len(s);

	if (idx < 0)
		idx += len;

	if ((size_t) idx == len)
		return FALSE;					/* End of string, silent failure */

	if (idx < 0 || (size_t) idx > len) {
		s_carp("%s(): invalid start offset %zd: string has only %zu byte%s",
			caller, offset, PLURAL(len));
		return FALSE;
	}

	if (keep_pos) {
		if (NULL == pos) {
			s_carp("%s(): cannot keep position with a NULL `pos' argument!",
				caller);
			return FALSE;
		}

		if (0 == pos[0].re_end)
			idx = 0;					/* First matching attempt */
		else if (-1 == pos[0].re_end)
			return FALSE; 				/* Did not match earlier, finished! */
		else
			idx = pos[0].re_end;		/* Continue past last match */

		if ((size_t) idx >= len)
			return FALSE;				/* Reached end of the text */
	}

	if (npos > 1 && npos < 1 + re_group_count(re)) {
		s_carp("%s(): supplied group capturing too small: "
			"can hold %zu group%s, but regex \"%s\" defines %zu groups",
			caller, PLURAL(npos - 1), re_pattern(re), re_group_count(re));
		/* Just a friendly warning, this does not prevent execution */
	}

	match = re_execute_full(re, str + idx, len - idx, pos, npos, eflags);

	if (match < 0) {
		s_carp("%s(): error executing regex \"%s\": %s",
			caller, re_pattern(re), re_execute_strerror(match));
		return FALSE;
	}

	if (pos != NULL)
		str_match_offset_pos(pos, npos, idx);

	/*
	 * If they keep the position and the end of the match is at the same offset
	 * as we started, it means we are matching an empty string.
	 *
	 * Looping until there is no longer a match would result in an endless loop,
	 * hence loudly warn and report a failure.
	 */

	if (keep_pos && match && idx == pos[0].re_end) {
		s_carp("%s(): executing regex \"%s\" matches empty string "
			"at offset %zd (text length: %zu byte%s) -- stopping 'c' and failing!",
			caller, re_pattern(re), idx, PLURAL(len));
		return FALSE;
	}

	return booleanize(match);
}

/**
 * Attempt a match on `s' using regular expression `pat'.  If `pos' is non-NULL,
 * it is filled with the starting and ending offsets within `s' of the first match.
 *
 * The match starts at `offset' within s.  If offset is negative, its absolute
 * value refers to a position before the end of the string, i.e. -1 is the last
 * character.
 *
 * @param s			the string over which matching is attempted
 * @param offset	starting offset in string
 * @param caller	calling routine name, for error reporting
 * @param pat		the regular expression pattern to match
 * @param cflags	pattern compilation flags
 * @param pos		if non-NULL, filled with matching position
 *
 * @return TRUE if a match occurred, with `pos' filled if supplied, otherwise
 * FALSE with `pos' left untouched.
 */
bool
str_match_re_plain_internal(const str_t *s, ssize_t offset,
	const char *caller, const char *pat, uint32 cflags, re_match_t *pos)
{
	re_regex_t *re;
	int match;

	str_check(s);
	g_assert(pat != NULL);

	/*
	 * We cache the compiled form, hence we will not free the regex here.
	 */

	re = str_re_compile(caller, pat, cflags, TRUE);
	if (NULL == re)
		return FALSE;

	match = str_match_rec_internal(caller,
				s, offset, re, pos, NULL != pos, FALSE, 0);

	return booleanize(match);
}

/**
 * Attempt a match on `s' using regular expression `pat'.  If `pos' is non-NULL,
 * it is filled with the starting and ending offsets within `s' of the first match.
 *
 * @param s		the string over which matching is attempted
 * @param pat	the regular expression pattern to match
 * @param pos	if non-NULL, filled with matching position
 *
 * @return TRUE if a match occurred, with `pos' filled if supplied, otherwise
 * FALSE with `pos' left untouched.
 */
bool
str_match_re_plain(const str_t *s, const char *pat, re_match_t *pos)
{
	return str_match_re_plain_internal(s, 0, G_STRFUNC, pat, RE_F_NOSUB, pos);
}

/**
 * Attempt a case-insensitive match on `s' using regular expression `pat'.
 * If `pos' is non-NULL, it is filled with the starting and ending offsets
 * within `s' of the first match.
 *
 * @param s		the string over which matching is attempted
 * @param pat	the regular expression pattern to match
 * @param pos	if non-NULL, filled with matching position
 *
 * @return TRUE if a match occurred, with `pos' filled if supplied, otherwise
 * FALSE with `pos' left untouched.
 */
bool
str_case_match_re_plain(const str_t *s, const char *pat, re_match_t *pos)
{
	return str_match_re_plain_internal(s, 0, G_STRFUNC,
				pat, RE_F_NOSUB | RE_F_ICASE, pos);
}

/**
 * Attempt a match on `s', at offset `offset', using regular expression `pat'.
 *
 * If `pos' is non-NULL, it is filled with the starting and ending offsets
 * within `s' of the first match.
 *
 * If `offset' is negative, its absolute value stands for the amount of bytes
 * starting from the end of the string (hence -1 is the last byte).
 *
 * @param s		the string over which matching is attempted
 * @param off	the string offset at which matching must start
 * @param pat	the regular expression pattern to match
 * @param pos	if non-NULL, filled with matching position
 *
 * @return TRUE if a match occurred, with `pos' filled if supplied, otherwise
 * FALSE with `pos' left untouched.
 */
bool
str_match_re_plain_offset(const str_t *s,
	ssize_t off, const char *pat, struct re_match *pos)
{
	return str_match_re_plain_internal(s, off, G_STRFUNC, pat, RE_F_NOSUB, pos);
}

/**
 * Attempt a case-insensitive match on `s', at offset `offset', using regular
 * expression `pat'.
 *
 * If `pos' is non-NULL, it is filled with the starting and ending offsets
 * within `s' of the first match.
 *
 * If `offset' is negative, its absolute value stands for the amount of bytes
 * starting from the end of the string (hence -1 is the last byte).
 *
 * @param s		the string over which matching is attempted
 * @param off	the string offset at which matching must start
 * @param pat	the regular expression pattern to match
 * @param pos	if non-NULL, filled with matching position
 *
 * @return TRUE if a match occurred, with `pos' filled if supplied, otherwise
 * FALSE with `pos' left untouched.
 */
bool
str_case_match_re_plain_offset(const str_t *s,
	ssize_t off, const char *pat, struct re_match *pos)
{
	return str_match_re_plain_internal(s, off, G_STRFUNC,
				pat, RE_F_NOSUB | RE_F_ICASE, pos);
}

/**
 * Attempt a match on `s', at offset `offset', using regular expression `pat'.
 *
 * If `pos' is non-NULL, it is filled with the starting and ending offsets
 * within `s' of the first match.
 *
 * If `offset' is negative, its absolute value stands for the amount of bytes
 * starting from the end of the string (hence -1 is the last byte).
 *
 * The `opt' argument specifies options for the regex match, each letter modifying
 * the way the regular expression will be handled:
 *
 * "c": continue matching where we left off last match
 * "m": multi-line mode ("^" and "$" match at the start/end of each line in string)
 * "s": single-line mode ("." will match all, even a newline).
 * "i": case-insensitive match
 * "n": no group capturing -- all capturing groups transformed in non-capturing
 * "o": once -- compile pattern, but do not bother to cache it
 *
 * When the "c" option is supplied, we ignore `offset' and instead use the
 * ending position in pos[0] to continue matching further.  This means that
 * on the first invocation, pos[0].re_end must be 0.
 *
 * @param s			the string over which matching is attempted
 * @param offset	the string offset at which matching must start
 * @param pat		the regular expression pattern to match
 * @param opt		options, as a set of characters in any order (may be NULL)
 * @param pos		if non-NULL, filled with matching position
 * @param npos		how many items in the `pos' array (for getting group matches)
 *
 * @return TRUE if a match occurred, with `pos' filled if supplied, otherwise
 * FALSE with `pos' left untouched.
 *
 * If there are groups, pos[0] will indicate the overall match and pos[i],
 * for i > 0, will refer to the text matched by group #i in the pattern.
 */
bool
str_match_re_full(const str_t *s, ssize_t offset,
	const char *pat, const char *opt, re_match_t *pos, size_t npos)
{
	uint32 cflags = 0;
	uint32 eflags = 0;
	bool cache_re = TRUE;
	bool keep_pos = FALSE;
	re_regex_t *re;
	int match;

	str_check(s);
	g_assert(pat != NULL);
	g_assert(equiv(NULL == pos, npos == 0));

	if (opt != NULL) {
		int c;

		while ((c = *opt++)) {
			switch (c) {
			case 'c': keep_pos = TRUE;           break;
			case 'i': cflags |= RE_F_ICASE;      break;
			case 'm': eflags |= RE_X_MULTI_LINE; break;
			case 'n': cflags |= RE_F_NOSUB;      break;
			case 'o': cache_re = FALSE;          break;
			case 's': cflags |= RE_F_NEWLINE;    break;
			default:
				s_carp("%s(): unknown matching option '%c', ignoring",
					G_STRFUNC, c);
				break;

			}
		}

		if (keep_pos) {
			/*
			 * Regardless of 'o', cache compiled form if 'c', since
			 * we can reasonably expect to be called again soon with the
			 * same pattern if we match here.
			 */

			cache_re = TRUE;
		}
	}

	re = str_re_compile(G_STRFUNC, pat, cflags, cache_re);

	if (NULL == re)
		return FALSE;

	match = str_match_rec_internal(G_STRFUNC,
				s, offset, re, pos, npos, keep_pos, eflags);

	if (!cache_re)
		re_free(re);

	return booleanize(match);
}

/**
 * Attempt a match on `s', at offset `offset', using compiled regex `re'.
 *
 * If `pos' is non-NULL, it is filled with the starting and ending offsets
 * within `s' of the first match.
 *
 * If `offset' is negative, its absolute value stands for the amount of bytes
 * starting from the end of the string (hence -1 is the last byte).
 *
 * The `opt' argument specifies options for the regex match, each letter modifying
 * the way the regular expression will be handled:
 *
 * "c": continue matching where we left off last match
 * "m": multi-line mode ("^" and "$" match at the start/end of each line in string)
 * "n": no group capturing
 *
 * When the "c" option is supplied, we ignore `offset' and instead use the
 * ending position in pos[0] to continue matching further.  This means that
 * on the first invocation, pos[0].re_end must be 0.
 *
 * @param s			the string over which matching is attempted
 * @param offset	the string offset at which matching must start
 * @param re		the compiled regular expression to match
 * @param opt		options, as a set of characters in any order (may be NULL)
 * @param pos		if non-NULL, filled with matching position
 * @param npos		how many items in the `pos' array (for getting group matches)
 *
 * @return TRUE if a match occurred, with `pos' filled if supplied, otherwise
 * FALSE with `pos' left untouched.
 *
 * If there are groups, pos[0] will indicate the overall match and pos[i],
 * for i > 0, will refer to the text matched by group #i in the pattern.
 */
bool str_match_rec_full(const str_t *s, ssize_t offset,
	const re_regex_t *re, const char *opt, re_match_t *pos, size_t npos)
{
	uint32 eflags = 0;
	bool keep_pos = FALSE;
	int match;

	str_check(s);
	g_assert(equiv(NULL == pos, npos == 0));

	if (opt != NULL) {
		int c;

		while ((c = *opt++)) {
			switch (c) {
			case 'c': keep_pos = TRUE;           break;
			case 'm': eflags |= RE_X_MULTI_LINE; break;
			case 'n': eflags |= RE_X_NOSUB;      break;
			default:
				s_carp("%s(): unknown matching option '%c', ignoring",
					G_STRFUNC, c);
				break;

			}
		}
	}

	match = str_match_rec_internal(G_STRFUNC,
				s, offset, re, pos, npos, keep_pos, eflags);

	return booleanize(match);
}

/**
 * Same as str_match_re_full() with offset = 0.
 */
bool
str_match_re(const str_t *s,
	const char *pat, const char *opt, re_match_t *pos, size_t npos)
{
	return str_match_re_full(s, 0, pat, opt, pos, npos);
}

/*
 * Same as str_match_rec_full() with offset = 0.
 */
bool str_match_rec(const str_t *s,
	const re_regex_t *re, const char *opt, re_match_t *pos, size_t npos)
{
	return str_match_rec_full(s, 0, re, opt, pos, npos);
}

/**
 * Free str_match_t structure.
 */
void
str_match_free(str_match_t *m)
{
	str_match_check(m);

	str_destroy_null(&m->source);
	HFREE_NULL(m->pos);
	m->magic = 0;
	WFREE(m);
}

/**
 * Free str_match_t structure and nullify pointer.
 */
void
str_match_free_null(str_match_t **m_ptr)
{
	str_match_t *m = *m_ptr;

	if (m != NULL) {
		str_match_free(m);
		*m_ptr = NULL;
	}
}

/**
 * Construct result for str_match_rec?_keep.*() routines.
 */
static str_match_t *
str_match_new(const str_t *s, int match, re_match_t *pos, size_t npos)
{
	if (match) {
		str_match_t *m;

		WALLOC0(m);
		m->magic = STR_MATCH_MAGIC;
		m->source = str_clone(s);
		m->pos = pos;
		m->npos = npos;
		return m;
	} else {
		HFREE_NULL(pos);
		return NULL;
	}

	g_assert_not_reached();
}

/**
 * Attempt a match on `s', at offset `offset', using regular expression `pat'.
 *
 * If `offset' is negative, its absolute value stands for the amount of bytes
 * starting from the end of the string (hence -1 is the last byte).
 *
 * The `opt' argument specifies options for the regex match, each letter modifying
 * the way the regular expression will be handled:
 *
 * "m": multi-line mode ("^" and "$" match at the start/end of each line in string)
 * "s": single-line mode ("." will match all, even a newline).
 * "i": case-insensitive match
 * "n": no group capturing -- all capturing groups transformed in non-capturing
 * "o": once -- compile pattern, but do not bother to cache it
 *
 * @param s			the string over which matching is attempted
 * @param offset	the string offset at which matching must start
 * @param pat		the regular expression pattern to match
 * @param opt		options, as a set of characters in any order (may be NULL)
 *
 * @return NULL if no match occurred, otherwise an opaque structure that can be
 * re-used to construct strings based on the capturing groups, on the matched
 * text, on what precedes or follows the matched text.  This structure needs to
 * be disposed of by calling str_match_free_null() when done.
 */
str_match_t *
str_match_re_keep_offset(
	const str_t *s, ssize_t offset, const char *pat, const char *opt)
{
	uint32 cflags = 0;
	uint32 eflags = 0;
	bool cache_re = TRUE;
	re_regex_t *re;
	int match;
	re_match_t *pos;
	size_t npos;

	str_check(s);
	g_assert(pat != NULL);

	if (opt != NULL) {
		int c;

		while ((c = *opt++)) {
			switch (c) {
			case 'i': cflags |= RE_F_ICASE;      break;
			case 'm': eflags |= RE_X_MULTI_LINE; break;
			case 'n': cflags |= RE_F_NOSUB;      break;
			case 'o': cache_re = FALSE;          break;
			case 's': cflags |= RE_F_NEWLINE;    break;
			default:
				s_carp("%s(): unknown matching option '%c', ignoring",
					G_STRFUNC, c);
				break;

			}
		}
	}

	re = str_re_compile(G_STRFUNC, pat, cflags, cache_re);

	if (NULL == re)
		return NULL;

	npos = 1 + re_group_count(re);
	HALLOC_ARRAY(pos, npos);

	match = str_match_rec_internal(G_STRFUNC,
				s, offset, re, pos, npos, FALSE, eflags);

	if (!cache_re)
		re_free(re);

	return str_match_new(s, match, pos, npos);
}

/*
 * Same as str_match_re_keep_offset() with offset = 0.
 */
str_match_t *
str_match_re_keep(const str_t *s, const char *pat, const char *opt)
{
	return str_match_re_keep_offset(s, 0, pat, opt);
}

/**
 * Attempt a match on `s', at offset `offset', using regular expression `pat'.
 *
 * If `offset' is negative, its absolute value stands for the amount of bytes
 * starting from the end of the string (hence -1 is the last byte).
 *
 * The `opt' argument specifies options for the regex match, each letter modifying
 * the way the regular expression will be handled:
 *
 * "m": multi-line mode ("^" and "$" match at the start/end of each line in string)
 * "n": no group capturing
 *
 * @param s			the string over which matching is attempted
 * @param offset	the string offset at which matching must start
 * @param re		the compiled regular expression to match
 * @param opt		options, as a set of characters in any order (may be NULL)
 *
 * @return NULL if no match occurred, otherwise an opaque structure that can be
 * re-used to construct strings based on the capturing groups, on the matched
 * text, on what precedes or follows the matched text.  This structure needs to
 * be disposed of by calling str_match_free_null() when done.
 */
str_match_t *
str_match_rec_keep_offset(const str_t *s, ssize_t offset,
	const re_regex_t *re, const char *opt)
{
	uint32 eflags = 0;
	int match;
	re_match_t *pos;
	size_t npos;

	str_check(s);

	if (opt != NULL) {
		int c;

		while ((c = *opt++)) {
			switch (c) {
			case 'm': eflags |= RE_X_MULTI_LINE; break;
			case 'n': eflags |= RE_X_NOSUB;      break;
			default:
				s_carp("%s(): unknown matching option '%c', ignoring",
					G_STRFUNC, c);
				break;

			}
		}
	}

	npos = 1 + ((eflags & RE_X_NOSUB) ? 0 : re_group_count(re));
	HALLOC_ARRAY(pos, npos);

	match = str_match_rec_internal(G_STRFUNC,
				s, offset, re, pos, npos, FALSE, eflags);

	return str_match_new(s, match, pos, npos);
}

/*
 * Same as str_match_rec_keep_offset() with offset = 0.
 */
str_match_t *
str_match_rec_keep(const str_t *s, const re_regex_t *re, const char *opt)
{
	return str_match_rec_keep_offset(s, 0, re, opt);
}

/**
 * Create a new string using captured match groups.
 *
 * @param m		the capture match groups
 * @param idx	the index of the group to use (0 = matched string)
 *
 * @return new string, empty with a loud warning if idx is out of range.
 */
str_t *
str_new_from_match(const str_match_t *m, size_t idx)
{
	str_match_check(m);
	g_assert(size_is_non_negative(idx));

	if (idx >= m->npos) {
		s_carp("%s(): index %zu out of range (max possible is %zu)",
			G_STRFUNC, idx, m->npos - 1);
		return str_new_from("");
	}

	return str_slice(m->source, m->pos[idx].re_start, m->pos[idx].re_end);
}

/**
 * @return string before the recorded match.
 */
str_t *
str_new_before_match(const str_match_t *m)
{
	str_match_check(m);

	return str_slice(m->source, 0, m->pos[0].re_start);
}

/**
 * @return string after the recorded match.
 */
str_t *
str_new_after_match(const str_match_t *m)
{
	ssize_t off;
	str_match_check(m);

	off = m->pos[0].re_end;

	return str_substr(m->source, off, str_len(m->source) - off);
}

/**
 * @return string at the match, i.e. the part matched by the regular expression.
 */
str_t *
str_new_at_match(const str_match_t *m)
{
	return str_new_from_match(m, 0);
}

/**
 * Parse variable in `src', with leading '$' already read.
 *
 * If everything goes well, sets `end' to be one byte past the end of the parsed
 * variable in `src', otherwise sets `end' to be `src'.
 *
 * If the variable is a group number, sets `idx' to that group number.
 * If the variable is a special variable, sets `special' to the variable char
 * and sets `idx' to -1.
 */
static void
str_new_getvar(
	const char *src, const char **end, size_t *idx, int *special)
{
	const char *p = src;
	bool end_brace = FALSE;
	size_t value = 0;

	if ('{' == *p) {
		p++;
		end_brace = TRUE;		/* Will require closing '}' */
	}

	if (!is_ascii_digit(*p)) {
		/* Special one-char variable */
		*special = *p++;
		*idx = (size_t) -1;
		goto done;
	}

	while (is_ascii_digit(*p))
		value = value * 10 + (*p++ - '0');

	*idx = value;

	/* FALL THROUGH */

done:
	if (end_brace) {
		if ('}' == *p) {
			p++;
		} else {
			p = src;	/* Opening '{' has no closing '}', signal error */
		}
	}

	*end = p;
}

#define POS_LEN(x)	((x).re_end - (x).re_start)

/**
 * Fill destination buffer `dest', of size `dlen' bytes with variable
 * substitution using match information.
 *
 * When `dest' is NULL and `dlen' is 0, we only compute the length of the
 * overall result.
 *
 * @param caller		calling routine name
 * @param expr			text with possible variables
 * @param dest			destination buffer filled with variable substitution
 * @param dlen			length of `dest' in bytes
 * @param is_plain		if non-NULL, set to whether `expr' holds escapes or vars
 *
 * @return the amount of bytes that would be (that were) filled in `dest'.
 */
static size_t
str_new_fill(
	const char *caller,
	const str_match_t *m, const char *expr,
	char *dest, size_t dlen, bool *is_plain)
{
	size_t len = 0;
	const char *p = expr;
	char *q = dest;
	int c;
	bool plain = TRUE;

	str_match_check(m);
	g_assert(implies(NULL == dest, 0 == dlen));
	g_assert(expr != NULL);
	g_assert(size_is_non_negative(dlen));

	while ('\0' != (c = *p++)) {
		switch (c) {
		case '\\':
			c = *p++;
			if ('\0' == c) {
				if (plain) {
					/* Plain text so far, keep trailing '\\' then */
					len++;
					if (q != NULL) *q++ = '\\';
				} else if (NULL == q) {
					s_carp("%s(): dangling trailing '\\' ignored in \"%s\"",
						caller, expr);
				}
				goto done;
			} else if ('$' == c || '\\' == c) {
				plain = FALSE;
				len++;
				if (q != NULL) *q++ = c;
			} else {
				/*
				 * A '\' in front of something other than '$' or '\' is not
				 * considered as an escape and stands for itself.
				 *
				 * Keep it and do not alter `plain'.
				 */
				len += 2;
				if (q != NULL) {
					*q++ = '\\';
					*q++ = c;
				}
			}
			break;
		case '$':
			plain = FALSE;
			{
				const char *end;
				int special = 0;
				size_t idx;

				str_new_getvar(p, &end, &idx, &special);
				if (end == p) {
					if (NULL == q) {
						s_carp("%s(): bad trailing variable "
							"at offset %zd in \"%s\"",
							caller, p - expr, expr);
					}
					goto done;
				}
				if ((size_t) -1 == idx) {
					size_t varlen = 0;
					switch (special) { 		/* Special variable: $`, $& or $' */
					case '`':
						varlen = m->pos[0].re_start;
						if (q != NULL)
							q = mempcpy(q, m->source->s_data, varlen);
						break;
					case '&':
						varlen = POS_LEN(m->pos[0]);
						if (q != NULL) {
							q = mempcpy(q,
								m->source->s_data + m->pos[0].re_start, varlen);
						}
						break;
					case '\'':
						varlen = str_len(m->source) - m->pos[0].re_end;
						if (q != NULL) {
							q = mempcpy(q,
								m->source->s_data + m->pos[0].re_end, varlen);
						}
						break;
					default:
						if (NULL == q) {
							s_carp("%s(): ignoring variable $%c "
								"at offset %zd in \"%s\"",
								caller, special, p - expr, expr);
						}
						break;
					}
					len += varlen;
				} else if (idx >= m->npos) {
					if (NULL == q) {
						s_carp("%s(): out-of-range $%zu at offset %zd in \"%s\"",
							caller, idx, p - expr, expr);
					}
				} else {
					size_t varlen = POS_LEN(m->pos[idx]);
					len += varlen;
					if (q != NULL) {
						q = mempcpy(q,
							m->source->s_data + m->pos[idx].re_start, varlen);
					}
				}
				p = end;
			}
			break;
		default:
			len++;
			if (q != NULL) *q++ = c;
		}
	}

	/* FALL THROUGH */

done:

	g_assert(ptr_add_offset(dest, dlen) == q);		/* Filled dest, if any */

	/* Note that there is no trailing NUL appended at the end */

	if (is_plain != NULL)
		*is_plain = plain;

	return len;
}

/**
 * Evaluate `expr' in the context of the given match, substituting $1 and friends
 * (such as $4 or ${4}) with the corresponding subgroup, and replacing $` and $'
 * with the string before and after the match. One can also use $0 or ${0} or $&
 * to refer to the matched string.
 *
 * @return new string.
 */
str_t *
str_new_using_match(const str_match_t *m, const char *expr)
{
	size_t len;
	str_t *s;
	bool is_plain;

	/*
	 * To avoid moving memory around and possible costly memory resizing, we
	 * run two passes: the first pass computes the length of the resulting
	 * string, the second pass fills the string with the proper values by
	 * simply appending text to the pre-sized object.
	 */

	len = str_new_fill(G_STRFUNC, m, expr, NULL, 0, &is_plain);

	if (is_plain)					/* No variables nor escapes to process */
		return str_new_from(expr);	/* Faster than using str_new_fill() again */

	/*
	 * Second pass: for speed, we directly operate on the underlying string
	 * data buffer, and we do not go through the str_*() routines to append
	 * variable text or characters from the expression.
	 */

	s = str_new(len + 1);	/* Leave room for trailing NUL */
	(void) str_new_fill(G_STRFUNC, m, expr, s->s_data, len, NULL);
	s->s_len = len;

	return s;
}

/**
 * Perform matching and substitution over string.
 *
 * @param caller	calling routine
 * @param s			string to match and substitute
 * @param re		the compiled regular expression to match
 * @param plain		whether replacement is plain or contains variables
 * @param repl		replacement string
 * @param eflags	regex execution flags
 * @param all		whether to perform match/subst globally over string
 *
 * @return amount of substitutions performed.
 */
static size_t
str_subst_internal(
	const char *caller,
	str_t *s, const re_regex_t *re,
	bool plain, const char *repl,
	uint32 eflags, bool all)
{
	re_match_t pos;
	re_match_t *gpos = &pos;
	size_t ngpos = 1;
	size_t matched = 0;
	size_t off = 0;
	size_t rlen;
	str_match_t m;

	if (!plain && 0 == (eflags & RE_X_NOSUB)) {
		/*
		 * Need to keep all the matching groups in case they are required
		 * to interpolate the replacement string.
		 */

		ngpos = 1 + re_group_count(re);
		if (ngpos > 1)
			gpos = alloca(ngpos * sizeof gpos[0]);
	}

	if (plain) {
		rlen = vstrlen(repl);		/* Fixed string, no variable */
	} else {
		/*
		 * We do not clone the whole string each time: we create the matching
		 * structure once, but this will force us to create the replacement
		 * string before we actually replace the data, since `gpos' still refers
		 * to the original string before replacement.
		 */

		m.magic = STR_MATCH_MAGIC;
		m.source = s;
		m.pos = gpos;
		m.npos = ngpos;
	}

	for (;;) {
		int match =
			str_match_rec_internal(caller, s, off, re, gpos, ngpos, FALSE, eflags);

		if (match <= 0)
			break;				/* No more matches, or execution error */

		matched++;

	replace:

		if (plain) {
			str_replace_len(s, gpos[0].re_start, POS_LEN(gpos[0]), repl, rlen);
			off = rlen + gpos[0].re_start;		/* Move past last replacement */
		} else {
			size_t len;
			bool is_plain;
			char *buf;

			/*
			 * This is the same code as str_new_using_match() but here we
			 * do not return a string: we compute the replacement buffer,
			 * and we also detect whether the replacement text is plain to
			 * avoid coming back here next time if `all' is TRUE.
			 */

			len = str_new_fill(caller, &m, repl, NULL, 0, &is_plain);

			if (is_plain) {
				rlen = len;
				plain = TRUE;
				goto replace;	/* Go back to perform fixed string substitution */
			}

			/* Construct the replacement string whilst `m' refers to original */

			buf = halloc(len);
			(void) str_new_fill(caller, &m, repl, buf, len, NULL);

			/* Replace the matched part with `buf' */

			str_replace_len(s, gpos[0].re_start, POS_LEN(gpos[0]), buf, len);
			hfree(buf);

			off = len + gpos[0].re_start;		/* Move past last replacement */
		}

		if (!all)
			break;
	}

	return matched;
}

/**
 * Handle regex compile and execution options before calling the generic
 * str_subst_internal() routine which expects a compiled regex.
 *
 * @param caller	the calling r outine
 * @param s			the sting over which we are matching and substituting
 * @param pat		the pattern to match
 * @param plain		if TRUE, then `repl' does not hold any variable to interpolate
 * @param repl		replacement string
 * @param opt		regex compilation and execution options
 *
 * @return the amount of substitutions performed.
 */
static size_t
str_subst_re_internal(
	const char *caller,
	str_t *s, const char *pat, bool plain, const char *repl, const char *opt)
{
	uint32 cflags = 0;
	uint32 eflags = 0;
	bool cache_re = TRUE;
	re_regex_t *re;
	bool all = FALSE;
	size_t matched;

	str_check(s);
	g_assert(pat != NULL);

	if (opt != NULL) {
		int c;

		while ((c = *opt++)) {
			switch (c) {
			case 'i': cflags |= RE_F_ICASE;      break;
			case 'm': eflags |= RE_X_MULTI_LINE; break;
			case 'n': cflags |= RE_F_NOSUB;      break;
			case 'o': cache_re = FALSE;          break;
			case 's': cflags |= RE_F_NEWLINE;    break;
			case 'g': all = TRUE;                break;
			default:
				s_carp("%s(): unknown matching option '%c', ignoring",
					caller, c);
				break;

			}
		}
	}

	re = str_re_compile(caller, pat, cflags, cache_re);

	if (NULL == re)
		return 0;

	matched = str_subst_internal(caller, s, re, plain, repl, eflags, all);

	if (!cache_re)
		re_free(re);

	return matched;
}

/**
 * Replace portions of `s' that match `pat' with plain string `repl'.
 *
 * The `opt' argument specifies options for the regex match, each letter modifying
 * the way the regular expression will be handled:
 *
 * "m": multi-line mode ("^" and "$" match at the start/end of each line in string)
 * "s": single-line mode ("." will match all, even a newline).
 * "i": case-insensitive match
 * "n": no group capturing -- all capturing groups transformed in non-capturing
 * "o": once -- compile pattern, but do not bother to cache it
 * "g": general -- replaces all occurrences of the specified pattern
 *
 * @param s			the string over which matching is attempted
 * @param pat		the regular expression pattern to match
 * @param repl		the replacement string (fixed text)
 * @param opt		options, as a set of characters in any order (may be NULL)
 *
 * @return the amount of substitutions performed in-place within string.
 */
size_t
str_subst_re_plain(str_t *s, const char *pat, const char *repl, const char *opt)
{
	return str_subst_re_internal(G_STRFUNC, s, pat, TRUE, repl, opt);
}

/**
 * Replace portions of `s' that match `pat' with interpolated string `repl'.
 *
 * The `opt' argument specifies options for the regex match, each letter modifying
 * the way the regular expression will be handled:
 *
 * "m": multi-line mode ("^" and "$" match at the start/end of each line in string)
 * "s": single-line mode ("." will match all, even a newline).
 * "i": case-insensitive match
 * "n": no group capturing -- all capturing groups transformed in non-capturing
 * "o": once -- compile pattern, but do not bother to cache it
 * "g": general -- replaces all occurrences of the specified pattern
 *
 * @param s			the string over which matching is attempted
 * @param pat		the regular expression pattern to match
 * @param repl		the replacement string (holds variables)
 * @param opt		options, as a set of characters in any order (may be NULL)
 *
 * @return the amount of substitutions performed in-place within string.
 */
size_t
str_subst_re(str_t *s, const char *pat, const char *repl, const char *opt)
{
	return str_subst_re_internal(G_STRFUNC, s, pat, FALSE, repl, opt);
}


/**
 * Replace portions of `s' that match compiled `re' with plain string `repl'.
 *
 * The `opt' argument specifies options for the regex match, each letter modifying
 * the way the regular expression will be handled:
 *
 * "m": multi-line mode ("^" and "$" match at the start/end of each line in string)
 * "n": disable capturing -- capturing ignored during execution
 * "g": general -- replaces all occurrences of the specified pattern
 *
 * @param s			the string over which matching is attempted
 * @param re		the compiled regular expression to match
 * @param repl		the replacement string (fixed text)
 * @param opt		options, as a set of characters in any order (may be NULL)
 *
 * @return the amount of substitutions performed in-place within string.
 */
size_t
str_subst_rec_plain(
	str_t *s, const re_regex_t *re, const char *repl, const char *opt)
{
	uint32 eflags = 0;
	bool all = FALSE;

	str_check(s);

	if (opt != NULL) {
		int c;

		while ((c = *opt++)) {
			switch (c) {
			case 'g': all = TRUE;                break;
			case 'm': eflags |= RE_X_MULTI_LINE; break;
			case 'n': eflags |= RE_X_NOSUB;      break;
			default:
				s_carp("%s(): unknown matching option '%c', ignoring",
					G_STRFUNC, c);
				break;

			}
		}
	}

	return str_subst_internal(G_STRFUNC, s, re, TRUE, repl, eflags, all);
}

/**
 * Replace portions of `s' that match compiled `re' with interpolated string `repl'.
 *
 * The `opt' argument specifies options for the regex match, each letter modifying
 * the way the regular expression will be handled:
 *
 * "m": multi-line mode ("^" and "$" match at the start/end of each line in string)
 * "n": disable capturing -- capturing ignored during execution
 * "g": general -- replaces all occurrences of the specified pattern
 *
 * @param s			the string over which matching is attempted
 * @param re		the compiled regular expression to match
 * @param repl		the replacement string (holds variables)
 * @param opt		options, as a set of characters in any order (may be NULL)
 *
 * @return the amount of substitutions performed in-place within string.
 */
size_t
str_subst_rec(
	str_t *s, const re_regex_t *re, const char *repl, const char *opt)
{
	uint32 eflags = 0;
	bool all = FALSE;

	str_check(s);

	if (opt != NULL) {
		int c;

		while ((c = *opt++)) {
			switch (c) {
			case 'g': all = TRUE;                break;
			case 'm': eflags |= RE_X_MULTI_LINE; break;
			case 'n': eflags |= RE_X_NOSUB;      break;
			default:
				s_carp("%s(): unknown matching option '%c', ignoring",
					G_STRFUNC, c);
				break;

			}
		}
	}

	return str_subst_internal(G_STRFUNC, s, re, FALSE, repl, eflags, all);
}

/* vi: set ts=4 sw=4 cindent: */
