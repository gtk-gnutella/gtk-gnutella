/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * String tokenizer.
 *
 * From a static array of lexicographically-sorted strings, determine
 * the numerical token value of a string, if it matches a known token string.
 *
 * The convention is that token 0 is RESERVED to mean "not found", i.e. the
 * input string does not correspond to any token.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#ifndef _tokenizer_h_
#define _tokenizer_h_

/**
 * A tokenizer item is a mapping between a string and a number (non-zero).
 */
typedef struct tokenizer {
	const char *token;			/**< The token string */
	unsigned value;				/**< The token value associated with string */
} tokenizer_t;

/*
 * Public interface.
 */

unsigned tokenizer_lookup(const char *s, const tokenizer_t *tvec, size_t tcnt);
unsigned tokenizer_lookup_with(const char *s, strcmp_fn_t cmp,
	const tokenizer_t *tvec, size_t tcnt);

void tokenizer_check_sorted(const char *name,
	const tokenizer_t *tvec, size_t tcnt);
void tokenizer_check_sorted_with(const char *name,
	const tokenizer_t *tvec, size_t tcnt, strcmp_fn_t cmp);

#define TOKENIZE(s, vec)	tokenizer_lookup((s), (vec), N_ITEMS(vec))

#define TOKENIZE_WITH(s, c, vec) \
	tokenizer_lookup_with((s), (c), (vec), N_ITEMS(vec))

#define TOKENIZE_CHECK_SORTED(vec) \
	tokenizer_check_sorted(STRINGIFY(vec), (vec), N_ITEMS((vec)))

#define TOKENIZE_CHECK_SORTED_WITH(vec, c) \
	tokenizer_check_sorted_with(STRINGIFY(vec), (vec), N_ITEMS((vec)), (c))

#endif /* _tokenizer_h_ */

/* vi: set ts=4 sw=4 cindent: */
