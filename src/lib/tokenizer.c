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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * String tokenizer, using a binary search to lookup tokens in a sorted array.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "tokenizer.h"

#include "misc.h"

#include "override.h"			/* Must be the last header included */

/**
 * Lookup token in a sorted array of tokens.
 *
 * The string comparison function is supplied by the caller.
 *
 * @param s		the input string
 * @param cmp	the string comparison function to use
 * @param tvec	the vector of tokenizer_t items, defining the tokens
 * @param tcnt	the amount of items in the token vector
 *
 * @return the token value if found, 0 if not found.
 */
unsigned
tokenizer_lookup_with(const char *s, strcmp_fn_t cmp,
	const tokenizer_t *tvec, size_t tcnt)
{
#define GET_KEY(i) (tvec[(i)].token)
#define FOUND(i) G_STMT_START { \
	return tvec[(i)].value; \
	/* NOTREACHED */ \
} G_STMT_END

	/* Perform a binary search to find ``s'' in tvec[] */
	BINARY_SEARCH(const char *, s, tcnt, (*cmp), GET_KEY, FOUND);

#undef FOUND
#undef GET_KEY

	return 0;		/* Not found */
}

/**
 * Lookup token in a sorted array of tokens.
 *
 * @param s		the input string
 * @param tvec	the vector of tokenizer_t items, defining the tokens
 * @param tcnt	the amount of items in the token vector
 *
 * @return the token value if found, 0 if not found.
 */
unsigned
tokenizer_lookup(const char *s, const tokenizer_t *tvec, size_t tcnt)
{
	return tokenizer_lookup_with(s, strcmp, tvec, tcnt);
}

/* vi: set ts=4 sw=4 cindent: */
