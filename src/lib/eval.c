/*
 * Copyright (c) 2003, Raphael Manfredi
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
 * String evaluation.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#include "common.h"
#ifdef I_PWD
#include <pwd.h>
#endif

#include "eval.h"

#include "ascii.h"
#include "constants.h"
#include "debug.h"
#include "gethomedir.h"
#include "glib-missing.h"
#include "halloc.h"
#include "hstrfn.h"
#include "path.h"
#include "unsigned.h"

#include "override.h"		/* Must be the last header included */

#define MAX_STRING	1024	/**< Max length for substitution */

/**
 * Extract variable name from string `s', then fetch value from environment.
 *
 * @return variable's value, or "" if not found and set `end' to the address
 * of the character right after the variable name.
 */
static const char *
get_variable(const char *s, const char **end)
{
	const char *value, *p = s;
	bool end_brace = FALSE;

	/*
	 * Grab variable's name.
	 */

	if (*p == '{') {
		p++;
		s++;
		end_brace = TRUE;
	}

	while (is_ascii_alnum(*p) || *p == '_') {
		p++;
	}

	if (end_brace && *p == '}')
		*end = &p[1];
	else
		*end = p;

	/*
	 * Get value from environment.
	 */

	{
		char *name;

		name = h_strndup(s, p - s);
		value = getenv(name);

		if (value == NULL)
			value = "";

		if (common_dbg > 4)
			g_debug("variable \"%s\" is \"%s\"", name, value);

		HFREE_NULL(name);
	}

	return value;
}

/**
 * Insert value `val' at beginning of string `start'.
 *
 * The string `start' is held in a buffer capable of holding a string of
 * `maxlen' bytes, and the string is currently `len' bytes long, with `start'
 * being at the offset `off' within buffer.
 *
 * @return the pointer right after the inserted value.
 */
static char *
insert_value(const char *val, char *start, size_t off,
	size_t len, size_t maxlen)
{
	size_t vlen = strlen(val);

	g_assert(len <= maxlen);
	g_assert(off <= len);

	if (vlen > maxlen - len) {
		g_warning("ignoring variable substitution text \"%s\"", val);
		return start;
	}

	memmove(&start[vlen], start, len + 1 - off);
	memmove(start, val, vlen);

	return &start[vlen];
}

/**
 * Needs brief description here.
 *
 * Substitutes variables from string:
 *
 * - The leading "~" is replaced by the home directory.
 * - Variables like "$PATH" or "${PATH}" are replaced by their value, as
 *   fetched from the environment, or the empty string if not found.
 *
 * If given a NULL input, we return NULL.
 *
 * @return string constant, which is not meant to be freed until exit time.
 */
const char *
eval_subst(const char *str)
{
	char buf[MAX_STRING];
	char *end = &buf[sizeof(buf)];
	char *p;
	size_t len;
	char c;

	if (str == NULL)
		return NULL;

	len = g_strlcpy(buf, str, sizeof buf);
	if (len >= sizeof buf) {
		g_warning("%s(): string too large for substitution (%zu bytes)",
			G_STRFUNC, len);
		return constant_str(str);
	}


	if (common_dbg > 3)
		g_debug("%s: on entry: \"%s\"", G_STRFUNC, buf);

	for (p = buf, c = *p++; c; c = *p++) {
		const char *val = NULL;
		char *start = p - 1;

		switch (c) {
		case '~':
			if (start == buf && ('\0' == buf[1] || '/' == buf[1])) {
				/* Leading ~ only */
				val = gethomedir();
				g_assert(val);
				memmove(start, &start[1], len - (start - buf));
				len--;

				g_assert(size_is_non_negative(len));
			}
			break;
		case '$':
			{
				const char *after;

				val = get_variable(p, &after);
				g_assert(val);
				memmove(start, after, len + 1 - (after - buf));
				len -= after - start;		/* Also removing leading '$' */

				g_assert(size_is_non_negative(len));
			}
			break;
		}

		if (val != NULL) {
			char *next;

			next = insert_value(val, start, start - buf, len, sizeof buf - 1);
			len += next - start;
			p = next;

			g_assert(len < sizeof buf);
			g_assert(p < end);
		}

		g_assert(p <= &buf[len]);
	}

	if (common_dbg > 3)
		g_debug("%s: on exit: \"%s\"", G_STRFUNC, buf);

	g_assert(len == strlen(buf));

	return constant_str(buf);
}

/* vi: set ts=4 sw=4 cindent: */
