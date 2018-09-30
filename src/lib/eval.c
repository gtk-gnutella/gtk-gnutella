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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "atoms.h"
#include "constants.h"
#include "cstr.h"
#include "debug.h"
#include "gethomedir.h"
#include "glib-missing.h"
#include "halloc.h"
#include "hstrfn.h"
#include "path.h"
#include "str.h"
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
eval_get_variable(const char *s, const char **end)
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

	while (is_ascii_ident(*p))
		p++;

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
 * Perform leading ~ and $ENV variable substitutions on string.
 *
 * @param s			the string being edited inplace
 */
static void
eval_substitute(str_t *s)
{
	size_t i;

	if (common_dbg > 3)
		s_debug("%s(): on entry: \"%s\"", G_STRFUNC, str_2c(s));

	/*
	 * Handle standalone "~" or leading "~/".
	 */

	if ('~' == str_at(s, 0) && (1 == str_len(s) || '/' == str_at(s, 1)))
		str_replace(s, 0, 1, gethomedir());

	for (i = 0; i < str_len(s); i++) {
		const char *val, *start, *after;

		if ('$' != str_at(s, i))
			continue;

		start = str_2c_from(s, i + 1);
		val = eval_get_variable(start, &after);
		str_replace(s, i, after - start + 1, val);
		i += vstrlen(val) - 1;
	}

	if (common_dbg > 3)
		s_debug("%s(): on exit: \"%s\"", G_STRFUNC, str_2c(s));
}

/**
 * Substitutes variables from string:
 *
 * - The leading "~" is replaced by the home directory.
 * - Variables like "$PATH" or "${PATH}" are replaced by their value, as
 *   fetched from the environment, or the empty string if not found.
 *
 * If given a NULL input, we return NULL.
 *
 * @param str		string where variables must be substituted
 *
 * @return string constant, which is not meant to be freed until exit time.
 */
const char *
eval_subst(const char *str)
{
	str_t *s;
	const char *constant;

	if G_UNLIKELY(NULL == str)
		return NULL;

	s = str_new_from(str);
	eval_substitute(s);
	constant = constant_str(str_2c(s));
	str_destroy_null(&s);

	return constant;
}

/*
 * Perform leading ~ substitution and environment variable substitutions.
 *
 * Substitutes variables from string:
 *
 * - The leading "~" is replaced by the home directory.
 * - Variables like "$PATH" or "${PATH}" are replaced by their value, as
 *   fetched from the environment, or the empty string if not found.
 *
 * There are no size limitations.
 *
 * @return a string atom.
 */
const char *
eval_subst_atom(const char *str)
{
	str_t *s = str_new_from(str);
	const char *atom;

	eval_substitute(s);
	atom = atom_str_get(str_2c(s));
	str_destroy_null(&s);

	return atom;
}

/* vi: set ts=4 sw=4 cindent: */
