/*
 * $Id$
 *
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

RCSID("$Id$")

#ifdef I_PWD
#include <pwd.h>
#endif

#include "eval.h"
#include "atoms.h"
#include "glib-missing.h"
#include "misc.h"			/* For g_strlcpy() */

#include "override.h"		/* Must be the last header included */

#define MAX_STRING	1024	/**< Max length for substitution */

static guint32 common_dbg = 0;	/**< XXX -- need to init lib's props --RAM */

static GHashTable *constants;
static const gchar *home;	/* string atom */

static const gchar *get_home(void);
static const gchar *get_variable(const gchar *s, const gchar **end);
static gboolean initialized;

/**
 * Create a constant string, or reuse an existing one if possible.
 *
 * @returns a string atom.
 */
static const gchar *
constant_make(const gchar *s)
{
	const gchar *v;

	v = g_hash_table_lookup(constants, s);
	if (v != NULL)
		return v;			/* Already exists */

	v = atom_str_get(s);
	gm_hash_table_insert_const(constants, v, v);

	return v;
}

/**
 * Initialize string evaluation.
 */
void
eval_init(void)
{
	g_return_if_fail(!initialized);

	constants = g_hash_table_new(g_str_hash, g_str_equal);
	home = get_home();
	g_assert(home);

	initialized = TRUE;
}

static void
constants_free_kv(gpointer key,
	gpointer unused_val, gpointer unused_x)
{
	(void) unused_val;
	(void) unused_x;
	atom_str_free(key);
}

/**
 * Cleanup local structures at shutdown time.
 */
void
eval_close(void)
{
	if (home) {
		atom_str_free(home);
		home = NULL;
	}
	g_hash_table_foreach(constants, constants_free_kv, NULL);
	g_hash_table_destroy(constants);
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
static gchar *
insert_value(const gchar *val, gchar *start, size_t off,
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
 * @return string atom, which is not meant to be freed until exit time.
 */
const gchar *
eval_subst(const gchar *str)
{
	gchar buf[MAX_STRING];
	gchar *end = &buf[sizeof(buf)];
	gchar *p;
	size_t len;
	gchar c;

	g_assert(initialized);

	if (str == NULL)
		return NULL;

	len = g_strlcpy(buf, str, sizeof buf);
	if (len >= sizeof buf) {
		g_warning("eval_subst: string too large for substitution (%lu bytes)",
			(unsigned long) len);
		return constant_make(str);
	}


	if (common_dbg > 3)
		printf("eval_subst: on entry: \"%s\"\n", buf);

	for (p = buf, c = *p++; c; c = *p++) {
		const gchar *val = NULL;
		gchar *start = p - 1;

		switch (c) {
		case '~':
			if (start == buf) {		/* Leading ~ only */
				val = home;
				g_assert(val);
				memmove(start, &start[1], len - (start - buf));
				len--;

				g_assert((ssize_t) len >= 0);
			}
			break;
		case '$':
			{
				const gchar *after;

				val = get_variable(p, &after);
				g_assert(val);
				memmove(start, after, len + 1 - (after - buf));
				len -= after - start;		/* Also removing leading '$' */

				g_assert((ssize_t) len >= 0);
			}
			break;
		}

		if (val != NULL) {
			gchar *next;
			
			next = insert_value(val, start, start - buf, len, sizeof buf - 1);
			len += next - start;
			p = next;

			g_assert(len < sizeof buf);
			g_assert(p < end);
		}

		g_assert(p <= &buf[len]);
	}

	if (common_dbg > 3)
		printf("eval_subst: on exit: \"%s\"\n", buf);

	g_assert(len == strlen(buf));

	return constant_make(buf);
}

/**
 * Compute the user's home directory.
 * Uses the HOME environment variable first, then the entry from /etc/passwd.
 *
 * @return string atom.
 */
static const gchar *
get_home(void)
{
	const char *dir;

	dir = getenv("HOME");

	if (dir && !is_absolute_path(dir)) {
		/* Ignore $HOME if it's empty or a relative path */
		dir = NULL;
	}
	
#if defined(HAS_GETLOGIN)
	if (!dir) {
		const char *name;
		
		name = getlogin();
		if (name) {
			static const struct passwd *pp;

			pp = getpwnam(name);
			if (pp)
				dir = pp->pw_dir;
		}
	}
#endif

#if defined(HAS_GETUID)
	if (!dir) {
		static const struct passwd *pp;
		
		pp = getpwuid(getuid());
		if (pp)
			dir = pp->pw_dir;
	}
#endif /* HAS_GETUID */

	if (!dir)
		dir = g_get_home_dir();

	if (!dir) {
		g_warning("Could not determine home directory");
		dir = "/";
	}

	return atom_str_get(dir);
}

/**
 * Extract variable name from string `s', then fetch value from environment.
 *
 * @return variable's value, or "" if not found and set `end' to the address
 * of the character right after the variable name.
 */
static const gchar *
get_variable(const gchar *s, const gchar **end)
{
	const gchar *value, *p = s;
	gboolean end_brace = FALSE;

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
		gchar *name;

		name = g_strndup(s, p - s);
		value = getenv(name);

		if (value == NULL)
			value = "";

		if (common_dbg > 4)
			printf("variable \"%s\" is \"%s\"\n", name, value);

		G_FREE_NULL(name);
	}

	return value;
}

/* vi: set ts=4 sw=4 cindent: */
