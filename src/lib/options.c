/*
 * $Id$
 *
 * Copyright (c) 2007, Raphael Manfredi
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
 * Options parsing.
 *
 * @author Raphael Manfredi
 * @date 2007
 */

#include "common.h"

RCSID("$Id$")

#include "options.h"
#include "glib-missing.h"
#include "misc.h"
#include "override.h"		/* Must be the last header included */

/**
 * Locate the option letter in the vector array, returning the pointer
 * to the entry if found, or NULL if it wasn't.
 */
static option_t *
option_lookup(gchar letter, option_t *ovec, gint osize)
{
	gint i;

	for (i = 0; i < osize; i++) {
		option_t *entry = &ovec[i];

		g_assert(entry->letter);

		if (entry->letter[0] == letter)
			return entry;
	}

	return NULL;
}

/**
 * Parse the arguments, looking for specific single-letter options.  Whenever
 * an option is found, the value in the option_t vector is set.  The `end'
 * parameter is filled with the offset in argv[] of the first non-option
 * argument.
 *
 * Options start with a "-" and option parsing stops when "--" is encountered.
 * Several argumentless options can be concatenated together after the initial
 * "-".  The value of the option can immediately follow the option letter,
 * or be given by the next argument.
 *
 * Unrecognized options or missing arguments stop processing: `end' is set with
 * the ASCII value of the bad option, and FALSE is returned.
 * 
 * @param argc		the initial argument count
 * @param argv		the initial argument vector
 * @param ovec		the single-letter option description vector
 * @param osize		the amount of entries in ovec
 * @param end		where the offset of the first non-option in argv is written
 * @param errptr	where a pointer to the error will be written (static string)
 *
 * @return TRUE if options were processed and validated, FALSE on error.
 */
gboolean
options_parse(
	gint argc, const gchar *argv[], option_t *ovec,
	gint osize, gint *end, gchar **errptr)
{
	guint8 options[256];
	option_t *current;
	gint i;
	static gchar error[80];
	static gchar *empty = "";

	/*
	 * Compile valid options.
	 */

	memset(options, 0, sizeof options);

	for (i = 0; i < osize; i++) {
		option_t *o = &ovec[i];
		gint idx;

		g_assert(o->letter);
		idx = o->letter[0];
		g_assert(!options[idx]);			/* No duplicates */

		options[idx] = 0x1;					/* Signals: valid */
		if (o->letter[1] == ':')
			options[idx] |= 0x2;			/* Signals: value expected */

		if (o->value)
			*o->value = NULL;
	}

	/*
	 * Analyze the arguments, starting at argv[1].
	 * (argv[0] is the command name).
	 */

	for (current = NULL, i = 1; i < argc; i++) {
		const gchar *arg = argv[i];
		gchar c;

		if (0 == strcmp(arg, "--")) {		/* End of options */
			if (current) {					/* This option lacks its argument */
				gm_snprintf(error, sizeof error,
					"missing value for -%c", current->letter[0]);
				*end = current->letter[0];
				goto error;
			}
			*end = i + 1;					/* Skip "--" */
			return TRUE;
		}

		if (current) {
			/*
			 * We're expecting the next argument to be the value of the switch
			 * we parsed earlier.
			 */
			
			if (current->value)
				*current->value = deconstify_gpointer(arg);

			current = NULL;
			continue;
		}

		if (*arg++ != '-') {				/* Non-option found */
			*end = i;						/* First non-option argument */
			return TRUE;
		}

		/*
		 * Argument is an option, that can contain multiple argumentless
		 * switches, or a switch and its value.
		 */

		g_assert(current == NULL);

		while ((c = *arg++)) {
			gint idx = c;
			guint8 valid = options[idx];
			option_t *opt;

			if (!valid) {
				gm_snprintf(error, sizeof error, "invalid -%c switch", c);
				*end = c;
				goto error;
			}

			opt = option_lookup(c, ovec, osize);
			g_assert(opt);					/* Must have been found */

			if (valid & 0x2) {				/* A value is expected */
				if (*arg) {					/* And it follows */
					if (opt->value)
						*opt->value = deconstify_gpointer(arg);
				} else
					current = opt;			/* Expecting value as next arg */
			} else {
				if (opt->value)
					*opt->value = empty;	/* Signals option was present */
			}
		}
	}

	*end = argc;
	return TRUE;

error:
	if (errptr)
		*errptr = error;

	return FALSE;
}

/* vi: set sw=4 ts=4: */
