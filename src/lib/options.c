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

enum {
	OPTION_F_VALID	= 1 << 0,	/* Signals: valid */
	OPTION_F_VALUE	= 1 << 1	/* Signals: value expected */
};

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

static gchar error_string[80];

const gchar *
options_parse_last_error(void)
{
	return error_string;
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
 * @param argv		the initial argument vector
 * @param ovec		the single-letter option description vector
 * @param osize		the amount of entries in ovec
 *
 * @return The number of options processed and validated, -1 on error.
 */
gint
options_parse(const gchar *argv[], option_t *ovec, gint osize)
{
	guchar options[127];	/* ASCII only */
	option_t *current;
	gint i;

	g_assert(argv);
	g_assert(osize >= 0);
	g_assert(0 == osize || NULL != ovec);

	/*
	 * Compile valid options.
	 */

	memset(options, 0, sizeof options);
	error_string[0] = '\0';

	for (i = 0; i < osize; i++) {
		option_t *o = &ovec[i];
		guchar idx;

		g_assert(o->letter);
		idx = o->letter[0];
		if (UNSIGNED(idx) >= G_N_ELEMENTS(options)) {
			g_assert_not_reached();
			goto error; /* ASCII only */
		}
		g_assert(!options[idx]);			/* No duplicates */

		options[idx] = OPTION_F_VALID;
		if (o->letter[1] == ':')
			options[idx] |= OPTION_F_VALUE;

		if (o->value)
			*o->value = NULL;
	}

	/*
	 * Analyze the arguments, starting at argv[1].
	 * (argv[0] is the command name).
	 */

	current = NULL;
	for (i = 0; NULL != argv[i]; i++) {
		const gchar *arg = argv[i];
		guchar c;

		if (0 == i)
			continue;

		if (0 == strcmp(arg, "--")) {		/* End of options */
			if (current) {					/* This option lacks its argument */
				gm_snprintf(error_string, sizeof error_string,
					"missing value for -%c", current->letter[0]);
				goto error;
			}
			return i + 1;
		}

		if (current) {
			/*
			 * We're expecting the next argument to be the value of the switch
			 * we parsed earlier.
			 */
			
			if (current->value)
				*current->value = arg;

			current = NULL;
			continue;
		}

		if (*arg++ != '-') {				/* Non-option found */
			return i; /* First non-option argument */
		}

		/*
		 * Argument is an option, that can contain multiple argumentless
		 * switches, or a switch and its value.
		 */

		g_assert(current == NULL);

		while ((c = *arg++)) {
			option_t *opt;
			gint flags;

			if (UNSIGNED(c) >= G_N_ELEMENTS(options)) {
				gm_snprintf(error_string, sizeof error_string,
					"invalid non-ASCII switch");
				goto error;
			}

			flags = options[c];
			if (!(flags & OPTION_F_VALID)) {
				gm_snprintf(error_string, sizeof error_string,
					"invalid -%c switch", c);
				goto error;
			}

			opt = option_lookup(c, ovec, osize);
			g_assert(opt);					/* Must have been found */

			if (flags & OPTION_F_VALUE) {	/* A value is expected */
				if (*arg) {					/* And it follows */
					if (opt->value)
						*opt->value = arg;
				} else
					current = opt;			/* Expecting value as next arg */
			} else {
				if (opt->value)
					*opt->value = "";	/* Signals option was present */
			}
		}
	}

	return i;

error:
	return -1;
}

/* vi: set sw=4 ts=4: */
