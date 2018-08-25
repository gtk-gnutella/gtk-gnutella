/*
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

#include "options.h"
#include "misc.h"
#include "str.h"

#include "override.h"		/* Must be the last header included */

enum {
	OPTION_F_VALID	= 1 << 0,	/* Signals: valid */
	OPTION_F_VALUE	= 1 << 1	/* Signals: value expected */
};

/**
 * Locate the option letter in the vector array, returning the pointer
 * to the entry if found, or NULL if it wasn't.
 */
static const option_t *
option_lookup(char letter, const option_t *ovec, int osize)
{
	int i;

	for (i = 0; i < osize; i++) {
		const option_t *entry = &ovec[i];

		g_assert(entry->letter);

		if (entry->letter[0] == letter)
			return entry;
	}

	return NULL;
}

static char error_string[80];

/**
 * Returns error string resulting from the last call to options_parse().
 */
const char *
options_parse_last_error(void)
{
	return error_string;
}

/**
 * Parse the arguments, looking for specific single-letter options.  Whenever
 * an option is found, the value in the option_t vector is set.
 *
 * Options start with a "-" and option parsing stops when "--" is encountered.
 * Several argumentless options can be concatenated together after the initial
 * "-".  The value of the option can immediately follow the option letter,
 * or be given by the next argument.
 *
 * Unrecognized options or missing arguments stop processing.
 *
 * @param argv		the initial argument vector
 * @param ovec		the single-letter option description vector
 * @param osize		the amount of entries in ovec
 *
 * @return The number of options processed and validated, -1 on error.
 */
int
options_parse(const char *argv[], const option_t *ovec, int osize)
{
	uchar options[127];	/* ASCII only */
	const option_t *current;
	int i;

	g_assert(argv);
	g_assert(osize >= 0);
	g_assert(0 == osize || NULL != ovec);

	/*
	 * Compile valid options.
	 */

	ZERO(&options);
	error_string[0] = '\0';

	for (i = 0; i < osize; i++) {
		const option_t *o = &ovec[i];
		uchar idx;

		g_assert(o->letter);
		idx = o->letter[0];
		if (UNSIGNED(idx) >= N_ITEMS(options)) {
			g_assert_not_reached();
			return -1; /* ASCII only */
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
		const char *arg = argv[i];
		uchar c;

		if (0 == i)
			continue;

		if (0 == strcmp(arg, "--")) {		/* End of options */
			if (current) {					/* This option lacks its argument */
				str_bprintf(error_string, sizeof error_string,
					"missing value for -%c", current->letter[0]);
				return -1;
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
			const option_t *opt;
			int flags;

			if (UNSIGNED(c) >= N_ITEMS(options)) {
				str_bprintf(error_string, sizeof error_string,
					"invalid non-ASCII switch");
				return -1;
			}

			flags = options[c];
			if (!(flags & OPTION_F_VALID)) {
				str_bprintf(error_string, sizeof error_string,
					"invalid -%c switch", c);
				return -1;
			}

			opt = option_lookup(c, ovec, osize);
			g_assert(opt);					/* Must have been found */

			if (flags & OPTION_F_VALUE) {	/* A value is expected */
				if (*arg) {					/* And it follows */
					if (opt->value) {
						*opt->value = arg;
					}
					break;					/* Argument held option value */
				} else
					current = opt;			/* Expecting value as next arg */
			} else {
				if (opt->value)
					*opt->value = "";	/* Signals option was present */
			}
		}
	}

	return i;
}

/* vi: set ts=4 sw=4 cindent: */
