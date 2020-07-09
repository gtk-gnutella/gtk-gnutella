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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#ifndef _options_h_
#define _options_h_

#include "common.h"

/**
 * Option description structure for single-letter options.
 *
 * An option letter consists of an initial letter, followed by ":" if it
 * takes an argument.
 *
 * The value is a pointer to a variable that will get filled with NULL if
 * the option is not present, with a pointer to a static empty string if
 * the option is found and does not have any argument, or with the actual
 * value.
 */
typedef struct option {
	const char *letter;		/* Option letter */
	const char **value;		/* Variable where option value will be put */
} option_t;

int options_parse(const char *argv[], const option_t *ovec, int osize);
const char *options_parse_last_error(void);

#endif /* _options_h_ */

/* vi: set ts=4 sw=4 cindent: */
