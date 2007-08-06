/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * Line-oriented parsing from memory buffer.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _getline_h_
#define _getline_h_

#include "common.h"

#define MAX_LINE_SIZE	1024	/**< Maximum length for regular line */

/*
 * getline() return codes.
 */

typedef enum getline_result {
	READ_MORE,		/**< OK, expecting more */
	READ_DONE,		/**< OK, got whole line */
	READ_OVERFLOW,	/**< Reached max line size */
} getline_result_t;

/**
 * A getline "object".
 */

typedef struct getline {
	size_t maxlen;				/**< Maximum authorized length */
	size_t size;				/**< Current allocated size for `line' */
	gchar *line;				/**< Accumulator, NUL terminated when done */
	size_t pos;					/**< Next writing position in line[] */
} getline_t;

#define getline_maxlen(o)	((o)->maxlen)

/*
 * Public interface.
 */

getline_t *getline_make(size_t maxsize);
void getline_free(getline_t *);
void getline_reset(getline_t *);
getline_result_t getline_read(getline_t *,
					const gchar *data, size_t len, size_t *used);
const gchar *getline_str(getline_t *);
size_t getline_length(getline_t *);
void getline_copy(getline_t *source, getline_t *dest);
void getline_set_maxlen(getline_t *, size_t);

#endif	/* _getline_h_ */

/* vi: set ts=4: */

