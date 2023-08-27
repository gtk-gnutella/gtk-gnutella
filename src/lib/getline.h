/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
	READ_OVERFLOW	/**< Reached max line size */
} getline_result_t;

struct getline;
typedef struct getline getline_t;

/*
 * Public interface.
 */

getline_t *getline_make(size_t maxsize);
void getline_free(getline_t *);
void getline_free_null(getline_t **);
void getline_reset(getline_t *);
getline_result_t getline_read(getline_t *,
					const char *data, size_t len, size_t *used);
const char *getline_str(const getline_t *);
size_t getline_length(const getline_t *);
void getline_copy(const getline_t *source, getline_t *dest);
void getline_set_maxlen(getline_t *, size_t);

#endif	/* _getline_h_ */

/* vi: set ts=4 sw=4 cindent: */
