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
 * Header parsing routines.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _header_h_
#define _header_h_

#include "common.h"

/**
 * Header parsing and holding data structures.
 */

typedef struct header header_t;

int header_num_lines(const header_t *h);

/*
 * Error codes.
 */

#define HEAD_OK				0		/**< OK */
#define HEAD_CONTINUATION	1		/**< Unexpected continuation line */
#define HEAD_MALFORMED		2		/**< Malformed header line */
#define HEAD_BAD_CHARS		3		/**< Invalid characters in field name */
#define HEAD_EOH_REACHED	4		/**< End of header already reached */
#define HEAD_SKIPPED		5		/**< Skipped continuation line */
#define HEAD_TOO_LARGE		6		/**< Header too large */
#define HEAD_MANY_LINES		7		/**< Header has too many lines */
#define HEAD_EOH			8		/**< End of header reached */

/*
 * Our sanity limits
 */

#define HEAD_MAX_LINES		128		/**< Maximum amount of header lines */
#define HEAD_MAX_SIZE		16384	/**< Maximum size of header data */

/*
 * Public interface.
 */

header_t *header_make(void);
header_t *header_refcnt_inc(header_t *o);
void header_free(header_t *o);
void header_free_null(header_t **o_ptr);
void header_reset(header_t *o);
int header_append(header_t *o, const char *text, int len);
void header_dump(FILE *out, const header_t *o, const char *trailer);
const char *header_strerror(uint errnum);
char *header_get(const header_t *o, const char *field);
char *header_get_extended(const header_t *o, const char *field, size_t *lptr);

typedef struct header_fmt header_fmt_t;

header_fmt_t *header_fmt_make(const char *field, const char *separator,
	size_t len_hint, size_t max_size);
void header_fmt_free(header_fmt_t **hf);
void header_fmt_set_line_length(header_fmt_t *hf, size_t maxlen);
bool header_fmt_value_fits(const header_fmt_t *hf, size_t len);
bool header_fmt_append(header_fmt_t *hf, const char *str, const char *sep);
bool header_fmt_append_value(header_fmt_t *hf, const char *str);
size_t header_fmt_length(const header_fmt_t *hf);
void header_fmt_end(header_fmt_t *hf);
const char *header_fmt_string(const header_fmt_t *hf);
const char *header_fmt_to_string(const header_fmt_t *hf);

#endif	/* _header_h_ */

/* vi: set ts=4 sw=4 cindent: */
