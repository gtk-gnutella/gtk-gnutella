/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * HTTP range handling routines.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _http_range_h_
#define _http_range_h_

#include "common.h"

/**
 * HTTP range description.
 *
 * The `end' field defines the last byte of the range, and is therefore
 * included in the range.
 */
typedef struct http_range {
	filesize_t start;
	filesize_t end;			/**< HTTP_OFFSET_MAX if unbounded */
} http_range_t;

#define HTTP_OFFSET_MAX		((filesize_t) -1)

struct http_rangeset;
typedef struct http_rangeset http_rangeset_t;

/**
 * Returned values for http_range_extract_first().
 */
enum http_range_extract_status {
	HTTP_RANGE_NONE = 0,		/* No range found, parsing error */
	HTTP_RANGE_SINGLE,			/* OK, there was only a single range */
	HTTP_RANGE_MULTI,			/* Multiple ranges were present */
};

/*
 * Public interface.
 */

void set_http_range_debug(uint32 level);

http_rangeset_t *http_rangeset_create(void);
void http_rangeset_free_null(http_rangeset_t **hrs_ptr);
void http_rangeset_clear(http_rangeset_t *hrs);
void http_rangeset_insert(http_rangeset_t *hrs,
	filesize_t start, filesize_t end);
filesize_t http_rangeset_length(const http_rangeset_t *hrs);
size_t http_rangeset_count(const http_rangeset_t *hrs);
const char *http_rangeset_to_string(const http_rangeset_t *hrs);
filesize_t http_rangeset_merge(http_rangeset_t *hd, const http_rangeset_t *hs);
bool http_rangeset_equal(const http_rangeset_t *h1, const http_rangeset_t *h2);
bool http_rangeset_contains(const http_rangeset_t *hrs,
	filesize_t start, filesize_t end);
const http_range_t *http_rangeset_lookup(const http_rangeset_t *hrs,
	filesize_t start, filesize_t end);
const http_range_t *http_rangeset_lookup_first(const http_rangeset_t *hrs,
	filesize_t start, filesize_t end);

http_rangeset_t *http_rangeset_extract(const char *field, const char *value,
	filesize_t size, const char *vendor);
enum http_range_extract_status http_range_extract_first(
	const char *field, const char *value, filesize_t size, const char *vendor,
	filesize_t *start, filesize_t *end);

const http_range_t *http_range_first(const http_rangeset_t *hrs);
const http_range_t *http_range_next(const http_rangeset_t *hrs,
	const http_range_t *r);
const http_range_t *http_rangeset_lookup_over(const http_rangeset_t *hrs,
	filesize_t start, filesize_t end, const http_range_t *r);

int http_range_overlap_cmp(const void *a, const void *b);

void http_range_test(void);

#define HTTP_RANGE_FOREACH(hrs, r) \
	for ((r) = http_range_first(hrs); \
		(r) != NULL; \
		(r) = http_range_next((hrs), (r)))

#endif /* _http_range_h_ */

/* vi: set ts=4 sw=4 cindent: */
