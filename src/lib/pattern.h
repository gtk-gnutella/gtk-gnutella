/*
 * Copyright (c) 2001-2003, 2018 Raphael Manfredi
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
 * Sunday pattern search data structures.
 *
 * @author Raphael Manfredi
 * @date 2001-2003, 2018
 */

#ifndef _pattern_h_
#define _pattern_h_

#include "common.h"

/**
 * Flags for pattern_init() verbosity control.
 */
#define PATTERN_INIT_PROGRESS	(1 << 0)	/**< Basic progress traces */
#define PATTERN_INIT_STATS		(1 << 1)	/**< Basic statistics  traces */
#define PATTERN_INIT_SELECTED	(1 << 2)	/**< Routines selected */
#define PATTERN_INIT_BENCH_INFO	(1 << 3)	/**< Benchmarking information */
#define PATTERN_INIT_BENCH_TIME	(1 << 4)	/**< Benchmarking time stats */
#define PATTERN_INIT_BENCH_DBG	(1 << 5)	/**< Benchmarking debugging logs */

typedef struct cpattern cpattern_t;

typedef enum {
	qs_any = 0,				/**< Match anywhere */
	qs_begin,				/**< Match if starting with a word boundary */
	qs_end,					/**< Match if ending with a word boundary */
	qs_whole				/**< Match whole words (start and end at boundary) */
} qsearch_mode_t;

cpattern_t *pattern_compile(const char *pattern, bool icase);
cpattern_t *pattern_compile_fast(const char *pattern, size_t plen, bool icase);
void pattern_free(cpattern_t *cpat);
void pattern_free_null(cpattern_t **cpat_ptr);
size_t pattern_len(const cpattern_t *p);
const char *pattern_string(const cpattern_t *p);
char *pattern_strstr(const char *haystack, const cpattern_t *p);
char *pattern_strstrlen(const char *haystack, size_t hlen, const cpattern_t *p);

const char *pattern_search(const cpattern_t *cpat,
	const char *text, size_t tlen, size_t toffset, qsearch_mode_t word);

const char *pattern_qsearch_force(const cpattern_t *cpat,
	const char *text, size_t tlen, size_t toffset, qsearch_mode_t word);
const char *pattern_match_force(const cpattern_t *cpat,
	const char *text, size_t tlen, size_t toffset, qsearch_mode_t word);

void *pattern_memchr(const void *s, int c, size_t n);
void *pattern_memrchr(const void *s, int c, size_t n);
char *pattern_strchr(const char *s, int c);
char *pattern_strrchr(const char *s, int c);

#ifdef PATTERN_BENCHMARKING_SOURCE
/* These routines are for benchmarking only */
char *pattern_qs(const char *haystack, const char *needle);
char *pattern_2way(const char *haystack, const char *needle);
#endif	/* PATTERN_BENCHMARKING */

size_t pattern_strlen(const char *s);

void pattern_init(int verbose);

/**
 * Compile a static string.
 */
#define PATTERN_COMPILE_CONST(x) \
	pattern_compile_fast((x), CONST_STRLEN(x), FALSE)

/*
 * Drop-ins for memchr(), strchr() and strlen() which will attempt to
 * use the libc version or our own implementation if it ends up being faster.
 */

#ifndef HAS_MEMRCHR
#define memrchr(s,c,n)	pattern_memrchr((s),(c),(n))
#endif

typedef void *(pattern_memchr_t)(const void *s, int c, size_t n);
typedef char *(pattern_strchr_t)(const char *s, int c);
typedef size_t (pattern_strlen_t)(const char *s);

extern pattern_memchr_t *fast_memchr;
extern pattern_memchr_t *fast_memrchr;
extern pattern_strchr_t *fast_strchr;
extern pattern_strchr_t *fast_strrchr;
extern pattern_strlen_t *fast_strlen;

#define vmemchr(s,c,n)	fast_memchr(s,c,n)
#define vmemrchr(s,c,n)	fast_memrchr(s,c,n)
#define vstrchr(s,c)	fast_strchr(s,c)
#define vstrrchr(s,c)	fast_strrchr(s,c)
#define vstrlen(s)		fast_strlen(s)

char *vstrstr(const char *haystack, const char *needle);
char *vstrcasestr(const char *haystack, const char *needle);

#endif /* _pattern_h_ */

/* vi: set ts=4 sw=4 cindent: */
