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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Sunday pattern search data structures.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _pattern_h_
#define _pattern_h_

#include "common.h"

typedef struct cpattern cpattern_t;

typedef enum {
	qs_any = 0,					/**< Match anywhere */
	qs_begin,					/**< Match beginning of words */
	qs_whole					/**< Match whole words only */
} qsearch_mode_t;

void pattern_init(void);
void pattern_close(void);

cpattern_t *pattern_compile(const char *pattern);
cpattern_t *pattern_compile_fast(const char *pattern, size_t plen);
void pattern_free(cpattern_t *cpat);
void pattern_free_null(cpattern_t **cpat_ptr);
const char *pattern_qsearch(const cpattern_t *cpat,
	const char *text, size_t tlen, size_t toffset, qsearch_mode_t word);
size_t pattern_len(const cpattern_t *p);

#endif /* _pattern_h_ */

/* vi: set ts=4 sw=4 cindent: */
