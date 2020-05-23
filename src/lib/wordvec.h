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
 * Word vector.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _wordvec_h_
#define _wordvec_h_

#include "common.h"

/**
 * Search query splitting.
 */

typedef struct {				/**< Query word vector */
	char *word;					/**< The word to search */
	int len;					/**< The word's length */
	uint amount;				/**< Amount of expected occurrences */
} word_vec_t;

void word_vec_init(void);
void word_vec_close(void);

uint word_vec_make(const char *query, word_vec_t **wovec);
void word_vec_free(word_vec_t *wovec, uint n);

#endif	/* _wordvec_h_ */

/* vi: set ts=4 sw=4 cindent: */
