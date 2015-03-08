/*
 * Copyright (c) 2009, Raphael Manfredi
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
 * String delimitor-based tokenizer.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _strtok_h_
#define _strtok_h_

#include "common.h"

struct strtok;

typedef struct strtok strtok_t;

strtok_t *strtok_make(const char *string, bool no_lead, bool no_end);
struct strtok *strtok_make_strip(const char *string);
struct strtok *strtok_make_nostrip(const char *string);
void strtok_free_null(strtok_t **s);
void strtok_restart(strtok_t *s);
void strtok_skip(strtok_t *s, const char *delim, size_t n);
const char *strtok_next(strtok_t *s, const char *delim);
const char *strtok_next_extended(strtok_t *s, const char *delim,
	bool no_lead, bool no_end);
const char *strtok_next_length(strtok_t *s, const char *delim, size_t *length);
bool strtok_eos(const strtok_t *s);
const char *strtok_ptr(const strtok_t *s);
char strtok_char(const strtok_t *s);
char strtok_delim(const strtok_t *s);
bool strtok_has(const char *string, const char *delim, const char *what);
bool strtok_case_has(const char *str, const char *delim, const char *what);

void strtok_test(void);

#endif	/* _strtok_h_ */

/* vi: set sw=4 ts=4: */
