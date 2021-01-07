/*
 * Copyright (c) 2004, 2010, 2012 Raphael Manfredi
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
 * Symbol address / name mapping.
 *
 * @author Raphael Manfredi
 * @date 2004, 2010, 2012
 */

#ifndef _symbols_h_
#define _symbols_h_

#include "tm.h"		/* For tm_t */

/**
 * An entry in the symbol table.
 */
struct symbol {
	const void *addr;			/**< Symbol address */
	const char *name;			/**< Symbol name */
};

struct symbols;
typedef struct symbols symbols_t;

/**
 * Self-assessed stacktrace symbol quality.
 */
enum symbol_quality {
	SYMBOL_Q_GOOD = 0,
	SYMBOL_Q_STALE,
	SYMBOL_Q_MISMATCH,
	SYMBOL_Q_GARBAGE,

	SYMBOL_Q_MAX
};

/*
 * Public interface.
 */

const char *symbol_quality_string(const enum symbol_quality sq);
void symbols_set_verbose(bool verbose);
symbols_t *symbols_make(size_t capacity, bool once);
void symbols_free_null(symbols_t **st_ptr);
const char *symbols_name(const symbols_t *st, const void *pc, bool offset);
const char *symbols_name_only(const symbols_t *st, const void *pc, bool offset);
const char *symbols_name_light(const symbols_t *st, const void *pc, size_t *off);
const void *symbols_addr(const symbols_t *st, const void *pc);
void symbols_load_from(symbols_t *st, const char *path, const  char *lpath);
enum symbol_quality symbols_quality(const symbols_t *st);
size_t symbols_count(const symbols_t *st);
void symbols_mark_stale(symbols_t *st);
size_t symbols_memory_size(const symbols_t *st);
size_t symbols_sort(symbols_t *st);
void symbols_append(symbols_t *st, const void *addr, const char *name);

void symbols_lock(symbols_t *st);
void symbols_unlock(symbols_t *st);

#endif /* _symbols_h_ */

/* vi: set ts=4 sw=4 cindent: */
