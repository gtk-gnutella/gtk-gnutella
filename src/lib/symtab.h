/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * Symbol table.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _symtab_h_
#define _symtab_h_

#include "common.h"

#include "nv.h"

struct symtab;
typedef struct symtab symtab_t;

/*
 * Public interface.
 */

symtab_t *symtab_make(void);
void symtab_free(symtab_t *syt);
void symtab_free_null(symtab_t **syt_ptr);
void *symtab_lookup(const symtab_t *syt, const char *name);
bool symtab_insert_pair(symtab_t *syt, nv_pair_t *symbol, unsigned depth);
bool symtab_insert(symtab_t *syt,
	const char *name, void *value, size_t len, unsigned depth);
void symtab_leave(symtab_t *syt, unsigned depth);

#endif /* _symtab_h_ */

/* vi: set ts=4 sw=4 cindent: */
