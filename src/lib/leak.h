/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * Memory leak reporting utilities.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _leak_h_
#define _leak_h_

struct leak_set;
typedef struct leak_set leak_set_t;

struct stackatom;

/*
 * Public interface.
 */

leak_set_t *leak_init(void);
void leak_close_null(leak_set_t **ls_ptr);
void leak_add(leak_set_t *ls, size_t size, const char *file, int line);
void leak_stack_add(leak_set_t *ls, size_t size, const struct stackatom *sa);
void leak_dump(const leak_set_t *ls);

#endif	/* _leak_h_ */

/* vi: set ts=4 sw=4 cindent: */

