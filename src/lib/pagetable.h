/*
 * Copyright (c) 2006, Christian Biere
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
 * @author Christian Biere
 * @date 2007
 */

#ifndef _page_table_h_
#define _page_table_h_

#include "common.h"

typedef struct page_table page_table_t;

typedef void (*page_table_foreach_func)(void *p, size_t size, void *data);

page_table_t *page_table_new(void);
void page_table_destroy(page_table_t *ht);

int page_table_insert(page_table_t *ht, const void *p, size_t size);
void page_table_replace(page_table_t *tab, const void *p, size_t size);
size_t page_table_lookup(page_table_t *ht, const void *p);
int page_table_remove(page_table_t *ht, const void *p);
void page_table_foreach(page_table_t *ht, page_table_foreach_func func,
		void *data);

#endif /* _page_table_h_ */
/* vi: set ts=4 sw=4 cindent: */
