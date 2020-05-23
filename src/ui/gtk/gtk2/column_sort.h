/*
 * Copyright (c) 2014 Raphael Manfredi
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

#ifndef _gtk2_column_sort_h_
#define _gtk2_column_sort_h_

#include "gtk/gui.h"

typedef void (*column_tristate_cb_t)(GtkTreeViewColumn *column, void *udata);

struct sorting_context;

void column_sort_tristate(GtkTreeViewColumn *column,
	struct sorting_context *ctx);

void
column_sort_tristate_register(GtkTreeViewColumn *column,
	column_tristate_cb_t cb, void *udata);

#endif /* _gtk2_column_sort_h_ */

/* vi: set ts=4 sw=4 cindent: */
