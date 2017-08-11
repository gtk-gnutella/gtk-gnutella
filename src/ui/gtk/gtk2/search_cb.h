/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _gtk2_search_cb_h_
#define _gtk2_search_cb_h_

#include "gtk/gui.h"

struct search;
struct record;

void on_tree_view_search_results_select_row(GtkTreeView *, void *user_data);
void on_tree_view_search_results_unselect_row(GtkTreeView *,
	int row, int column, GdkEvent *, void *user_data);

void search_update_tooltip(GtkTreeView *, GtkTreePath *);

void *search_gui_get_record(GtkTreeModel *, GtkTreeIter *);

const struct record *search_gui_get_record_at_path(GtkTreeView *,
			GtkTreePath *);

#endif /* _gtk2_search_cb_h_ */

/* vi: set ts=4 sw=4 cindent: */
