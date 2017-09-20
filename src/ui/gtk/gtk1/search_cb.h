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

#ifndef _gtk1_search_cb_h_
#define _gtk1_search_cb_h_

#include "gtk/gui.h"

void search_gui_set_cursor_position(int x, int y);

void on_clist_search_select_row(GtkCList *, int row, int column, GdkEvent *,
	void *user_data);
void on_clist_search_results_click_column(GtkCList *, int column,
	void *user_data);

void on_ctree_search_results_select_row(GtkCTree *, GList *node,
	int column, void *user_data);
void on_ctree_search_results_unselect_row(GtkCTree *, GList *node,
	int column, void *user_data);

void on_clist_search_details_select_row(GtkCList *, int row, int column,
	GdkEventButton *, void *user_data);
void on_clist_search_details_unselect_row(GtkCList *, int row, int column,
	GdkEventButton *, void *unused_udata);

#endif /* _gtk1_search_cb_h_ */

/* vi: set ts=4 sw=4 cindent: */
