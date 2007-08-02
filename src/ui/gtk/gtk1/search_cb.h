/*
 * $Id$
 *
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

#include "common.h"
#include <gtk/gtk.h>

void search_gui_set_cursor_position(gint x, gint y);

void on_search_popdown_switch(GtkWidget *, gpointer data);
void on_search_notebook_switch(GtkNotebook *, GtkNotebookPage *,
	gint page_num, gpointer user_data);
void on_clist_search_select_row(GtkCList *, gint row, gint column, GdkEvent *,
	gpointer user_data);
void on_search_selected(GtkItem *, gpointer data);
void on_button_search_clicked (GtkButton *, gpointer user_data);
void on_entry_search_activate (GtkEditable *, gpointer user_data);
void on_entry_search_changed (GtkEditable *, gpointer user_data);
void on_button_search_clear_clicked(GtkButton *, gpointer user_data);
void on_button_search_close_clicked (GtkButton *, gpointer user_data);
void on_button_search_download_clicked (GtkButton *, gpointer user_data);
void on_button_search_collapse_all_clicked (GtkButton *, gpointer user_data);
void on_button_search_expand_all_clicked (GtkButton *, gpointer user_data);

gboolean on_clist_search_results_key_press_event(GtkWidget *, GdkEventKey *,
		gpointer user_data);
gboolean on_clist_search_results_button_press_event(GtkWidget *,
		GdkEventButton *, gpointer user_data);
void on_button_search_filter_clicked(GtkButton *, gpointer user_data);
void on_clist_search_results_click_column(GtkCList *, gint column,
	gpointer user_data);
void on_button_search_passive_clicked (GtkButton *, gpointer user_data);

void on_ctree_search_results_select_row(GtkCTree *, GList *node,
	gint column, gpointer user_data);
void on_ctree_search_results_unselect_row(GtkCTree *, GList *node,
	gint column, gpointer user_data);

gchar *search_details_get_text(GtkWidget *);
void on_clist_search_details_select_row(GtkCList *, gint row, gint column,
	GdkEventButton *, gpointer user_data);
void on_clist_search_details_unselect_row(GtkCList *, gint row, gint column,
	GdkEventButton *, gpointer unused_udata);
gboolean on_clist_search_details_key_press_event(GtkWidget *, GdkEventKey *,
	gpointer user_data);

void search_gui_callbacks_shutdown(void);

#endif /* _gtk1_search_cb_h_ */
