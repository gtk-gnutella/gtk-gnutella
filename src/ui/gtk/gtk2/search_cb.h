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

#ifndef _gtk2_search_cb_h_
#define _gtk2_search_cb_h_

#include <gtk/gtk.h>

void on_combo_entry_searches_activate(GtkEditable *editable, gpointer user_data);
void on_entry_search_activate(GtkEditable *editable, gpointer user_data);
void on_entry_search_changed(GtkEditable *editable, gpointer unused_udata);
void on_search_popdown_switch(GtkWidget * w, gpointer data);
void on_search_notebook_switch(GtkNotebook * notebook, GtkNotebookPage * page, gint page_num, gpointer user_data);
void on_search_notebook_focus_tab(GtkNotebook * notebook, GtkNotebookTab arg1, gpointer user_data);
void on_tree_view_search_cursor_changed(GtkTreeView *tv, gpointer user_data);
void on_search_selected(GtkItem * i, gpointer data);
void on_button_search_clicked(GtkButton *button, gpointer user_data);
void on_button_search_clear_clicked(GtkButton * button, gpointer user_data);
void on_button_search_close_clicked(GtkButton *button, gpointer user_data);
void on_button_search_download_clicked(GtkButton *button, gpointer user_data);

gboolean on_tree_view_search_results_key_press_event(GtkWidget *widget, GdkEventKey *event, gpointer user_data);
gboolean on_tree_view_search_results_button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer user_data);
void on_button_search_filter_clicked (GtkButton *button, gpointer user_data);
void on_tree_view_search_results_click_column(GtkTreeViewColumn * tree_view_column, gpointer user_data);
void on_tree_view_search_results_select_row(GtkTreeView * tree_view, gpointer user_data);
void on_tree_view_search_results_unselect_row(GtkTreeView * tree_view, gint row, gint column, GdkEvent * event, gpointer user_data);
void on_tree_view_search_results_resize_column(GtkTreeView * tree_view, gint column, gint width, gpointer user_data);
void on_button_search_passive_clicked (GtkButton *button, gpointer user_data);

void search_update_tooltip(GtkTreeView *tv, GtkTreePath *path);
void search_callbacks_shutdown(void);

gpointer search_gui_get_record(GtkTreeModel *model, GtkTreeIter *iter);
gboolean search_gui_update_rank(GtkTreeModel *model,
		GtkTreePath *path, GtkTreeIter *iter, gpointer udata);
gchar *search_gui_get_magnet(GtkTreeModel *model, GtkTreeIter *iter);
gchar *search_details_get_text(GtkWidget *widget);

gboolean on_treeview_search_details_key_press_event(GtkWidget *widget,
	GdkEventKey *event, gpointer unused_udata);

#endif /* _gtk2_search_cb_h_ */
