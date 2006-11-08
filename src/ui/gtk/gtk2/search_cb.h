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
gboolean on_tree_view_search_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata);
gboolean on_tree_view_search_results_button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer user_data);
void on_button_search_filter_clicked (GtkButton *button, gpointer user_data);
gboolean on_tree_view_search_results_click_column(GtkTreeViewColumn * tree_view_column, gpointer user_data);
void on_tree_view_search_results_select_row(GtkTreeView * tree_view, gpointer user_data);
void on_tree_view_search_results_unselect_row(GtkTreeView * tree_view, gint row, gint column, GdkEvent * event, gpointer user_data);
void on_tree_view_search_results_resize_column(GtkTreeView * tree_view, gint column, gint width, gpointer user_data);
void on_button_search_passive_clicked (GtkButton *button, gpointer user_data);

void search_update_tooltip(GtkTreeView *tv, GtkTreePath *path);
void search_callbacks_shutdown(void);




/***
 *** Search results popup
 ***/
void on_popup_search_download_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_drop_name_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_drop_sha1_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_drop_host_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_drop_name_global_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_drop_sha1_global_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_drop_host_global_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_edit_filter_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_clear_results_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_close_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_duplicate_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_restart_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_resume_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_stop_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_config_cols_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_expand_all_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_collapse_all_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_metadata_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_copy_magnet_activate(GtkMenuItem *menuitem, gpointer user_data);

/***
 *** Search list popup
 ***/
void on_popup_search_list_clear_results_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_list_close_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_list_duplicate_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_list_restart_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_list_resume_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_list_stop_activate(GtkMenuItem *menuitem, gpointer user_data);


gpointer search_gui_get_record(GtkTreeModel *model, GtkTreeIter *iter);
gboolean search_gui_update_rank(GtkTreeModel *model,
		GtkTreePath *path, GtkTreeIter *iter, gpointer udata);
gchar *search_gui_get_magnet(GtkTreeModel *model, GtkTreeIter *iter);

#endif /* _gtk2_search_cb_h_ */
