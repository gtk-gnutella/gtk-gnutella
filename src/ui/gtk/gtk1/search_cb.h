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

void on_search_popdown_switch(GtkWidget * w, gpointer data);
void on_search_notebook_switch(GtkNotebook * notebook, GtkNotebookPage * page, gint page_num, gpointer user_data);
void on_clist_search_select_row(GtkCList * clist, gint row, gint column, GdkEvent * event, gpointer user_data);
void on_search_selected(GtkItem * i, gpointer data);
void on_button_search_clicked (GtkButton *button, gpointer user_data);
void on_entry_search_activate (GtkEditable *editable, gpointer user_data);
void on_entry_search_changed (GtkEditable *editable, gpointer user_data);
void on_button_search_clear_clicked(GtkButton * button, gpointer user_data);
void on_button_search_close_clicked (GtkButton *button, gpointer user_data);
void on_button_search_download_clicked (GtkButton *button, gpointer user_data);
void on_button_search_collapse_all_clicked (GtkButton *button, gpointer user_data);
void on_button_search_expand_all_clicked (GtkButton *button, gpointer user_data);

gboolean on_clist_search_results_key_press_event(GtkWidget *widget, GdkEventKey *event, gpointer user_data);
gboolean on_clist_search_results_button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer user_data);
void on_button_search_filter_clicked (GtkButton *button, gpointer user_data);
void on_clist_search_results_click_column(GtkCList * clist, gint column, gpointer user_data);
void on_button_search_passive_clicked (GtkButton *button, gpointer user_data);

void on_ctree_search_results_select_row(GtkCTree *ctree, GList *node, gint column, gpointer user_data);
void on_ctree_search_results_unselect_row(GtkCTree *ctree, GList *node, gint column, gpointer user_data);
void on_ctree_search_results_resize_column(GtkCList * clist, gint column, gint width, gpointer user_data);

gchar *search_details_get_text(GtkWidget *widget);
void on_clist_search_details_select_row(GtkCList *unused_clist,
	gint row, gint unused_column, GdkEventButton *unused_event,
	gpointer unused_udata);
void on_clist_search_details_unselect_row(GtkCList *unused_clist,
	gint unused_row, gint unused_column, GdkEventButton *unused_event,
	gpointer unused_udata);
gboolean on_clist_search_details_key_press_event(GtkWidget *unused_widget,
	GdkEventKey *event, gpointer unused_udata);
void on_clist_search_details_selection_get(GtkWidget *unused_widget,
	GtkSelectionData *data, guint unused_info,
	guint unused_eventtime, gpointer unused_udata);
gint on_clist_search_details_selection_clear_event(GtkWidget *unused_widget,
	GdkEventSelection *unused_event);

#endif /* _gtk1_search_cb_h_ */
