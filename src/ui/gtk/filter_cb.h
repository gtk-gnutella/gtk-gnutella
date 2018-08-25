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

#ifndef _gtk_filter_cb_h_
#define _gtk_filter_cb_h_

#include <gtk/gtk.h>

void filter_cb_close(void);

/*
 * Filter dialog
 */
gboolean on_dlg_filters_delete_event(GtkWidget *widget, gpointer user_data);

#ifdef USE_GTK1
void on_clist_filter_rules_select_row(GtkCList * clist, gint row, gint column, GdkEvent * event, gpointer user_data);
void on_clist_filter_rules_unselect_row(GtkCList * clist, gint row, gint column, GdkEvent * event, gpointer user_data);
void on_clist_filter_rules_drag_end(GtkWidget *widget, GdkDragContext *drag_context, gpointer user_data);
void on_ctree_filter_filters_tree_select_row(GtkCTree * ctree, GList *node, gint column, gpointer user_data);
gboolean on_clist_filter_rules_button_press_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data);
#endif /* USE_GTK1 */

#ifdef USE_GTK2
gboolean on_treeview_filter_rules_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata);
void on_treeview_filter_filters_select_row(GtkTreeView *tv,
	gpointer unused_udata);
void on_treeview_filter_rules_select_row(GtkTreeView *tv,
	gpointer unused_udata);
#endif /* USE_GTK2 */

void on_button_filter_add_rule_text_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_add_rule_ip_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_add_rule_size_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_add_rule_jump_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_add_rule_flag_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_add_rule_state_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_ok_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_add_rule_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_apply_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_revert_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_cancel_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_clear_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_abort_rule_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_remove_rule_clicked(GtkButton *button, gpointer user_data);
void on_entry_filter_new_activate (GtkEditable *editable, gpointer user_data);
void on_button_filter_remove_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_create_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_reset_all_rules_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_reset_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_reset_all_clicked(GtkButton *button, gpointer user_data);
void on_button_filter_reset_rule_clicked(GtkButton *button, gpointer user_data);
void on_checkbutton_filter_enabled_toggled(GtkToggleButton * togglebutton, gpointer user_data);

gboolean on_entry_filter_size_focus_out_event(GtkEditable *editable, gpointer unused_udata);
gboolean on_entry_filter_size_key_press_event(GtkWidget *widget, GdkEventKey *event, gpointer unused_udata);

/*
 * Filter popup for rule list
 */
void on_popup_filter_rule_copy_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_filter_rule_paste_activate(GtkMenuItem *menuitem, gpointer user_data);

#endif /* _gtk_filter_cb_h_ */

/* vi: set ts=4 sw=4 cindent: */
