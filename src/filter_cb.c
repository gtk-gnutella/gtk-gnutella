/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * GUI filtering functions.
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

#include "gnutella.h"
#include "filter.h"
#include "filter_cb.h"
#include "filter_gui.h"
#include "gui_property_priv.h"

/*
 * Private variables
 */
static rule_t *rule_clipboard = NULL;

void filter_cb_close()
{
    if (rule_clipboard != NULL)
        filter_free_rule(rule_clipboard);
}

/*
 * on_checkbutton_filter_enabled_toggled:
 *
 * Change the active stats of the current work_filter to what
 * the togglebutton indicates.
 */
void on_checkbutton_filter_enabled_toggled
    (GtkToggleButton *togglebutton, gpointer user_data)
{
    if (work_filter == NULL)
        return;

    filter_set_enabled
        (work_filter, gtk_toggle_button_get_active(togglebutton));
}



void on_ctree_filter_filters_tree_select_row
    (GtkCTree * ctree, GList *node, gint column, gpointer user_data)
{
    static gboolean lock = FALSE;
    filter_t *filter;

    if (lock)
        return;
    
    lock = TRUE;

    filter = (filter_t *) gtk_ctree_node_get_row_data
        (GTK_CTREE(ctree), GTK_CTREE_NODE(node));

    filter_set(filter);

    lock = FALSE;
}

void on_button_filter_reset_all_clicked
    (GtkButton *button, gpointer user_data)
{
    gint row;
    GtkCTree *ctree;
    GtkCList *clist;

    if (filter_dialog == NULL)
        return;

    ctree = GTK_CTREE(lookup_widget(filter_dialog, "ctree_filter_filters"));
    clist = GTK_CLIST(ctree);

    for (row = 0; row < clist->rows; row ++) {
        filter_t *filter;
        GtkCTreeNode *node;
        
        node = gtk_ctree_node_nth(ctree, row);

        filter = (filter_t *) gtk_ctree_node_get_row_data(ctree, node);

        if (filter == NULL)
            continue;

        filter_reset_stats(filter);
    }
}

void on_button_filter_reset_clicked
    (GtkButton *button, gpointer user_data)
{
    if (work_filter != NULL)
        filter_reset_stats(work_filter);
}



void on_ctree_filter_filters_resize_column
    (GtkCList * clist, gint column, gint width, gpointer user_data)
{
    filter_filters_col_widths[column] = width;
}

void on_clist_filter_rules_resize_column
    (GtkCList * clist, gint column, gint width, gpointer user_data)
{
    filter_rules_col_widths[column] = width;
}

gboolean on_dlg_filters_delete_event(GtkWidget *widget, gpointer user_data)
{
    filter_close_dialog(FALSE);

    return TRUE;
}

void on_clist_filter_rules_select_row(GtkCList * clist, gint row, gint column,
							          GdkEvent * event, gpointer user_data)
{
    rule_t * r;

    r = (rule_t *) gtk_clist_get_row_data(clist, row);
    g_assert(r != NULL);
   
    filter_gui_edit_rule(r);
}

void on_clist_filter_rules_unselect_row
    (GtkCList * clist, gint row, gint column, 
    GdkEvent * event, gpointer user_data)
{
    if (clist->selection == NULL)
        filter_gui_edit_rule(NULL);
}

void on_clist_filter_rules_drag_end(GtkWidget *widget, 
    GdkDragContext *drag_context, gpointer user_data)
{
    filter_adapt_order();
}


void on_button_filter_add_rule_text_clicked(GtkButton *button, gpointer user_data)
{
    gtk_clist_unselect_all
        (GTK_CLIST(lookup_widget(filter_dialog, "clist_filter_rules")));
    filter_gui_edit_text_rule(NULL);
}

void on_button_filter_add_rule_ip_clicked(GtkButton *button, gpointer user_data)
{
    gtk_clist_unselect_all
        (GTK_CLIST(lookup_widget(filter_dialog, "clist_filter_rules")));
    filter_gui_edit_ip_rule(NULL);
}

void on_button_filter_add_rule_size_clicked(GtkButton *button, gpointer user_data)
{
    gtk_clist_unselect_all
        (GTK_CLIST(lookup_widget(filter_dialog, "clist_filter_rules")));
    filter_gui_edit_size_rule(NULL);
}

void on_button_filter_add_rule_jump_clicked(GtkButton *button, gpointer user_data)
{
    gtk_clist_unselect_all
        (GTK_CLIST(lookup_widget(filter_dialog, "clist_filter_rules")));
    filter_gui_edit_jump_rule(NULL);
}

void on_button_filter_add_rule_flag_clicked(GtkButton *button, gpointer user_data)
{
    gtk_clist_unselect_all
        (GTK_CLIST(lookup_widget(filter_dialog, "clist_filter_rules")));
    filter_gui_edit_flag_rule(NULL);
}

void on_button_filter_add_rule_state_clicked(GtkButton *button, gpointer user_data)
{
    gtk_clist_unselect_all
        (GTK_CLIST(lookup_widget(filter_dialog, "clist_filter_rules")));
    filter_gui_edit_state_rule(NULL);
}

void on_button_filter_ok_clicked(GtkButton *button, gpointer user_data)
{
    filter_close_dialog(TRUE);
}

void on_button_filter_add_rule_clicked(GtkButton *button, gpointer user_data)
{
    rule_t * r = NULL;
    gint page = gtk_notebook_get_current_page
        (GTK_NOTEBOOK(lookup_widget(filter_dialog, "notebook_filter_detail")));
    GtkCList *clist_filter_rules = GTK_CLIST
        (lookup_widget(filter_dialog, "clist_filter_rules"));

    switch (page) {
    case nb_filt_page_text:
    case nb_filt_page_ip:
    case nb_filt_page_size:
    case nb_filt_page_jump:
    case nb_filt_page_flag:
    case nb_filt_page_state:
        r = filter_gui_get_rule();
        break;
    case nb_filt_page_sha1:
        /*
         * SHA1 rules are not changeable yet (maybe never).
         * So we just return here.
         */
        filter_gui_edit_rule(NULL);
        return;
    case nb_filt_page_buttons:
    default:
        g_error("on_button_filter_on_clicked: invalid page %d", page);
    };

    /*
     *if a row is selected, we change the filter there
     *else we add a new filter to the end of the list
     */

    if (clist_filter_rules->selection != NULL) {
        GList *l = clist_filter_rules->selection;
        rule_t *oldrule;

        /* modify row */
        oldrule = (rule_t *) 
            gtk_clist_get_row_data(clist_filter_rules, (gint)l->data);
        g_assert(oldrule != NULL);
        
        filter_replace_rule_in_session(work_filter, oldrule, r);
    } else {
        filter_append_rule_to_session(work_filter, r);   
    }

    filter_gui_edit_rule(NULL);
}

void on_button_filter_cancel_clicked(GtkButton *button, gpointer user_data)
{
    gint page = gtk_notebook_get_current_page
        (GTK_NOTEBOOK
            (lookup_widget(filter_dialog, "notebook_filter_detail")));

    if (page == nb_filt_page_buttons) {
        filter_close_dialog(FALSE);
        return;
    }
    filter_gui_edit_rule(NULL);
}

void on_button_filter_apply_clicked(GtkButton *button, gpointer user_data)
{
    filter_apply_changes();
    filter_gui_edit_rule(NULL);
}

void on_button_filter_revert_clicked(GtkButton *button, gpointer user_data)
{
    filter_revert_changes();
    filter_gui_edit_rule(NULL);
}


void on_button_filter_clear_clicked(GtkButton *button, gpointer user_data)
{
    GtkCList *clist = GTK_CLIST
        (lookup_widget(filter_dialog, "clist_filter_rules"));

    gtk_clist_freeze(clist);

    while (clist->rows != 0) {
        rule_t *r;

        r = (rule_t *) gtk_clist_get_row_data(clist, 0);
       
        filter_remove_rule_from_session(work_filter, r);
    }

    gtk_clist_thaw(clist);
    gtk_notebook_set_page(
        GTK_NOTEBOOK
            (lookup_widget(filter_dialog, "notebook_filter_detail")), 
        nb_filt_page_buttons);
}

void on_button_filter_remove_rule_clicked(GtkButton *button, gpointer user_data)
{
    GtkCList *clist = GTK_CLIST
        (lookup_widget(filter_dialog, "clist_filter_rules"));
    rule_t *r;

    if (!clist->selection)
        return;

    r = (rule_t *) 
        gtk_clist_get_row_data(clist, (gint)clist->selection->data);
       
    filter_remove_rule_from_session(work_filter, r);

    gtk_notebook_set_page(
        GTK_NOTEBOOK
            (lookup_widget(filter_dialog, "notebook_filter_detail")), 
        nb_filt_page_buttons);
}

void on_button_filter_abort_rule_clicked(GtkButton *button, gpointer user_data)
{
    gtk_notebook_set_page(
        GTK_NOTEBOOK(lookup_widget(filter_dialog, "notebook_filter_detail")), 
        nb_filt_page_buttons);
}

void on_button_filter_remove_clicked
    (GtkButton *button, gpointer user_data)
{
    if (work_filter != NULL)
        filter_remove_from_session(work_filter);
}

void on_entry_filter_new_activate 
    (GtkEditable *editable, gpointer user_data)
{
    gchar *name = gtk_editable_get_chars(editable, 0, -1);
    filter_t *filter;

    g_strstrip(name);
    if (*name && (filter_find_by_name_in_session(name) == NULL)) {
        filter = filter_new(name);
        filter_add_to_session(filter);
        gtk_entry_set_text(GTK_ENTRY(editable), "");
        filter_set(filter);
    } else
        gdk_beep();
}

void on_button_filter_create_clicked
    (GtkButton *button, gpointer user_data)
{
    /*
     * Delegate to on_entry_filter_new_activate.
     */
    on_entry_filter_new_activate
        (GTK_EDITABLE(lookup_widget(filter_dialog, "entry_filter_new")), NULL);
}

void on_button_filter_reset_rule_clicked
    (GtkButton *button, gpointer user_data)
{
    rule_t *rule;
    GtkCList *clist_filter_rules = GTK_CLIST
        (lookup_widget(filter_dialog, "clist_filter_rules"));

    if (clist_filter_rules->selection == NULL)
        return;

    rule = (rule_t *) 
        gtk_clist_get_row_data
            (clist_filter_rules, (gint) clist_filter_rules->selection->data);

    filter_rule_reset_stats(rule);
}

void on_button_filter_reset_all_rules_clicked
    (GtkButton *button, gpointer user_data)
{
    gint row;
    GtkCList *clist_filter_rules = GTK_CLIST
        (lookup_widget(filter_dialog, "clist_filter_rules"));

    for (row = 0; row < clist_filter_rules->rows; row ++) {
        rule_t *rule;
    
        rule = (rule_t *) gtk_clist_get_row_data(clist_filter_rules, row);

        if (rule == NULL)
            continue;

        filter_rule_reset_stats(rule);
    }
}

gboolean on_clist_filter_rules_button_press_event
    (GtkWidget * widget, GdkEventButton * event, gpointer user_data)
{
    gboolean sensitive;
    GtkCList *clist_filter_rules = GTK_CLIST
        (lookup_widget(filter_dialog, "clist_filter_rules"));

    if (event->button != 3)
		return FALSE;

    /*
     * If the target is no longer valid, free the rule and
     * clear the clipboard.
     */
    if ((rule_clipboard != NULL) &&
        !filter_is_valid_in_session(rule_clipboard->target)) {
        filter_free_rule(rule_clipboard);
        rule_clipboard = NULL;
        return TRUE;
    }

    sensitive = (clist_filter_rules->selection != NULL) &&
        (work_filter != NULL);

    gtk_widget_set_sensitive
        (lookup_widget(filter_dialog, "popup_filter_rule_copy"), sensitive);
    gtk_widget_set_sensitive(
        lookup_widget(filter_dialog, "popup_filter_rule_paste"), 
        rule_clipboard != NULL);

    gtk_menu_popup
        (GTK_MENU(popup_filter_rule), NULL, NULL, NULL, NULL, 
        event->button, event->time);

	return TRUE;
}

void on_popup_filter_rule_copy_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    GtkCList *clist_filter_rules = GTK_CLIST
        (lookup_widget(filter_dialog, "clist_filter_rules"));

    if (rule_clipboard != NULL)
        filter_free_rule(rule_clipboard);

    if (clist_filter_rules->selection != NULL) {
        rule_t *r;
        gint row;

        row = (gint) clist_filter_rules->selection->data;

        r = (rule_t *) gtk_clist_get_row_data(clist_filter_rules, row);
        g_assert(r != NULL);
   
        rule_clipboard = filter_duplicate_rule(r);
    }
}

void on_popup_filter_rule_paste_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    rule_t *r;

    if ((work_filter == NULL) || (rule_clipboard == NULL))
        return;

    /*
     * If the target is no longer valid, free the rule and
     * clear the clipboard.
     */
    if (!filter_is_valid_in_session(rule_clipboard->target)) {
        filter_free_rule(rule_clipboard);
        rule_clipboard = NULL;
        return;
    }

    /*
     * Since a rule may not be added to two filters, we copy again here.
     * We want to keep the original copy in the clipboard since we may
     * want to paste it elsewhere.
     * The filter takes ownership of the added rule.
     */
    r = filter_duplicate_rule(rule_clipboard);

    filter_append_rule_to_session(work_filter, r);
}
