/*
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
#include "interface.h"
#include "filter.h"
#include "filter_cb.h"

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
    filter_t *filter;

    filter = (filter_t *) gtk_ctree_node_get_row_data
        (GTK_CTREE(ctree), GTK_CTREE_NODE(node));

    filter_set(filter);
}

void on_button_filter_reset_all_clicked
    (GtkButton *button, gpointer user_data)
{
    gint row;

    for (row = 0; row < GTK_CLIST(ctree_filter_filters)->rows; row ++) {
        filter_t *filter;
        GtkCTreeNode *node;
        
        node = gtk_ctree_node_nth(GTK_CTREE(ctree_filter_filters), row);

        filter = (filter_t *) gtk_ctree_node_get_row_data
            (GTK_CTREE(ctree_filter_filters), node);

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



void on_ctree_filter_filters_resize_column(GtkCList * clist, gint column, 
                                           gint width, gpointer user_data)
{
    filter_filters_col_widths[column] = width;
}

void on_clist_filter_rules_resize_column(GtkCList * clist, gint column, 
                                   gint width, gpointer user_data)
{
    filter_table_col_widths[column] = width;
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
   
    filter_edit_rule(r);
}

void on_clist_filter_rules_unselect_row(GtkCList * clist, gint row, gint column,
	  						            GdkEvent * event, gpointer user_data)
{
    if (clist->selection == NULL)
        filter_edit_rule(NULL);
}

void on_clist_filter_rules_drag_end(GtkWidget *widget, 
    GdkDragContext *drag_context, gpointer user_data)
{
    filter_adapt_order();
}


void on_button_filter_add_rule_text_clicked(GtkButton *button, gpointer user_data)
{
    gtk_clist_unselect_all(GTK_CLIST(clist_filter_rules));
    filter_edit_text_rule(NULL);
}

void on_button_filter_add_rule_ip_clicked(GtkButton *button, gpointer user_data)
{
    gtk_clist_unselect_all(GTK_CLIST(clist_filter_rules));
    filter_edit_ip_rule(NULL);
}

void on_button_filter_add_rule_size_clicked(GtkButton *button, gpointer user_data)
{
    gtk_clist_unselect_all(GTK_CLIST(clist_filter_rules));
    filter_edit_size_rule(NULL);
}

void on_button_filter_add_rule_jump_clicked(GtkButton *button, gpointer user_data)
{
    gtk_clist_unselect_all(GTK_CLIST(clist_filter_rules));
    filter_edit_jump_rule(NULL);
}

void on_button_filter_ok_clicked(GtkButton *button, gpointer user_data)
{
    rule_t * r = NULL;

    gint page = gtk_notebook_get_current_page
        (GTK_NOTEBOOK(notebook_filter_detail));

    if (page == nb_filt_page_buttons) {
        filter_close_dialog(TRUE);
        return;
    }

    switch (page) {
    case nb_filt_page_text:
    case nb_filt_page_ip:
    case nb_filt_page_size:
    case nb_filt_page_jump:
        r = filter_get_rule();
        break;
    case nb_filt_page_buttons:
    default:
        g_warning("Unknown page: %d", page);
        g_assert_not_reached();
    };

    /*
     *if a row is selected, we change the filter there
     *else we add a new filter to the end of the list
     */

    if (GTK_CLIST(clist_filter_rules)->selection != NULL) {
        GList *l = GTK_CLIST(clist_filter_rules)->selection;
        rule_t *oldrule;

        /* modify row */
        oldrule = (rule_t *) gtk_clist_get_row_data(
            GTK_CLIST(clist_filter_rules),
            (gint)l->data);
        g_assert(oldrule != NULL);
        
        filter_replace_rule(work_filter, oldrule, r);
    } else {
        filter_append_rule(work_filter, r);   
    }
}

void on_button_filter_cancel_clicked(GtkButton *button, gpointer user_data)
{
    gint page = gtk_notebook_get_current_page
        (GTK_NOTEBOOK(notebook_filter_detail));

    if (page == nb_filt_page_buttons) {
        filter_close_dialog(FALSE);
        return;
    }

    filter_edit_rule(NULL);
}

void on_button_filter_clear_clicked(GtkButton *button, gpointer user_data)
{
    GtkCList *clist = GTK_CLIST(clist_filter_rules);

    gtk_clist_freeze(clist);

    while (clist->rows != 0) {
        rule_t *r;

        r = (rule_t *) gtk_clist_get_row_data(clist, 0);
       
        filter_remove_rule(work_filter, r);
    }

    gtk_clist_thaw(clist);
    gtk_notebook_set_page
        (GTK_NOTEBOOK(notebook_filter_detail), nb_filt_page_buttons);
}

void on_button_filter_remove_rule_clicked(GtkButton *button, gpointer user_data)
{
    GtkCList *clist = GTK_CLIST(clist_filter_rules);
    rule_t *r;

    if (!clist->selection)
        return;

    r = (rule_t *) 
        gtk_clist_get_row_data(clist, (gint)clist->selection->data);
       
    filter_remove_rule(work_filter, r);

    gtk_notebook_set_page
        (GTK_NOTEBOOK(notebook_filter_detail), nb_filt_page_buttons);
}

void on_button_filter_remove_clicked
    (GtkButton *button, gpointer user_data)
{
    /*
     * filter_free removes the filter from display.
     */

    if (work_filter != NULL)
        filter_free(work_filter);
}

void on_entry_filter_new_activate 
    (GtkEditable *editable, gpointer user_data)
{
    gchar *name = gtk_editable_get_chars(editable, 0, -1);
    filter_t *filter;

    g_strstrip(name);
    if (*name) {
        filter = filter_new(name);
        gtk_entry_set_text(GTK_ENTRY(editable), "");
        filter_set(filter);
    }
}

void on_button_filter_create_clicked
    (GtkButton *button, gpointer user_data)
{
    /*
     * Delegate to on_entry_filter_new_activate.
     */
    on_entry_filter_new_activate(GTK_EDITABLE(entry_filter_new), NULL);
}

void on_button_filter_reset_rule_clicked
    (GtkButton *button, gpointer user_data)
{
    rule_t *rule;
    
    if (GTK_CLIST(clist_filter_rules)->selection == NULL)
        return;

    rule = (rule_t *) gtk_clist_get_row_data(
        GTK_CLIST(clist_filter_rules),
        (gint) GTK_CLIST(clist_filter_rules)->selection->data);

    filter_rule_reset_stats(rule);
}

void on_button_filter_reset_all_rules_clicked
    (GtkButton *button, gpointer user_data)
{
    gint row;

    for (row = 0; row < GTK_CLIST(clist_filter_rules)->rows; row ++) {
        rule_t *rule;
    
        rule = (rule_t *) gtk_clist_get_row_data
            (GTK_CLIST(clist_filter_rules), row);

        if (rule == NULL)
            continue;

        filter_rule_reset_stats(rule);
    }
}


