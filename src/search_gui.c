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
#include "search_gui.h"
#include "search_cb.h"
#include "gtk-missing.h"
#include "gui_property.h"
#include "gui_property_priv.h"


/*
 * If no search are currently allocated 
 */
GtkWidget *default_search_clist = NULL;
GtkWidget *default_scrolled_window = NULL;

void search_gui_init(void)
{
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (lookup_widget(main_window, "notebook_search_results"));
    GtkCombo *combo_searches = GTK_COMBO
        (lookup_widget(main_window, "combo_searches"));

	gui_search_create_clist(&default_scrolled_window, &default_search_clist);
    gtk_notebook_remove_page(notebook_search_results, 0);
	gtk_notebook_set_scrollable(notebook_search_results, TRUE);
	gtk_notebook_append_page
        (notebook_search_results, default_scrolled_window, NULL);
  	gtk_notebook_set_tab_label_text
        (notebook_search_results, default_scrolled_window, "(no search)");
    
	gtk_signal_connect(GTK_OBJECT(combo_searches->popwin),
					   "hide", GTK_SIGNAL_FUNC(on_search_popdown_switch),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(notebook_search_results), "switch_page",
					   GTK_SIGNAL_FUNC(on_search_notebook_switch), NULL);

    /*
     * Now we restore the column visibility
     */
    {
        gint i;
        GtkCList *clist;

        clist = (current_search != NULL) ? 
                GTK_CLIST(current_search->clist) : 
                GTK_CLIST(default_search_clist);
         
        for (i = 0; i < clist->columns; i ++)
            gtk_clist_set_column_visibility
                (clist, i, (gboolean) search_results_col_visible[i]);
    }
}

/*
 * search_gui_remove_search:
 *
 * Remove the search from the gui and update all widget accordingly.
 */
void search_gui_remove_search(search_t * sch)
{
    gint row;
    GList *glist;
    gboolean sensitive;
    GtkCList *clist_search = GTK_CLIST
        (lookup_widget(main_window, "clist_search"));
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (lookup_widget(main_window, "notebook_search_results"));
    GtkCombo *combo_searches = GTK_COMBO
         (lookup_widget(main_window, "combo_searches"));

    g_assert(sch != NULL);

   	glist = g_list_prepend(NULL, (gpointer) sch->list_item);
	gtk_list_remove_items(GTK_LIST(combo_searches->list), glist);

    row = gtk_clist_find_row_from_data(clist_search, sch);
    gtk_clist_remove(clist_search, row);

    gtk_timeout_remove(sch->tab_updating);

    if (searches) {				/* Some other searches remain. */
		gtk_notebook_remove_page(notebook_search_results,
			gtk_notebook_page_num(notebook_search_results, 
				sch->scrolled_window));
	} else {
		/*
		 * Keep the clist of this search, clear it and make it the
		 * default clist
		 */
        GtkWidget *spinbutton_minimum_speed =
            lookup_widget(main_window, "spinbutton_minimum_speed");

		gtk_clist_clear(GTK_CLIST(sch->clist));

		default_search_clist = sch->clist;
		default_scrolled_window = sch->scrolled_window;

        search_selected = current_search = NULL;

		gui_search_update_items(NULL);

		gtk_entry_set_text
            (GTK_ENTRY(lookup_widget(main_window, "combo_entry_searches")), "");

        gtk_notebook_set_tab_label_text
            (notebook_search_results, default_scrolled_window, "(no search)");

		gtk_widget_set_sensitive
            (lookup_widget(main_window, "button_search_clear"), FALSE);
		gtk_widget_set_sensitive
            (lookup_widget(popup_search, "popup_search_clear_results"), FALSE);
        gtk_widget_set_sensitive(spinbutton_minimum_speed, FALSE);
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(spinbutton_minimum_speed), 0);
	}
    
	gtk_widget_set_sensitive(GTK_WIDGET(combo_searches), searches != NULL);
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_close"), searches != NULL);

    sensitive = current_search && GTK_CLIST(current_search->clist)->selection;
    gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_download"), sensitive);
}

void search_gui_view_search(search_t *sch) 
{
	search_t *old_sch = current_search;
    GtkCTreeNode * node;
    gint row;
    static gboolean locked = FALSE;

	g_return_if_fail(sch);

    if (locked)
        return;

    locked = TRUE;

    /*
     * We now propagate the column visibility from the current_search
     * to the new current_search.
     */
    if (current_search != NULL) {
        gint i;
        GtkCList *list;
        
        list = GTK_CLIST(current_search->clist);

        for (i = 0; i < list->columns; i ++)
            gtk_clist_set_column_visibility
                (GTK_CLIST(sch->clist), i, list->column[i].visible);
    }

	current_search = sch;
	sch->unseen_items = 0;

	if (old_sch)
		gui_search_force_update_tab_label(old_sch);
	gui_search_force_update_tab_label(sch);

	gui_search_update_items(sch);

    {
        GtkWidget *spinbutton_minimum_speed =
            lookup_widget(main_window, "spinbutton_minimum_speed");

        gtk_spin_button_set_value
            (GTK_SPIN_BUTTON(spinbutton_minimum_speed), sch->speed);
        gtk_widget_set_sensitive(spinbutton_minimum_speed, TRUE);
    }

	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_download"), 
        GTK_CLIST(sch->clist)->selection != NULL);

	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_clear"), 
        sch->items != 0);
	gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_clear_results"), 
        sch->items != 0);
	gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_restart"), 
        !sch->passive);
	gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_duplicate"), 
        !sch->passive);
	gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_stop"), 
        sch->passive ? !sch->frozen : sch->reissue_timeout);
	gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_resume"), 
        sch->passive ? sch->frozen : sch->reissue_timeout);

    /*
     * Reissue timeout
     */
    {
        GtkWidget *sb = lookup_widget
            (main_window, "spinbutton_search_reissue_timeout");

        if (sch != NULL)
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(sb), sch->reissue_timeout);
        
        gtk_widget_set_sensitive(sb, (sch != NULL) && (!sch->passive));
    }

    /*
     * Sidebar searches list.
     */
    {
        GtkCList *clist_search = GTK_CLIST
            (lookup_widget(main_window, "clist_search"));

        row = gtk_clist_find_row_from_data(clist_search, sch);
        gtk_clist_select_row(clist_search,row,0);
    }

    /*
     * Combo "Active searches"
     */
  	gtk_list_item_select(GTK_LIST_ITEM(sch->list_item));

    /*
     * Search results notebook
     */
    {
        GtkNotebook *notebook_search_results = GTK_NOTEBOOK
            (lookup_widget(main_window, "notebook_search_results"));

        gtk_notebook_set_page(notebook_search_results,
  			  gtk_notebook_page_num(notebook_search_results,
                  sch->scrolled_window));
    }

    /*
     * Tree menu
     */
    {
        GtkCTree *ctree_menu = GTK_CTREE
            (lookup_widget(main_window, "ctree_menu"));

        node = gtk_ctree_find_by_row_data(
            ctree_menu,
            gtk_ctree_node_nth(ctree_menu,0),
            (gpointer) nb_main_page_search);
    
        if (node != NULL)
            gtk_ctree_select(ctree_menu,node);
    }

    locked = FALSE;
}

/*
 * search_gui_search_results_col_widths_changed:
 *
 * Callback to update the columns withs in the currently visible search.
 * This is not in settings_gui because the current search should not be
 * known outside this file.
 */
gboolean search_gui_search_results_col_widths_changed(property_t prop)
{
    guint32 *val;
    GtkCList *clist;

    val = gui_prop_get_guint32(PROP_SEARCH_RESULTS_COL_WIDTHS, NULL, 0, 0);

    clist = GTK_CLIST((current_search != NULL) ? 
        current_search->clist : default_search_clist);

    if (clist != NULL) {
        gint i;
    
        for (i = 0; i < clist->columns; i ++)
            gtk_clist_set_column_width(clist, i, val[i]);
    }

    g_free(val);
    return FALSE;
}

/*
 * search_gui_search_results_col_widths_changed:
 *
 * Callback to update the columns withs in the currently visible search.
 * This is not in settings_gui because the current search should not be
 * known outside this file.
 */
gboolean search_gui_search_results_col_visible_changed(property_t prop)
{
    guint32 *val;
    GtkCList *clist;

    val = gui_prop_get_guint32(PROP_SEARCH_RESULTS_COL_VISIBLE, NULL, 0, 0);

    clist = GTK_CLIST((current_search != NULL) ? 
        current_search->clist : default_search_clist);

    if (clist != NULL) {
        gint i;
    
        for (i = 0; i < clist->columns; i ++)
            gtk_clist_set_column_visibility(clist, i, val[i]);
    }

    g_free(val);
    return FALSE;
}
