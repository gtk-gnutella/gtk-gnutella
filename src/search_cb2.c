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

#include "gui.h"
#include <gdk/gdkkeysyms.h>

#include "search_cb2.h"
#include "search_gui.h"
#include "statusbar_gui.h"

RCSID("$Id$");

/* Privat variables */

static gchar tmpstr[4096];

/***
 *** Private functions
 ***/

static void refresh_popup(void)
{
	gboolean sensitive;
	search_t *current_search;

    current_search = search_gui_get_current_search();

/*	sensitive = current_search && 
        (gboolean) GTK_CLIST(current_search->clist)->selection;
*/
	sensitive = current_search != NULL;

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_download"), sensitive);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_name"), sensitive);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_sha1"), sensitive);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_host"), sensitive);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_drop_name_global"), 
        sensitive);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_drop_sha1_global"), 
        sensitive);   
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_drop_host_global"), 
        sensitive);   
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_autodownload_name"), 
        sensitive);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_autodownload_sha1"), 
        sensitive);   
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_new_from_selected"), 
        sensitive);   

    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_restart"), 
        (gboolean) current_search);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_duplicate"), 
        (gboolean) current_search);

    if (current_search) {
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_stop"), 
                        !search_is_frozen(current_search->search_handle));
	gtk_widget_set_sensitive(
		lookup_widget(popup_search, "popup_search_resume"),
		search_is_frozen(current_search->search_handle));
	if (current_search->passive)
		gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_restart"), 
                FALSE);
    } else {
		gtk_widget_set_sensitive(
			lookup_widget(popup_search, "popup_search_stop"), FALSE);
		gtk_widget_set_sensitive(
			lookup_widget(popup_search, "popup_search_resume"), FALSE);
    }

}

/***
 *** Glade callbacks
 ***/
void on_combo_entry_searches_activate
    (GtkEditable *editable, gpointer user_data)
{
    // FIXME
}


void on_search_popdown_switch(GtkWidget *w, gpointer data)
{
	if (search_selected != NULL)
		search_gui_set_current_search(search_selected);
}

void on_search_notebook_switch(GtkNotebook * notebook,
							   GtkNotebookPage * page, gint page_num,
							   gpointer user_data)
{
	search_t *sch = (search_t *) gtk_object_get_user_data(
		GTK_OBJECT(gtk_notebook_get_nth_page(notebook, page_num)));

	g_return_if_fail(sch);

	search_gui_set_current_search(sch);
}

void on_search_notebook_focus_tab(GtkNotebook * notebook,
							   GtkNotebookTab arg1,
							   gpointer user_data)
{
	search_t *sch;
	GtkWidget *widget;
	gint page_num;

	page_num = gtk_notebook_get_current_page(notebook);
	widget = gtk_notebook_get_nth_page(notebook, page_num); 
	sch = (search_t *) gtk_object_get_user_data(GTK_OBJECT(widget));

	g_return_if_fail(sch);

	search_gui_set_current_search(sch);
}

void on_tree_view_search_select_row(GtkTreeView * treeview, gpointer user_data)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	search_t *sch;

	g_assert(treeview != NULL);
	selection = gtk_tree_view_get_selection(treeview);
	if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
		gtk_tree_model_get(model, &iter, c_sl_sch, &sch, -1);
		if (NULL != sch) {
			gtk_notebook_set_page(
				GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")),
				nb_main_page_search);
			search_gui_set_current_search(sch);
		}
	}
}

void on_search_selected(GtkItem * i, gpointer data)
{
        search_selected = (search_t *) data;
}

void on_button_search_clicked(GtkButton *button, gpointer user_data)
{
	gchar *e = gtk_editable_get_chars
        (GTK_EDITABLE(lookup_widget(main_window, "entry_search")), 0, -1);

        /*
         * Even though we might not be on_the_net() yet, record the search.
         * There is a callback mechanism when a new node is connected, which
         * will launch the search there if it has not been sent already.
         *              --patch from Mark Schreiber, 10/01/2002
         */

    g_strstrip(e);
    if (*e) {
        filter_t *default_filter;
        search_t *search;
        gboolean res;

		/*
		 * It's important gui_search_history_add is called before
		 * new_search, otherwise the search entry will not be
		 * cleared.
		 *      --BLUE, 04/05/2002
		 */
		gui_search_history_add(e);


		/*
		 * We have to capture the selection here already, because
		 * new_search will trigger a rebuild of the menu as a
		 * side effect.
		 */
		default_filter = (filter_t *)option_menu_get_selected_data
				(lookup_widget(main_window, "optionmenu_search_filter"));

		res = search_gui_new_search(e, 0, &search);

		/*
		 * If we should set a default filter, we do that.
		 */
		if (res && (default_filter != NULL)) {
				rule_t *rule = filter_new_jump_rule
						(default_filter, RULE_FLAG_ACTIVE);

				/*
				 * Since we don't want to distrub the shadows and
				 * do a "force commit" without the user having pressed
				 * the "ok" button in the dialog, we add the rule
				 * manually.
				 */
				search->filter->ruleset = 
						g_list_append(search->filter->ruleset, rule);
				rule->target->refcount ++;
		}
         
	if (!res)
		gdk_beep();
	}

	G_FREE_NULL(e);
}

void on_entry_search_activate(GtkEditable * editable, gpointer user_data)
{
    /*
     * Delegate to: on_button_search_clicked.
     *      --BLUE, 30/04/2002
     */

        on_button_search_clicked(NULL, user_data);
}

void on_entry_search_changed(GtkEditable * editable, gpointer user_data)
{
        gchar *e = gtk_editable_get_chars(editable, 0, -1);
        g_strstrip(e);
        gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search"), *e != 0);
        G_FREE_NULL(e);
}

void on_button_search_clear_clicked(GtkButton * button, gpointer user_data)
{
        gui_search_clear_results();

        gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_clear"), FALSE);
}

void on_button_search_close_clicked(GtkButton * button, gpointer user_data)
{
    search_t *current_search;

    current_search = search_gui_get_current_search();

    if (current_search != NULL)
        search_gui_close_search(current_search);
}

void on_button_search_download_clicked(GtkButton * button, gpointer user_data)
{
    search_gui_download_files();
}

gboolean on_tree_view_search_results_key_press_event
    (GtkWidget *widget, GdkEventKey * event, gpointer user_data)
{
    g_assert(event != NULL);

    switch(event->keyval) {
    case GDK_Return:
        search_gui_download_files();
        return TRUE;
    default:
        return FALSE;
    };
}

gboolean on_tree_view_search_results_button_press_event
    (GtkWidget *widget, GdkEventButton * event, gpointer user_data)
{
	static guint click_time = 0;
	search_t *current_search;

	current_search = search_gui_get_current_search();

	switch (event->button) {
	case 1:
        /* left click section */
		if (event->type == GDK_2BUTTON_PRESS) {
			gtk_signal_emit_stop_by_name(GTK_OBJECT(widget),
				"button_press_event");
			return FALSE;
		}
		if (event->type == GDK_BUTTON_PRESS) {
			if ((event->time - click_time) <= 250) {
				/*
				 * 2 clicks within 250 msec == doubleclick.
				 * Surpress further events
				 */
				gtk_signal_emit_stop_by_name(GTK_OBJECT(widget),
					"button_press_event");
				search_gui_download_files();

				return TRUE;
			} else {
				click_time = event->time;
				return FALSE;
			}
		}
		return FALSE;

        case 3:
        /* right click section (popup menu) */
        refresh_popup();


        {
            gboolean search_results_show_tabs;

            gui_prop_get_boolean(
                PROP_SEARCH_RESULTS_SHOW_TABS,
                &search_results_show_tabs, 0, 1);

            g_strlcpy(tmpstr,
				search_results_show_tabs ?  "Show search list" : "Show tabs",
				sizeof(tmpstr));
        }

        gtk_label_set(GTK_LABEL((GTK_MENU_ITEM
            (lookup_widget(popup_search, "popup_search_toggle_tabs"))
                ->item.bin.child)), tmpstr);
                gtk_menu_popup(GTK_MENU(popup_search), NULL, NULL, NULL, NULL,
                     event->button, event->time);
                return TRUE;

        default: ;
        }

	return FALSE;
}

void on_button_search_filter_clicked(
    GtkButton *button, gpointer user_data)
{
	filter_open_dialog();
}

void on_tree_view_search_results_click_column(
    GtkTreeViewColumn *tree_view_column, gpointer user_data)
{
	/* FIXME:
	 * 			+--> sort descending -> sort ascending -> unsorted -+
     *      	|                                                   |
     *      	+-----------------------<---------------------------+
     */
}

static guint32 autoselect_files_fuzzy_threshold;
static gboolean autoselect_files_lock;

static void autoselect_files_helper(
    GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data) 
{
	record_t *rc;
	gint x = 1;
	guint32 fuzzy_threshold = autoselect_files_fuzzy_threshold;
	GtkTreeIter	model_iter;
	GtkTreeIter	child;
	gboolean more_rows;
	GtkTreeSelection	*selection;

	if (autoselect_files_lock)
		return;
	autoselect_files_lock = TRUE;

	/* 
	 * Rows with NULL data can appear when inserting new rows
	 * because the selection is resynced and the row data can not
	 * be set until insertion (and therefore also selection syncing
	 * is done.
	 *      --BLUE, 20/06/2002
	 */

	selection = GTK_TREE_SELECTION(data);
	gtk_tree_model_get(model, iter, c_sr_record, &rc, -1);

	if (!gtk_tree_model_iter_parent(model, &model_iter, iter))
		model_iter = *iter;

	if (
		search_autoselect_ident &&
		gtk_tree_model_iter_children(model, &child, &model_iter)
	) {
		gtk_tree_selection_select_iter(selection, &model_iter);
		do {
			gtk_tree_selection_select_iter(selection, &child);
			x++;
		} while (gtk_tree_model_iter_next(model, &child));
	}
		
	else

	/*
	 * Note that rc != NULL is embedded in the "for condition".
	 */

		for (more_rows = gtk_tree_model_get_iter_first(model, &model_iter);
			rc != NULL && more_rows;
			more_rows = gtk_tree_model_iter_next(model, &model_iter)) 
		{
			gboolean sha1_ident;
			gboolean select_file;
			record_t *rc2;

			gtk_tree_model_get(model, &model_iter, c_sr_record, &rc2, -1);

			/*
		 	 * Skip the line we selected in the first place.
		 	 */
			if (rc == rc2)
				continue;

			if (rc2 == NULL) {
				g_warning(" on_tree_view_search_results_select_row: "
					"detected row with NULL data, skipping");
				continue;
			}

			sha1_ident = rc->sha1 != NULL && rc2->sha1 != NULL &&
				0 == memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE);

			/*
	 	 	* size check added to workaround buggy
	 	 	* servents. -vidar, 2002-08-08
	 	 	*/
			select_file = search_autoselect_ident
				? (
					sha1_ident && rc->size == rc2->size
				) ||
				(
					rc->sha1 == NULL && rc2->size == rc->size &&
					(
						(
							!search_autoselect_fuzzy &&
							0 == strcmp(rc2->name, rc->name)
						)
					|| (
						search_autoselect_fuzzy &&
						fuzzy_compare(rc2->name, rc->name) * 100
				 			>= (fuzzy_threshold << FUZZY_SHIFT)
						)
					)
				)

				: sha1_ident ||
					(
						rc2 && rc2->size >= rc->size &&
						0 == strcmp(rc2->name, rc->name)
					);

				if (select_file) {
					gtk_tree_selection_select_iter(selection, &model_iter);
					x++;
				}	
		}

    if (x > 1) {
		statusbar_gui_message(15, "%d auto selected by filename%s", x, 
			NULL != rc->sha1 ? " and urn:sha1" : "");
	} else if (x == 1)
		statusbar_gui_message(15, "none auto selected");
}

static void autoselect_files(GtkTreeView *tree_view)
{
    gboolean search_autoselect;
    gboolean search_autoselect_ident;
    gboolean search_autoselect_fuzzy;
	GtkTreeSelection *selection;

    gui_prop_get_boolean(
        PROP_SEARCH_AUTOSELECT,
        &search_autoselect, 0, 1);

    gui_prop_get_boolean(
        PROP_SEARCH_AUTOSELECT_IDENT,
        &search_autoselect_ident, 0, 1);

    gui_prop_get_boolean(
        PROP_SEARCH_AUTOSELECT_FUZZY,
        &search_autoselect_fuzzy, 0, 1);

    /*
     * Block this signal so we don't emit it for every autoselected item.
     */
    g_signal_handlers_block_by_func(
        G_OBJECT(tree_view),
        G_CALLBACK(on_tree_view_search_results_select_row),
        NULL);

    refresh_popup();

	gnet_prop_get_guint32(PROP_FUZZY_THRESHOLD, 
		&autoselect_files_fuzzy_threshold, 0, 1);

    /* 
     * check if config setting select all is on and only autoselect if
     * only one item is selected (no way to merge two autoselections)
     */

	selection = gtk_tree_view_get_selection(tree_view);
	autoselect_files_lock = FALSE;
	if (search_autoselect)
		gtk_tree_selection_selected_foreach(selection, autoselect_files_helper,
			selection);

    g_signal_handlers_unblock_by_func(
        G_OBJECT(tree_view),
        G_CALLBACK(on_tree_view_search_results_select_row),
        NULL);
}

/**
 * on_tree_view_search_results_select_row:
 *
 * This function is called when the user selectes a row in the
 * search results pane. Autoselection takes place here.
 */
void on_tree_view_search_results_select_row(
    GtkTreeView *tree_view, gpointer user_data)
{
	static gboolean autoselection_running = FALSE;
	GtkTreePath *path;

	gtk_tree_view_get_cursor(tree_view, &path, NULL);
	if (NULL != path) {
		GtkTreeModel *model;
		record_t *rc;
		gchar *filename;
		GtkTreeIter iter;

		model = gtk_tree_view_get_model(tree_view);
		gtk_tree_model_get_iter(model, &iter, path);
		gtk_tree_model_get(model, &iter,
			c_sr_filename, &filename,
			c_sr_record, &rc,
			-1);
		gtk_label_set_text(
			GTK_LABEL(lookup_widget(main_window, "label_result_info_filename")),
			filename);
		gtk_label_set_text(
			GTK_LABEL(lookup_widget(main_window, "label_result_info_sha1")),
			rc->sha1 != NULL ? sha1_base32(rc->sha1) : "<none>");
		gtk_label_set_text(
			GTK_LABEL(lookup_widget(main_window, "label_result_info_source")),
			ip_port_to_gchar(rc->results_set->ip, rc->results_set->port));
		gm_snprintf(tmpstr, sizeof(tmpstr), "%u",
			(guint) rc->results_set->speed);
		gtk_label_set_text(
			GTK_LABEL(lookup_widget(main_window, "label_result_info_speed")),
			tmpstr);
		gm_snprintf(tmpstr, sizeof(tmpstr), "%s (%lu byte)",
			short_size(rc->size), (gulong) rc->size);
		gtk_label_set_text(
			GTK_LABEL(lookup_widget(main_window, "label_result_info_size")),
			tmpstr);
	}

	if (!autoselection_running) {
		autoselection_running = TRUE;
		autoselect_files(tree_view);
		autoselection_running = FALSE;
	}
}

void on_tree_view_search_results_resize_column(
    GtkTreeView * tree_view, gint column, gint width, gpointer user_data)
{
//    guint32 buf = width;

    /* remember the width for storing it to the config file later */
//    gui_prop_set_guint32(PROP_SEARCH_RESULTS_COL_WIDTHS, &buf, column, 1);
}

void on_button_search_passive_clicked(
    GtkButton *button, gpointer user_data)
{
    filter_t *default_filter;
        search_t *search;

    /*
     * We have to capture the selection here already, because
     * new_search will trigger a rebuild of the menu as a
     * side effect.
     */
    default_filter = (filter_t *)
        option_menu_get_selected_data
            (lookup_widget(main_window, "optionmenu_search_filter"));

	search_gui_new_search("Passive", SEARCH_PASSIVE, &search);

    /*
     * If we should set a default filter, we do that.
     */
    if (default_filter != NULL) {
        rule_t *rule = filter_new_jump_rule
            (default_filter, RULE_FLAG_ACTIVE);

        /*
         * Since we don't want to distrub the shadows and
         * do a "force commit" without the user having pressed
         * the "ok" button in the dialog, we add the rule
         * manually.
         */
        search->filter->ruleset =
            g_list_append(search->filter->ruleset, rule);
        rule->target->refcount ++;
    }

}



/***
 *** Search results popup
 ***/

void on_popup_search_drop_name_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;
	GtkTreeSelection *selection;
    GSList *sl;

    current_search = search_gui_get_current_search();
    g_assert(current_search != NULL);
	selection = gtk_tree_view_get_selection(
					GTK_TREE_VIEW(current_search->tree_view));

    sl = tree_selection_collect_data(selection, FALSE, gui_record_name_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_name_rule,
        current_search->filter);
    g_slist_free(sl);
}

void on_popup_search_drop_sha1_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;
	GtkTreeSelection *selection;
    GSList *sl;

    current_search = search_gui_get_current_search();
    g_assert(current_search != NULL);
	selection = gtk_tree_view_get_selection(
					GTK_TREE_VIEW(current_search->tree_view));

    sl = tree_selection_collect_data(selection, FALSE,gui_record_sha1_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_sha1_rule,
        current_search->filter);
    g_slist_free(sl);
}

void on_popup_search_drop_host_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;
	GtkTreeSelection *selection;
    GSList *sl;

    current_search = search_gui_get_current_search();
    g_assert(current_search != NULL);
	selection = gtk_tree_view_get_selection(
					GTK_TREE_VIEW(current_search->tree_view));

    sl = tree_selection_collect_data(selection, FALSE, gui_record_host_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_host_rule,
        current_search->filter);
    g_slist_free(sl);
}

void on_popup_search_drop_name_global_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;
	GtkTreeSelection *selection;
    GSList *sl;

    current_search = search_gui_get_current_search();
    g_assert(current_search != NULL);
	selection = gtk_tree_view_get_selection(
					GTK_TREE_VIEW(current_search->tree_view));

    sl = tree_selection_collect_data(selection, FALSE, gui_record_name_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_name_rule,
        filter_get_global_pre());
    g_slist_free(sl);
}

void on_popup_search_drop_sha1_global_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;
	GtkTreeSelection *selection;
    GSList *sl;

    current_search = search_gui_get_current_search();
    g_assert(current_search != NULL);
	selection = gtk_tree_view_get_selection(
					GTK_TREE_VIEW(current_search->tree_view));


    sl = tree_selection_collect_data(selection, FALSE, gui_record_sha1_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_sha1_rule,
        filter_get_global_pre());
    g_slist_free(sl);
}

void on_popup_search_drop_host_global_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;
	GtkTreeSelection *selection;
    GSList *sl;

    current_search = search_gui_get_current_search();
    g_assert(current_search != NULL);
	selection = gtk_tree_view_get_selection(
				GTK_TREE_VIEW(current_search->tree_view));

    sl = tree_selection_collect_data(selection, FALSE, gui_record_host_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_host_rule,
        filter_get_global_pre());
    g_slist_free(sl);
}

void on_popup_search_autodownload_name_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;
	GtkTreeSelection *selection;
    GSList *sl;

    current_search = search_gui_get_current_search();
    g_assert(current_search != NULL);
	selection = gtk_tree_view_get_selection(
        GTK_TREE_VIEW(current_search->tree_view));

    sl = tree_selection_collect_data(selection, FALSE, gui_record_name_eq);
    g_slist_foreach(sl, (GFunc) filter_add_download_name_rule,
        current_search->filter);
    g_slist_free(sl);
}

void on_popup_search_autodownload_sha1_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;
	GtkTreeSelection *selection;
    GSList *sl;

    current_search = search_gui_get_current_search();
    g_assert(current_search != NULL);
	selection = gtk_tree_view_get_selection(
        GTK_TREE_VIEW(current_search->tree_view));

    sl = tree_selection_collect_data(selection, FALSE, gui_record_sha1_eq);
    g_slist_foreach(sl, (GFunc) filter_add_download_sha1_rule,
        current_search->filter);
    g_slist_free(sl);
}

void on_popup_search_new_from_selected_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;
	GtkTreeSelection *selection;
    GSList *sl;

    current_search = search_gui_get_current_search();
    g_assert(current_search != NULL);
	selection = gtk_tree_view_get_selection(
        GTK_TREE_VIEW(current_search->tree_view));

    sl = tree_selection_collect_data(selection, FALSE,
        gui_record_sha1_or_name_eq);
    g_slist_foreach(sl, (GFunc) gui_add_targetted_search,
        current_search->filter);
    g_slist_free(sl);
}

void on_popup_search_edit_filter_activate(
    GtkMenuItem * menuitem,	gpointer user_data)
{
    filter_open_dialog();
}

void on_popup_search_duplicate_activate(
    GtkMenuItem * menuitem,	gpointer user_data)
{
    search_t *current_search;
    guint32 search_reissue_timeout;

    gnet_prop_get_guint32(
        PROP_SEARCH_REISSUE_TIMEOUT,
        &search_reissue_timeout, 0, 1);

    current_search = search_gui_get_current_search();
    // FIXME: should also duplicate filters!
    // FIXME: should call search_duplicate which has to be written.
    // FIXME: should properly duplicate passive searches.
    if (current_search)
        search_gui_new_search_full(current_search->query,
            search_get_minimum_speed(current_search->search_handle), 
            search_reissue_timeout,
            0, NULL);

}

void on_popup_search_restart_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;

    current_search = search_gui_get_current_search();
        if (current_search)
                search_gui_restart_search(current_search);
}

void on_popup_search_resume_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
    search_t *current_search;

    current_search = search_gui_get_current_search();
	if (current_search) {
		search_start(current_search->search_handle);
/*        gtk_clist_set_foreground(
            GTK_CLIST(lookup_widget(main_window, "clist_search")),
            gtk_notebook_get_current_page
                GTK_NOTEBOOK
                    (lookup_widget(main_window, "notebook_search_results")),
					NULL);*/
	}

}

void on_popup_search_stop_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *current_search;

    current_search = search_gui_get_current_search();
	if (current_search) {
/*		GtkTreeView *tree_view_search = GTK_TREE_VIEW
			(lookup_widget(main_window, "tree_view_search"));*/

		search_stop(current_search->search_handle);
/*        gtk_clist_set_foreground(
            tree_view_search,
            gtk_notebook_get_current_page
                GTK_NOTEBOOK
                    (lookup_widget(main_window, "notebook_search_results")),
            &gtk_widget_get_style(GTK_WIDGET(clist_search))
                ->fg[GTK_STATE_INSENSITIVE]);*/
        }

}

void on_popup_search_config_cols_activate(GtkMenuItem * menuitem,
										  gpointer user_data)
{
    search_t *current_search;

    current_search = search_gui_get_current_search();
    g_return_if_fail(current_search != NULL);
    g_assert(current_search->tree_view != NULL);

/*    {
        GtkWidget * cc;
*/
        // FIXME: needs to work also in Gtk2 or be replaced.
/*        cc = gtk_column_chooser_new(GTK_TREE_VIEW(current_search->tree_view));
        gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);

        GtkColumnChooser takes care of cleaing up itself 
    }
*/
}

void search_callbacks_shutdown(void)
{
	/*
 	 *	Remove delayed callbacks
 	 */
}

