/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#include "gtkcolumnchooser.h"
#include "search_cb2.h"
#include "search_gui.h"
#include "statusbar_gui.h"

RCSID("$Id$");

/* Privat variables */

/***
 *** Private functions
 ***/

static void refresh_popup(void)
{
	static const char *popup_names[] = {
		"popup_search_download",
		"popup_search_drop_name",
		"popup_search_drop_sha1",
		"popup_search_drop_host",
		"popup_search_drop_name_global",
		"popup_search_drop_host_global",
		"popup_search_autodownload_name",
		"popup_search_autodownload_sha1",
		"popup_search_new_from_selected",
		"popup_search_restart",
		"popup_search_duplicate",
		NULL
	};
	search_t *search = search_gui_get_current_search();
	gboolean sensitive = NULL != search;
	guint i;

	for (i = 0; NULL != popup_names[i]; i++)
		gtk_widget_set_sensitive(lookup_widget(popup_search, popup_names[i]),
			sensitive);

    if (search) {
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_stop"), 
			!search_is_frozen(search->search_handle));
		gtk_widget_set_sensitive(
			lookup_widget(popup_search, "popup_search_resume"),
			search_is_frozen(search->search_handle));
		if (search->passive)
			gtk_widget_set_sensitive(
				lookup_widget(popup_search, "popup_search_restart"), FALSE);
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
    /* FIXME */
}


void on_search_popdown_switch(GtkWidget *w, gpointer data)
{
	g_return_if_fail(NULL != search_selected);
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

		g_return_if_fail(NULL != sch);

		gtk_notebook_set_page(
		GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")),
		nb_main_page_search);
		search_gui_set_current_search(sch);
	}
}

void on_search_selected(GtkItem * i, gpointer data)
{
	search_selected = (search_t *) data;
}

void on_button_search_clicked(GtkButton *button, gpointer user_data)
{
	gchar *e = gtk_editable_get_chars(
		GTK_EDITABLE(lookup_widget(main_window, "entry_search")), 0, -1);

        /*
         * Even though we might not be on_the_net() yet, record the search.
         * There is a callback mechanism when a new node is connected, which
         * will launch the search there if it has not been sent already.
         *              --patch from Mark Schreiber, 10/01/2002
         */

    g_strstrip(e);
    if ('\0' != *e) {
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
			rule_t *rule = filter_new_jump_rule(
								default_filter, RULE_FLAG_ACTIVE);

				/*
				 * Since we don't want to distrub the shadows and
				 * do a "force commit" without the user having pressed
				 * the "ok" button in the dialog, we add the rule
				 * manually.
				 */
			search->filter->ruleset = g_list_append(
											search->filter->ruleset, rule);
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
	gtk_widget_set_sensitive(
		lookup_widget(main_window, "button_search"), '\0' != *e);
	G_FREE_NULL(e);
}

void on_button_search_clear_clicked(GtkButton * button, gpointer user_data)
{
	gui_search_clear_results();
	gtk_widget_set_sensitive(
		lookup_widget(main_window, "button_search_clear"), FALSE);
}

void on_button_search_close_clicked(GtkButton * button, gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
	g_return_if_fail(NULL != search);
	search_gui_close_search(search);
}

gboolean on_tree_view_search_results_key_press_event
    (GtkWidget *widget, GdkEventKey * event, gpointer user_data)
{
    g_assert(event != NULL);

    switch (event->keyval) {
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
	gboolean search_results_show_tabs;

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
		gui_prop_get_boolean_val(PROP_SEARCH_RESULTS_SHOW_TABS,
                &search_results_show_tabs);
        gtk_label_set(GTK_LABEL((GTK_MENU_ITEM(
			lookup_widget(popup_search, "popup_search_toggle_tabs"))
                ->item.bin.child)),
			search_results_show_tabs ? "Show search list" : "Show tabs");
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

void on_button_search_download_selected_clicked(
	GtkButton *button, gpointer user_data)
{
    search_gui_download_files();
}

gboolean on_tree_view_search_results_click_column(
    GtkTreeViewColumn *column, gpointer user_data)
{
	/* FIXME:
	 * 			+--> sort descending -> sort ascending -> unsorted -+
     *      	|                                                   |
     *      	+-----------------------<---------------------------+
     */
	return FALSE;
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
	GtkTreeSelection *selection;
    GtkTreeView *treeview = GTK_TREE_VIEW(data);

	if (autoselect_files_lock)
		return;
	autoselect_files_lock = TRUE;

	selection = gtk_tree_view_get_selection(treeview);
	gtk_tree_model_get(model, iter, c_sr_record, &rc, (-1));

    /* If only identical files should be auto-selected, exploit the
     * fact that the results are grouped by SHA1 and simply select all
     * children of the parent. */
	if (search_autoselect_ident) {

        /* If the selected iter is a children, move to the parent. */
        if (!gtk_tree_model_iter_parent(model, &model_iter, iter))
	        model_iter = *iter;

        /* If the iter has no children, we're already done. */
	    if (gtk_tree_model_iter_children(model, &child, &model_iter)) {

            /* Expand to the current path, otherwise any changes to
             * the selection would be discarded. */
            gtk_tree_view_expand_row(treeview, path, FALSE);

            /* Now select all children. */
		    gtk_tree_selection_select_iter(selection, &model_iter);
		    do {
			    gtk_tree_selection_select_iter(selection, &child);
			    x++;
		    } while (gtk_tree_model_iter_next(model, &child));
	    }
		
	} else

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

			gtk_tree_model_get(model, &model_iter, c_sr_record, &rc2, (-1));

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

			sha1_ident = rc->sha1 != NULL
                && rc2->sha1 != NULL
                && (rc->sha1 == rc2->sha1 ||
                    0 == memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE));

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
                    GtkTreePath* p;

                    /* Expand to the current path, otherwise any changes to
                     * the selection would be discarded. */
            
                    p = gtk_tree_model_get_path(model, &model_iter);
                    gtk_tree_view_expand_row(treeview, p, FALSE);
                    gtk_tree_path_free(p);

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

static void autoselect_files(GtkTreeView *treeview)
{
    gboolean autoselect;

    gui_prop_get_boolean_val(PROP_SEARCH_AUTOSELECT, &autoselect);

    /*
     * Block this signal so we don't emit it for every autoselected item.
     */
    g_signal_handlers_block_by_func(
        G_OBJECT(treeview),
        G_CALLBACK(on_tree_view_search_results_select_row),
        NULL);

    refresh_popup();

	gnet_prop_get_guint32_val(PROP_FUZZY_THRESHOLD, 
		&autoselect_files_fuzzy_threshold);

    /* 
     * check if config setting select all is on and only autoselect if
     * only one item is selected (no way to merge two autoselections)
     */

	autoselect_files_lock = FALSE;
	if (autoselect)
		gtk_tree_selection_selected_foreach(
            gtk_tree_view_get_selection(treeview),
            autoselect_files_helper,
			treeview);

    g_signal_handlers_unblock_by_func(
        G_OBJECT(treeview),
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
	static gchar tmpstr[4096];
	GtkTreePath *path;

	gtk_tree_view_get_cursor(tree_view, &path, NULL);
	if (NULL != path) {
		GtkTreeModel *model;
		record_t *rc;
		gchar *filename;
		const gchar *vendor;
		GtkTreeIter iter;

		model = gtk_tree_view_get_model(tree_view);
		gtk_tree_model_get_iter(model, &iter, path);
		gtk_tree_model_get(model, &iter, c_sr_filename, &filename,
			c_sr_record, &rc, (-1));
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_filename")),
			filename);
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_sha1")),
			rc->sha1 != NULL ? sha1_base32(rc->sha1) : "<none>");
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_source")),
			ip_port_to_gchar(rc->results_set->ip, rc->results_set->port));
		gm_snprintf(tmpstr, sizeof(tmpstr), "%u",
			(guint) rc->results_set->speed);
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_speed")),
			tmpstr);
		gm_snprintf(tmpstr, sizeof(tmpstr), "%s (%lu byte)",
			short_size(rc->size), (gulong) rc->size);
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_size")),
			tmpstr);
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_guid")),
			guid_hex_str(rc->results_set->guid));
		g_strlcpy(tmpstr, ctime(&rc->results_set->stamp), 25); /* discard \n */
		gtk_entry_set_text(GTK_ENTRY(
			lookup_widget(main_window, "entry_result_info_timestamp")),
			tmpstr);
		vendor = lookup_vendor_name(rc->results_set->vendor);
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_vendor")),
			vendor != NULL ? vendor : "");
		gm_snprintf(tmpstr, sizeof(tmpstr), "%lu", (gulong) rc->index);
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_index")),
			tmpstr);
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_tag")),
			rc->tag ? locale_to_utf8(rc->tag, 0) : "");
	}

	g_return_if_fail(!autoselection_running);

	autoselection_running = TRUE;
	autoselect_files(tree_view);
	autoselection_running = FALSE;
}

void on_tree_view_search_results_resize_column(
    GtkTreeView * tree_view, gint column, gint width, gpointer user_data)
{
/* FIXME */
#if 0
    guint32 buf = width; 

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_SEARCH_RESULTS_COL_WIDTHS, &buf, column, 1);
#endif
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
    default_filter = (filter_t *) option_menu_get_selected_data(
		lookup_widget(main_window, "optionmenu_search_filter"));

	search_gui_new_search("Passive", SEARCH_PASSIVE, &search);

    /*
     * If we should set a default filter, we do that.
     */
    if (default_filter != NULL) {
        rule_t *rule = filter_new_jump_rule(default_filter, RULE_FLAG_ACTIVE);

        /*
         * Since we don't want to distrub the shadows and
         * do a "force commit" without the user having pressed
         * the "ok" button in the dialog, we add the rule
         * manually.
         */
        search->filter->ruleset = g_list_append(search->filter->ruleset, rule);
        rule->target->refcount ++;
    }
}



/***
 *** Search results popup
 ***/

void on_popup_search_download_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_gui_download_files();
}

void on_popup_search_drop_name_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_name_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_name_rule, search->filter);
    g_slist_free(sl);
}

void on_popup_search_drop_sha1_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_sha1_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_sha1_rule, search->filter);
    g_slist_free(sl);
}

void on_popup_search_drop_host_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_host_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_host_rule, search->filter);
    g_slist_free(sl);
}

void on_popup_search_drop_name_global_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_name_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_name_rule,
        filter_get_global_pre());
    g_slist_free(sl);
}

void on_popup_search_drop_sha1_global_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_sha1_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_sha1_rule,
        filter_get_global_pre());
    g_slist_free(sl);
}

void on_popup_search_drop_host_global_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_host_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_host_rule,
        filter_get_global_pre());
    g_slist_free(sl);
}

void on_popup_search_autodownload_name_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_name_eq);
    g_slist_foreach(sl, (GFunc) filter_add_download_name_rule, search->filter);
    g_slist_free(sl);
}

void on_popup_search_autodownload_sha1_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

	search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_sha1_eq);
    g_slist_foreach(sl, (GFunc) filter_add_download_sha1_rule, search->filter);
    g_slist_free(sl);
}

void on_popup_search_new_from_selected_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_sha1_or_name_eq);
    g_slist_foreach(sl, (GFunc) gui_add_targetted_search, search->filter);
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
    search_t *search;
    guint32 timeout;

    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &timeout);

    search = search_gui_get_current_search();
    g_return_if_fail(NULL != search);

    /* FIXME: should also duplicate filters! */
    /* FIXME: should call search_duplicate which has to be written. */
    /* FIXME: should properly duplicate passive searches. */

	search_gui_new_search_full(search->query,
		search_get_minimum_speed(search->search_handle), 
		timeout, search->sort_col, search->sort_order,
		search->enabled ? SEARCH_ENABLED : 0, NULL);
}

void on_popup_search_restart_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
	g_return_if_fail(NULL != search);
	search_gui_restart_search(search);
}

void on_popup_search_resume_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
    g_return_if_fail(NULL != search);
    search_start(search->search_handle);
   /* FIXME: Mark graphicaly this entry as active again in the searches list. */
	search->enabled = TRUE;
}

void on_popup_search_stop_activate(
	GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
    g_return_if_fail(NULL != search);

    search_stop(search->search_handle);
    /* FIXME: Mark graphicaly this entry as inactive in the searches list. */
    search->enabled = FALSE;
}

void on_popup_search_config_cols_activate(GtkMenuItem * menuitem,
										  gpointer user_data)
{
	GtkWidget * cc;
    search_t *search;

    search = search_gui_get_current_search();
	g_return_if_fail(NULL != search);

	cc = gtk_column_chooser_new(GTK_WIDGET(search->tree_view));
   	gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);

	/* GtkColumnChooser takes care of cleaning up itself */
}

void search_callbacks_shutdown(void)
{
	/*
 	 *	Remove delayed callbacks
 	 */
}

