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

#include "gtkcolumnchooser.h"
#include "search_cb.h"
#include "search_gui.h"
#include "statusbar_gui.h"

RCSID("$Id$");

static gchar tmpstr[4096];

/***
 *** Private functions
 ***/


static void refresh_popup(void)
{
	gboolean sensitive;
    search_t *search;

    search = search_gui_get_current_search();

	sensitive = search && 
        (gboolean) GPOINTER_TO_INT(GTK_CLIST(search->clist)->selection);
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
        lookup_widget(popup_search, "popup_search_restart"), NULL != search);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_duplicate"), NULL != search);

    if (search) {
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_stop"), 
			!search_is_frozen(search->search_handle));
		gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_resume"),
			search_is_frozen(search->search_handle));
		if (search->passive)
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
    /* FIXME */
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
	search_t *sch;

	sch = (search_t *) gtk_object_get_user_data(
		GTK_OBJECT(gtk_notebook_get_nth_page(notebook, page_num)));

	g_return_if_fail(sch);

    search_gui_set_current_search(sch);
}

void on_clist_search_select_row(GtkCList * clist, gint row,
								 gint column, GdkEvent * event,
								 gpointer user_data)
{
    gpointer sch;

    g_assert(clist != NULL);

    sch = gtk_clist_get_row_data(clist, row);

    if (sch == NULL)
        return;

    search_gui_set_current_search((search_t *)sch);
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
	 *		--patch from Mark Schreiber, 10/01/2002
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

	g_free(e);
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
	g_free(e);
}

void on_button_search_clear_clicked(GtkButton * button, gpointer user_data)
{
	gui_search_clear_results();

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_clear"), FALSE);
}

void on_button_search_close_clicked(GtkButton * button, gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();

    if (search != NULL)
        search_gui_close_search(search);
}

void on_button_search_download_clicked(GtkButton * button, gpointer user_data)
{
    search_gui_download_files();
}

gboolean on_clist_search_results_key_press_event
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

gboolean on_clist_search_results_button_press_event
    (GtkWidget *widget, GdkEventButton * event, gpointer user_data)
{
	gint row = 0;
	gint column = 0;
	static guint click_time = 0;
    search_t *search;

    search = search_gui_get_current_search();

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
				if (
					gtk_clist_get_selection_info(GTK_CLIST(widget), event->x,
						event->y, &row, &column)
				) {
					/*
					 * Manually reselect to force the autoselection to behave
					 * correctly.
					 */
					gtk_clist_select_row(GTK_CLIST(widget), row, column);
					search_gui_download_files();

                    return TRUE;
				}
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

            gm_snprintf(tmpstr, sizeof(tmpstr), (search_results_show_tabs) ? 
                "Show search list" : "Show tabs");
        }

        gtk_label_set(GTK_LABEL((GTK_MENU_ITEM
            (lookup_widget(popup_search, "popup_search_toggle_tabs"))
                ->item.bin.child)), tmpstr);
		gtk_menu_popup(GTK_MENU(popup_search), NULL, NULL, NULL, NULL, 
                     event->button, event->time);
		return TRUE;

	default:
		break;
	}

	return FALSE;
}

void on_button_search_filter_clicked(
    GtkButton *button, gpointer user_data)
{
	filter_open_dialog();
}

void on_clist_search_results_click_column(
    GtkCList *clist, gint column, gpointer user_data)
{
    search_t *search;

    g_assert(clist != NULL);

    search = search_gui_get_current_search();

	if (search == NULL)
		return;

    /* rotate or initialize search order */
	if (column == search->sort_col) {
        switch (search->sort_order) {
        case SORT_ASC:
            search->sort_order = SORT_DESC;
           	break;
        case SORT_DESC:
            search->sort_order = SORT_NONE;
            break;
        case SORT_NONE:
            search->sort_order = SORT_ASC;
        }
	} else {
		search->sort_col = column;
		search->sort_order = SORT_ASC;
	}
	
	search_gui_sort_column(search, column); /* Sort column, draw arrow */
 

}

/**
 * on_clist_search_results_select_row:
 *
 * This function is called when the user selectes a row in the
 * search results pane. Autoselection takes place here.
 */
void on_clist_search_results_select_row(
    GtkCList * clist, gint row, gint col, GdkEvent * event, gpointer data)
{
    gboolean search_autoselect;
    gboolean search_autoselect_ident;
    gboolean search_autoselect_fuzzy;

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
    gtk_signal_handler_block_by_func(
        GTK_OBJECT(clist),
        GTK_SIGNAL_FUNC(on_clist_search_results_select_row),
        NULL);

    refresh_popup();

    gtk_clist_freeze(clist);

    /* 
     * check if config setting select all is on and only autoselect if
     * only one item is selected (no way to merge two autoselections)
     */
	if (search_autoselect && 
       (clist->selection->next == NULL)) {
		record_t *rc;
		gint x, i;
        GList *l;
        guint32 fuzzy_threshold;

        gnet_prop_get_guint32(PROP_FUZZY_THRESHOLD, &fuzzy_threshold, 0, 1);

        /* 
         * Rows with NULL data can appear when inserting new rows
         * because the selection is resynced and the row data can not
         * be set until insertion (and therefore also selection syncing
         * is done.
         *      --BLUE, 20/06/2002
         */
		rc = (record_t *) gtk_clist_get_row_data(clist, row);

        /*
         * Note that rc != NULL is embedded in the "for condition".
         * No need to copy row_list since we do not modify it.
         */
        x = 1;
        for (
            l = clist->row_list, i = 0; 
            (rc != NULL) && (l != NULL); 
            l = l->next, ++ i
        ) {
            record_t *rc2 = (record_t *)((GtkCListRow *) l->data)->data;

            /*
             * Skip the line we selected in the first place.
             */
            if (rc == rc2)
                continue;

            if (rc2 == NULL) {
                g_warning(" on_clist_search_results_select_row: "
                          "detected row with NULL data, skipping: %d", i);
                continue;
            }
    
            if (search_autoselect_ident) {
                if ((
                        /*
						 * size check added to workaround buggy
                         * servents. -vidar, 2002-08-08
						 */
                        rc->size == rc2->size && 
                        rc->sha1 != NULL && rc2->sha1 != NULL &&
                        memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE) == 0
                    ) || (
                        (rc->sha1 == NULL) && 
                        (rc2->size == rc->size) && (
                            (!search_autoselect_fuzzy &&
								!strcmp(rc2->name, rc->name)) ||
                            (search_autoselect_fuzzy &&
(fuzzy_compare(rc2->name, rc->name) * 100 >= (fuzzy_threshold << FUZZY_SHIFT)))
                        )
                    )) {
                        gtk_clist_select_row(clist, i, 0);
                        x++;
                    }
                } else {
                    if (
                        ((rc->sha1 != NULL && rc2->sha1 != NULL &&
                        memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE) == 0) || 
                        (rc2 && !strcmp(rc2->name, rc->name))) &&
                        (rc2->size >= rc->size)
                    ) {
                        gtk_clist_select_row(clist, i, 0);
                        x++;
                    }
                }
        }
    
        if (x > 1) {
            statusbar_gui_message(15, 
                "%d auto selected %s",
                x, (rc->sha1 != NULL) ? 
                    "by urn:sha1 and filename" : "by filename");
        } else if (x == 1) {
            statusbar_gui_message(15, "none auto selected");
        }
	}

    gtk_clist_thaw(clist);

    gtk_signal_handler_unblock_by_func(
        GTK_OBJECT(clist),
        GTK_SIGNAL_FUNC(on_clist_search_results_select_row),
        NULL);
}

void on_clist_search_results_unselect_row(
    GtkCList * clist, gint row, gint col, GdkEvent * event, gpointer data)
{
    refresh_popup();
}

void on_clist_search_results_resize_column(
    GtkCList * clist, gint column, gint width, gpointer user_data)
{
    guint32 buf = width;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_SEARCH_RESULTS_COL_WIDTHS, &buf, column, 1);
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
    GSList *sl = NULL;
    search_t *search;

    search = search_gui_get_current_search();

    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->clist));

    sl = clist_collect_data(GTK_CLIST(search->clist), 
        FALSE, gui_record_name_eq);

    g_slist_foreach(sl, 
        (GFunc) filter_add_drop_name_rule, search->filter);

    g_slist_free(sl);

    gtk_clist_thaw(GTK_CLIST(search->clist));
}

void on_popup_search_drop_sha1_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    GSList *sl = NULL;
    search_t *search;

    search = search_gui_get_current_search();

    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->clist));

    sl = clist_collect_data(GTK_CLIST(search->clist), 
        FALSE, gui_record_sha1_eq);

    g_slist_foreach(sl, 
        (GFunc) filter_add_drop_sha1_rule, search->filter);

    g_slist_free(sl);

    gtk_clist_thaw(GTK_CLIST(search->clist));
}

void on_popup_search_drop_host_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    GSList *sl = NULL;
    search_t *search;

    search = search_gui_get_current_search();

    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->clist));

    sl = clist_collect_data(GTK_CLIST(search->clist), 
        FALSE, gui_record_sha1_eq);

    g_slist_foreach(sl, (GFunc) filter_add_drop_host_rule, search->filter);

    g_slist_free(sl);

    gtk_clist_thaw(GTK_CLIST(search->clist));
}

void on_popup_search_drop_name_global_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    GSList *sl = NULL;
    search_t *search;

    search = search_gui_get_current_search();

    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->clist));

    sl = clist_collect_data(GTK_CLIST(search->clist), 
        FALSE, gui_record_name_eq);

    g_slist_foreach(sl, (GFunc) filter_add_drop_name_rule, 
        filter_get_global_pre());

    g_slist_free(sl);

    gtk_clist_thaw(GTK_CLIST(search->clist));
}

void on_popup_search_drop_sha1_global_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    GSList *sl = NULL;
    search_t *search;

    search = search_gui_get_current_search();

    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->clist));

    sl = clist_collect_data(GTK_CLIST(search->clist), 
        FALSE, gui_record_sha1_eq);

    g_slist_foreach(sl, (GFunc) filter_add_drop_sha1_rule, 
        filter_get_global_pre());

    g_slist_free(sl);

    gtk_clist_thaw(GTK_CLIST(search->clist));
}

void on_popup_search_drop_host_global_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    GSList *sl = NULL;
    search_t *search;

    search = search_gui_get_current_search();

    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->clist));

    sl = clist_collect_data(GTK_CLIST(search->clist), 
        FALSE, gui_record_sha1_eq);

    g_slist_foreach(sl,(GFunc) filter_add_drop_host_rule, 
        filter_get_global_pre());

    g_slist_free(sl);

    gtk_clist_thaw(GTK_CLIST(search->clist));
}

void on_popup_search_autodownload_name_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    GSList *sl = NULL;
    search_t *search;

    search = search_gui_get_current_search();

    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->clist));

    sl = clist_collect_data(GTK_CLIST(search->clist), 
        FALSE, gui_record_name_eq);

    g_slist_foreach(sl, (GFunc) filter_add_download_name_rule, search->filter);

    g_slist_free(sl);

    gtk_clist_thaw(GTK_CLIST(search->clist));
}

void on_popup_search_autodownload_sha1_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    GSList *sl = NULL;
    search_t *search;

    search = search_gui_get_current_search();

    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->clist));

    sl = clist_collect_data(GTK_CLIST(search->clist), 
        FALSE, gui_record_sha1_eq);

    g_slist_foreach(sl, (GFunc) filter_add_download_sha1_rule, search->filter);

    g_slist_free(sl);

    gtk_clist_thaw(GTK_CLIST(search->clist));
}

void on_popup_search_new_from_selected_activate(
    GtkMenuItem *menuitem, gpointer user_data)
{
    GSList *sl = NULL;
    search_t *search;

    /* grab current search pointer to extract selected items */
    search = search_gui_get_current_search();

    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->clist));

    sl = clist_collect_data(GTK_CLIST(search->clist), 
        FALSE, gui_record_sha1_eq);

    g_slist_foreach(sl, (GFunc) gui_add_targetted_search, search->filter);

    g_slist_free(sl);

    gtk_clist_thaw(GTK_CLIST(search->clist));
}

void on_popup_search_edit_filter_activate(GtkMenuItem * menuitem,
									gpointer user_data)
{
    filter_open_dialog();
}

void on_popup_search_duplicate_activate(GtkMenuItem * menuitem,
										gpointer user_data)
{
    search_t *search;
    guint32 timeout;

    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &timeout);

    search = search_gui_get_current_search();
    /* FIXME: should also duplicate filters! */
    /* FIXME: should call search_duplicate which has to be written. */
    /* FIXME: should properly duplicate passive searches. */
	if (search)
		search_gui_new_search_full(search->query, 
            search_get_minimum_speed(search->search_handle),
			search->enabled, timeout,
            search->sort_col, search->sort_order, 0, NULL);
}

void on_popup_search_restart_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
	if (search)
		search_gui_restart_search(search);
}

void on_popup_search_resume_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
	if (search) {
		search_start(search->search_handle, TRUE);
		/* FIXME: Mark graphically this entry as active again in the list. */
		search->enabled = TRUE;

        gtk_clist_set_foreground(
            GTK_CLIST(lookup_widget(main_window, "clist_search")),
            gtk_notebook_get_current_page
                GTK_NOTEBOOK
                    (lookup_widget(main_window, "notebook_search_results")),
            NULL);
	}
}

void on_popup_search_stop_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
	if (search) {
        GtkCList * clist_search = GTK_CLIST
            (lookup_widget(main_window, "clist_search"));

		search_stop(search->search_handle);
		/* FIXME: Mark graphically this entry as inactive in the searches */
		search->enabled = FALSE;
        gtk_clist_set_foreground(
            clist_search,
            gtk_notebook_get_current_page
                GTK_NOTEBOOK
                    (lookup_widget(main_window, "notebook_search_results")),
            &gtk_widget_get_style(GTK_WIDGET(clist_search))
                ->fg[GTK_STATE_INSENSITIVE]);
	}
}

void on_popup_search_config_cols_activate(GtkMenuItem * menuitem,
										  gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
    g_return_if_fail(search != NULL);
    g_assert(search->clist != NULL);

    {
        GtkWidget * cc;

        /* FIXME: needs to work also in Gtk2 or be replaced. */
        cc = gtk_column_chooser_new(GTK_WIDGET(search->clist));
        gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);

        /* GtkColumnChooser takes care of cleaning up itself */
    }
}
