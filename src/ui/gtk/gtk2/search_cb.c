/* -*- mode: cc-mode; tab-width:4; -*-
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

#include "gtk/gui.h"

RCSID("$Id$");

#include <gdk/gdkkeysyms.h>

#include "search_cb.h"

#include "gtk/gtkcolumnchooser.h"
#include "gtk/search.h"
#include "gtk/misc.h"
#include "gtk/columns.h"
#include "gtk/notebooks.h"
#include "gtk/gtk-missing.h"
#include "gtk/settings.h"

#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/glib-missing.h"
#include "lib/iso3166.h"
#include "lib/utf8.h"
#include "lib/vendors.h"
#include "lib/override.h"		/* Must be the last header included */

/* Privat variables */

static search_t *search_selected = NULL;

/***
 *** Private functions
 ***/

static void
refresh_popups(void)
{
	static const char * const popup_names[] = {
		"popup_search_download",
		"popup_search_drop_name",
		"popup_search_drop_sha1",
		"popup_search_drop_host",
		"popup_search_drop_name_global",
		"popup_search_drop_host_global",
		"popup_search_autodownload_name",
		"popup_search_autodownload_sha1",
		"popup_search_new_from_selected",
	};
	search_t *search = search_gui_get_current_search();
	gboolean sensitive = NULL != search;
	guint i;

	for (i = 0; i < G_N_ELEMENTS(popup_names); i++)
		gtk_widget_set_sensitive(lookup_widget(popup_search, popup_names[i]),
			sensitive);

    if (search) {
        gtk_widget_set_sensitive(
            lookup_widget(popup_search_list, "popup_search_stop"),
			!guc_search_is_frozen(search->search_handle));
		gtk_widget_set_sensitive(
			lookup_widget(popup_search_list, "popup_search_resume"),
			guc_search_is_frozen(search->search_handle));
		if (search->passive)
			gtk_widget_set_sensitive(
				lookup_widget(popup_search_list, "popup_search_restart"),
				FALSE);
    } else {
		gtk_widget_set_sensitive(
			lookup_widget(popup_search_list, "popup_search_stop"), FALSE);
		gtk_widget_set_sensitive(
			lookup_widget(popup_search_list, "popup_search_resume"), FALSE);
    }

}

/***
 *** Glade callbacks
 ***/
void
on_combo_entry_searches_activate(GtkEditable *unused_editable,
	gpointer unused_udata)
{
    /* FIXME */
	(void) unused_editable;
	(void) unused_udata;
}


void
on_search_popdown_switch(GtkWidget *unused_w, gpointer unused_data)
{
	(void) unused_w;
	(void) unused_data;
	g_return_if_fail(NULL != search_selected);
	search_gui_set_current_search(search_selected);
}

void
on_search_notebook_switch(GtkNotebook *notebook, GtkNotebookPage *unused_page,
	gint page_num, gpointer unused_udata)
{
	search_t *sch = (search_t *) gtk_object_get_user_data(
		GTK_OBJECT(gtk_notebook_get_nth_page(notebook, page_num)));

	(void) unused_page;
	(void) unused_udata;
	g_return_if_fail(sch);

	search_gui_set_current_search(sch);
}

void
on_search_notebook_focus_tab(GtkNotebook *notebook, GtkNotebookTab unused_tab,
	gpointer unused_udata)
{
	search_t *sch;
	GtkWidget *widget;
	gint page_num;

	(void) unused_tab;
	(void) unused_udata;
	page_num = gtk_notebook_get_current_page(notebook);
	widget = gtk_notebook_get_nth_page(notebook, page_num);
	sch = (search_t *) gtk_object_get_user_data(GTK_OBJECT(widget));

	g_return_if_fail(sch);

	search_gui_set_current_search(sch);
}

void
on_tree_view_search_select_row(GtkTreeView *treeview, gpointer unused_udata)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	search_t *sch;

	(void) unused_udata;
	g_assert(treeview != NULL);
	selection = gtk_tree_view_get_selection(treeview);
	if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
		gtk_tree_model_get(model, &iter, c_sl_sch, &sch, (-1));

		g_return_if_fail(NULL != sch);

		gtk_notebook_set_page(
			GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")),
			nb_main_page_search);
		search_gui_set_current_search(sch);
	}
}

void
on_search_selected(GtkItem *unused_item, gpointer data)
{
	(void) unused_item;
	search_selected = (search_t *) data;
}

void
on_button_search_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	gchar *e = STRTRACK(gtk_editable_get_chars(
		GTK_EDITABLE(lookup_widget(main_window, "entry_search")), 0, -1));

        /*
         * Even though we might not be on_the_net() yet, record the search.
         * There is a callback mechanism when a new node is connected, which
         * will launch the search there if it has not been sent already.
         *              --patch from Mark Schreiber, 10/01/2002
         */

	(void) unused_button;
	(void) unused_udata;

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
			search->filter->ruleset =
                g_list_append(search->filter->ruleset, rule);
			rule->target->refcount ++;
		}

		if (!res)
			gdk_beep();
	}

	G_FREE_NULL(e);
}

void
on_entry_search_activate(GtkEditable *unused_editable, gpointer user_data)
{
    /*
     * Delegate to: on_button_search_clicked.
     *      --BLUE, 30/04/2002
     */

	(void) unused_editable;
	on_button_search_clicked(NULL, user_data);
}

void
on_entry_search_changed(GtkEditable * editable, gpointer unused_udata)
{
	gchar *e = STRTRACK(gtk_editable_get_chars(editable, 0, -1));

	(void) unused_udata;
	g_strstrip(e);
	gtk_widget_set_sensitive(
		lookup_widget(main_window, "button_search"), '\0' != *e);
	G_FREE_NULL(e);
}

void
on_button_search_clear_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	gui_search_clear_results();
	gtk_widget_set_sensitive(
		lookup_widget(main_window, "button_search_clear"), FALSE);
}

void
on_button_search_close_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	search_gui_close_search(search_gui_get_current_search());
}

void
on_popup_search_close_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_close_search(search_gui_get_current_search());
}

gboolean
on_tree_view_search_results_key_press_event(GtkWidget *unused_widget,
	GdkEventKey *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;
    g_assert(event != NULL);

    switch (event->keyval) {
    case GDK_Return:
        search_gui_download_files();
        return TRUE;
	case GDK_Delete:
        search_gui_discard_files();
		return TRUE;
    default:
        return FALSE;
    }
}

gboolean
on_tree_view_search_results_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata)
{
	static guint click_time = 0;
	gboolean search_results_show_tabs;

	(void) unused_udata;

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
		if (search_gui_get_current_search()) {
        	refresh_popups();
			gui_prop_get_boolean_val(PROP_SEARCH_RESULTS_SHOW_TABS,
                &search_results_show_tabs);
        	gtk_label_set(GTK_LABEL((GTK_MENU_ITEM(
				lookup_widget(popup_search, "popup_search_toggle_tabs"))
                	->item.bin.child)),
				search_results_show_tabs ?
					_("Show search list") : _("Show tabs"));
			gtk_menu_popup(GTK_MENU(popup_search), NULL, NULL, NULL, NULL,
				event->button, event->time);
		}
		return TRUE;
    }

	return FALSE;
}

gboolean
on_tree_view_search_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	switch (event->button) {
	case 3:
        /* right click section (popup menu) */
		if (search_gui_get_current_search()) {
			refresh_popups();
			gtk_menu_popup(GTK_MENU(popup_search_list), NULL, NULL, NULL, NULL,
				event->button, event->time);
		}
		return TRUE;
    }

	return FALSE;
}

void
on_button_search_filter_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
	filter_open_dialog();
}

void
on_button_search_download_selected_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
    search_gui_download_files();
}

gboolean
on_tree_view_search_results_click_column(GtkTreeViewColumn *unused_column,
	gpointer unused_udata)
{
	/* FIXME:
	 * 			+--> sort descending -> sort ascending -> unsorted -+
     *      	|                                                   |
     *      	+-----------------------<---------------------------+
     */
	(void) unused_column;
	(void) unused_udata;
	return FALSE;
}

static const record_t *
search_get_record_at_path(GtkTreeView *tv, GtkTreePath *path)
{
	const GList *l = search_gui_get_searches();
	search_t *sch = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;
	const record_t *rc;

	for (/* NOTHING */; NULL != l; l = g_list_next(l)) {
		if (tv == GTK_TREE_VIEW(((search_t *) l->data)->tree_view)) {
			sch = (search_t *) l->data;
			break;
		}
	}
	g_return_val_if_fail(NULL != sch, NULL);
	
	model = GTK_TREE_MODEL(sch->model);
	gtk_tree_model_get_iter(model, &iter, path);
	gtk_tree_model_get(model, &iter, c_sr_record, &rc, (-1));

	return rc;
}

static const gchar *
search_get_vendor_from_record(const record_t *rc)
{
	gchar *s;

	g_assert(rc != NULL);	

	s = lookup_vendor_name(rc->results_set->vendor);
	if (s == NULL)
		return _("Unknown");
	
	if (rc->results_set->version) {
		static gchar buf[128];

		gm_snprintf(buf, sizeof buf, "%s/%s", s, rc->results_set->version);
		return buf;
	}

	return s;
}

void
search_update_tooltip(GtkTreeView *tv, GtkTreePath *path)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	const record_t *rc;

	g_assert(tv != NULL);
	if (!path) {
		rc = NULL;
	} else {
		model = gtk_tree_view_get_model(tv);
		if (!gtk_tree_model_get_iter(model, &iter, path)) {
			g_warning("gtk_tree_model_get_iter() failed");
			return;
		}

		rc = search_get_record_at_path(tv, path);
	}

	if (!rc) {
		GtkWidget *w;
		
		gtk_tooltips_set_tip(settings_gui_tooltips(), GTK_WIDGET(tv),
			_("Move the cursor over a row to see details."), NULL);
		w = settings_gui_tooltips()->tip_window;
		if (w)
			gtk_widget_hide(w);
	} else {
		gchar text[1024];

		gm_snprintf(text, sizeof text,
			"%s %s\n"
			"%s %s (%s)\n"
			"%s %.64s\n"
			"%s %s\n"
			"%s %s\n"
			"%s %s",
			_("Peer:"),
			ip_port_to_gchar(rc->results_set->ip, rc->results_set->port),
			_("Country:"),
			iso3166_country_name(rc->results_set->country),
			iso3166_country_cc(rc->results_set->country),
			_("Vendor:"),
			search_get_vendor_from_record(rc),
			_("SHA1:"),
			rc->sha1 != NULL ? sha1_base32(rc->sha1) : _("<none>"),
			_("GUID:"),
			guid_hex_str(rc->results_set->guid),
			_("Size:"),
			short_size(rc->size));
		
		gtk_tooltips_set_tip(settings_gui_tooltips(), GTK_WIDGET(tv),
			text, NULL);
	}
}

static void
search_update_details(GtkTreeView *tv, GtkTreePath *path)
{
	GtkTextBuffer *txt;
	const record_t *rc = NULL;
	gchar bytes[32];

	g_assert(tv != NULL);
	g_assert(path != NULL);

	rc = search_get_record_at_path(tv, path);
	g_return_if_fail(rc != NULL);

	gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_filename")),
			lazy_locale_to_utf8(rc->name, 0));

	gtk_entry_printf(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_sha1")),
			"%s%s",
			rc->sha1 ? "urn:sha1:" : _("<none>"),
			rc->sha1 ? sha1_base32(rc->sha1) : "");

	if (rc->results_set->hostname)
		gtk_entry_set_text(GTK_ENTRY(
					lookup_widget(main_window, "entry_result_info_source")),
				hostname_port_to_gchar(
					rc->results_set->hostname, rc->results_set->port));
	else
		gtk_entry_set_text(GTK_ENTRY(
					lookup_widget(main_window, "entry_result_info_source")),
				ip_port_to_gchar(rc->results_set->ip, rc->results_set->port));

	gm_snprintf(bytes, sizeof bytes, "%" PRIu64, (guint64) rc->size);
	gtk_entry_printf(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_size")),
			_("%s (%s bytes)"), short_size(rc->size), bytes);

	gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_guid")),
			guid_hex_str(rc->results_set->guid));

	gtk_entry_printf(GTK_ENTRY(
				lookup_widget(main_window, "entry_result_info_timestamp")),
			"%24.24s", ctime(&rc->results_set->stamp));
			/* discard trailing '\n' (see ctime(3) */

	gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_vendor")),
			search_get_vendor_from_record(rc));

	gtk_entry_printf(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_index")),
			"%lu", (gulong) rc->index);

	gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_tag")),
			rc->tag ? lazy_locale_to_utf8(rc->tag, 0) : "");

	txt = gtk_text_view_get_buffer(GTK_TEXT_VIEW(lookup_widget(main_window,
					"textview_result_info_xml"))); 
	gtk_text_buffer_set_text(txt, rc->xml ? rc->xml : _("<none>"), -1);

}


/**
 * This function is called when the user selectes a row in the
 * search results pane. Autoselection takes place here.
 */
void
on_tree_view_search_results_select_row(GtkTreeView *tv, gpointer unused_udata)
{
	GtkTreePath *path;

	(void) unused_udata;

	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (path != NULL) {
		search_update_tooltip(tv, path);
		search_update_details(tv, path);
		gtk_tree_path_free(path);
		path = NULL;
    	refresh_popups();
	}
}

void
on_button_search_passive_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
    filter_t *default_filter;
	search_t *search;

	(void) unused_button;
	(void) unused_udata;

    /*
     * We have to capture the selection here already, because
     * new_search will trigger a rebuild of the menu as a
     * side effect.
     */
    default_filter = (filter_t *) option_menu_get_selected_data(
		lookup_widget(main_window, "optionmenu_search_filter"));

	search_gui_new_search(_("Passive"), SEARCH_PASSIVE, &search);

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

void
on_popup_search_download_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    search_gui_download_files();
}

void
on_popup_search_drop_name_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_name_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_name_rule, search->filter);
    g_slist_free(sl);
}

void
on_popup_search_drop_sha1_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_sha1_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_sha1_rule, search->filter);
    g_slist_free(sl);
}

void
on_popup_search_drop_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_host_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_host_rule, search->filter);
    g_slist_free(sl);
}

void on_popup_search_drop_name_global_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_name_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_name_rule,
        filter_get_global_pre());
    g_slist_free(sl);
}

void
on_popup_search_drop_sha1_global_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_sha1_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_sha1_rule,
        filter_get_global_pre());
    g_slist_free(sl);
}

void
on_popup_search_drop_host_global_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_host_eq);
    g_slist_foreach(sl, (GFunc) filter_add_drop_host_rule,
        filter_get_global_pre());
    g_slist_free(sl);
}

void
on_popup_search_autodownload_name_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_name_eq);
    g_slist_foreach(sl, (GFunc) filter_add_download_name_rule, search->filter);
    g_slist_free(sl);
}

void
on_popup_search_autodownload_sha1_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_sha1_eq);
    g_slist_foreach(sl, (GFunc) filter_add_download_sha1_rule, search->filter);
    g_slist_free(sl);
}

void
on_popup_search_new_from_selected_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;
	GtkTreeSelection *selection;
    GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_assert(search != NULL);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
    sl = tree_selection_collect_data(selection, gui_record_sha1_or_name_eq);
    g_slist_foreach(
        sl, (GFunc) search_gui_add_targetted_search, search->filter);
    g_slist_free(sl);
}

void
on_popup_search_edit_filter_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    filter_open_dialog();
}

void
on_popup_search_duplicate_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;
    guint32 timeout;

	(void) unused_menuitem;
	(void) unused_udata;

    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &timeout);

    search = search_gui_get_current_search();
    g_return_if_fail(NULL != search);

    /* FIXME: should also duplicate filters! */
    /* FIXME: should call search_duplicate which has to be written. */
    /* FIXME: should properly duplicate passive searches. */

	search_gui_new_search_full(search->query,
		timeout, search->sort_col, search->sort_order,
		search->enabled ? SEARCH_ENABLED : 0, NULL);
}

void
on_popup_search_restart_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
	g_return_if_fail(NULL != search);
	search_gui_restart_search(search);
}

void
on_popup_search_resume_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_return_if_fail(NULL != search);
	gui_search_set_enabled(search, TRUE);
}

void
on_popup_search_stop_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    search_t *search;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_return_if_fail(NULL != search);
	gui_search_set_enabled(search, FALSE);
}

void
on_popup_search_config_cols_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkWidget * cc;
    search_t *search;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
	g_return_if_fail(NULL != search);

	cc = gtk_column_chooser_new(GTK_WIDGET(search->tree_view));
   	gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);

	/* GtkColumnChooser takes care of cleaning up itself */
}


void
on_popup_search_expand_all_activate (GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_expand_all();
}

void
on_popup_search_collapse_all_activate (GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_collapse_all();
}


/**
 * Queue a bitzi query
 */
void
on_popup_search_metadata_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	search_t *search;
	GtkTreeSelection *selection;
	GSList *sl, *sl_records;

	(void) unused_menuitem;
	(void) unused_udata;

	g_message("on_search_meta_data_active: called");

	/* collect the list of files selected */

	search = search_gui_get_current_search();
	g_assert(search != NULL);

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
	sl_records = tree_selection_collect_data(selection, gui_record_sha1_eq);

	/* Queue up our requests */
	g_message("on_search_meta_data: %d items", g_slist_length(sl_records));

	for (sl = sl_records; sl; sl = g_slist_next(sl)) {
		record_t    *rec;

		rec = sl->data;
		if (rec->sha1) {
			GtkTreeIter *parent;

	    	guc_query_bitzi_by_urn(rec->sha1);

			/* set the feedback */
			parent = find_parent_with_sha1(search->parents, rec->sha1);
			g_assert(parent != NULL);
			gtk_tree_store_set(GTK_TREE_STORE(search->model), parent,
				c_sr_meta, _("Query queued..."),
				(-1));
		}
    }

	g_slist_free(sl_records);

}


void
search_callbacks_shutdown(void)
{
	/*
 	 *	Remove delayed callbacks
 	 */
}

/* vi: set ts=4 sw=4 cindent: */
