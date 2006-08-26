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

/**
 * @ingroup gtk
 * @file
 *
 * GUI filtering functions.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gtk/gui.h"

RCSID("$Id$")

#include <gdk/gdkkeysyms.h>

#include "search_cb.h"

#include "gtk/gtkcolumnchooser.h"
#include "gtk/search.h"
#include "gtk/statusbar.h"
#include "gtk/misc.h"
#include "gtk/columns.h"
#include "gtk/notebooks.h"
#include "gtk/gtk-missing.h"
#include "gtk/settings.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/gnet_property.h"
#include "if/bridge/ui2c.h"
#include "if/core/sockets.h"

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
	/*
	 * The following popup items are set insensitive if nothing is currently
	 * selected (actually if the cursor is unset).
	 */
	static const struct {
		const gchar *name;
	} menu[] = {
		{	"popup_search_download" },
		{	"popup_search_drop" },
		{	"popup_search_drop_global" },
		{	"popup_search_autodownload" },
		{	"popup_search_new_from_selected" },
		{	"popup_search_metadata" },
		{	"popup_search_browse_host" },
		{	"popup_search_copy_magnet" },
	};
	search_t *search = search_gui_get_current_search();
	gboolean sensitive;
	guint i;

	if (!search) {
		sensitive = FALSE;
	} else {
		GtkTreePath *path;
		
		gtk_tree_view_get_cursor(GTK_TREE_VIEW(search->tree_view), &path, NULL);
		sensitive = NULL != path;	
	}
	
	gtk_widget_set_sensitive(
		lookup_widget(main_window, "button_search_download"),
		sensitive);

	for (i = 0; i < G_N_ELEMENTS(menu); i++) {
		GtkWidget *w;

		w = lookup_widget(popup_search, menu[i].name);
		if (w) {
			gtk_widget_set_sensitive(w, sensitive);
		}
	}

    if (search) {
        gtk_widget_set_sensitive(
            lookup_widget(popup_search_list, "popup_search_stop"),
			!guc_search_is_frozen(search->search_handle));
		gtk_widget_set_sensitive(
			lookup_widget(popup_search_list, "popup_search_resume"),
			guc_search_is_frozen(search->search_handle)
				&& !search_gui_is_expired(search));
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
	(void) unused_editable;
	(void) unused_udata;
}

void
on_entry_search_activate(GtkEditable *unused_editable,
	gpointer unused_udata)
{
    /*
     * Delegate to: on_button_search_clicked.
     *      --BLUE, 30/04/2002
     */

	(void) unused_editable;
	(void) unused_udata;

	search_gui_new_search_entered();
}

/**
 *	When a search string is entered, activate the search button
 */
void
on_entry_search_changed(GtkEditable *editable, gpointer unused_udata)
{
	gchar *s = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
	gchar *normalized;
	gboolean changed;

	(void) unused_udata;

	/* Gimmick: Normalize the input on the fly because Gtk+ currently
	 * renders them differently (for example decomposed) if they're are
	 * not in Normalization Form Canonic (NFC)
	 */
	normalized = utf8_normalize(s, UNI_NORM_GUI);
	changed = normalized != s && 0 != strcmp(s, normalized);
	
	if (changed)
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_search")), normalized);

	if (normalized != s)
		G_FREE_NULL(normalized);

	if (!changed) {
		g_strstrip(s);
		gtk_widget_set_sensitive(lookup_widget(main_window, "button_search"),
			s[0] != '\0');
	}
	G_FREE_NULL(s);
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
	sch = gtk_object_get_user_data(GTK_OBJECT(widget));

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
	(void) unused_button;
	(void) unused_udata;
	search_gui_new_search_entered();
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
on_button_search_download_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
    search_gui_download_files();
}

gboolean
on_tree_view_search_results_click_column(GtkTreeViewColumn *column,
	gpointer udata)
{
	GtkTreeSortable *model;
	search_t *sch = udata;
	GtkSortType order;
	gint sort_col;

	/* The default treeview is empty */
	if (!sch)
		return FALSE;

	model = GTK_TREE_SORTABLE(sch->model);

	/*
	 * Here we enforce a tri-state sorting. Normally, Gtk+ would only
	 * switch between ascending and descending but never switch back
	 * to the unsorted state.
	 *
	 * 			+--> sort ascending -> sort descending -> unsorted -+
     *      	|                                                   |
     *      	+-----------------------<---------------------------+
     */

	/*
	 * "order" is set to the current sort-order, not the previous one
	 * i.e., Gtk+ has already changed the order
	 */
	g_object_get(G_OBJECT(column), "sort-order", &order, (void *) 0);

	gtk_tree_sortable_get_sort_column_id(model, &sort_col, NULL);

	/* If the user switched to another sort column, reset the sort order. */
	if (sch->sort_col != sort_col) {
		guint32 rank = 0;

		sch->sort_order = SORT_NONE;
		/*
		 * Iterate over all rows and record their current rank/position so
	 	 * that re-sorting is stable.
		 */
		gtk_tree_model_foreach(GTK_TREE_MODEL(model),
			search_gui_update_rank, &rank);
	}

	sch->sort_col = sort_col;

	/* The search has to keep state about the sort order itself because
	 * Gtk+ knows only ASCENDING/DESCENDING but not NONE (unsorted). */
	switch (sch->sort_order) {
	case SORT_NONE:
	case SORT_NO_COL:
		sch->sort_order = SORT_ASC;
		break;
	case SORT_ASC:
		sch->sort_order = SORT_DESC;
		break;
	case SORT_DESC:
		sch->sort_order = SORT_NONE;
		break;
	}

	if (SORT_NONE == sch->sort_order) {
		/*
		 * Reset the sorting and let the arrow disappear from the
		 * header. Gtk+ actually seems to change the order of the
		 * rows back to the original order (i.e., chronological).
		 */
		gtk_tree_view_column_set_sort_indicator(column, FALSE);
#if GTK_CHECK_VERSION(2,6,0)
		gtk_tree_sortable_set_sort_column_id(model,
			GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID, order);
#endif /* Gtk+ >= 2.6.0 */
	} else {
		/*
		 * Enforce the order as decided from the search state. Gtk+
		 * might disagree but it'll do as told.
		 */
		gtk_tree_sortable_set_sort_column_id(model, sort_col,
			SORT_ASC == sch->sort_order
				? GTK_SORT_ASCENDING : GTK_SORT_DESCENDING);
	}
	/* Make the column stays clickable. */
	gtk_tree_view_column_set_clickable(column, TRUE);

	return FALSE;
}

static const gchar *
search_get_vendor_from_record(const record_t *rc)
{
	const gchar *s;

	g_assert(rc != NULL);

	s = lookup_vendor_name(rc->results_set->vcode);
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

		rc = search_gui_get_record_at_path(tv, path);
	}

	if (!rc) {
		GtkWidget *w;

		gtk_tooltips_set_tip(settings_gui_tooltips(), GTK_WIDGET(tv),
			_("Move the cursor over a row to see details."), NULL);
		w = settings_gui_tooltips()->tip_window;
#if 0
		if (w)
			gtk_widget_hide(w);
#endif
	} else {
		gchar text[4096], extra[1024];
		gboolean has_extra;

		if (rc->utf8_name && utf8_can_dejap(rc->utf8_name)) {
			utf8_dejap(extra, sizeof extra, rc->utf8_name);
		} else {
			0[extra] = '\0';
		}

		has_extra = '\0' != 0[extra];
		gm_snprintf(text, sizeof text,
			"%s %s\n"
			"%s %s (%s)\n"
			"%s %.64s\n"
			"%s %s"
			"%s%s",
			_("Peer:"),
			host_addr_port_to_string(rc->results_set->addr,
				rc->results_set->port),
			_("Country:"),
			iso3166_country_name(rc->results_set->country),
			iso3166_country_cc(rc->results_set->country),
			_("Vendor:"),
			search_get_vendor_from_record(rc),
			_("Size:"),
			short_size(rc->size, show_metric_units()),
			has_extra ? "\nExtra: " : "",
			has_extra ? extra : "");

		gtk_tooltips_set_tip(settings_gui_tooltips(), GTK_WIDGET(tv),
			text, NULL);
	}
}

static void
search_update_details(GtkTreeView *tv, GtkTreePath *path)
{
	const record_t *rc = NULL;
	gchar bytes[UINT64_DEC_BUFLEN];
	gchar *xml_txt;

	g_assert(tv != NULL);
	g_assert(path != NULL);

	rc = search_gui_get_record_at_path(tv, path);
	g_return_if_fail(rc != NULL);
	
	gtk_entry_set_text(
		GTK_ENTRY(lookup_widget(main_window, "entry_result_info_filename")),
		rc->name
			? lazy_unknown_to_utf8_normalized(rc->name, UNI_NORM_GUI, NULL)
			: "");
	
	gtk_entry_printf(
		GTK_ENTRY(lookup_widget(main_window, "entry_result_info_sha1")),
		"%s%s",
		rc->sha1 ? "urn:sha1:" : _("<no SHA1 known>"),
		rc->sha1 ? sha1_base32(rc->sha1) : "");

	if (rc->results_set->hostname)
		gtk_entry_set_text(GTK_ENTRY(
					lookup_widget(main_window, "entry_result_info_source")),
				hostname_port_to_string(
					rc->results_set->hostname, rc->results_set->port));
	else
		gtk_entry_set_text(GTK_ENTRY(
					lookup_widget(main_window, "entry_result_info_source")),
				host_addr_port_to_string(rc->results_set->addr,
					rc->results_set->port));

	uint64_to_string_buf(rc->size, bytes, sizeof bytes);
	gtk_entry_printf(
			GTK_ENTRY(lookup_widget(main_window, "entry_result_info_size")),
			_("%s (%s bytes)"), short_size(rc->size, show_metric_units()),
			bytes);

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

	{
		const gchar *query = rc->results_set->query;
		GtkEntry *entry;
	   
		entry = GTK_ENTRY(lookup_widget(main_window, "entry_result_info_tag"));
		query = rc->results_set->query;
		if (query) {
			gchar *s;

			s = unknown_to_utf8_normalized(query, UNI_NORM_GUI, NULL);
			gtk_entry_set_text(entry, s ? s : "");
			if (query != s) {
				G_FREE_NULL(s);
			}
		} else {
			gtk_entry_set_text(entry, "");
		}
	}

	/* Display XML data from the result if any */
	{
		GtkTextBuffer *txt;
		
		txt = gtk_text_view_get_buffer(GTK_TEXT_VIEW(lookup_widget(main_window,
					"textview_result_info_xml")));
	
		/*
		 * Character set detection usually fails here because XML
		 * is mostly ASCII so that the thresholds are not reached.
		 */
		if (rc->xml) {
			gchar *s = unknown_to_utf8_normalized(rc->xml, UNI_NORM_GUI, NULL);
			xml_txt = search_xml_indent(s);
			if (rc->xml != s)
				G_FREE_NULL(s);
		} else {
			xml_txt = NULL;
		}
		gtk_text_buffer_set_text(txt, EMPTY_STRING(xml_txt), -1);
		G_FREE_NULL(xml_txt);
	}

#if 0
	/**
	 * Dump the raw filename to enhance the character set detection.
	 * The following helps to figure out what the actual encoding is:
	 *
	 *	for cs in $(iconv -l); do
	 *	  printf "${cs}: ${filename}" | iconv -f "${cs}" -t UTF-8 2>/dev/null
	 *	done
	 */
	g_message("filename[] = \"%s\"",
		rc->name ? lazy_string_to_printf_escape(rc->name) : "(null)");
	(void) lazy_string_to_printf_escape("");	/* release buffer if any */
#endif
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
    default_filter = option_menu_get_selected_data(GTK_OPTION_MENU(
					lookup_widget(main_window, "optionmenu_search_filter")));

	search_gui_new_search(_("Passive"), SEARCH_F_PASSIVE, &search);

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
    sl = tree_selection_collect_data(selection,
			search_gui_get_record, gui_record_name_eq);
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
    sl = tree_selection_collect_data(selection,
			search_gui_get_record, gui_record_sha1_eq);
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
    sl = tree_selection_collect_data(selection,
			search_gui_get_record, gui_record_host_eq);
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
    sl = tree_selection_collect_data(selection,
			search_gui_get_record, gui_record_name_eq);
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
    sl = tree_selection_collect_data(selection,
			search_gui_get_record, gui_record_sha1_eq);
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
    sl = tree_selection_collect_data(selection,
			search_gui_get_record, gui_record_host_eq);
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
    sl = tree_selection_collect_data(selection,
			search_gui_get_record, gui_record_name_eq);
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
    sl = tree_selection_collect_data(selection,
			search_gui_get_record, gui_record_sha1_eq);
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
    sl = tree_selection_collect_data(selection, search_gui_get_record,
			gui_record_sha1_or_name_eq);
    g_slist_foreach(sl, search_gui_add_targetted_search, search->filter);
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

	search_gui_new_search_full(search->query, tm_time(), search_lifetime,
		timeout, search->sort_col, search->sort_order,
		search->enabled ? SEARCH_F_ENABLED : 0, NULL);
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
	if (!search_gui_is_expired(search)) {
		gui_search_set_enabled(search, TRUE);
		search_gui_update_expiry(search);
	}
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
	search_gui_update_expiry(search);
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
 * Queue a bitzi query.
 */
void
on_popup_search_metadata_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	guint32 bitzi_debug;

	(void) unused_menuitem;
	(void) unused_udata;

    gnet_prop_get_guint32_val(PROP_BITZI_DEBUG, &bitzi_debug);
	if (bitzi_debug)
		g_message("on_search_meta_data_active: called");

	search_gui_request_bitzi_data();
}

static void
search_gui_browse_selected_helper(gpointer data, gpointer unused_udata)
{
	const record_t *rc = data;
	guint32 flags = 0;

	(void) unused_udata;
	
	flags |= (rc->results_set->status & ST_FIREWALL) ? SOCK_F_PUSH : 0;
	flags |= (rc->results_set->status & ST_TLS) ? SOCK_F_TLS : 0;
	
	search_gui_new_browse_host(
		rc->results_set->hostname,
		rc->results_set->addr,
		rc->results_set->port,
		rc->results_set->guid,
		rc->results_set->proxies,
		flags);
}

/**
 * Request host browsing for the selected host.
 */
void
search_gui_browse_selected(void)
{
	search_t *search;
    GSList *sl;
   
	search = search_gui_get_current_search();
	if (!search)
		return;

    sl = tree_selection_collect_data(
			gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view)),
			search_gui_get_record,
			gui_record_host_eq);
    g_slist_foreach(sl, search_gui_browse_selected_helper, NULL);
    g_slist_free(sl);

}

void
on_popup_search_copy_magnet_activate(GtkMenuItem *unused_item, gpointer unused_udata)
{
	search_t *search;
	GtkTreeView *tv;
	GtkTreeIter iter;
	GtkTreePath *path;
	GtkTreeModel *model;

	(void) unused_item;
	(void) unused_udata;

	search = search_gui_get_current_search();
	if (!search)
		return;

	tv = GTK_TREE_VIEW(search->tree_view);
	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (!path) {
		return;
	}
	
	model = gtk_tree_view_get_model(tv);
	if (gtk_tree_model_get_iter(model, &iter, path)) {
		gchar *url;

		url = search_gui_get_magnet(model, &iter);
		if (url) {
			gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_PRIMARY));
			gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY),
				url, -1);
			gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD));
			gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD),
				url, -1);
			G_FREE_NULL(url);
		}
	}
	gtk_tree_path_free(path);
}


void
search_callbacks_shutdown(void)
{
	/*
 	 *	Remove delayed callbacks
 	 */
}

/* -*- mode: cc-mode; tab-width:4; -*- */
/* vi: set ts=4 sw=4 cindent: */
