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

#include "search_cb.h"

#include "gtk/columns.h"
#include "gtk/drag.h"
#include "gtk/filter_core.h"
#include "gtk/gtkcolumnchooser.h"
#include "gtk/misc.h"
#include "gtk/notebooks.h"
#include "gtk/search_common.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/gnet_property.h"
#include "if/bridge/ui2c.h"
#include "if/core/sockets.h"

#include "lib/cq.h"
#include "lib/halloc.h"
#include "lib/iso3166.h"
#include "lib/misc.h"			/* For xml_indent() */
#include "lib/str.h"
#include "lib/utf8.h"
#include "lib/vendors.h"

#include "lib/override.h"		/* Must be the last header included */

void
search_update_tooltip(GtkTreeView *tv, GtkTreePath *path)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	const record_t *rc;

	g_return_if_fail(tv);

	if (path) {
		model = gtk_tree_view_get_model(tv);
		if (!gtk_tree_model_get_iter(model, &iter, path)) {
			g_warning("gtk_tree_model_get_iter() failed");
			return;
		}

		rc = search_gui_get_record_at_path(tv, path);
	} else {
		rc = NULL;
	}

	if (!rc) {
		gtk_tooltips_set_tip(settings_gui_tooltips(), GTK_WIDGET(tv),
			_("Move the cursor over a row to see details."), NULL);
	} else {
		gchar text[4096];

		str_bprintf(text, sizeof text,
			"%s %s\n"
			"%s %s (%s)\n"
			"%s %.64s\n"
			"%s %s",
			_("Peer:"),
			host_addr_port_to_string(rc->results_set->addr,
				rc->results_set->port),
			_("Country:"),
			iso3166_country_name(rc->results_set->country),
			iso3166_country_cc(rc->results_set->country),
			_("Vendor:"),
			search_gui_get_vendor(rc->results_set),
			_("Size:"),
			short_size(rc->size, show_metric_units()));

		gtk_tooltips_set_tip(settings_gui_tooltips(), GTK_WIDGET(tv),
			text, NULL);
	}
}

char *
search_gui_details_get_text(GtkWidget *widget)
{
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_val_if_fail(widget, NULL);

	if (drag_get_iter(GTK_TREE_VIEW(widget), &model, &iter)) {
		static const GValue zero_value;
		GValue value;

		value = zero_value;
		gtk_tree_model_get_value(model, &iter, 1, &value);
		return g_strdup(g_value_get_string(&value));
	} else {
		return NULL;
	}
}

/* Display Bitzi data for the result if any */
static void
search_set_xml(GtkWidget *widget, const char *xml)
{
	GtkTextBuffer *txt;
	char *xml_txt;

	g_return_if_fail(widget);

	txt = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget));
	g_return_if_fail(txt);
	
	/*
	 * Character set detection usually fails here because XML
	 * is mostly ASCII so that the thresholds are not reached.
	 */
	if (xml) {
		char *s = unknown_to_utf8_normalized(xml, UNI_NORM_GUI, NULL);
		xml_txt = xml_indent(s);
		if (xml != s) {
			G_FREE_NULL(s);
		}
	} else {
		xml_txt = NULL;
	}
	gtk_text_buffer_set_text(txt, EMPTY_STRING(xml_txt), -1);
	HFREE_NULL(xml_txt);
}

void
search_gui_set_bitzi_metadata_text(const char *text)
{
	GtkTextBuffer *buffer;
	GtkWidget *widget;

	g_return_if_fail(text);

	widget = gui_main_window_lookup("textview_result_info_bitzi");
	g_return_if_fail(widget);

	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget));
	g_return_if_fail(buffer);

	gtk_text_buffer_set_text(buffer, text, -1);
}

/* Display XML data from the result if any */
static void
search_set_xml_metadata(const record_t *rc)
{
	const char *xml;

	xml = rc ? rc->xml : NULL;
	search_set_xml(gui_main_window_lookup("textview_result_info_xml"), xml);
}

static GtkTreeView *
search_gui_treeview_search_details(void)
{
	static GtkTreeView *tv;

	if (NULL == tv) {
		tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_search_details"));
	}
	return tv;
}

void
search_gui_clear_details(void)
{
	GtkTreeView *tv;

	tv = search_gui_treeview_search_details();
	g_return_if_fail(tv);

	gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(tv)));
}

void
search_gui_append_detail(const gchar *title, const gchar *value)
{
	GtkTreeModel *model;
	GtkTreeView *tv;
	GtkTreeIter iter;

	tv = search_gui_treeview_search_details();
	g_return_if_fail(tv);

	model = gtk_tree_view_get_model(tv);
	gtk_list_store_append(GTK_LIST_STORE(model), &iter);
	gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, title, 1, value, (-1));
}

static void
search_gui_refresh_details(const record_t *rc)
{
	GtkTreeView *tv;

	tv = search_gui_treeview_search_details();
	g_return_if_fail(tv);

	g_object_freeze_notify(G_OBJECT(tv));
	search_gui_set_details(rc);
	g_object_thaw_notify(G_OBJECT(tv));
	search_set_xml_metadata(rc);
	search_gui_set_bitzi_metadata(rc);
}

static void
search_update_details(GtkTreeView *tv, GtkTreePath *path)
{
	g_assert(tv);
	g_assert(path);
	
	search_gui_refresh_details(search_gui_get_record_at_path(tv, path));
}

static cevent_t *row_selected_ev;

#define ROW_SELECT_TIMEOUT	100 /* milliseconds */

static void
row_selected_expire(cqueue_t *unused_cq, gpointer unused_udata)
{
	GtkTreePath *path = NULL;
	GtkTreeView *tv;
	search_t *search;

	(void) unused_cq;
	(void) unused_udata;

	row_selected_ev = NULL;
    search = search_gui_get_current_search();

	if (search) {
		tv = GTK_TREE_VIEW(search->tree);
		gtk_tree_view_get_cursor(tv, &path, NULL);
	} else {
		tv = NULL;
		path = NULL;
	}
	if (path) {
		search_update_tooltip(tv, path);
		search_update_details(tv, path);
		gtk_tree_path_free(path);
       	search_gui_refresh_popup();
	} else {
		search_gui_clear_details();
	}
}

/**
 * This function is called when the user selectes a row in the
 * search results pane. Autoselection takes place here.
 */
void
on_tree_view_search_results_select_row(GtkTreeView *unused_tv,
	gpointer unused_udata)
{
	(void) unused_tv;
	(void) unused_udata;

	if (row_selected_ev) {
		cq_resched(row_selected_ev, ROW_SELECT_TIMEOUT);
	} else {
		row_selected_ev = cq_main_insert(ROW_SELECT_TIMEOUT,
							row_selected_expire, NULL);
	}
}

/***
 *** Search results popup
 ***/

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
	if (bitzi_debug > 10) {
		g_message("on_search_meta_data_active: called");
	}
	search_gui_request_bitzi_data(search_gui_get_current_search());
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

	search = search_gui_get_current_search();
	if (search) {
    	GSList *sl;


		sl = tree_selection_collect_data(
				gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree)),
				search_gui_get_record,
				gui_record_host_eq);
		search_gui_option_menu_searches_freeze();
		g_slist_foreach(sl, search_gui_browse_selected_helper, NULL);
		search_gui_option_menu_searches_thaw();
		g_slist_free(sl);
	}
}

void
on_popup_search_copy_magnet_activate(GtkMenuItem *unused_item,
	gpointer unused_udata)
{
	search_t *search;
	GtkTreeView *tv;
	GtkTreeIter iter;
	GtkTreePath *path = NULL;
	GtkTreeModel *model;

	(void) unused_item;
	(void) unused_udata;

	search = search_gui_get_current_search();
	g_return_if_fail(search);

	tv = GTK_TREE_VIEW(search->tree);
	gtk_tree_view_get_cursor(tv, &path, NULL);
	g_return_if_fail(path);

	model = gtk_tree_view_get_model(tv);
	if (gtk_tree_model_get_iter(model, &iter, path)) {
		gchar *url;

		url = search_gui_get_magnet(search,
					search_gui_get_record(model, &iter));
		clipboard_set_text(GTK_WIDGET(tv), url);
		HFREE_NULL(url);
	}
	gtk_tree_path_free(path);
}


void
search_gui_callbacks_shutdown(void)
{
	/*
 	 *	Remove delayed callbacks
 	 */
	cq_cancel(&row_selected_ev);
}

/* -*- mode: cc-mode; tab-width:4; -*- */
/* vi: set ts=4 sw=4 cindent: */
