/*
 * Copyright (c) 2001-2005, Raphael Manfredi, Richard Eckart
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
 *
 * @author Raphael Manfredi
 * @date 2005
 */

#include "gtk/gui.h"

#include "search_cb.h"

#include "gtk/bitzi.h"
#include "gtk/columns.h"
#include "gtk/filter_core.h"
#include "gtk/misc.h"
#include "gtk/search_common.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/gnet_property.h"
#include "if/bridge/ui2c.h"
#include "if/core/sockets.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/misc.h"			/* Fox xml_indent() */
#include "lib/utf8.h"
#include "lib/vendors.h"		/* For T_GTKG */

#include "lib/override.h"		/* Must be the last header included */

static record_t *selected_record; 

char * 
search_gui_details_get_text(GtkWidget *widget)
{
	char *text = NULL;
	int row;

	g_return_val_if_fail(widget, NULL);

	row = clist_get_cursor_row(GTK_CLIST(widget));
	if (row >= 0 && gtk_clist_get_text(GTK_CLIST(widget), row, 1, &text)) {
		return g_strdup(text);
	} else {
		return NULL;
	}
}

/***
 *** Private functions
 ***/

static void
set_text_buffer(GtkWidget *widget, const char *text)
{
	GtkText *buffer;

	g_return_if_fail(widget);
	g_return_if_fail(text);

	buffer = GTK_TEXT(widget);
	g_return_if_fail(buffer);

	gtk_text_freeze(buffer);
	gtk_text_set_point(buffer, 0);
	gtk_text_forward_delete(buffer, gtk_text_get_length(buffer));
	gtk_text_set_point(buffer, 0);
	gtk_text_insert(buffer, NULL, NULL, NULL,
		lazy_utf8_to_ui_string(text), (-1));
	gtk_text_thaw(buffer);
}

/* Display XML data from the result if any */
static void
search_set_xml_metadata(const record_t *rc)
{
	char *indented;

	indented = (rc && rc->xml) ? xml_indent(rc->xml) : NULL;
	set_text_buffer(gui_main_window_lookup("text_result_info_xml"),
		EMPTY_STRING(indented));
	HFREE_NULL(indented);
}

void
search_gui_set_bitzi_metadata_text(const char *text)
{
	g_return_if_fail(text);

	set_text_buffer(gui_main_window_lookup("text_result_info_bitzi"), text);
}

static GtkCList *clist_search_details;

void
search_gui_clear_details(void)
{
	if (clist_search_details) {
		gtk_clist_clear(clist_search_details);
	}
}

void
search_gui_append_detail(const gchar *name, const gchar *value)
{
 	const gchar *titles[2];

	g_return_if_fail(clist_search_details);

	titles[0] = name;
	titles[1] = EMPTY_STRING(value);
    gtk_clist_append(clist_search_details, (gchar **) titles);
}
	
/**
 *	Activates/deactivates buttons and popups based on what is selected
 */
/**
 * Set or clear (when rc == NULL) the information about the record.
 */
static void
search_gui_refresh_details(const record_t *rc)
{
	if (NULL == clist_search_details) {
		static const gchar name[] = "clist_search_details";
		clist_search_details = GTK_CLIST(gui_main_window_lookup(name));
		gtk_clist_set_column_auto_resize(clist_search_details, 0, TRUE);
	}
	g_return_if_fail(clist_search_details);

    gtk_clist_freeze(clist_search_details);
	search_gui_set_details(rc);
    gtk_clist_thaw(clist_search_details);
	search_set_xml_metadata(rc);
	search_gui_set_bitzi_metadata(rc);
}

record_t *
search_gui_get_record(GtkCTree *ctree, GtkCTreeNode *node)
{
	gui_record_t *grc;

	/*
     * Rows with NULL data can appear when inserting new rows
     * because the selection is resynced and the row data cannot
     * be set until insertion and therefore also selection syncing
     * is done.
     *      -- Richard, 20/06/2002
     *
     * Can this really happen???
     *      -- Richard, 18/04/2004
     */
	grc = node ? gtk_ctree_node_get_row_data(ctree, node) : NULL;
	return grc ? grc->shared_record : NULL;
}

/**
 *	Sort search according to selected column
 */
void
on_clist_search_results_click_column(GtkCList *clist, gint column,
	gpointer unused_udata)
{
    search_t *search;

	(void) unused_udata;
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

static cevent_t *row_selected_ev;

#define ROW_SELECT_TIMEOUT	100 /* milliseconds */

static void
row_selected_expire(cqueue_t *cq, gpointer unused_udata)
{
	search_t *search;

	(void) unused_udata;

	cq_zero(cq, &row_selected_ev);

    search = search_gui_get_current_search();
	if (search) {
    	search_gui_refresh_popup();
		search_gui_refresh_details(selected_record);
	} else {
		search_gui_clear_details();
	}
}

static void
selected_row_changed(GtkCTree *ctree)
{
	int row;
	
	if (selected_record) {
		search_gui_unref_record(selected_record);
		selected_record = NULL;
	}

	row = clist_get_cursor_row(GTK_CLIST(ctree));
	if (row >= 0) {
		GtkCTreeNode *node;

		node = gtk_ctree_node_nth(GTK_CTREE(ctree), row);
		selected_record = search_gui_get_record(ctree, GTK_CTREE_NODE(node));
		if (selected_record) {
			search_gui_ref_record(selected_record);
		}
	}

	if (row_selected_ev) {
		cq_resched(row_selected_ev, ROW_SELECT_TIMEOUT);
	} else {
		row_selected_ev = cq_main_insert(ROW_SELECT_TIMEOUT,
							row_selected_expire, NULL);
	}
}

/**
 *	This function is called when the user selects a row in the
 *	search results pane. Autoselection takes place here.
 */
void
on_ctree_search_results_select_row(GtkCTree *ctree,
	GList *unused_node, gint unused_column, gpointer unused_udata)
{
	(void) unused_column;
	(void) unused_udata;
	(void) unused_node;

	selected_row_changed(ctree);
}

/***
 *** Search results popup
 ***/

/**
 * Request host browsing for the selected entries.
 */
void
search_gui_browse_selected(void)
{
    search_t *search;
	GtkCTree *ctree;
	GList *selected;
	GList *l;;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    ctree = GTK_CTREE(search->tree);
	selected = GTK_CLIST(ctree)->selection;

	if (selected == NULL) {
        statusbar_gui_message(15, "*** No search result selected! ***");
		return;
	}

	search_gui_option_menu_searches_freeze();
	for (l = selected; l != NULL; l = g_list_next(l)) {
		GtkCTreeNode *node = l->data;
		gui_record_t *grc;
		results_set_t *rs;
		record_t *rc;
		guint32 flags = 0;

		if (node == NULL)
			break;

		grc = gtk_ctree_node_get_row_data(ctree, node);
		rc = grc->shared_record;

		if (!rc)
			continue;

		rs = rc->results_set;
		flags |= 0 != (rs->status & ST_FIREWALL) ? SOCK_F_PUSH : 0;
		flags |= 0 != (rs->status & ST_TLS) ? SOCK_F_TLS : 0;
		flags |= ((rs->status & ST_G2) && T_GTKG != rs->vendor) ? SOCK_F_G2 : 0;

		(void) search_gui_new_browse_host(
				rs->hostname, rs->addr, rs->port,
				rs->guid, rs->proxies, flags);
	}
	search_gui_option_menu_searches_thaw();
}

/**
 *	Given a GList of GtkCTreeNodes, return a new list pointing to the shared
 *	record contained by the row data.
 *	List will have to be freed later on.
 */
GSList *
search_cb_collect_ctree_data(GtkCTree *ctree,
	GList *node_list, GCompareFunc cfn)
{
	GSList *data_list = NULL;
	gui_record_t *grc;
	record_t *rc;

	for (/* empty */; node_list != NULL; node_list = g_list_next(node_list)) {

		if (node_list->data != NULL) {
			grc = gtk_ctree_node_get_row_data(ctree, node_list->data);
			rc = grc->shared_record;
			if (!cfn || NULL == g_slist_find_custom(data_list, rc, cfn))
				data_list = g_slist_prepend(data_list, rc);
		}
	}

	return g_slist_reverse(data_list);
}

/**
 * Queue a bitzi queries from the search context menu
 */
void
on_popup_search_metadata_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GList *node_list;
	GSList *data_list;
    search_t *search;
	guint32 bitzi_debug;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->tree));

	node_list = g_list_copy(GTK_CLIST(search->tree)->selection);
	data_list = search_cb_collect_ctree_data(GTK_CTREE(search->tree),
					node_list, gui_record_sha1_eq);

	/* Make sure the column is actually visible. */
	{
		static const gint min_width = 80;
		GtkCList *clist = GTK_CLIST(search->tree);

    	gtk_clist_set_column_visibility(clist, c_sr_meta, TRUE);
		if (clist->column[c_sr_meta].width < min_width)
    		gtk_clist_set_column_width(clist, c_sr_meta, min_width);
	}
	
	/* Queue up our requests */
    gnet_prop_get_guint32_val(PROP_BITZI_DEBUG, &bitzi_debug);
	if (bitzi_debug > 10)
		g_debug("on_popup_search_metadata_activate: %d items, %p",
			  g_slist_position(data_list, g_slist_last(data_list)) + 1,
			  cast_to_gconstpointer(data_list));

	G_SLIST_FOREACH(data_list, search_gui_queue_bitzi_by_sha1);

	gtk_clist_thaw(GTK_CLIST(search->tree));
	g_slist_free(data_list);
	g_list_free(node_list);
}

void
on_popup_search_copy_magnet_activate(GtkMenuItem *unused_item,
	gpointer unused_udata)
{
	search_t *search;

	(void) unused_item;
	(void) unused_udata;

	search = search_gui_get_current_search();
	g_return_if_fail(search);

	if (selected_record) {
		char *magnet = search_gui_get_magnet(search, selected_record);
		clipboard_set_text(gui_main_window(), magnet);
		HFREE_NULL(magnet);
	}
}

void
search_gui_callbacks_shutdown(void)
{
	/*
 	 *	Remove delayed callbacks
 	 */
	cq_cancel(&row_selected_ev);
	search_gui_clear_details();
	if (selected_record) {
		search_gui_unref_record(selected_record);
		selected_record = NULL;
	}
}

/* -*- mode: cc-mode; tab-width:4; -*- */
/* vi: set ts=4 sw=4 cindent: */
