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

#include "common.h"

RCSID("$Id$")

#include "gtk/gui.h"
#include "gtk/misc.h"
#include "gtk/nodes_common.h"
#include "gtk/nodes.h"
#include "gtk/notebooks.h"
#include "gtk/columns.h"

#include "if/gui_property_priv.h"
#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/glib-missing.h"
#include "lib/iso3166.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/override.h"	/* Must be the last header included */

#define UPDATE_MIN	60		/**< Update screen every minute at least */

/*
 * These hash tables record which information about which nodes has
 * changed. By using this the number of updates to the gui can be
 * significantly reduced.
 */
static GHashTable *ht_node_info_changed;
static GHashTable *ht_node_flags_changed;

static void nodes_gui_update_node_info(gnet_node_info_t *n, gint row);
static void nodes_gui_update_node_flags(const node_id_t node_id,
				gnet_node_flags_t *flags, gint row);

static gboolean 
remove_item(GHashTable *ht, const node_id_t node_id)
{
	gpointer orig_key;

	g_return_val_if_fail(ht, FALSE);
	g_return_val_if_fail(node_id, FALSE);
	
	orig_key = g_hash_table_lookup(ht, node_id);
	if (orig_key) {
    	g_hash_table_remove(ht, orig_key);
		node_id_unref(orig_key);
		return TRUE;
	} else {
		return FALSE;
	}
}

static gboolean
nodes_gui_is_visible(void)
{
	static GtkNotebook *notebook = NULL;
	gint current_page;

	if (!main_gui_window_visible())
		return FALSE;

	if (notebook == NULL)
		notebook = GTK_NOTEBOOK(gui_main_window_lookup("notebook_main"));

	current_page = gtk_notebook_get_current_page(notebook);

	return current_page == nb_main_page_network;
}

/***
 *** Callbacks
 ***/

/**
 * Callback: called when a node is removed from the backend.
 *
 * Removes all references to the node from the frontend.
 */
static void
nodes_gui_node_removed(const node_id_t node_id)
{
    if (GUI_PROPERTY(gui_debug) >= 5)
        g_message("nodes_gui_node_removed(%s)", node_id_to_string(node_id));

    nodes_gui_remove_node(node_id);
}

/**
 * Callback: called when a node is added from the backend.
 *
 * Adds the node to the gui.
 */
static void
nodes_gui_node_added(const node_id_t node_id)
{
    gnet_node_info_t info;

    if (GUI_PROPERTY(gui_debug) >= 5)
        g_message("nodes_gui_node_added(%s)", node_id_to_string(node_id));

    guc_node_fill_info(node_id, &info);
    nodes_gui_add_node(&info);
    guc_node_clear_info(&info);
}

/**
 * Callback: called when node information was changed by the backend.
 *
 * This schedules an update of the node information in the gui at the
 * next tick.
 */
static void
nodes_gui_node_info_changed(const node_id_t node_id)
{
    if (!g_hash_table_lookup(ht_node_info_changed, node_id)) {
		const node_id_t key = node_id_ref(node_id);
    	gm_hash_table_insert_const(ht_node_info_changed, key, key);
	}
}

/**
 * Callback invoked when the node's user-visible flags are changed.
 *
 * This schedules an update of the node information in the gui at the
 * next tick.
 */
static void
nodes_gui_node_flags_changed(const node_id_t node_id)
{
    if (!g_hash_table_lookup(ht_node_flags_changed, node_id)) {
		const node_id_t key = node_id_ref(node_id);
    	gm_hash_table_insert_const(ht_node_flags_changed, key, key);
	}
}


/***
 *** Private functions
 ***/

/**
 * Update the row with the given nodeinfo. If row is -1 the row number
 * is determined by the node_id contained in the gnet_node_info_t.
 */
static void
nodes_gui_update_node_info(gnet_node_info_t *n, gint row)
{
    GtkCList *clist = GTK_CLIST(gui_main_window_lookup("clist_nodes"));

    g_assert(n != NULL);

    if (row == -1) {
        row = gtk_clist_find_row_from_data(clist,
					deconstify_gpointer(n->node_id));
    }

    if (row != -1) {
		gchar ver_buf[64];
        gnet_node_status_t status;
        time_t now = tm_time();

        if (guc_node_get_status(n->node_id, &status)) {
			gtk_clist_set_text(clist, row, c_gnet_user_agent,
					n->vendor ? lazy_utf8_to_locale(n->vendor) : "...");

			gtk_clist_set_text(clist, row, c_gnet_loc,
					deconstify_gchar(iso3166_country_cc(n->country)));

			gm_snprintf(ver_buf, sizeof ver_buf, "%d.%d",
					n->proto_major, n->proto_minor);
			gtk_clist_set_text(clist, row, c_gnet_version, ver_buf);

			if (status.status == GTA_NODE_CONNECTED)
				gtk_clist_set_text(clist, row, c_gnet_connected,
						short_uptime(delta_time(now, status.connect_date)));

			if (status.up_date)
				gtk_clist_set_text(clist, row, c_gnet_uptime,
						status.up_date
						? short_uptime(delta_time(now, status.up_date)) : "...");

			gtk_clist_set_text(clist, row, c_gnet_info,
					nodes_gui_common_status_str(&status));
		}
    } else {
        g_warning("%s: no matching row found", G_GNUC_PRETTY_FUNCTION);
    }
}

/**
 * Updates the flags for given node and row.
 */
static void
nodes_gui_update_node_flags(const node_id_t node_id, gnet_node_flags_t *flags,
	gint row)
{
    GtkCList *clist = GTK_CLIST(gui_main_window_lookup("clist_nodes"));

    if (row == -1)
        row = gtk_clist_find_row_from_data(clist, deconstify_gpointer(node_id));

    if (row != -1) {
        gtk_clist_set_text(clist, row, c_gnet_flags,
			guc_node_flags_to_string(flags));
	if (NODE_P_LEAF == flags->peermode || NODE_P_NORMAL == flags->peermode) {
		GdkColor *color = &(gtk_widget_get_style(GTK_WIDGET(clist))
			->fg[GTK_STATE_INSENSITIVE]);
		gtk_clist_set_foreground(clist, row, color);
	}

    } else {
        g_warning("%s: no matching row found", G_GNUC_PRETTY_FUNCTION);
    }
}

/***
 *** Public functions
 ***/

/**
 * Initialized the widgets.
 */
void
nodes_gui_early_init(void)
{
	static const struct {
		const gchar *name;
	} items[] = {
		{ "popup_nodes_disconnect" },
		{ "popup_nodes_browse_host" },
	};
	guint i;
	
	for (i = 0; i < G_N_ELEMENTS(items); i++) {
    	gtk_widget_set_sensitive(gui_popup_nodes_lookup(items[i].name),
			FALSE);
	}
}

static const char *
nodes_gui_column_title(int column)
{
	switch ((enum c_gnet) column) {
    case c_gnet_host:		return _("Host");
    case c_gnet_loc:		return _("Country");
	case c_gnet_flags:		return _("Flags");
	case c_gnet_user_agent:	return _("User-Agent");
	case c_gnet_version:	return _("Ver");
	case c_gnet_connected:	return _("Connected time");
	case c_gnet_uptime:		return _("Uptime");
	case c_gnet_info:		return _("Status");
	case c_gnet_num:
		break;
	}
	g_assert_not_reached();
	return NULL;
}

/**
 * Initialize the nodes controller. Register callbacks in the backend.
 */
void
nodes_gui_init(void)
{
	unsigned i;
	GtkCList *clist;

	clist = GTK_CLIST(gui_main_window_lookup("clist_nodes"));

    gtk_clist_column_titles_passive(clist);
	for (i = 0; i < c_gnet_num; i++) {
    	gtk_clist_set_column_name(clist, i, nodes_gui_column_title(i));
	}
	clist_restore_visibility(clist, PROP_NODES_COL_VISIBLE);
	clist_restore_widths(clist, PROP_NODES_COL_WIDTHS);

    ht_node_info_changed = g_hash_table_new(node_id_hash, node_id_eq_func);
    ht_node_flags_changed = g_hash_table_new(node_id_hash, node_id_eq_func);

    guc_node_add_node_added_listener(nodes_gui_node_added);
    guc_node_add_node_removed_listener(nodes_gui_node_removed);
    guc_node_add_node_info_changed_listener(nodes_gui_node_info_changed);
    guc_node_add_node_flags_changed_listener(nodes_gui_node_flags_changed);
}

static gboolean
free_node_id(gpointer key, gpointer value, gpointer unused_udata)
{
	g_assert(key == value);
	(void) unused_udata;
	node_id_unref(key);
	return TRUE;
}

static void
nodes_gui_remove_all_nodes(void)
{
	GtkCList *clist;
	GList *iter;

    clist = GTK_CLIST(gui_main_window_lookup("clist_nodes"));
	g_return_if_fail(clist);

    gtk_clist_freeze(clist);
	for (iter = clist->row_list; NULL != iter; iter = g_list_next(iter)) {
		const node_id_t node_id = ((GtkCListRow *) iter->data)->data;
		node_id_unref(node_id);
	}
    gtk_clist_thaw(clist);

}

/**
 * Unregister callbacks in the backend and clean up.
 */
void
nodes_gui_shutdown(void)
{
	GtkCList *clist;

	clist = GTK_CLIST(gui_main_window_lookup("clist_nodes"));
	clist_save_visibility(clist, PROP_NODES_COL_VISIBLE);
	clist_save_widths(clist, PROP_NODES_COL_WIDTHS);

    guc_node_remove_node_added_listener(nodes_gui_node_added);
    guc_node_remove_node_removed_listener(nodes_gui_node_removed);
    guc_node_remove_node_info_changed_listener(nodes_gui_node_info_changed);
    guc_node_remove_node_flags_changed_listener(nodes_gui_node_flags_changed);

	g_hash_table_foreach_remove(ht_node_info_changed, free_node_id, NULL);
    g_hash_table_destroy(ht_node_info_changed);
    ht_node_info_changed = NULL;

	g_hash_table_foreach_remove(ht_node_flags_changed, free_node_id, NULL);
    g_hash_table_destroy(ht_node_flags_changed);
    ht_node_flags_changed = NULL;

	nodes_gui_remove_all_nodes();
}

/**
 * Removes all references to the given node handle in the gui.
 */
void
nodes_gui_remove_node(const node_id_t node_id)
{
    GtkWidget *clist_nodes;
    gint row;

    clist_nodes = gui_main_window_lookup("clist_nodes");

    /*
     * Make sure node is remove from the "changed" hash table so
     * we don't try an update.
     */
    g_assert(NULL != ht_node_info_changed);
    g_assert(NULL != ht_node_flags_changed);

    remove_item(ht_node_info_changed, node_id);
    remove_item(ht_node_flags_changed, node_id);

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes),
				deconstify_gpointer(node_id));
    if (row != -1) {
        gtk_clist_remove(GTK_CLIST(clist_nodes), row);
		node_id_unref(node_id);
	} else {
        g_warning("nodes_gui_remove_node: no matching row found");
	}
}

/**
 * Adds the given node to the gui.
 */
void
nodes_gui_add_node(gnet_node_info_t *n)
{
    GtkCList *clist_nodes;
	const gchar *titles[c_gnet_num];
	gchar proto_tmp[32];
    gint row;

    g_assert(n != NULL);

   	gm_snprintf(proto_tmp, sizeof proto_tmp, "%d.%d",
		n->proto_major, n->proto_minor);

    titles[c_gnet_host]       = host_addr_port_to_string(n->addr, n->port);
    titles[c_gnet_flags]      = "...";
    titles[c_gnet_user_agent] = n->vendor
									? lazy_utf8_to_locale(n->vendor)
									: "...";
    titles[c_gnet_loc]        = iso3166_country_cc(n->country);
    titles[c_gnet_version]    = proto_tmp;
    titles[c_gnet_connected]  = "...";
    titles[c_gnet_uptime]     = "...";
    titles[c_gnet_info]       = "...";

    clist_nodes = GTK_CLIST(gui_main_window_lookup("clist_nodes"));

    row = gtk_clist_append(clist_nodes, (gchar **) titles); /* override const */
    gtk_clist_set_row_data(clist_nodes, row,
		deconstify_gpointer(node_id_ref(n->node_id)));
}

/**
 * Update all the nodes at the same time.
 *
 * @bug
 * FIXME: We should remember for every node when it was last
 *        updated and only refresh every node at most once every
 *        second. This information should be kept in a struct pointed
 *        to by the row user_data and should be automatically freed
 *        when removing the row (see upload stats code).
 */
void
nodes_gui_update_nodes_display(time_t now)
{
	GtkCList *clist;
	GList *l;
	gint row = 0;
    gnet_node_status_t status;
    static time_t last_update = 0;

    if (last_update == now)
        return;

	/*
	 * Usually don't perform updates if nobody is watching.  However,
	 * we do need to perform periodic cleanup of dead entries or the
	 * memory usage will grow.  Perform an update every UPDATE_MIN minutes
	 * at least.
	 *		--RAM, 28/12/2003
	 */
	if (!nodes_gui_is_visible() && delta_time(now, last_update) < UPDATE_MIN)
		return;

    if (last_update == now)
        return;

    last_update = now;

    clist = GTK_CLIST(gui_main_window_lookup("clist_nodes"));
    gtk_clist_freeze(clist);

	for (l = clist->row_list, row = 0; l; l = l->next, row++) {
		const node_id_t node_id = ((GtkCListRow *) l->data)->data;

        guc_node_get_status(node_id, &status);

        /*
         * Update additional info too if it has recorded changes.
         */
        if (remove_item(ht_node_info_changed, node_id)) {
            gnet_node_info_t info;

            guc_node_fill_info(node_id, &info);
            nodes_gui_update_node_info(&info, row);
            guc_node_clear_info(&info);
        }

        if (remove_item(ht_node_flags_changed, node_id)) {
            gnet_node_flags_t flags;

            guc_node_fill_flags(node_id, &flags);
            nodes_gui_update_node_flags(node_id, &flags, -1);
        }

		/*
		 * Don't update times if we've already disconnected.
		 */
		if (status.status == GTA_NODE_CONNECTED) {
	        gtk_clist_set_text(clist, row, c_gnet_connected,
        			short_uptime(delta_time(now, status.connect_date)));

			if (status.up_date)
				gtk_clist_set_text(clist, row, c_gnet_uptime,
					status.up_date ?
						short_uptime(delta_time(now, status.up_date)) : "...");
		}
        gtk_clist_set_text(clist, row, c_gnet_info,
			nodes_gui_common_status_str(&status));
    }
    gtk_clist_thaw(clist);
}

/* vi: set ts=4 sw=4 cindent: */
