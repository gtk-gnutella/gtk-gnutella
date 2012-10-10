/*
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
#include "lib/hset.h"
#include "lib/nid.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/utf8.h"

#include "lib/override.h"	/* Must be the last header included */

/*
 * These hash tables record which information about which nodes has
 * changed. By using this the number of updates to the gui can be
 * significantly reduced.
 */
static hset_t *hs_node_info_changed;
static hset_t *hs_node_flags_changed;

static void nodes_gui_update_node_info(gnet_node_info_t *n, gint row);
static void nodes_gui_update_node_flags(const struct nid *node_id,
				gnet_node_flags_t *flags, gint row);

static bool 
remove_item(hset_t *hs, const struct nid *node_id)
{
	const void *orig_key;

	g_return_val_if_fail(hs, FALSE);
	g_return_val_if_fail(node_id, FALSE);
	
	if (hset_contains_extended(hs, node_id, &orig_key)) {
    	hset_remove(hs, orig_key);
		nid_unref(orig_key);
		return TRUE;
	} else {
		return FALSE;
	}
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
nodes_gui_node_removed(const struct nid *node_id)
{
    if (GUI_PROPERTY(gui_debug) >= 5)
        g_debug("nodes_gui_node_removed(%s)", nid_to_string(node_id));

    nodes_gui_remove_node(node_id);
}

/**
 * Callback: called when a node is added from the backend.
 *
 * Adds the node to the gui.
 */
static void
nodes_gui_node_added(const struct nid *node_id)
{
    gnet_node_info_t info;

    if (GUI_PROPERTY(gui_debug) >= 5)
        g_debug("nodes_gui_node_added(%s)", nid_to_string(node_id));

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
nodes_gui_node_info_changed(const struct nid *node_id)
{
    if (!hset_contains(hs_node_info_changed, node_id)) {
		const struct nid *key = nid_ref(node_id);
    	hset_insert(hs_node_info_changed, key);
	}
}

/**
 * Callback invoked when the node's user-visible flags are changed.
 *
 * This schedules an update of the node information in the gui at the
 * next tick.
 */
static void
nodes_gui_node_flags_changed(const struct nid *node_id)
{
    if (!hset_contains(hs_node_flags_changed, node_id)) {
		const struct nid *key = nid_ref(node_id);
    	hset_insert(hs_node_flags_changed, key);
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
nodes_gui_update_node_flags(const struct nid *node_id, gnet_node_flags_t *flags,
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
	case c_gnet_version:	return _("Version");
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
G_GNUC_COLD void
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

	widget_add_popup_menu(GTK_WIDGET(clist), nodes_gui_get_popup_menu);

    hs_node_info_changed = hset_create_any(nid_hash, nid_hash2, nid_equal);
    hs_node_flags_changed = hset_create_any(nid_hash, nid_hash2, nid_equal);

    guc_node_add_node_added_listener(nodes_gui_node_added);
    guc_node_add_node_removed_listener(nodes_gui_node_removed);
    guc_node_add_node_info_changed_listener(nodes_gui_node_info_changed);
    guc_node_add_node_flags_changed_listener(nodes_gui_node_flags_changed);

	main_gui_add_timer(nodes_gui_timer);
}

static bool
free_node_id(const void *key, void *unused_udata)
{
	(void) unused_udata;
	nid_unref(key);
	return TRUE;
}

static G_GNUC_COLD void
nodes_gui_remove_all_nodes(void)
{
	GtkCList *clist;
	GList *iter;

    clist = GTK_CLIST(gui_main_window_lookup("clist_nodes"));
	g_return_if_fail(clist);

    gtk_clist_freeze(clist);
	for (iter = clist->row_list; NULL != iter; iter = g_list_next(iter)) {
		const struct nid *node_id = ((GtkCListRow *) iter->data)->data;
		nid_unref(node_id);
	}
    gtk_clist_thaw(clist);

}

/**
 * Unregister callbacks in the backend and clean up.
 */
G_GNUC_COLD void
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

	hset_foreach_remove(hs_node_info_changed, free_node_id, NULL);
    hset_free_null(&hs_node_info_changed);

	hset_foreach_remove(hs_node_flags_changed, free_node_id, NULL);
    hset_free_null(&hs_node_flags_changed);

	nodes_gui_remove_all_nodes();
}

/**
 * Removes all references to the given node handle in the gui.
 */
void
nodes_gui_remove_node(const struct nid *node_id)
{
    GtkWidget *clist_nodes;
    gint row;

    clist_nodes = gui_main_window_lookup("clist_nodes");

    /*
     * Make sure node is remove from the "changed" hash table so
     * we don't try an update.
     */
    g_assert(NULL != hs_node_info_changed);
    g_assert(NULL != hs_node_flags_changed);

    remove_item(hs_node_info_changed, node_id);
    remove_item(hs_node_flags_changed, node_id);

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes),
				deconstify_gpointer(node_id));
    if (row != -1) {
        gtk_clist_remove(GTK_CLIST(clist_nodes), row);
		nid_unref(node_id);
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
		deconstify_gpointer(nid_ref(n->node_id)));
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
nodes_gui_update_display(time_t now)
{
	GtkCList *clist;
	GList *l;
	gint row = 0;
    gnet_node_status_t status;

    clist = GTK_CLIST(gui_main_window_lookup("clist_nodes"));
    gtk_clist_freeze(clist);

	for (l = clist->row_list, row = 0; l; l = l->next, row++) {
		const struct nid *node_id = ((GtkCListRow *) l->data)->data;

        guc_node_get_status(node_id, &status);

        /*
         * Update additional info too if it has recorded changes.
         */
        if (remove_item(hs_node_info_changed, node_id)) {
            gnet_node_info_t info;

            guc_node_fill_info(node_id, &info);
            nodes_gui_update_node_info(&info, row);
            guc_node_clear_info(&info);
        }

        if (remove_item(hs_node_flags_changed, node_id)) {
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
