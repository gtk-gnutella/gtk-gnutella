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

#include "nodes_gui.h"

/*
 * gNet connections table columns
 */
enum {
    COL_NODE_HOST,
    COL_NODE_TYPE,
    COL_NODE_VENDOR,
    COL_NODE_VERSION,
    COL_NODE_CONNECTED,
    COL_NODE_UPTIME,
    COL_NODE_INFO,
    COL_NODE_HANDLE,
    NODE_COLUMNS
};

static gchar gui_tmp[4096];
static GtkListStore *nodes_model = NULL;

static void nodes_gui_node_removed(
    gnet_node_t n, guint32, guint32);
static void nodes_gui_node_added(
    gnet_node_t n, const gchar *t, guint32, guint32);
static void nodes_gui_node_info_changed(gnet_node_t);
static void nodes_gui_add_column(GtkTreeView *, gint, const gchar *);

/*
 * nodes_gui_find_node:
 *
 * Fetches the GtkTreeIter that points to the row which holds the
 * data about the given node.
 */
gboolean nodes_gui_find_node(gnet_node_t n, GtkTreeIter *iter)
{
    gboolean valid;
    
    g_assert(iter != NULL);

    valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(nodes_model), iter);

    while (valid) {
        GValue val = { 0, };

        gtk_tree_model_get_value(GTK_TREE_MODEL(nodes_model), 
            iter, COL_NODE_HANDLE, &val);

        if (g_value_get_uint(&val) == n)
            break;

        valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(nodes_model), iter);
    }

    return valid;
}

/*
 * nodes_gui_early_init:
 *
 * Initialized the widgets.
 */
void nodes_gui_early_init(void)
{
    // FIXME: create a popup again.
    //popup_nodes = create_popup_nodes();
}

/*
 * nodes_gui_init:
 *
 * Initialize the nodes controller. Register callbacks in the backend.
 */
void nodes_gui_init() 
{
    GtkTreeView *tree;

    /* Create a model.  We are using the store model for now, though we
     * could use any other GtkTreeModel */
    nodes_model = gtk_list_store_new(NODE_COLUMNS, 
        G_TYPE_STRING,   /* COL_NODE_HOST */
        G_TYPE_STRING,   /* COL_NODE_TYPE */
        G_TYPE_STRING,   /* COL_NODE_VENDOR */
        G_TYPE_STRING,   /* COL_NODE_VERSION */
        G_TYPE_STRING,   /* COL_NODE_CONNECTED */
        G_TYPE_STRING,   /* COL_NODE_UPTIME */
        G_TYPE_STRING,   /* COL_NODE_INFO */
        G_TYPE_UINT);    /* COL_NODE_HANDLE */

    /* Get the monitor widget */
    tree = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_nodes"));

    gtk_tree_view_set_model(tree, GTK_TREE_MODEL(nodes_model));

    /* The view now holds a reference.  We can get rid of our own
     * reference */
    g_object_unref(G_OBJECT (nodes_model));


    nodes_gui_add_column(tree, COL_NODE_HOST, "Host");
    nodes_gui_add_column(tree, COL_NODE_TYPE, "Type");
    nodes_gui_add_column(tree, COL_NODE_VENDOR, "Vendor");
    nodes_gui_add_column(tree, COL_NODE_VERSION, "Ver");
    nodes_gui_add_column(tree, COL_NODE_CONNECTED, "Connected");
    nodes_gui_add_column(tree, COL_NODE_UPTIME, "Uptime");
    nodes_gui_add_column(tree, COL_NODE_INFO, "Info");

    node_add_node_added_listener(nodes_gui_node_added);
    node_add_node_removed_listener(nodes_gui_node_removed);
    node_add_node_info_changed_listener(nodes_gui_node_info_changed);
}

/*
 * nodes_gui_shutdown:
 *
 * Unregister callbacks in the backend and clean up.
 */
void nodes_gui_shutdown() 
{
    node_remove_node_added_listener(nodes_gui_node_added);
    node_remove_node_removed_listener(nodes_gui_node_removed);
    node_remove_node_info_changed_listener(nodes_gui_node_info_changed);
}

/*
 * nodes_gui_remove_node:
 *
 * Removes all references to the given node handle in the gui.
 */
void nodes_gui_remove_node(gnet_node_t n)
{
    GtkTreeIter iter;
    gboolean valid;

    valid = nodes_gui_find_node(n, &iter);

    if (valid)
        gtk_list_store_remove(nodes_model, &iter);
    else
        g_warning("nodes_gui_remove_node: no matching row found");
}

/*
 * nodes_gui_add_node:
 *
 * Adds the given node to the gui.
 */
void nodes_gui_add_node(gnet_node_info_t *n, const gchar *type)
{
    GtkTreeIter iter;
	gchar proto_tmp[16];
    gchar type_tmp[64];
    guint handle;

    g_assert(n != NULL);

    gtk_list_store_append(nodes_model, &iter);

   	g_snprintf(proto_tmp, sizeof(proto_tmp), "%d.%d",
		n->proto_major, n->proto_minor);
    g_snprintf(type_tmp, sizeof(type_tmp), "%s", type);
    handle = n->node_handle;

    gtk_list_store_set(nodes_model, &iter, 
        COL_NODE_HOST,    ip_port_to_gchar(n->ip, n->port),
        COL_NODE_TYPE,    type_tmp,
        COL_NODE_VENDOR,  n->vendor ? n->vendor : "...",
        COL_NODE_VERSION, proto_tmp,
        COL_NODE_CONNECTED, "...",
        COL_NODE_UPTIME,  "...",
        COL_NODE_INFO,    "...",
        COL_NODE_HANDLE,  handle,
        -1);
}



/*
 * gui_node_status_str
 *
 * Compute info string for node.
 * Returns pointer to static data.
 */
static gchar *gui_node_status_str(const gnet_node_status_t *n, time_t now)
{
	gchar *a;

	switch (n->status) {
	case GTA_NODE_CONNECTING:
		a = "Connecting...";
		break;

	case GTA_NODE_HELLO_SENT:
		a = "Hello sent";
		break;

	case GTA_NODE_WELCOME_SENT:
		a = "Welcome sent";
		break;

	case GTA_NODE_CONNECTED:
		if (n->sent || n->received) {
			gint slen = 0;
			if (n->tx_compressed)
				slen += g_snprintf(gui_tmp, sizeof(gui_tmp), "TXc=%d,%d%%",
					n->sent, (gint) (n->tx_compression_ratio * 100));
			else
				slen += g_snprintf(gui_tmp, sizeof(gui_tmp), "TX=%d", n->sent);

			if (n->rx_compressed)
				slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" RXc=%d,%d%%",
					n->received, (gint) (n->rx_compression_ratio * 100));
			else
				slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" RX=%d", n->received);

			slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				" Query(TX=%d, Q=%d) Drop(TX=%d, RX=%d)"
				" Dup=%d Bad=%d W=%d Q=%d,%d%% %s",
				n->squeue_sent, n->squeue_count,
				n->tx_dropped, n->rx_dropped, n->n_dups, n->n_bad, n->n_weird,
				n->mqueue_count, n->mqueue_percent_used,
				n->in_tx_flow_control ? " [FC]" : "");
			a = gui_tmp;
		} else
			a = "Connected";
		break;

	case GTA_NODE_SHUTDOWN:
		{
			g_snprintf(gui_tmp, sizeof(gui_tmp),
				"Closing: %s [Stop in %ds] RX=%d Q=%d,%d%%",
				n->message, n->shutdown_remain, n->received,
				n->mqueue_count, n->mqueue_percent_used);
			a = gui_tmp;
		}
		break;

	case GTA_NODE_REMOVING:
		a = (gchar *) ((*n->message) ? n->message : "Removing");
		break;

	case GTA_NODE_RECEIVING_HELLO:
		a = "Receiving hello";
		break;

	default:
		a = "UNKNOWN STATUS";
	}

	return a;
}



void gui_update_c_gnutellanet(guint32 cnodes, guint32 nodes)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_connections"));
    gfloat frac;
    
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u gnutellaNet", cnodes, nodes);
    gtk_progress_bar_set_text(pg, gui_tmp);

    frac = MIN(cnodes, nodes) != 0 ? (float)MIN(cnodes, nodes) / nodes : 0;

    gtk_progress_bar_set_fraction(pg, frac);
}



/*
 * gui_update_nodes_display
 *
 * Update all the nodes at the same time.
 */

// FIXME: we should remember for every node when it was last
//        updated and only refresh every node at most once every
//        second. This information should be kept in a struct pointed
//        to by the row user_data and should be automatically freed
//        when removing the row (see upload stats code).

void nodes_gui_update_nodes_display(time_t now)
{
    static time_t last_update = 0;
    GtkTreeIter iter;
    gboolean valid;
    gnet_node_status_t status;

    if (last_update == now)
        return;

    valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(nodes_model), &iter);
    
    while (valid) {
        GValue val = { 0, };
        gchar timestr[32];

        gtk_tree_model_get_value(GTK_TREE_MODEL(nodes_model),
            &iter, COL_NODE_HANDLE, &val);

        node_get_status(g_value_get_uint(&val), &status);

		g_strlcpy(timestr, status.connect_date ? 
			short_uptime(now - status.connect_date)  : "...", sizeof(timestr));
        gtk_list_store_set(nodes_model, &iter, 
            COL_NODE_CONNECTED, timestr,
            COL_NODE_UPTIME, status.up_date ?
				short_uptime(now - status.up_date) : "...",
            COL_NODE_INFO, gui_node_status_str(&status, now),
            -1);

        valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(nodes_model), &iter);
    }
}

void nodes_gui_update_node_info(gnet_node_info_t *n)
{
    GtkTreeIter iter;
    gboolean valid;

    g_assert(n != NULL);

    valid = nodes_gui_find_node(n->node_handle, &iter);

    if (valid) {
		gchar version[16];
        gnet_node_status_t status;
        time_t now = time((time_t *) NULL);

        node_get_status(n->node_handle, &status);

        g_snprintf(version, sizeof(version), "%d.%d",
            n->proto_major, n->proto_minor);

        gtk_list_store_set(nodes_model, &iter, 
            COL_NODE_VENDOR,  n->vendor ? n->vendor : "...",
            COL_NODE_VERSION, version,
            COL_NODE_INFO,    gui_node_status_str(&status, now),
            -1);
    } else
        g_warning("nodes_gui_update_node: no matching row found");
}




/***
 *** Callbacks
 ***/

/*
 * nodes_gui_node_removed:
 *
 * Callback: called when a node is removed from the backend.
 *
 * Removes all references to the node from the frontend.
 */
static void nodes_gui_node_removed(
    gnet_node_t n, guint32 connected, guint32 total)
{
    if (gui_debug >= 5)
        printf("nodes_gui_node_removed(%u)\n", n);

    nodes_gui_remove_node(n);
    gui_update_c_gnutellanet(connected, total);
}

/*
 * nodes_gui_node_added:
 *
 * Callback: called when a node is added from the backend.
 *
 * Adds the node to the gui.
 */
static void nodes_gui_node_added(
    gnet_node_t n, const gchar *t, guint32 connected, guint32 total)
{
    gnet_node_info_t *info;

    if (gui_debug >= 5)
        printf("nodes_gui_node_added(%u, %s)\n", n, t);

    info = node_get_info(n);
    nodes_gui_add_node(info, t);
    gui_update_c_gnutellanet(connected, total);
    node_free_info(info);
}

/*
 * nodes_gui_node_changed:
 *
 * Callback: called when node information was changed by the backend.
 *
 * This updates the node information in the gui. 
 */
static void nodes_gui_node_info_changed(gnet_node_t n)
{
    gnet_node_info_t *info;
    
    info = node_get_info(n);

    nodes_gui_update_node_info(info);

    node_free_info(info);
}


/* Create a column, associating the "text" attribute of the
 * cell_renderer to the first column of the model */
static void nodes_gui_add_column(
	GtkTreeView *tree, gint column_id, const gchar *title)
{
    GtkTreeViewColumn *column;

    column = gtk_tree_view_column_new_with_attributes 
        (title, gtk_cell_renderer_text_new (), "text", column_id, NULL);
    gtk_tree_view_column_set_reorderable(column, TRUE);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);
}
