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

#include "gnutella.h"
#include "nodes_gui.h"
#include "gtk-missing.h"

#include "gui_property_priv.h"

static gchar gui_tmp[4096];

static void nodes_gui_node_removed(gnet_node_t n);
static void nodes_gui_node_added(gnet_node_t n, const gchar *t);
static void nodes_gui_node_changed
    (gnet_node_t, gboolean, gboolean, gboolean);

/*
 * nodes_gui_init:
 *
 * Initialize the nodes controller. Register callbacks in the backend.
 */
void nodes_gui_init() 
{
    node_add_node_added_listener(nodes_gui_node_added);
    node_add_node_removed_listener(nodes_gui_node_removed);
    node_add_node_changed_listener(nodes_gui_node_changed);
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
    node_remove_node_changed_listener(nodes_gui_node_changed);
}

static void nodes_gui_update_node_proto(gnet_node_info_t *n)
{
	gint row;
    GtkCList *clist = GTK_CLIST
        (lookup_widget(main_window, "clist_nodes"));

    g_assert(n != NULL);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%d.%d",
		n->proto_major, n->proto_minor);

	row = gtk_clist_find_row_from_data(clist, (gpointer) n->node_handle);
    if (row != -1)
        gtk_clist_set_text(clist, row, 3, gui_tmp);
    else
        g_warning("nodes_gui_update_node_proto: no matching row found");
}

static void nodes_gui_update_node_vendor(gnet_node_info_t *n)
{
	gint row;
    GtkCList *clist = GTK_CLIST
        (lookup_widget(main_window, "clist_nodes"));

    g_assert(n != NULL);

	row = gtk_clist_find_row_from_data(clist, (gpointer) n->node_handle);
    if (row != -1)
        gtk_clist_set_text(clist, row, 2, n->vendor ? n->vendor : "");
    else
        g_warning("nodes_gui_update_node_vendor: no matching row found");
}


/*
 * nodes_gui_remove_node:
 *
 * Removes all references to the given node handle in the gui.
 */
void nodes_gui_remove_node(gnet_node_t n)
{
    GtkWidget *clist_nodes;
    gint row;

    clist_nodes = lookup_widget(main_window, "clist_nodes");

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
    if (row != -1)
        gtk_clist_remove(GTK_CLIST(clist_nodes), row);
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
    GtkCList *clist_nodes;
    gint row;
	gchar *titles[5];
	gchar proto_tmp[16];

    g_assert(n != NULL);

   	g_snprintf(proto_tmp, sizeof(proto_tmp), "%d.%d",
		n->proto_major, n->proto_minor);

    titles[0] = ip_port_to_gchar(n->ip, n->port);
    titles[1] = g_strdup(type);
    titles[2] = "...";
    titles[3] = proto_tmp;
    titles[4] = "...";

    clist_nodes = GTK_CLIST(lookup_widget(main_window, "clist_nodes"));

    row = gtk_clist_append(clist_nodes, titles);
    gtk_clist_set_row_data(clist_nodes, row, (gpointer) n->node_handle);
    
    g_free(titles[1]);
}

/*
 * gui_node_info_str
 *
 * Compute info string for node.
 * Returns pointer to static data.
 */
static gchar *gui_node_info_str(const gnet_node_info_t *n, time_t now)
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
			gint spent = now - n->shutdown_date;
			gint remain = n->shutdown_delay - spent;
			if (remain < 0)
				remain = 0;
			g_snprintf(gui_tmp, sizeof(gui_tmp),
				"Closing: %s [Stop in %ds] RX=%d Q=%d,%d%%",
				n->error_str, remain, n->received,
				n->mqueue_count, n->mqueue_percent_used);
			a = gui_tmp;
		}
		break;

	case GTA_NODE_REMOVING:
		a = (gchar *) ((n->remove_msg) ? n->remove_msg : "Removing");
		break;

	case GTA_NODE_RECEIVING_HELLO:
		a = "Receiving hello";
		break;

	default:
		a = "UNKNOWN STATUS";
	}

	return a;
}



/*
 * gui_update_nodes_display
 *
 * Update all the nodes at the same time.
 */
void nodes_gui_update_nodes_display(time_t now)
{
    static time_t last_update = 0;
	GtkCList *clist;
	GList *l;
	gchar *a;
	gint row = 0;

    if (last_update == now)
        return;

    clist = GTK_CLIST(lookup_widget(main_window, "clist_nodes"));

    last_update = now;

    gtk_clist_freeze(clist);

	for (l = clist->row_list, row = 0; l; l = l->next, row++) {
		gnet_node_t n = (gnet_node_t) ((GtkCListRow *) l->data)->data;
        gnet_node_info_t *info;

        info = node_get_info(n);
        if (info->last_update != now) {
            a = gui_node_info_str(info, now);
            gtk_clist_set_text(clist, row, 4, a);
        }
        node_free_info(info);
	}

    gtk_clist_thaw(clist);
}



static void gui_update_node_display(gnet_node_info_t *n, time_t now)
{
	gchar *a;
	gint row;
    GtkCList *clist = GTK_CLIST
        (lookup_widget(main_window, "clist_nodes"));
	a = gui_node_info_str(n, now);

	row = gtk_clist_find_row_from_data(clist, (gpointer) n->node_handle);
	gtk_clist_set_text(clist, row, 4, a);
}

void nodes_gui_update_node
    (gnet_node_info_t *n, gboolean force, gboolean vendor, gboolean proto)
{
	time_t now = time((time_t *) NULL);

    if (vendor)
        nodes_gui_update_node_vendor(n);
    if (proto)
        nodes_gui_update_node_proto(n);

	if (n->last_update == now && !force)
		return;
	n->last_update = now;

	gui_update_node_display(n, now);
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
static void nodes_gui_node_removed(gnet_node_t n)
{
    if (gui_debug >= 5)
        printf("nodes_gui_node_removed(%u)\n", n);

    nodes_gui_remove_node(n);
    gui_update_c_gnutellanet();
}

/*
 * nodes_gui_node_added:
 *
 * Callback: called when a node is added from the backend.
 *
 * Adds the node to the gui.
 */
static void nodes_gui_node_added(gnet_node_t n, const gchar *t)
{
    gnet_node_info_t *info;

    if (gui_debug >= 5)
        printf("nodes_gui_node_added(%u, %s)\n", n, t);

    info = node_get_info(n);
    nodes_gui_add_node(info, t);
    gui_update_c_gnutellanet();
    node_free_info(info);
}

/*
 * nodes_gui_node_changed:
 *
 * Callback: called when node information was changed by the backend.
 *
 * This updates the node information in the gui. If important is TRUE,
 * the update is forced and the connection stats are refreshed.
 */
static void nodes_gui_node_changed
    (gnet_node_t n, gboolean important, gboolean vendor, gboolean proto)
{
    gnet_node_info_t *info;

    if (gui_debug >= 5)
        printf("nodes_gui_node_changed(%u, %d, %d, %d)\n", n, important,
            vendor, proto);

    info = node_get_info(n);

    nodes_gui_update_node(info, important, vendor, proto);
    if (important)
        gui_update_c_gnutellanet();
    node_free_info(info);
}
