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

#ifdef USE_GTK1

#include "interface-glade1.h"
#include "nodes_gui_common.h"
#include "nodes_gui.h"

RCSID("$Id$");

static gchar gui_tmp[4096];

static void nodes_gui_update_node_info(gnet_node_info_t *n);
static void nodes_gui_update_node_flags(
	gnet_node_t n, gnet_node_flags_t *flags);


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
    node_free_info(info);
}

/*
 * nodes_gui_node_info_changed:
 *
 * Callback: called when node information was changed by the backend.
 *
 * This updates the node information in the gui. 
 */
static void nodes_gui_node_info_changed(gnet_node_t n)
{
    gnet_node_info_t info;
    
    node_fill_info(n, &info);
    nodes_gui_update_node_info(&info);
    node_clear_info(&info);
}

/*
 * nodes_gui_node_flags_changed
 *
 * Callback invoked when the node's user-visible flags are changed.
 */
static void nodes_gui_node_flags_changed(gnet_node_t n)
{
    gnet_node_flags_t flags;

    node_fill_flags(n, &flags);
    nodes_gui_update_node_flags(n, &flags);
}


/***
 *** Private functions
 ***/

static void nodes_gui_update_node_info(gnet_node_info_t *n)
{
	gint row;
    GtkCList *clist = GTK_CLIST
        (lookup_widget(main_window, "clist_nodes"));

    g_assert(n != NULL);

	row = gtk_clist_find_row_from_data(clist, GUINT_TO_POINTER(n->node_handle));

    if (row != -1) {
        gnet_node_status_t status;
        time_t now = time((time_t *) NULL);

        node_get_status(n->node_handle, &status);

        gtk_clist_set_text(clist, row, 2, n->vendor ? n->vendor : "...");

        gm_snprintf(gui_tmp, sizeof(gui_tmp), "%d.%d",
            n->proto_major, n->proto_minor);
        gtk_clist_set_text(clist, row, 3, gui_tmp);

		if (status.status == GTA_NODE_CONNECTED)
	        gtk_clist_set_text(clist, row, 4, 
       			short_uptime(now - status.connect_date));

		if (status.up_date)
    	    gtk_clist_set_text(clist, row, 5, 
	        	status.up_date ?  short_uptime(now - status.up_date) : "...");

        gtk_clist_set_text(clist, row, 6,
			nodes_gui_common_status_str(&status, now));
    } else {
        g_warning("%s: no matching row found", G_GNUC_PRETTY_FUNCTION);
    }
}

/*
 * nodes_gui_update_node_flags
 *
 */
static void nodes_gui_update_node_flags(gnet_node_t n, gnet_node_flags_t *flags)
{
	gint row;
    GtkCList *clist = GTK_CLIST
        (lookup_widget(main_window, "clist_nodes"));

	row = gtk_clist_find_row_from_data(clist, GUINT_TO_POINTER(n));
    if (row != -1) {
        gtk_clist_set_text(clist, row, 1,
			nodes_gui_common_flags_str(flags));
    } else {
        g_warning("%s: no matching row found", G_GNUC_PRETTY_FUNCTION);
    }
}

/***
 *** Public functions
 ***/

/*
 * nodes_gui_early_init:
 *
 * Initialized the widgets.
 */
void nodes_gui_early_init(void)
{
	popup_nodes = create_popup_nodes();
}

/*
 * nodes_gui_init:
 *
 * Initialize the nodes controller. Register callbacks in the backend.
 */
void nodes_gui_init(void) 
{
    gtk_clist_column_titles_passive(
        GTK_CLIST(lookup_widget(main_window, "clist_nodes")));

    gtk_widget_set_sensitive
        (lookup_widget(popup_nodes, "popup_nodes_remove"), FALSE);

    node_add_node_added_listener(nodes_gui_node_added);
    node_add_node_removed_listener(nodes_gui_node_removed);
    node_add_node_info_changed_listener(nodes_gui_node_info_changed);
    node_add_node_flags_changed_listener(nodes_gui_node_flags_changed);
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
    GtkWidget *clist_nodes;
    gint row;

    clist_nodes = lookup_widget(main_window, "clist_nodes");

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes),
		GUINT_TO_POINTER(n));
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
	gchar *titles[7];
	gchar proto_tmp[32];

    g_assert(n != NULL);

   	gm_snprintf(proto_tmp, sizeof(proto_tmp), "%d.%d",
		n->proto_major, n->proto_minor);

    titles[0] = ip_port_to_gchar(n->ip, n->port);
    titles[1] = "...";
    titles[2] = n->vendor ? n->vendor : "...";
    titles[3] = proto_tmp;
    titles[4] = "...";
    titles[5] = "...";
    titles[6] = "...";

    clist_nodes = GTK_CLIST(lookup_widget(main_window, "clist_nodes"));

    row = gtk_clist_append(clist_nodes, titles);
    gtk_clist_set_row_data(clist_nodes, row, GUINT_TO_POINTER(n->node_handle));
}



/*
 * gui_update_nodes_display
 *
 * Update all the nodes at the same time.
 */

/* FIXME: we should remember for every node when it was last
 *        updated and only refresh every node at most once every
 *        second. This information should be kept in a struct pointed
 *        to by the row user_data and should be automatically freed
 *        when removing the row (see upload stats code).
 */
void nodes_gui_update_nodes_display(time_t now)
{
    static time_t last_update = 0;
	GtkCList *clist;
	GList *l;
	gint row = 0;
    gnet_node_status_t status;

    if (last_update == now)
        return;

    last_update = now;


    clist = GTK_CLIST(lookup_widget(main_window, "clist_nodes"));
    gtk_clist_freeze(clist);

	for (l = clist->row_list, row = 0; l; l = l->next, row++) {
		gnet_node_t n =
			(gnet_node_t) GPOINTER_TO_UINT(((GtkCListRow *) l->data)->data);

        node_get_status(n, &status);

		/*
		 * Don't update times if we've already disconnected.
		 */

		if (status.status == GTA_NODE_CONNECTED) {
	        gtk_clist_set_text(clist, row, 4, 
        			short_uptime(now - status.connect_date));
		
			if (status.up_date)
				gtk_clist_set_text(clist, row, 5, 
					status.up_date ?
						short_uptime(now - status.up_date) : "...");
		}
        gtk_clist_set_text(clist, row, 6,
			nodes_gui_common_status_str(&status, now));
    }
    gtk_clist_thaw(clist);
}

#endif	/* USE_GTK1 */
