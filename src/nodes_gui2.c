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
#include "nodes_gui_common.h"
#include "nodes_gui.h"

RCSID("$Id$");

#define pretty_node_vendor(n) ((n)->vendor != NULL ? (n)->vendor : "...")

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

static GtkListStore *nodes_model = NULL;
static GtkCellRenderer *nodes_gui_cell_renderer = NULL;
static GHashTable *nodes_handles = NULL;

/***
 *** Private functions
 ***/

static void nodes_gui_node_removed(gnet_node_t);
static void nodes_gui_node_added(gnet_node_t, const gchar *);
static void nodes_gui_node_info_changed(gnet_node_t);
static void nodes_gui_node_flags_changed(gnet_node_t);

/*
 * on_nodes_gui_column_resized:
 *
 * Callback which updates the column width property
 */
static void on_nodes_gui_column_resized(
	GtkTreeViewColumn *column, GParamSpec *param, gpointer data)
{
    guint32 width;
    gint column_id = GPOINTER_TO_INT(data);
    static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	g_assert(column_id >= 0 && column_id <= 6);
	g_static_mutex_lock(&mutex);
	width = gtk_tree_view_column_get_width(column);
	gui_prop_set_guint32(PROP_NODES_COL_WIDTHS, &width, column_id, 1);
	g_static_mutex_unlock(&mutex);
}

/*
 * nodes_gui_add_column
 *
 * Create a column, associating the "text" attribute of the
 * cell_renderer to the first column of the model
 */
static void nodes_gui_add_column(
	GtkTreeView *tree, gint column_id, const gchar *title)
{
    GtkTreeViewColumn *column;

   	column = gtk_tree_view_column_new_with_attributes(
		title, nodes_gui_cell_renderer, "text", column_id, NULL);
    gtk_tree_view_column_set_reorderable(column, TRUE);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 1);
    gtk_tree_view_append_column(GTK_TREE_VIEW (tree), column);
	g_object_notify(G_OBJECT(column), "width");
	g_signal_connect(G_OBJECT(column), "notify::width",
		G_CALLBACK(on_nodes_gui_column_resized), GINT_TO_POINTER(column_id));
}

static void nodes_gui_remove_selected_helper(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	GSList **list = data;
	guint handle;

	gtk_tree_model_get(model, iter, COL_NODE_HANDLE, &handle, -1);
	*list = g_slist_append(*list, GUINT_TO_POINTER(handle));
}

/*
 * nodes_gui_find_node:
 *
 * Fetches the GtkTreeIter that points to the row which holds the
 * data about the given node.
 */
static gboolean nodes_gui_find_node(gnet_node_t n, GtkTreeIter **iter)
{
	gpointer orig_key;
    
    g_assert(iter != NULL);
	return g_hash_table_lookup_extended(nodes_handles,
		GUINT_TO_POINTER(n), &orig_key, (gpointer) iter);
}

/*
 * nodes_gui_update_node_info:
 *
 * Updates vendor, version and info column 
 */
static void nodes_gui_update_node_info(gnet_node_info_t *n)
{
    GtkTreeIter *iter;

    g_assert(n != NULL);

    if (nodes_gui_find_node(n->node_handle, &iter)) {
		static gchar version[32];
        gnet_node_status_t status;
        time_t now = time((time_t *) NULL);

        node_get_status(n->node_handle, &status);

        gm_snprintf(version, sizeof(version), "%d.%d",
            n->proto_major, n->proto_minor);

        gtk_list_store_set(nodes_model, iter, 
            COL_NODE_VENDOR, locale_to_utf8(pretty_node_vendor(n), 0),
            COL_NODE_VERSION, version,
            COL_NODE_INFO, nodes_gui_common_status_str(&status, now),
            -1);
    } else
        g_warning("nodes_gui_update_node: no matching row found");
}

/*
 * nodes_gui_update_node_flags
 *  
 */
static void nodes_gui_update_node_flags(gnet_node_t n, gnet_node_flags_t *flags)
{
    GtkTreeIter *iter;

    if (nodes_gui_find_node(n, &iter))
		gtk_list_store_set(nodes_model, iter, COL_NODE_TYPE,  
			nodes_gui_common_flags_str(flags), -1);
    else
        g_warning("%s: no matching row found", G_GNUC_PRETTY_FUNCTION);
}

static void nodes_gui_free_iter(gpointer iter)
{
	wfree(iter, sizeof(GtkTreeIter));
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
    /* FIXME: create a popup again. */
    /* popup_nodes = create_popup_nodes(); */
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
    g_object_unref(G_OBJECT(nodes_model));
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(tree),
		GTK_SELECTION_MULTIPLE);

    nodes_gui_cell_renderer = gtk_cell_renderer_text_new();
	gtk_cell_renderer_text_set_fixed_height_from_font(
		GTK_CELL_RENDERER_TEXT(nodes_gui_cell_renderer), 1);
    g_object_set(nodes_gui_cell_renderer,
		"ypad", (gint) GUI_CELL_RENDERER_YPAD, NULL);
    nodes_gui_add_column(tree, COL_NODE_HOST, "Host");
    nodes_gui_add_column(tree, COL_NODE_TYPE, "Flags");
    nodes_gui_add_column(tree, COL_NODE_VENDOR, "User-agent");
    nodes_gui_add_column(tree, COL_NODE_VERSION, "Ver");
    nodes_gui_add_column(tree, COL_NODE_CONNECTED, "Connected");
    nodes_gui_add_column(tree, COL_NODE_UPTIME, "Uptime");
    nodes_gui_add_column(tree, COL_NODE_INFO, "Info");
	nodes_handles = g_hash_table_new_full(
		NULL, NULL, NULL, (gpointer) &nodes_gui_free_iter);
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
void nodes_gui_shutdown(void) 
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
    GtkTreeIter *iter;

	if (nodes_gui_find_node(n, &iter)) {
        gtk_list_store_remove(nodes_model, iter);
		g_hash_table_remove(nodes_handles, GUINT_TO_POINTER(n));
	} else
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
    GtkTreeIter *iter_cp;
	static gchar proto_tmp[32];

    g_assert(n != NULL);

    gtk_list_store_append(nodes_model, &iter);
	iter_cp = walloc(sizeof(GtkTreeIter));
	memcpy(iter_cp, &iter, sizeof(*iter_cp));

   	gm_snprintf(proto_tmp, sizeof(proto_tmp), "%d.%d",
		n->proto_major, n->proto_minor);
	g_hash_table_insert(nodes_handles,
		GUINT_TO_POINTER(n->node_handle), iter_cp);
    gtk_list_store_set(nodes_model, &iter, 
        COL_NODE_HOST,    ip_port_to_gchar(n->ip, n->port),
        COL_NODE_TYPE,    NULL,
        COL_NODE_VENDOR,  locale_to_utf8(pretty_node_vendor(n), 0),
        COL_NODE_VERSION, proto_tmp,
        COL_NODE_CONNECTED, NULL,
        COL_NODE_UPTIME,  NULL,
        COL_NODE_INFO,    NULL,
        COL_NODE_HANDLE,  n->node_handle,
        -1);
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

    if (last_update >= (now - 1))
        return;

	last_update = now;

    valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(nodes_model), &iter);
    while (valid) {
        GValue val = { 0, };
        static gchar timestr[SIZE_FIELD_MAX];

        gtk_tree_model_get_value(GTK_TREE_MODEL(nodes_model),
            &iter, COL_NODE_HANDLE, &val);

        node_get_status(g_value_get_uint(&val), &status);

		if (status.connect_date) {
			g_strlcpy(timestr, short_uptime(now - status.connect_date),
				sizeof(timestr));
        	gtk_list_store_set(nodes_model, &iter, 
            	COL_NODE_CONNECTED, timestr,
            	COL_NODE_UPTIME, status.up_date ?
					short_uptime(now - status.up_date) : NULL,
            	COL_NODE_INFO, nodes_gui_common_status_str(&status, now),
            	-1);
		} else
            gtk_list_store_set(nodes_model, &iter,
                COL_NODE_UPTIME, status.up_date ?
                    short_uptime(now - status.up_date) : NULL,
                COL_NODE_INFO, nodes_gui_common_status_str(&status, now),
                -1);

        valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(nodes_model), &iter);
    }
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
}

/*
 * nodes_gui_node_added:
 *
 * Callback: called when a node is added from the backend.
 *
 * Adds the node to the gui.
 */
static void nodes_gui_node_added(gnet_node_t n, const gchar *type)
{
    gnet_node_info_t *info;

    if (gui_debug >= 5)
        printf("nodes_gui_node_added(%u, %s)\n", n, type);

    info = node_get_info(n);
    nodes_gui_add_node(info, type);
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

/*
 * nodes_gui_remove_selected
 *
 * Removes all selected nodes from the treeview and disconnects them 
 */
void nodes_gui_remove_selected(void)
{
	GtkTreeView *treeview;
	GtkTreeSelection *selection;
	GSList *node_list = NULL;

	treeview = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_nodes"));
	selection = gtk_tree_view_get_selection(treeview);
	gtk_tree_selection_selected_foreach(selection,
		(gpointer) &nodes_gui_remove_selected_helper, &node_list);
	node_remove_nodes_by_handle(node_list);
	g_slist_free(node_list);
}

