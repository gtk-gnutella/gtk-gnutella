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
#include "gtk-missing.h"
#include "gtkcolumnchooser.h"
#include "nodes_gui_common.h"
#include "nodes_gui.h"
#include "interface-glade2.h"

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

static GtkTreeView *treeview_nodes = NULL;
static GtkListStore *nodes_model = NULL;
static GtkCellRenderer *nodes_gui_cell_renderer = NULL;

/* hash table for fast handle -> GtkTreeIter mapping */
static GHashTable *nodes_handles = NULL;
/* list of all node handles */
static GList *list_nodes = NULL;

/***
 *** Private functions
 ***/

static void nodes_gui_node_removed(gnet_node_t);
static void nodes_gui_node_added(gnet_node_t, const gchar *);
static void nodes_gui_node_info_changed(gnet_node_t);
static void nodes_gui_node_flags_changed(gnet_node_t);

void on_popup_nodes_config_cols_activate(
	GtkMenuItem *menuitem, gpointer user_data)
{
    GtkWidget *cc;

    cc = gtk_column_chooser_new(GTK_WIDGET(treeview_nodes));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);
}

/*
 * nodes_gui_add_column
 *
 * Create a column, associating the "text" attribute of the
 * cell_renderer to the first column of the model
 */
static void add_column(
	GtkTreeView *tree, gint column_id, gint width, const gchar *title)
{
    GtkTreeViewColumn *column;

   	column = gtk_tree_view_column_new_with_attributes(
		title, nodes_gui_cell_renderer, "text", column_id, NULL);
	g_object_set(G_OBJECT(column),
		"fixed-width", MAX(1, width),
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW (tree), column);
}

static inline void nodes_gui_remove_selected_helper(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	GSList **list = data;
	guint handle;

	gtk_tree_model_get(model, iter, COL_NODE_HANDLE, &handle, (-1));
	*list = g_slist_append(*list, GUINT_TO_POINTER(handle));
}

/*
 * find_node:
 *
 * Fetches the GtkTreeIter that points to the row which holds the
 * data about the given node.
 */
static inline GtkTreeIter *find_node(gnet_node_t n)
{
	GtkTreeIter *iter = NULL;

	g_hash_table_lookup_extended(nodes_handles, GUINT_TO_POINTER(n),
				NULL, (gpointer) &iter);
	return iter;
}

/*
 * nodes_gui_update_node_info:
 *
 * Updates vendor, version and info column 
 */
static inline void nodes_gui_update_node_info(gnet_node_info_t *n)
{
    time_t now = time((time_t *) NULL);
    GtkTreeIter *iter;
	static gchar version[32];
    gnet_node_status_t status;

    g_assert(n != NULL);

	iter = find_node(n->node_handle);
	g_assert(NULL != iter);

    node_get_status(n->node_handle, &status);
    gm_snprintf(version, sizeof(version), "%d.%d",
		n->proto_major, n->proto_minor);

	gtk_list_store_set(nodes_model, iter, 
		COL_NODE_VENDOR, lazy_locale_to_utf8(pretty_node_vendor(n), 0),
		COL_NODE_VERSION, version,
		COL_NODE_INFO, nodes_gui_common_status_str(&status, now),
		(-1));
}

/*
 * nodes_gui_update_node_flags
 *  
 */
static inline void nodes_gui_update_node_flags(
	gnet_node_t n, gnet_node_flags_t *flags)
{
    GtkTreeIter *iter;

	iter = find_node(n);
	g_assert(NULL != iter);
	gtk_list_store_set(nodes_model, iter, COL_NODE_TYPE,  
			nodes_gui_common_flags_str(flags), (-1));
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
    GtkTreeView *tree;
	guint32 *width;

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
	treeview_nodes = GTK_TREE_VIEW(lookup_widget(
		main_window, "treeview_nodes"));
	tree = treeview_nodes;
	
	gtk_tree_view_set_model(tree, GTK_TREE_MODEL(nodes_model));

    /* The view now holds a reference.  We can get rid of our own
     * reference */
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(tree),
		GTK_SELECTION_MULTIPLE);

    nodes_gui_cell_renderer = gtk_cell_renderer_text_new();
	gtk_cell_renderer_text_set_fixed_height_from_font(
		GTK_CELL_RENDERER_TEXT(nodes_gui_cell_renderer), 1);
    g_object_set(nodes_gui_cell_renderer,
		"ypad", GUI_CELL_RENDERER_YPAD, NULL);

	width = gui_prop_get_guint32(PROP_NODES_COL_WIDTHS, NULL, 0, 0);
    add_column(tree, COL_NODE_HOST, width[COL_NODE_HOST], "Host");
    add_column(tree, COL_NODE_TYPE, width[COL_NODE_TYPE], "Flags");
    add_column(tree, COL_NODE_VENDOR, width[COL_NODE_VENDOR], "User-agent");
    add_column(tree, COL_NODE_VERSION, width[COL_NODE_VERSION], "Ver");
    add_column(tree, COL_NODE_CONNECTED, width[COL_NODE_CONNECTED],
		"Connected");
    add_column(tree, COL_NODE_UPTIME, width[COL_NODE_UPTIME], "Uptime");
    add_column(tree, COL_NODE_INFO, width[COL_NODE_INFO], "Info");
	G_FREE_NULL(width);

	nodes_handles = g_hash_table_new_full(
		NULL, NULL, NULL, (gpointer) w_tree_iter_free);
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
	tree_view_save_widths(treeview_nodes, PROP_NODES_COL_WIDTHS);
    node_remove_node_added_listener(nodes_gui_node_added);
    node_remove_node_removed_listener(nodes_gui_node_removed);
    node_remove_node_info_changed_listener(nodes_gui_node_info_changed);
    node_remove_node_flags_changed_listener(nodes_gui_node_flags_changed);
	gtk_list_store_clear(nodes_model);
	g_object_unref(G_OBJECT(nodes_model));
	nodes_model = NULL;
	gtk_tree_view_set_model(treeview_nodes, NULL);
	g_hash_table_destroy(nodes_handles);
	nodes_handles = NULL;
	g_list_free(list_nodes);
	list_nodes = NULL;
}

/*
 * nodes_gui_remove_node:
 *
 * Removes all references to the given node handle in the gui.
 */
void inline nodes_gui_remove_node(gnet_node_t n)
{
    GtkTreeIter *iter;

	iter = find_node(n);
	g_assert(NULL != iter);
	gtk_list_store_remove(nodes_model, iter);
	g_hash_table_remove(nodes_handles, GUINT_TO_POINTER(n));
	list_nodes = g_list_remove(list_nodes, GUINT_TO_POINTER(n));
}

/*
 * nodes_gui_add_node:
 *
 * Adds the given node to the gui.
 */
void inline nodes_gui_add_node(gnet_node_info_t *n, const gchar *type)
{
    GtkTreeIter *iter = w_tree_iter_new();
	static gchar proto_tmp[32];

    g_assert(n != NULL);

   	gm_snprintf(proto_tmp, sizeof(proto_tmp), "%d.%d",
		n->proto_major, n->proto_minor);
    gtk_list_store_append(nodes_model, iter);
    gtk_list_store_set(nodes_model, iter, 
        COL_NODE_HOST,    ip_port_to_gchar(n->ip, n->port),
        COL_NODE_TYPE,    NULL,
        COL_NODE_VENDOR,  lazy_locale_to_utf8(pretty_node_vendor(n), 0),
        COL_NODE_VERSION, proto_tmp,
        COL_NODE_CONNECTED, NULL,
        COL_NODE_UPTIME,  NULL,
        COL_NODE_INFO,    NULL,
        COL_NODE_HANDLE,  n->node_handle,
        (-1));
	g_hash_table_insert(nodes_handles,
		GUINT_TO_POINTER(n->node_handle), iter);
	list_nodes = g_list_prepend(list_nodes, GUINT_TO_POINTER(n->node_handle));
}


static inline void update_row(gpointer data, const time_t *now)
{
	GtkTreeIter *iter;
	gnet_node_t n = (gnet_node_t) GPOINTER_TO_UINT(data);
	gnet_node_status_t status;
	static gchar timestr[SIZE_FIELD_MAX];

	iter = find_node(n);
	g_assert(NULL != iter);
	node_get_status(n, &status);

	if (status.connect_date) {
		g_strlcpy(timestr, short_uptime(*now - status.connect_date),
			sizeof(timestr));
		gtk_list_store_set(nodes_model, iter, 
			COL_NODE_CONNECTED, timestr,
			COL_NODE_UPTIME, status.up_date
				? short_uptime(*now - status.up_date) : NULL,
			COL_NODE_INFO, nodes_gui_common_status_str(&status, *now),
			(-1));
	} else {
		gtk_list_store_set(nodes_model, iter,
			COL_NODE_UPTIME, status.up_date
				? short_uptime(*now - status.up_date) : NULL,
			COL_NODE_INFO, nodes_gui_common_status_str(&status, *now),
			(-1));
	}
}

/*
 * gui_update_nodes_display
 *
 * Update all the nodes at the same time.
 */

/* FIXME: we should remember for every node when it was last
 *       updated and only refresh every node at most once every
 *       second. This information should be kept in a struct pointed
 *       to by the row user_data and should be automatically freed
 *       when removing the row (see upload stats code).
 */

void nodes_gui_update_nodes_display(time_t now)
{
    static time_t last_update = 0;

    if (last_update + 1 < now) {
		last_update = now;
		G_LIST_FOREACH(list_nodes, (GFunc) update_row, &now);
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
        g_warning("nodes_gui_node_removed(%u)\n", n);

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
        g_warning("nodes_gui_node_added(%u, %s)\n", n, type);

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

