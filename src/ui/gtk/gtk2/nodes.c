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

#include "gtk/misc.h"
#include "gtk/nodes_common.h"
#include "gtk/nodes.h"
#include "gtk/columns.h"
#include "gtk/notebooks.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"
#include "gtk/search_common.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/iso3166.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

/*
 * These hash tables record which information about which nodes has
 * changed. By using this the number of updates to the gui can be
 * significantly reduced.
 */
static GHashTable *ht_node_info_changed;
static GHashTable *ht_node_flags_changed;

static GtkTreeView *treeview_nodes;
static GtkListStore *nodes_model;

/* hash table for fast handle -> GtkTreeIter mapping */
static GHashTable *nodes_handles;
/* list of all node handles */

static GHashTable *ht_pending_lookups;

static tree_view_motion_t *tvm_nodes;

/***
 *** Private functions
 ***/

static void nodes_gui_node_removed(const node_id_t);
static void nodes_gui_node_added(const node_id_t);
static void nodes_gui_node_info_changed(const node_id_t);
static void nodes_gui_node_flags_changed(const node_id_t);

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

/**
 * Create a column, associating the attribute ``attr'' (usually "text") of the
 * cell_renderer to the first column of the model. Also associate the
 * foreground color with the c_gnet_fg column, so that we can set
 * the foreground color for the whole row.
 */
static void
add_column(GtkTreeView *tree, const gchar *title, 
	GtkTreeCellDataFunc cell_data_func, gpointer udata)
{
	GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;

	renderer = gtk_cell_renderer_text_new();
	g_object_set(G_OBJECT(renderer),
	     "xpad", GUI_CELL_RENDERER_XPAD,
	     "ypad", GUI_CELL_RENDERER_YPAD,
	     (void *) 0);

   	column = gtk_tree_view_column_new_with_attributes(title, renderer,
				(void *) 0);
	g_object_set(G_OBJECT(column),
		"title", title,
		"fixed-width", 1,
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		(void *) 0);
	
	if (cell_data_func != NULL)
		gtk_tree_view_column_set_cell_data_func(column, renderer,
			cell_data_func, udata, NULL);

    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), column);
}

struct node_data {
	const gchar *user_agent;	/* Atom */
	gchar *host;		/* walloc()ed */
	gchar *info;		/* walloc()ed */
	const GdkColor *fg;
	size_t host_size;
	size_t info_size;
	guint uptime;
	guint connected;
	guint16 country;
	GtkTreeIter iter;
	gchar version[24];
	gchar flags[16 + sizeof "<tt></tt>"];
	node_id_t node_id;
};

static void
node_data_free(gpointer value)
{
	struct node_data *data = value;

	atom_str_free_null(&data->user_agent);
	WFREE_NULL(data->host, data->host_size);
	WFREE_NULL(data->info, data->info_size);
	node_id_unref(data->node_id);
	WFREE_NULL(data, sizeof *data);
}

static gboolean
free_node_id(gpointer key, gpointer value, gpointer unused_udata)
{
	g_assert(key == value);
	(void) unused_udata;
	node_id_unref(key);
	return TRUE;
}

static gboolean 
free_node_data(gpointer unused_key, gpointer value, gpointer unused_udata)
{
	(void) unused_key;
	(void) unused_udata;
	
	node_data_free(value);
	return TRUE;
}

static GtkListStore *
create_nodes_model(void)
{
	static GType columns[1];
	GtkListStore *store;

	columns[0] = G_TYPE_POINTER;
	store = gtk_list_store_newv(G_N_ELEMENTS(columns), columns);
	return store;
}

static void
cell_renderer_func(GtkTreeViewColumn *column,
	GtkCellRenderer *cell, GtkTreeModel *model, GtkTreeIter *iter,
	gpointer udata)
{
	static const GValue zero_value;
	const struct node_data *data;
	const gchar *s, *attr;
	GValue value;

	if (!gtk_tree_view_column_get_visible(column))
		return;

	attr = "text";
	value = zero_value;
	gtk_tree_model_get_value(model, iter, 0, &value);
	data = g_value_get_pointer(&value);
	switch (GPOINTER_TO_UINT(udata)) {
	case c_gnet_user_agent:
		s = data->user_agent;
		break;
	case c_gnet_flags:
		s = data->flags;
		attr = "markup";
		break;
	case c_gnet_loc:
		s = iso3166_country_name(data->country);
		break;
	case c_gnet_version:
		s = data->version;
		break;
	case c_gnet_host:
		s = data->host;
		break;
	case c_gnet_connected:
		s = short_time(data->connected);
		break;
	case c_gnet_uptime:
		s = data->uptime > 0 ? short_time(data->uptime) : NULL;
		break;
	case c_gnet_info:
		s = data->info;
		break;
	default:
		s = NULL;
	}

	if (data->fg) {
		g_object_set(cell,
			attr, s,
			"foreground-gdk", data->fg,
			"foreground-set", TRUE,
			(void *) 0);
	} else {
		g_object_set(cell, attr, s, (void *) 0);
	}
}

/**
 * Sets up the treeview_nodes object for use by
 * settings_gui. (Uses a default width of one; actual
 * widths are set during nodes_gui_init. This
 * component must be able to be initialized before
 * width settings are initialized.)
 */
static void
nodes_gui_create_treeview_nodes(void)
{
	static const struct {
		const gchar * const title;
		const guint id;
	} columns[] = {
		{ N_("Host"),			c_gnet_host },
		{ N_("User-Agent"),		c_gnet_user_agent },
		{ N_("Flags"),			c_gnet_flags },
		{ N_("Country"),		c_gnet_loc },
		{ N_("Version"),		c_gnet_version },
		{ N_("Connected time"), c_gnet_connected },
		{ N_("Uptime"),			c_gnet_uptime },
		{ N_("Status"),			c_gnet_info },
	};
	GtkTreeView *tree;
	guint i;

    /*
     * Create a model.  We are using the store model for now, though we
     * could use any other GtkTreeModel
     */
    nodes_model = create_nodes_model();

    /*
     * Get the monitor widget
     */
	tree = GTK_TREE_VIEW(gui_main_window_lookup("treeview_nodes"));
	treeview_nodes = tree;
	gtk_tree_view_set_model(tree, GTK_TREE_MODEL(nodes_model));
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(tree),
		GTK_SELECTION_MULTIPLE);

	for (i = 0; i < G_N_ELEMENTS(columns); i++)
		add_column(tree, _(columns[i].title), cell_renderer_func,
			GUINT_TO_POINTER(columns[i].id));
}

static inline void
nodes_gui_remove_selected_helper(GtkTreeModel *model,
		GtkTreePath *unused_path, GtkTreeIter *iter, gpointer list_ptr)
{
	GSList **list = list_ptr;
	const struct node_data *data;

	(void) unused_path;

	gtk_tree_model_get(model, iter, 0, &data, (-1));
	*list = g_slist_prepend(*list, deconstify_gpointer(data->node_id));
}

/**
 * Fetches the node_data that holds the data about the given node
 * and knows the GtkTreeIter.
 */
static inline struct node_data *
find_node(const node_id_t node_id)
{
	return g_hash_table_lookup(nodes_handles, node_id);
}

/**
 * Updates vendor, version and info column.
 */
static void
nodes_gui_update_node_info(struct node_data *data, gnet_node_info_t *info)
{
    gnet_node_status_t status;

    g_assert(info != NULL);

    if (data == NULL)
        data = find_node(info->node_id);

	g_assert(NULL != data);
	g_assert(data->node_id == info->node_id);

    if (guc_node_get_status(info->node_id, &status)) {
		gm_snprintf(data->version, sizeof data->version, "%u.%u",
				info->proto_major, info->proto_minor);
		atom_str_free_null(&data->user_agent);
		data->user_agent = info->vendor ? atom_str_get(info->vendor) : NULL;
		data->country = info->country;
	}
}

/**
 *
 */
static void
nodes_gui_update_node_flags(struct node_data *data, gnet_node_flags_t *flags)
{
	gboolean ultra;
	
	g_assert(NULL != data);

	concat_strings(data->flags, sizeof data->flags,
		"<tt>", guc_node_flags_to_string(flags), "</tt>", (void *) 0);

	ultra = NODE_P_ULTRA == flags->peermode;
    data->fg = &(gtk_widget_get_style(GTK_WIDGET(treeview_nodes))
					->fg[ultra ? GTK_STATE_NORMAL : GTK_STATE_INSENSITIVE]);
}

static void
update_tooltip(GtkTreeView *tv, GtkTreePath *path)
{
	const struct node_data *data = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_assert(tv != NULL);

	if (path) {
		GtkTreeIter parent;
		
		model = gtk_tree_view_get_model(tv);
		if (!gtk_tree_model_get_iter(model, &iter, path)) {
			g_warning("gtk_tree_model_get_iter() failed");
			return;
		}
		if (gtk_tree_model_iter_parent(model, &parent, &iter))
			iter = parent;

		gtk_tree_model_get(model, &iter, 0, &data, (-1));
	}

	if (data && find_node(data->node_id)) {
		gnet_node_info_t info;
		gnet_node_flags_t flags;
		gchar text[1024];

		guc_node_fill_flags(data->node_id, &flags);
		guc_node_fill_info(data->node_id, &info);
		g_assert(info.node_id == data->node_id);

		gm_snprintf(text, sizeof text,
			"%s %s\n"
			"%s %s (%s)\n"
			"%s %s (%s)\n"
			"%s %.64s",
			_("Peer:"),
			host_addr_port_to_string(info.gnet_addr, info.gnet_port),
			_("Peermode:"),
			guc_node_peermode_to_string(flags.peermode),
			flags.incoming ? _("incoming") : _("outgoing"),
			_("Country:"),
			iso3166_country_name(info.country),
			iso3166_country_cc(info.country),
			_("Vendor:"),
			info.vendor ? info.vendor : _("Unknown"));

		guc_node_clear_info(&info);
		gtk_tooltips_set_tip(settings_gui_tooltips(),
			GTK_WIDGET(tv), text, NULL);
	} else {
		GtkWidget *w;

		gtk_tooltips_set_tip(settings_gui_tooltips(), GTK_WIDGET(tv),
			_("Move the cursor over a row to see details."), NULL);
		w = settings_gui_tooltips()->tip_window;
		if (w)
			gtk_widget_hide(w);
	}
}

static gboolean
on_leave_notify(GtkWidget *widget, GdkEventCrossing *unused_event,
	gpointer unused_udata)
{
	(void) unused_event;
	(void) unused_udata;

	update_tooltip(GTK_TREE_VIEW(widget), NULL);
	return FALSE;
}

static void
host_lookup_callback(const gchar *hostname, gpointer key)
{
	const node_id_t node_id = key;
	gnet_node_info_t info;
	struct node_data *data;
	GtkListStore *store;
	GtkTreeView *tv;
	host_addr_t addr;
	guint16 port;

	if (!ht_pending_lookups)
		goto finish;

	if (!remove_item(ht_pending_lookups, node_id))
		goto finish;

	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_nodes"));
	store = GTK_LIST_STORE(gtk_tree_view_get_model(tv));
	data = find_node(node_id);
	if (!data)
		goto finish;

	guc_node_fill_info(node_id, &info);
	g_assert(node_id == info.node_id);
	
	addr = info.addr;
	port = info.port;
	guc_node_clear_info(&info);

	WFREE_NULL(data->host, data->host_size);
	
	if (hostname) {
		const gchar *host;
		gchar *to_free;

		if (utf8_is_valid_string(hostname)) {
			to_free = NULL;
			host = hostname;
		} else {
			to_free = locale_to_utf8_normalized(hostname, UNI_NORM_GUI);
			host = to_free;
		}
		
		data->host_size = w_concat_strings(&data->host,
							host, " (",
							host_addr_port_to_string(addr, port), ")",
							(void *) 0);

		G_FREE_NULL(to_free);
	} else {
		statusbar_gui_warning(10,
			_("Reverse lookup for %s failed"), host_addr_to_string(addr));
		data->host_size = w_concat_strings(&data->host,
							host_addr_port_to_string(addr, port),
							(void *) 0);
	}

finish:
	node_id_unref(node_id);
}

static void
on_cursor_changed(GtkTreeView *tv, gpointer unused_udata)
{
	GtkTreePath *path = NULL;

	(void) unused_udata;
	g_assert(tv != NULL);

	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (path) {
		update_tooltip(tv, path);
		gtk_tree_path_free(path);
		path = NULL;
	}
}

/***
 *** Public functions
 ***/


/**
 * Initialize the widgets. Include creation of the actual treeview for
 * other init functions that manipulate it, notably settings_gui_init.
 */
void
nodes_gui_early_init(void)
{
	nodes_gui_create_treeview_nodes();
}

/**
 * Initialize the nodes controller. Register callbacks in the backend.
 */
void
nodes_gui_init(void)
{
	treeview_nodes = GTK_TREE_VIEW(gui_main_window_lookup( "treeview_nodes"));

	tree_view_restore_widths(treeview_nodes, PROP_NODES_COL_WIDTHS);
	tree_view_restore_visibility(treeview_nodes, PROP_NODES_COL_VISIBLE);
	tree_view_set_fixed_height_mode(treeview_nodes, TRUE);

	nodes_handles = g_hash_table_new(node_id_hash, node_id_eq_func);
    ht_node_info_changed = g_hash_table_new(node_id_hash, node_id_eq_func);
    ht_node_flags_changed = g_hash_table_new(node_id_hash, node_id_eq_func);
    ht_pending_lookups = g_hash_table_new(node_id_hash, node_id_eq_func);

    guc_node_add_node_added_listener(nodes_gui_node_added);
    guc_node_add_node_removed_listener(nodes_gui_node_removed);
    guc_node_add_node_info_changed_listener(nodes_gui_node_info_changed);
    guc_node_add_node_flags_changed_listener(nodes_gui_node_flags_changed);

	g_signal_connect(GTK_OBJECT(treeview_nodes), "cursor-changed",
		G_CALLBACK(on_cursor_changed), treeview_nodes);

	g_signal_connect(GTK_OBJECT(treeview_nodes), "leave-notify-event",
		G_CALLBACK(on_leave_notify), treeview_nodes);

	tvm_nodes = tree_view_motion_set_callback(treeview_nodes,
					update_tooltip, 400);

	main_gui_add_timer(nodes_gui_timer);
}

/**
 * Unregister callbacks in the backend and clean up.
 */
void
nodes_gui_shutdown(void)
{
	tree_view_motion_clear_callback(&tvm_nodes);
	tree_view_save_widths(treeview_nodes, PROP_NODES_COL_WIDTHS);
	tree_view_save_visibility(treeview_nodes, PROP_NODES_COL_VISIBLE);

    guc_node_remove_node_added_listener(nodes_gui_node_added);
    guc_node_remove_node_removed_listener(nodes_gui_node_removed);
    guc_node_remove_node_info_changed_listener(nodes_gui_node_info_changed);
    guc_node_remove_node_flags_changed_listener(nodes_gui_node_flags_changed);

	gtk_list_store_clear(nodes_model);
	g_object_unref(G_OBJECT(nodes_model));
	nodes_model = NULL;
	gtk_tree_view_set_model(treeview_nodes, NULL);

	g_hash_table_foreach_remove(nodes_handles, free_node_data, NULL);
	g_hash_table_destroy(nodes_handles);
	nodes_handles = NULL;

	g_hash_table_foreach_remove(ht_node_info_changed, free_node_id, NULL);
    g_hash_table_destroy(ht_node_info_changed);
    ht_node_info_changed = NULL;

	g_hash_table_foreach_remove(ht_node_flags_changed, free_node_id, NULL);
    g_hash_table_destroy(ht_node_flags_changed);
    ht_node_flags_changed = NULL;

	g_hash_table_foreach_remove(ht_pending_lookups, free_node_id, NULL);
    g_hash_table_destroy(ht_pending_lookups);
    ht_pending_lookups = NULL;
}

/**
 * Removes all references to the given node handle in the gui.
 */
void
nodes_gui_remove_node(const node_id_t node_id)
{
	struct node_data *data;

    /*
     * Make sure node is removed from the "changed" hash tables so
     * we don't try an update later.
     */

	remove_item(ht_node_info_changed, node_id);
	remove_item(ht_node_flags_changed, node_id);
	remove_item(ht_pending_lookups, node_id);

	data = find_node(node_id);
	if (data) {
		g_assert(node_id_eq(node_id, data->node_id));

		gtk_list_store_remove(nodes_model, &data->iter);
		g_hash_table_remove(nodes_handles, data->node_id);
		node_data_free(data);
	}
}

/**
 * Adds the given node to the gui.
 */
void
nodes_gui_add_node(gnet_node_info_t *info)
{
	static const struct node_data zero_data;
	struct node_data *data;
	gnet_node_flags_t flags;

    g_return_if_fail(info);
	g_return_if_fail(!g_hash_table_lookup(nodes_handles, info->node_id));

	data = walloc(sizeof *data);
	*data = zero_data;

	data->node_id = node_id_ref(info->node_id);
	data->user_agent = info->vendor ? atom_str_get(info->vendor) : NULL;
	data->country = info->country;
	data->host_size = w_concat_strings(&data->host,
						host_addr_port_to_string(info->addr, info->port),
						(void *) 0);
	gm_snprintf(data->version, sizeof data->version, "%u.%u",
		info->proto_major, info->proto_minor);

	guc_node_fill_flags(data->node_id, &flags);
	nodes_gui_update_node_flags(data, &flags);

	gm_hash_table_insert_const(nodes_handles, data->node_id, data);

    gtk_list_store_append(nodes_model, &data->iter);
    gtk_list_store_set(nodes_model, &data->iter, 0, data, (-1));

}

static inline void
update_row(gpointer key, gpointer value, gpointer user_data)
{
	struct node_data *data = value;
	time_t *now_ptr = user_data, now = *now_ptr;
	gnet_node_status_t status;

	g_assert(NULL != data);
	g_assert(data->node_id == key);

	if (!guc_node_get_status(data->node_id, &status))
		return;

    /*
     * Update additional info too if it has recorded changes.
     */
    if (remove_item(ht_node_info_changed, data->node_id)) {
        gnet_node_info_t info;

        if (guc_node_fill_info(data->node_id, &info)) {
			nodes_gui_update_node_info(data, &info);
			guc_node_clear_info(&info);
		}
    }

    if (remove_item(ht_node_flags_changed, data->node_id)) {
        gnet_node_flags_t flags;

        if (guc_node_fill_flags(data->node_id, &flags)) {
			nodes_gui_update_node_flags(data, &flags);
		}
    }

	if (status.connect_date)
		data->connected = delta_time(now, status.connect_date);

	if (status.up_date)
		data->uptime = delta_time(now, status.up_date);

	/* Update the status line */
	{	
		const gchar *s;
		size_t size;
		
		s = nodes_gui_common_status_str(&status);
		size = 1 + strlen(s);
		if (size > data->info_size) {
			WFREE_NULL(data->info, data->info_size);
			data->info = wcopy(s, size);
			data->info_size = size;
		} else {
			memcpy(data->info, s, size);
		}
	}

	tree_model_iter_changed(GTK_TREE_MODEL(nodes_model), &data->iter);
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
	g_object_freeze_notify(G_OBJECT(treeview_nodes));
	g_hash_table_foreach(nodes_handles, update_row, &now);
	g_object_thaw_notify(G_OBJECT(treeview_nodes));
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
        g_message("nodes_gui_node_removed(%s)\n", node_id_to_string(node_id));

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
    gnet_node_info_t *info;

    if (GUI_PROPERTY(gui_debug) >= 5)
        g_message("nodes_gui_node_added(%s)\n", node_id_to_string(node_id));

    info = guc_node_get_info(node_id);
	if (info) {
    	nodes_gui_add_node(info);
    	guc_node_free_info(info);
	}
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

/**
 * Removes all selected nodes from the treeview and disconnects them.
 */
void
nodes_gui_remove_selected(void)
{
	GtkTreeView *treeview;
	GtkTreeSelection *selection;
	GSList *node_list = NULL;

	treeview = GTK_TREE_VIEW(gui_main_window_lookup("treeview_nodes"));
	selection = gtk_tree_view_get_selection(treeview);
	gtk_tree_selection_selected_foreach(selection,
		nodes_gui_remove_selected_helper, &node_list);
	guc_node_remove_nodes_by_id(node_list);
	g_slist_free(node_list);
}

static inline void
nodes_gui_reverse_lookup_selected_helper(GtkTreeModel *model,
		GtkTreePath *unused_path, GtkTreeIter *iter, gpointer unused_data)
{
	struct node_data *data;
	gnet_node_info_t info;

	(void) unused_path;
	(void) unused_data;

	gtk_tree_model_get(model, iter, 0, &data, (-1));
	g_assert(NULL != find_node(data->node_id));

	if (NULL != g_hash_table_lookup(ht_pending_lookups, data->node_id))
		return;

	guc_node_fill_info(data->node_id, &info);
	g_assert(data->node_id == info.node_id);

	if (!info.is_pseudo) {
		const node_id_t key = node_id_ref(data->node_id);

		WFREE_NULL(data->host, data->host_size);
		data->host_size = w_concat_strings(&data->host,
				_("Reverse lookup in progress..."),
				" (", host_addr_port_to_string(info.addr, info.port), ")",
				(void *) 0);

		gm_hash_table_insert_const(ht_pending_lookups, key, key);
		adns_reverse_lookup(info.addr, host_lookup_callback,
			deconstify_gpointer(node_id_ref(key)));
	}
	guc_node_clear_info(&info);
}

/**
 * Performs a reverse lookup for all selected nodes.
 */
void
nodes_gui_reverse_lookup_selected(void)
{
	GtkTreeView *tv;
	GtkTreeSelection *selection;

	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_nodes"));
	selection = gtk_tree_view_get_selection(tv);
	gtk_tree_selection_selected_foreach(selection,
		nodes_gui_reverse_lookup_selected_helper, NULL);
}

static inline void
nodes_gui_browse_selected_helper(GtkTreeModel *model,
		GtkTreePath *unused_path, GtkTreeIter *iter, gpointer unused_data)
{
	gnet_node_info_t *info;
	struct node_data *data;

	(void) unused_path;
	(void) unused_data;
	
	gtk_tree_model_get(model, iter, 0, &data, (-1));
	info = guc_node_get_info(data->node_id);
	if (!info->is_pseudo) {
		search_gui_new_browse_host(NULL, info->gnet_addr, info->gnet_port,
			info->gnet_guid, NULL, 0);
	}
	guc_node_free_info(info);
}

void
nodes_gui_browse_selected(void)
{
	GtkTreeView *tv;
	GtkTreeSelection *selection;

	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_nodes"));
	selection = gtk_tree_view_get_selection(tv);
	gtk_tree_selection_selected_foreach(selection,
		nodes_gui_browse_selected_helper, NULL);
	
}

/* vi: set ts=4 sw=4 cindent: */
