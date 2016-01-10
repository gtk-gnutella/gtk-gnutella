/*
 * Copyright (c) 2001-2003, Richard Eckart
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

#include "gtk/gui.h"

#include "gtk/hcache.h"
#include "gtk/columns.h"
#include "gtk/misc.h"
#include "gtk/notebooks.h"

#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/override.h"		/* Must be the last header included */

static GtkTreeView *treeview_hcache;

static const struct {
	const gchar *text;
} hcache_col_labels[] = {
	{ N_("Cache contains") },
	{ N_("Hosts") },
	{ N_("Hits") },
	{ N_("Misses") }
};

/***
 *** Private functions
 ***/

static void
add_column(GtkTreeView *treeview,
	gint column_id, gfloat xalign, const gchar *label)
{
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = gtk_cell_renderer_text_new();
	gtk_cell_renderer_text_set_fixed_height_from_font(
		GTK_CELL_RENDERER_TEXT(renderer), 1);
	g_object_set(renderer,
		"xalign", xalign,
		"ypad", GUI_CELL_RENDERER_YPAD,
		NULL_PTR);
	column = gtk_tree_view_column_new_with_attributes(label, renderer,
		"text", column_id,
		NULL_PTR);
	g_object_set(column,
		"fixed-width", 100,
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL_PTR);
	gtk_tree_view_append_column(treeview, column);
}

/***
 *** Public functions
 ***/

void
hcache_gui_init(void)
{
    GtkTreeModel *model;
    gint n;

	STATIC_ASSERT(N_ITEMS(hcache_col_labels) ==
		HCACHE_STATS_VISIBLE_COLUMNS);

    treeview_hcache = GTK_TREE_VIEW(gui_main_window_lookup("treeview_hcache"));
	model = GTK_TREE_MODEL(gtk_list_store_new(4,
							G_TYPE_STRING, G_TYPE_UINT, G_TYPE_UINT,
							G_TYPE_UINT));

	for (n = 0; n < HCACHE_MAX; n++) {
		GtkTreeIter iter;

		if (n == HCACHE_NONE)
			continue;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
        gtk_list_store_set(GTK_LIST_STORE(model), &iter,
            c_hcs_name,       get_hcache_name(n),
            c_hcs_host_count, 0,
            c_hcs_hits,       0,
            c_hcs_misses,     0,
            (-1));
	}

	for (n = 0; (guint) n < N_ITEMS(hcache_col_labels); n++) {
		add_column(treeview_hcache, n, (gfloat) (n != 0),
			_(hcache_col_labels[n].text));
	}
    gtk_tree_view_set_model(treeview_hcache, model);
    tree_view_restore_widths(treeview_hcache, PROP_HCACHE_COL_WIDTHS);
	g_object_unref(model);

	tree_view_set_fixed_height_mode(treeview_hcache, TRUE);
	main_gui_add_timer(hcache_gui_timer);
}

void
hcache_gui_shutdown(void)
{
    tree_view_save_widths(treeview_hcache, PROP_HCACHE_COL_WIDTHS);
}

void
hcache_gui_update_display(void)
{
    hcache_stats_t stats[HCACHE_MAX];
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;

    guc_hcache_get_stats(stats);

	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview_hcache));
	if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter))
		return;

	for (n = 0; n < HCACHE_MAX; n++) {
		if (n == HCACHE_NONE)
			continue;

        gtk_list_store_set(store, &iter,
            c_hcs_host_count, stats[n].host_count,
            c_hcs_hits,       stats[n].hits,
            c_hcs_misses,     stats[n].misses,
            (-1));

		if (!gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter))
			break;
	}

	gtk_tree_view_set_model(treeview_hcache, GTK_TREE_MODEL(store));
}

/* vi: set ts=4 sw=4 cindent: */
