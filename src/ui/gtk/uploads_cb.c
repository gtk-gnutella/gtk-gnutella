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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#include "gui.h"

#include "uploads_cb.h"
#include "uploads.h"
#include "uploads_common.h"
#include "gtkcolumnchooser.h"
#include "columns.h"

#include "gtk/statusbar.h"		/* XXX: whilst we have a FIXME for BH */

#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/host_addr.h"
#include "lib/override.h"		/* Must be the last header included */

/***
 *** Private functions
 ***/

/**
 * Suited for use as a GFunc in a g_list_for_each.
 */
static void
kill_upload(gpointer data, gpointer unused_udata)
{
	upload_row_data_t *d = data;

	(void) unused_udata;

    if (d->valid)
        guc_upload_kill(d->handle);
}

/**
 * Suited for use as a GFunc in a g_list_for_each.
 */
static void
browse_uploading_host(gpointer data, gpointer unused_udata)
{
	upload_row_data_t *d = data;

	(void) unused_udata;

    if (host_addr_initialized(d->gnet_addr))
		uploads_gui_browse_host(d->gnet_addr, d->gnet_port);
}

/***
 *** Public functions
 ***/

void
on_button_uploads_clear_completed_clicked(
    GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
    uploads_gui_clear_completed();
}

#ifdef USE_GTK1
void
on_clist_uploads_select_row(GtkCList *clist, gint unused_row,
	gint unused_column, GdkEvent *unused_event, gpointer unused_udata)
{
    GtkWidget *button;

	(void) unused_row;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;

    button = gui_main_window_lookup("button_uploads_kill");
    gtk_widget_set_sensitive(button, clist->selection != NULL);
}

void
on_clist_uploads_unselect_row(GtkCList *clist,
    gint unused_row, gint unused_column, GdkEvent *unused_event,
	gpointer unused_udata)
{
    GtkWidget *button;

	(void) unused_row;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;
    button = gui_main_window_lookup("button_uploads_kill");
    gtk_widget_set_sensitive(button, clist->selection != NULL);
}

void
on_button_uploads_kill_clicked(GtkButton *unused_button, gpointer unused_udata)
{
    GSList *sl = NULL;
    GtkCList *clist;

	(void) unused_button;
	(void) unused_udata;

    clist = GTK_CLIST(gui_main_window_lookup("clist_uploads"));

    gtk_clist_freeze(clist);

    sl = clist_collect_data(clist, FALSE, NULL);
    g_slist_foreach(sl, kill_upload, NULL);
    g_slist_free(sl);

    gtk_clist_thaw(clist);
}

/* uploads popup menu */

gboolean
on_clist_uploads_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

    if (event->button != 3)
		return FALSE;

    gtk_menu_popup(GTK_MENU(gui_popup_uploads()), NULL, NULL, NULL, NULL,
                  event->button, event->time);

	return TRUE;
}

/**
 * Initiates a browse host request to the currently selected host.
 */
void
on_popup_uploads_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkCList *clist;
	GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	clist = GTK_CLIST(gui_main_window_lookup("clist_uploads"));

	sl = clist_collect_data(clist, FALSE, NULL);
	g_slist_foreach(sl, browse_uploading_host, NULL);
	g_slist_free(sl);
}

void
on_popup_uploads_config_cols_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkWidget *cc;

	(void) unused_menuitem;
	(void) unused_udata;

    cc = gtk_column_chooser_new(gui_main_window_lookup("clist_uploads"));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, GDK_CURRENT_TIME);
}
#endif /* USE_GTK1 */

#ifdef USE_GTK2
void
on_popup_uploads_config_cols_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkWidget *cc;

	(void) unused_menuitem;
	(void) unused_udata;

    cc = gtk_column_chooser_new(gui_main_window_lookup("treeview_uploads"));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, GDK_CURRENT_TIME);
}

static void
uploads_func_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer data)
{
	upload_row_data_t *d = NULL;
	GFunc func = cast_pointer_to_func(data);

	(void) unused_path;

	gtk_tree_model_get(model, iter, c_ul_data, &d, (-1));
	g_assert(NULL != d);
	(*func)(d, NULL);
}

void
on_button_uploads_kill_clicked(GtkButton *unused_button, gpointer unused_udata)
{
    GtkTreeView *treeview;
    GtkTreeSelection *selection;

	(void) unused_button;
	(void) unused_udata;

    treeview = GTK_TREE_VIEW(gui_main_window_lookup("treeview_uploads"));
    selection = gtk_tree_view_get_selection(treeview);
    gtk_tree_selection_selected_foreach(selection, uploads_func_helper,
		cast_func_to_pointer(kill_upload));
}

/**
 * Initiates a browse host request to the currently selected host.
 */
void
on_popup_uploads_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkTreeView *treeview;
    GtkTreeSelection *selection;

	(void) unused_menuitem;
	(void) unused_udata;

    treeview = GTK_TREE_VIEW(gui_main_window_lookup("treeview_uploads"));
    selection = gtk_tree_view_get_selection(treeview);
    gtk_tree_selection_selected_foreach(selection, uploads_func_helper,
		cast_func_to_pointer(browse_uploading_host));
}
#endif /* USE_GTK2 */

/* vi: set ts=4 sw=4 cindent: */
