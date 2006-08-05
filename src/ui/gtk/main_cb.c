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

#include "gui.h"

RCSID("$Id$")

#include "main_cb.h"
#include "main.h"
#include "misc.h"
#include "notebooks.h"

#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/override.h"	/* Must be the last header included */

/***
 *** Private functions
 ***/

static void
quit(gboolean force)
{
    gboolean confirm;

    gui_prop_get_boolean_val(PROP_CONFIRM_QUIT, &confirm);
    if (force || !confirm) {
       	guc_gtk_gnutella_exit(0);
	} else {
        gtk_widget_show(dlg_quit);
    	gdk_window_raise(dlg_quit->window);
	}
}

/***
 *** Main window
 ***/

gboolean
on_main_window_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
		gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	quit(FALSE);
	return TRUE;
}

void
on_button_quit_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    quit(FALSE);
}



/***
 *** menu bar
 ***/

void
on_menu_about_activate(GtkMenuItem *unused_menuitem, gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	g_return_if_fail(dlg_about);
    gtk_widget_show(dlg_about);
	g_return_if_fail(dlg_about->window);
	gdk_window_raise(dlg_about->window);
}

void
on_menu_faq_activate(GtkMenuItem *unused_menuitem, gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	g_return_if_fail(dlg_faq);
    gtk_widget_show(dlg_faq);
	g_return_if_fail(dlg_faq->window);
	gdk_window_raise(dlg_faq->window);
}

void
on_menu_prefs_activate(GtkMenuItem *unused_menuitem, gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	g_return_if_fail(dlg_prefs);
	
    gtk_widget_show(dlg_prefs);
	gui_restore_window(dlg_prefs, PROP_PREFS_DLG_COORDS);
	gdk_window_raise(dlg_prefs->window);
}

void
on_menu_keyboard_shortcuts_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	g_message("on_menu_keyboard_shortcuts_activate(): This is a stub");
}



/***
 *** about dialog
 ***/

void
on_button_about_close_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	g_return_if_fail(dlg_about);
	
    gtk_widget_hide(dlg_about);
}

gboolean
on_dlg_about_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	g_return_val_if_fail(dlg_about, TRUE);

	gtk_widget_hide(dlg_about);
	return TRUE;
}

/***
 *** FAQ dialog
 ***/
gboolean
on_dlg_faq_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	g_return_val_if_fail(dlg_faq, TRUE);

	gtk_widget_hide(dlg_faq);
	return TRUE;
}

/***
 *** prefs dialog
 ***/

void
on_button_prefs_close_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	g_return_if_fail(dlg_prefs);
	g_return_if_fail(GTK_WIDGET_REALIZED(dlg_prefs));
	g_return_if_fail(GTK_WIDGET_VISIBLE(dlg_prefs));

	gui_save_window(dlg_prefs, PROP_PREFS_DLG_COORDS);
    gtk_widget_hide(dlg_prefs);
}

gboolean
on_dlg_prefs_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	g_return_val_if_fail(dlg_prefs, TRUE);
	g_return_val_if_fail(GTK_WIDGET_REALIZED(dlg_prefs), TRUE);
	g_return_val_if_fail(GTK_WIDGET_VISIBLE(dlg_prefs), TRUE);

	gtk_widget_hide(dlg_prefs);
	return TRUE;
}


/***
 *** Quit dialog
 ***/

void
on_button_really_quit_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
	g_return_if_fail(dlg_quit);

    gtk_widget_hide(dlg_quit);
	quit(TRUE);
}

void
on_button_abort_quit_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	g_return_if_fail(dlg_quit);

    gtk_widget_hide(dlg_quit);
}

gboolean
on_dlg_quit_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	g_return_val_if_fail(dlg_quit, TRUE);
    gtk_widget_hide(dlg_quit);
    return TRUE;
}

#define GENERATE_MENU_HANDLER(item, tab) \
void \
on_menu_ ## item ## _activate(GtkMenuItem *unused_menuitem, \
	gpointer unused_udata) \
{ \
	(void) unused_menuitem; \
	(void) unused_udata; \
    gtk_notebook_set_page( \
		GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")), \
		nb_main_page_ ## tab ); \
}

GENERATE_MENU_HANDLER(net_connections, gnet);
GENERATE_MENU_HANDLER(net_stats, gnet_stats);
GENERATE_MENU_HANDLER(net_hostcache, hostcache);
GENERATE_MENU_HANDLER(uploads_transfers, uploads);
GENERATE_MENU_HANDLER(uploads_history, uploads_stats);
#ifdef USE_GTK1
GENERATE_MENU_HANDLER(downloads_files, dl_files);
GENERATE_MENU_HANDLER(downloads_active, dl_active);
GENERATE_MENU_HANDLER(downloads_queue, dl_queue);
#endif /* USE_GTK1 */
#ifdef USE_GTK2
GENERATE_MENU_HANDLER(downloads, downloads);
#endif /* USE_GTK2 */
GENERATE_MENU_HANDLER(search_results, search);
GENERATE_MENU_HANDLER(search_monitor, monitor);
GENERATE_MENU_HANDLER(search_stats, search_stats);

#undef GENERATE_MENU_HANDLER

#ifdef USE_GTK2
void
on_main_gui_treeview_menu_cursor_changed(GtkTreeView *treeview,
	gpointer unused_udata)
{
    GtkTreeSelection *selection;
    GtkTreeModel *model = NULL;
    GtkTreeIter iter;

	(void) unused_udata;
    g_assert(treeview != NULL);

    selection = gtk_tree_view_get_selection(treeview);
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
		gint id = 0;

        gtk_tree_model_get(GTK_TREE_MODEL(model), &iter, 1, &id, (-1));
		g_assert(id >= 0 && id < nb_main_page_num);
        gtk_notebook_set_current_page(
			GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")),
			id);
    }
}

void
on_main_gui_treeview_menu_row_collapsed(GtkTreeView *tree, GtkTreeIter *iter,
		GtkTreePath *unused_path, gpointer unused_data)
{
	GtkTreeModel *model;
	gpointer data = NULL;
	guint32 expanded = FALSE;
    gint id;

	(void) unused_path;
	(void) unused_data;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(tree));
	gtk_tree_model_get(GTK_TREE_MODEL(model), iter, 1, &data, (-1));
	id = GPOINTER_TO_UINT(data);
	g_assert(id >= 0 && id < nb_main_page_num);
	gui_prop_set_guint32(PROP_TREEMENU_NODES_EXPANDED, &expanded, id, 1);
}

void
on_main_gui_treeview_menu_row_expanded(GtkTreeView *tree, GtkTreeIter *iter,
	GtkTreePath *unused_path, gpointer unused_data)
{
	GtkTreeModel *model;
	gpointer data = NULL;
	guint32 expanded = TRUE;
    gint id;

	(void) unused_path;
	(void) unused_data;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(tree));
	gtk_tree_model_get(GTK_TREE_MODEL(model), iter, 1, &data, (-1));
	id = GPOINTER_TO_UINT(data);
	g_assert(id >= 0 && id < nb_main_page_num);
	gui_prop_set_guint32(PROP_TREEMENU_NODES_EXPANDED, &expanded, id, 1);
}
#endif /* USE_GTK2 */

void
on_notebook_main_switch_page(GtkNotebook *unused_notebook,
	GtkNotebookPage *unused_page, gint page_num, gpointer unused_udata)
#ifdef USE_GTK1
{
	static gboolean lock;
    GtkCTreeNode *node;
    GtkCTree *ctree;

	(void) unused_notebook;
	(void) unused_udata;
	(void) unused_page;

	if (lock)	/* Prevent recursion */
		return;
	lock = TRUE;

	ctree = GTK_CTREE(lookup_widget(main_window, "ctree_menu"));
    node = gtk_ctree_find_by_row_data(ctree, NULL, GINT_TO_POINTER(page_num));
	if (node) {
    	GtkCTreeNode *iter;

		for (iter = node; iter != NULL; iter = GTK_CTREE_ROW(iter)->parent)
			gtk_ctree_expand(ctree, iter);
		
        gtk_ctree_select(ctree, node);
		if (!GTK_WIDGET_HAS_FOCUS(GTK_WIDGET(ctree)))
			gtk_ctree_node_moveto(ctree, node, 0, 0.0, 0.0);
	}

	lock = FALSE;
}
#endif /* USE_GTK1 */
#ifdef USE_GTK2
{
	static gboolean lock;
	GtkTreeView *tv;
	GtkTreeModel *model;
	GtkTreeIter iter;

	(void) unused_notebook;
	(void) unused_udata;
	(void) unused_page;

	if (lock)	/* Prevent recursion */
		return;
	lock = TRUE;
	
	tv = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_menu"));
	model = gtk_tree_view_get_model(tv);
	if (tree_find_iter_by_data(model, 1, GINT_TO_POINTER(page_num), &iter)) {
		GtkTreePath *path;

		path = gtk_tree_model_get_path(model, &iter);
		while (gtk_tree_path_up(path))
			gtk_tree_view_expand_row(tv, path, FALSE);
		gtk_tree_path_free(path);
		
		path = gtk_tree_model_get_path(model, &iter);
		gtk_tree_view_set_cursor(tv, path, NULL, FALSE);
		gtk_tree_path_free(path);
	}
	
	lock = FALSE;
}
#endif /* USE_GTK1 */

/* vi: set ts=4 sw=4 cindent: */
