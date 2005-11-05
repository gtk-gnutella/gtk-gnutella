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

RCSID("$Id$");

#include "main_cb.h"
#include "main.h"
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
	gdk_window_raise(dlg_prefs->window);
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

#ifdef USE_GTK2
static void
menu_collapse(GtkTreeView *tv, GtkTreeIter *first)
{
	GtkTreeModel *model;
	GtkTreeSelection *s;
	GtkTreeIter iter, next;
	
	g_return_if_fail(tv);
	g_return_if_fail(first);
	
	model = gtk_tree_view_get_model(tv);
	s = gtk_tree_view_get_selection(tv);

	g_return_if_fail(model);
	g_return_if_fail(s);
	
	next = *first;
	do {
		gboolean blocked = FALSE;
		
		iter = next;
		if (!gtk_tree_selection_iter_is_selected(s, &iter)) {
			GtkTreeIter child;
			guint i = 0;

			while (gtk_tree_model_iter_nth_child(model, &child, &iter, i)) {
				if (gtk_tree_selection_iter_is_selected(s, &child)) {
					blocked = TRUE;
					break;
				}
				i++;
			}
		}
		if (!blocked) {
			GtkTreePath *p;
	
			p = gtk_tree_model_get_path(model, &iter);
			gtk_tree_view_collapse_row(tv, p);
			gtk_tree_path_free(p);
		}
		next = iter;
	} while (gtk_tree_model_iter_next(model, &next));
}

/**
 * Keeps track of whether the cursor is still inside the menu treeview
 * because tree motion events are delay and thus can be delivered after
 * the cursor has left the menu. These events should be discarded.
 */
static gboolean menu_has_cursor;

void
on_main_gui_treeview_menu_motion(GtkTreeView *tv, GtkTreePath *path)
{
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_assert(tv != NULL);

	if (!menu_has_cursor)
		return;
	
	model = gtk_tree_view_get_model(tv);
	g_return_if_fail(model);

	if (!path) {
		if (gtk_tree_model_get_iter_first(model, &iter))
			menu_collapse(tv, &iter);
		return;
	}
	
	if (!gtk_tree_model_get_iter(model, &iter, path))
		return;
	
	if (gtk_tree_model_iter_has_child(model, &iter)) {
		gtk_tree_view_expand_row(tv, path, FALSE);
		if (gtk_tree_model_iter_next(model, &iter))
			menu_collapse(tv, &iter);
	}
}

gboolean
on_main_gui_treeview_menu_enter_notify(GtkWidget *unused_widget,
	GdkEventCrossing *unused_event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;
	menu_has_cursor = TRUE;
	return FALSE;
}

gboolean
on_main_gui_treeview_menu_leave_notify(GtkWidget *widget,
	GdkEventCrossing *unused_event, gpointer unused_udata)
{
	GtkTreeView *tv;
	GtkTreeModel *model;
	GtkTreeIter first;
		
	(void) unused_event;
	(void) unused_udata;
	
	tv = GTK_TREE_VIEW(widget);
	model = gtk_tree_view_get_model(tv);
	g_assert(model);
	
	menu_has_cursor = FALSE;
	
	if (gtk_tree_model_get_iter_first(model, &first))
		menu_collapse(tv, &first);
	return FALSE;
}

void
on_main_gui_treeview_menu_cursor_changed(GtkTreeView *treeview,
	gpointer unused_udata)
{
    GtkTreeSelection *selection;
    GtkTreeModel *model = NULL;
    GtkTreeIter iter;
    gint tab = 0;

	(void) unused_udata;
    g_assert(treeview != NULL);

    selection = gtk_tree_view_get_selection(treeview);
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gtk_tree_model_get(GTK_TREE_MODEL(model), &iter, 1, &tab, (-1));
        gtk_notebook_set_page
            (GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")), tab);
    }
}

void
on_main_gui_treeview_menu_row_collapsed(GtkTreeView *tree, GtkTreeIter *iter,
		GtkTreePath *unused_path, gpointer unused_data)
{
	GtkTreeModel *model;
    gint id = 0;
	guint32 expanded = FALSE;

	(void) unused_path;
	(void) unused_data;

	/* FIXME:	This can crash at shutdown if the properties are
	 *			already destroyed.
	 */
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(tree));
	gtk_tree_model_get(GTK_TREE_MODEL(model), iter, 2, &id, (-1));
	g_assert(id >= 0 && id < nb_main_page_num);
	gui_prop_set_guint32(PROP_TREEMENU_NODES_EXPANDED, &expanded, id, 1);
}

void
on_main_gui_treeview_menu_row_expanded(GtkTreeView *tree, GtkTreeIter *iter,
	GtkTreePath *unused_path, gpointer unused_data)
{
	GtkTreeModel *model;
    gint id = 0;
	guint32 expanded = TRUE;

	(void) unused_path;
	(void) unused_data;

	/* FIXME:	This can crash at shutdown if the properties are
	 *			already destroyed.
	 */
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(tree));
	gtk_tree_model_get(GTK_TREE_MODEL(model), iter, 2, &id, (-1));
	g_assert(id >= 0 && id < nb_main_page_num);
	gui_prop_set_guint32(PROP_TREEMENU_NODES_EXPANDED, &expanded, id, 1);
}

#endif /* USE_GTK2 */

/* vi: set ts=4 sw=4 cindent: */
