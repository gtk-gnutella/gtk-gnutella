/*
 * $Id$
 *
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

#include "uploads_cb.h"
#include "uploads_gui.h"
#include "upload_stats.h" /* FIXME: remove this dependency */

RCSID("$Id$");

/***
 *** Private functions
 ***/

/*
 * kill_upload:
 *
 * Suited for use as a GFunc in a g_list_for_each.
 */
static void kill_upload(upload_row_data_t *d, gpointer user_data)
{
    if (d->valid)
        upload_kill(d->handle);
}

/***
 *** Public functions
 ***/

void on_clist_uploads_select_row(GtkCList *clist, 
    gint row, gint column, GdkEvent *event, gpointer user_data)
{
    GtkWidget *button;

    button = lookup_widget(main_window, "button_uploads_kill");

    gtk_widget_set_sensitive(button, clist->selection != NULL);
}

void on_clist_uploads_unselect_row(GtkCList * clist, 
    gint row, gint column, GdkEvent * event, gpointer user_data)
{
    GtkWidget *button;

    button = lookup_widget(main_window, "button_uploads_kill");

    gtk_widget_set_sensitive(button, clist->selection != NULL);
}

void on_clist_uploads_resize_column(GtkCList * clist, 
    gint column, gint width, gpointer user_data)
{
    /* FIXME: use properties */
	uploads_col_widths[column] = width;
}

#ifdef USE_GTK2
static void uploads_kill_helper(
    GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	upload_row_data_t *d = NULL;

	gtk_tree_model_get(model, iter, c_ul_data, &d, (-1));
	g_assert(NULL != d);
	kill_upload(d, NULL);
}

void on_button_uploads_kill_clicked(GtkButton *button, gpointer user_data)
{
    GtkTreeView *treeview;
    GtkTreeSelection *selection;

    treeview = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_uploads"));
    selection = gtk_tree_view_get_selection(treeview);
    gtk_tree_selection_selected_foreach(selection,
        (GtkTreeSelectionForeachFunc) uploads_kill_helper, NULL);
}

#else

void on_button_uploads_kill_clicked(GtkButton *button, gpointer user_data)
{
    GSList *sl = NULL;
    GtkCList *clist;

    clist = GTK_CLIST(lookup_widget(main_window, "clist_uploads"));

    gtk_clist_freeze(clist);

    sl = clist_collect_data(clist, FALSE, NULL);
    g_slist_foreach(sl, (GFunc) kill_upload, NULL);
    g_slist_free(sl);

    gtk_clist_thaw(clist);
}
#endif

void on_button_uploads_clear_completed_clicked(
    GtkButton *button, gpointer user_data)
{
    uploads_gui_clear_completed();
}

/* uploads popup menu */

gboolean on_clist_uploads_button_press_event
    (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row;
    gint col;
    GtkCList *clist_uploads = GTK_CLIST
        (lookup_widget(main_window, "clist_uploads"));

    if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(clist_uploads)->selection == NULL)
        return FALSE;

	if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_uploads), event->x, event->y, &row, &col))
		return FALSE;

    gtk_menu_popup(GTK_MENU(popup_uploads), NULL, NULL, NULL, NULL, 
                  event->button, event->time);

	return TRUE;
}

void on_popup_uploads_title_activate (GtkMenuItem *menuitem, gpointer user_data) 
{
	/* FIXME */
}

