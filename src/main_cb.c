/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
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

#include "main_cb.h"
#include "main_gui.h"

/***
 *** Private functions
 ***/

static void quit(gboolean force)
{
    gboolean confirm;

    gui_prop_get_boolean(PROP_CONFIRM_QUIT, &confirm, 0, 1);

    if (force || !confirm)
       	gtk_gnutella_exit(0);
    else
        gtk_widget_show(dlg_quit);
}

/***
 *** Main window
 ***/

gboolean on_main_window_delete_event
    (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
    quit(FALSE);
	return TRUE;
}

void on_button_quit_clicked(GtkButton * button, gpointer user_data)
{
    quit(FALSE);
}



/***
 *** menu bar
 ***/ 

void on_menu_about_activate(GtkMenuItem *menuitem, gpointer user_data)
{
    gtk_widget_show(dlg_about);
}




/***
 *** about dialog
 ***/

void on_button_about_close_clicked(GtkButton *button, gpointer user_data)
{
    gtk_widget_hide(dlg_about);
}

gboolean on_dlg_about_delete_event
    (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_hide(dlg_about);
	return TRUE;
}



/***
 *** Quit dialog
 ***/
void on_button_really_quit_clicked(GtkButton *button,gpointer user_data)
{
    gtk_widget_hide(dlg_quit);
	quit(TRUE);
}


void on_button_abort_quit_clicked(GtkButton *button, gpointer user_data)
{
    gtk_widget_hide(dlg_quit);
}

gboolean on_dlg_quit_delete_event(
    GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
    gtk_widget_hide(dlg_quit);
    return TRUE;
}

#ifdef USE_GTK2
void on_main_gui_treeview_menu_cursor_changed(
    GtkTreeView *treeview, gpointer user_data)
{   
    GtkTreeSelection *selection;
    GtkTreeModel *model = NULL;
    GtkTreeIter iter; 
    gint tab = 0;
    
    g_assert(treeview != NULL);
    selection = gtk_tree_view_get_selection(treeview);
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gtk_tree_model_get(GTK_TREE_MODEL(model), &iter, 1, &tab, -1);
        gtk_notebook_set_page
            (GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")), tab);
    }
}
#endif
