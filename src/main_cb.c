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
 *** Main window
 ***/

gboolean on_main_window_delete_event
    (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_gnutella_exit(0);
	return TRUE;
}

void on_button_quit_clicked(GtkButton * button, gpointer user_data)
{
	gtk_gnutella_exit(0);
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
