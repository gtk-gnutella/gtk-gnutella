/*
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

#ifndef _gtk_main_cb_h_
#define _gtk_main_cb_h_

#include "gui.h"
#ifdef HAVE_GTKOSXAPPLICATION
#include <gtkmacintegration-gtk2/gtkosxapplication.h>
#endif

/***
 *** General main window actions
 ***/
void on_button_quit_clicked(GtkButton *button, gpointer user_data);
gboolean on_main_window_delete_event(
    GtkWidget *widget, GdkEvent *event, gpointer user_data);

#ifdef HAVE_GTKOSXAPPLICATION
gboolean on_main_window_delete_event_hide(GtkWidget *unused_widget, 
	GdkEvent *unused_event, gpointer unused_udata);
gboolean on_NSApplicationOpenFile(GtkosxApplication *app, gchar *path, 
	gpointer user_data);
gboolean on_NSApplicationDidBecomeActive(GtkosxApplication *app, 
	gpointer user_data);
#endif
/***
 *** Menu bar
 ***/
void on_menu_about_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_faq_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_prefs_activate(GtkMenuItem * menuitem, gpointer user_data);


/***
 *** About dialog
 ***/
void on_button_about_close_clicked(GtkButton *button, gpointer user_data);
gboolean on_dlg_about_delete_event(
    GtkWidget *widget, GdkEvent *event, gpointer user_data);

/***
 *** Keyboard shortcut dialog
 ***/

void
on_menu_keyboard_shortcuts_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata);

void on_button_ancient_close_clicked(GtkButton *button, gpointer user_data);
gboolean on_dlg_ancient_delete_event(
    GtkWidget *widget, GdkEvent *event, gpointer user_data);

/***
 *** FAQ dialog
 ***/
gboolean on_dlg_faq_delete_event(GtkWidget *widget, GdkEvent *event,
		gpointer user_data);

/***
 *** Prefs dialog
 ***/
void on_button_prefs_close_clicked(GtkButton *button, gpointer user_data);
gboolean on_dlg_prefs_delete_event(
    GtkWidget *widget, GdkEvent *event, gpointer user_data);


/***
 *** Quit dialog
 ***/
void on_button_really_quit_clicked(GtkButton *button,gpointer user_data);
void on_button_abort_quit_clicked(GtkButton *button, gpointer user_data);
gboolean on_dlg_quit_delete_event(
    GtkWidget *widget, GdkEvent *event, gpointer user_data);


/***
 *** Tray menu
 ***/
void on_popup_tray_preferences_activate(GtkMenuItem *, gpointer user_data);
void on_popup_tray_quit_activate(GtkMenuItem *, gpointer user_data);

#endif /* _gtk_main_cb_h_ */
