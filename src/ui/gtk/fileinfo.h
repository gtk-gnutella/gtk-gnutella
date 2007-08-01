/*
 * $Id$
 *
 * Copyright (c) 2003, Richard Eckart
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
 * Displaying of file information in the GUI.
 *
 * @author Richard Eckart
 * @date 2003
 */

#ifndef _gtk_fileinfo_h_
#define _gtk_fileinfo_h_

#include "gui.h"

void fi_gui_init(void);
void fi_gui_update_display(time_t now);
void fi_gui_shutdown(void);

#ifdef USE_GTK1
gboolean on_clist_fileinfo_button_press_event(
    GtkWidget *, GdkEventButton *event, gpointer user_data);

void on_clist_fileinfo_select_row(
    GtkCList *, gint, gint, GdkEvent *, gpointer user_data);

void on_clist_fileinfo_unselect_row(
    GtkCList *, gint, gint, GdkEvent *, gpointer user_data);

void on_clist_fileinfo_click_column(GtkCList * clist,
	gint column, gpointer user_data);
#endif /* USE_GTK1 */

void on_button_fi_purge_clicked(
	GtkButton *button, gpointer user_data);

void on_entry_fi_regex_activate(
    GtkEditable *editable, gpointer user_data);

#endif /* _gtk_fileinfo_h_ */

