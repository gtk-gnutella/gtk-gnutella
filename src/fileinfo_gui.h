/*
 * $Id$
 *
 * Copyright (c) 2003, Richard Eckart
 *
 * Displaying of file information in the gui.
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

#ifndef _fileinfo_gui_h_
#define _fileinfo_gui_h_

#include "gui.h"

void fi_gui_init(void);
void fi_gui_shutdown(void);

#ifndef USE_GTK2
void on_clist_fileinfo_resize_column(GtkCList *, gint, gint, gpointer);
gboolean on_clist_fileinfo_button_press_event(
    GtkWidget *, GdkEventButton *event, gpointer user_data);

void on_clist_fileinfo_select_row(
    GtkCList *, gint, gint, GdkEvent *, gpointer user_data);

void on_clist_fileinfo_unselect_row(
    GtkCList *, gint, gint, GdkEvent *, gpointer user_data);
#endif /* USE_GTK2 */

#endif /* _fileinfo_gui_h_ */

