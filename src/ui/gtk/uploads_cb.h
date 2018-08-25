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

#ifndef _gtk_uploads_cb_h_
#define _gtk_uploads_cb_h_

#include "gui.h"

/***
 *** uploads panel
 ***/

void on_button_uploads_kill_clicked(GtkButton *, gpointer);
void on_button_uploads_remove_clicked(GtkButton *, gpointer);
void on_button_uploads_clear_completed_clicked(GtkButton *, gpointer);

void on_popup_uploads_browse_host_activate(GtkMenuItem *, gpointer);
void on_popup_uploads_config_cols_activate(GtkMenuItem *, gpointer);

#ifdef USE_GTK1
void on_clist_uploads_select_row(GtkCList *, gint, gint, GdkEvent *, gpointer);
void on_clist_uploads_unselect_row(GtkCList *, gint, gint, GdkEvent *,
	gpointer);
gboolean on_clist_uploads_button_press_event(GtkWidget *, GdkEventButton *,
	gpointer);
#endif /* USE_GTK1 */

#endif /* _gtk_uploads_cb_h_ */

/* vi: set ts=4 sw=4 cindent: */
