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

#ifndef _gtk_upload_stats_cb_h_
#define _gtk_upload_stats_cb_h_

#include "gui.h"

/***
 *** upload stats
 ***/

void on_button_ul_stats_clear_all_clicked(GtkButton *, gpointer);
void on_button_ul_stats_clear_deleted_clicked(GtkButton *, gpointer);

#ifdef USE_GTK1
gint compare_ul_norm(GtkCList *, gconstpointer, gconstpointer);

void on_clist_ul_stats_click_column(GtkCList *, gint, gpointer);
#endif /* USE_GTK1 */

#ifdef USE_GTK2
void on_popup_upload_stats_config_cols_activate(GtkMenuItem *, gpointer);
#endif /* USE_GTK2 */

#endif /* _gtk_upload_stats_cb_h_ */

/* vi: set ts=4 sw=4 cindent: */
