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

#ifndef _upload_stats_cb_h_
#define _upload_stats_cb_h_

#include "gui.h"

/***
 *** upload stats
 ***/

gint compare_ul_norm(GtkCList *clist, gconstpointer ptr1,
						 gconstpointer ptr2);

void on_button_ul_stats_clear_all_clicked(
	GtkButton * button, gpointer user_data);
void on_button_ul_stats_clear_deleted_clicked(
	GtkButton * button, gpointer user_data);
void on_clist_ul_stats_click_column(
	GtkCList * clist, gint column, gpointer user_data);
void on_clist_ul_stats_resize_column(
	GtkCList * clist, gint column, gint width, gpointer user_data);

#endif /* _upload_stats_cb_h_ */

