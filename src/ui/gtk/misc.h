/*
 * $Id$
 *
 * Copyright (c) 2001-2004, Raphael Manfredi, Richard Eckart
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

#ifndef _gtk_misc_h_
#define _gtk_misc_h_

#include "gui.h"
#include "if/ui/gtk/misc.h"
#include "lib/prop.h"

void gui_general_timer(time_t now);
void gui_update_traffic_stats(void);
void gui_update_stats_frames(void);
void gui_fix_coords(guint32 *coord);
void gui_save_window(GtkWidget *widget, property_t prop);
void gui_restore_window(GtkWidget *widget, property_t prop);

/*
 * Hit record comparison functions.
 */

gint gui_record_name_eq(gconstpointer rec1, gconstpointer rec2);
gint gui_record_sha1_eq(gconstpointer rec1, gconstpointer rec2);
gint gui_record_host_eq(gconstpointer rec1, gconstpointer rec2);
gint gui_record_sha1_or_name_eq(gconstpointer rec1, gconstpointer rec2);

#ifdef USE_GTK2
void gui_merge_window_as_tab(GtkWidget *toplvl, GtkWidget *notebook,
	GtkWidget *window);
gboolean tree_find_iter_by_data(GtkTreeModel *model, guint column,
	gconstpointer data, GtkTreeIter *iter);
#endif /* USE_GTK2 */

#endif /* _gtk_misc_h_ */
