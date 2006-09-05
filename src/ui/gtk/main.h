/*
 * $Id$
 *
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

#ifndef _gtk_main_h_
#define _gtk_main_h_

#include "common.h"

#include <gtk/gtk.h>

extern GtkWidget *main_window;
extern GtkWidget *shutdown_window;
extern GtkWidget *dlg_about;
extern GtkWidget *dlg_faq;
extern GtkWidget *dlg_prefs;
extern GtkWidget *dlg_quit;
extern GtkWidget *popup_downloads;
extern GtkWidget *popup_uploads;
extern GtkWidget *popup_search;
extern GtkWidget *popup_search_list;
extern GtkWidget *popup_nodes;
extern GtkWidget *popup_monitor;
extern GtkWidget *popup_queue;

void main_gui_early_init(gint, gchar **);
void main_gui_init(void);
void main_gui_run(const gchar *geometry_spec);
void main_gui_shutdown(void);
void main_gui_timer(time_t now);
void main_gui_update_coords(void);
void main_gui_shutdown_tick(guint);

#endif /* _gtk_main_h_ */
