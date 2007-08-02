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

#define WIDGET(name) \
	GtkWidget *gui_ ## name (void); \
	GtkWidget *gui_ ## name ## _lookup(const gchar *id);

WIDGET(dlg_about)
WIDGET(dlg_ancient)
WIDGET(dlg_faq)
WIDGET(dlg_prefs)
WIDGET(dlg_quit)
WIDGET(filter_dialog)
WIDGET(main_window)
WIDGET(popup_downloads)
WIDGET(popup_filter_rule)
WIDGET(popup_monitor)
WIDGET(popup_nodes)
WIDGET(popup_search)
WIDGET(popup_search_list)
WIDGET(popup_sources)
WIDGET(popup_uploads)
WIDGET(shutdown_window)
#undef WIDGET

void main_gui_early_init(gint argc, gchar **argv, gboolean disable_xshm);
void main_gui_init(void);
void main_gui_run(const gchar *geometry_spec);
void main_gui_shutdown(void);
void main_gui_timer(time_t now);
void main_gui_update_coords(void);
void main_gui_shutdown_tick(guint);
void main_gui_show_prefences(void);
gboolean main_gui_window_visible(void);

#endif /* _gtk_main_h_ */
/* vi: set ts=4 sw=4 cindent: */
