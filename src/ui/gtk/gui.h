/*
 * Copyright (c) 2004, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _gtk_ui_h_
#define _gtk_ui_h_

#include "common.h"

#ifdef USE_TOPLESS

#define settings_gui_save_if_dirty()
#define settings_gui_shutdown()

#define main_gui_early_init(argc, argv, disable_xshm)
#define main_gui_init()
#define main_gui_run(a, b)
#define main_gui_exit(x)
#define main_gui_timer(x)
#define main_gui_shutdown()
#define main_gui_shutdown_tick(remain)

#else	/* !USE_TOPLESS */

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include "gtk-missing.h"

#ifdef USE_GTK1
#include "gtk1/interface-glade.h"
#include "gtk1/support-glade.h"
#endif

#ifdef USE_GTK2
#include "gtk2/interface-glade.h"
#include "gtk2/support-glade.h"

#if !GTK_CHECK_VERSION(2,5,0)
#include "gtk2/pbarcellrenderer.h"
#endif

/* Common padding values for GtkCellRenderer */
#define GUI_CELL_RENDERER_XPAD ((guint) 4U)
#define GUI_CELL_RENDERER_YPAD ((guint) 0U)

#endif

#include "main.h"

/* GUI signal functions */
#ifdef USE_GTK1
#define gui_signal_connect(widget, name, func, data) \
	gtk_signal_connect(GTK_OBJECT(widget), (name), \
		GTK_SIGNAL_FUNC(func), (data))

#define gui_signal_connect_after(widget, name, func, data) \
	gtk_signal_connect_after(GTK_OBJECT(widget), (name), \
		GTK_SIGNAL_FUNC(func), (data))

#define gui_signal_disconnect(widget, func, data) \
	gtk_signal_disconnect_by_func(GTK_OBJECT(widget), \
		GTK_SIGNAL_FUNC(func), (data))

#define gui_signal_stop_emit_by_name(widget, name) \
	gtk_signal_emit_stop_by_name(GTK_OBJECT(widget), (name))

#endif /* USE_GTK1 */

#ifdef USE_GTK2
#define gui_signal_connect(widget, name, func, data) \
	g_signal_connect((widget), (name), \
		G_CALLBACK(func), (data))

#define gui_signal_connect_after(widget, name, func, data) \
	g_signal_connect_after((widget), (name), \
		G_CALLBACK(func), (data))

#define gui_signal_disconnect(widget, func, data) \
	g_signal_handlers_disconnect_by_func((widget), \
		cast_func_to_pointer(func), (data))

#define gui_signal_stop_emit_by_name(widget, name) \
	g_signal_stop_emission_by_name((widget), (name))

#endif	/* Gtk+ 2.0 */

/**
 * Sorting constants.
 */

enum sorting_order {
	SORT_DESC = -1,
	SORT_NONE = 0,
	SORT_ASC = 1,
	SORT_NO_COL = 2		/**< No column chosen yet */
};

struct sorting_context {
	int s_column;					/**< The column being sorted */
	enum sorting_order s_order;		/**< Sorting order attached to column */
};

#endif	/* USE_TOPLESS */
#endif /* _gtk_ui_h_ */

/* vi: set ts=4 sw=4 cindent: */
