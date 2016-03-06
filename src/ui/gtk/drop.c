/*
 * Copyright (c) 2004, Christian Biere
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
 * Drop support - no dragging, just dropping.
 *
 * @author Christian Biere
 * @date 2007
 */

#include "gui.h"

#include "drop.h"

#include "if/gui_property_priv.h"

#include "lib/glib-missing.h"
#include "lib/override.h"		/* Must be the last header included */

void
drop_widget_init(GtkWidget *widget, drag_data_received_cb callback,
	void *user_data)
{
	static const GtkTargetEntry targets[] = {
#if GTK_CHECK_VERSION(2,0,0)
        { "UTF8_STRING",				0, 3 },
        { "text/plain;charset=utf-8",	0, 4 },
#endif	/* Gtk+ >= 2.0 */
		{ "STRING",						0, 1 },
		{ "text/plain", 				0, 2 },
	};

	g_return_if_fail(widget);
	g_return_if_fail(callback);

	gtk_drag_dest_set(widget, GTK_DEST_DEFAULT_ALL, targets,
		N_ITEMS(targets), GDK_ACTION_COPY | GDK_ACTION_MOVE);

#if GTK_CHECK_VERSION(2,0,0)
	{
		static GtkClipboard *clipboard;

		if (!clipboard) {
			clipboard = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
		}
	}

	gtk_drag_dest_set_target_list(widget, gtk_target_list_new(targets,
		N_ITEMS(targets)));
#endif /* USE_GTK2 */

#if !GTK_CHECK_VERSION(2,0,0)

	gtk_selection_add_targets(widget, GDK_SELECTION_TYPE_STRING,
		targets, N_ITEMS(targets));
#endif /* USE_GTK1 */

	gui_signal_connect(GTK_OBJECT(widget), "drag-data-received",
		callback, user_data);
}

/* vi: set ts=4 sw=4 cindent: */
