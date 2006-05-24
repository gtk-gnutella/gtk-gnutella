/*
 * $Id$
 *
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
 * @date 2004
 */

#include "gui.h"

RCSID("$Id$");

#include "drop.h"
#include "statusbar.h"
#include "search.h"

#include "if/gui_property_priv.h"

#include "lib/glib-missing.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * Private functions
 */

static gboolean
handle_not_implemented(const gchar *url)
{
	g_return_val_if_fail(url, FALSE);
	statusbar_gui_warning(10,
			_("Support for this protocol is not yet implemented"));
	return FALSE;
}

static gboolean
handle_magnet(const gchar *url)
{
	const gchar *error_str;
	gboolean success;

	g_return_val_if_fail(url, FALSE);

	success = search_gui_handle_magnet(url, &error_str);
	if (!success) {
		statusbar_gui_warning(10, "%s", error_str);
	}
	return success;
}

static gboolean
handle_http(const gchar *url)
{
	const gchar *error_str;
	gboolean success;

	g_return_val_if_fail(url, FALSE);

	success = search_gui_handle_http(url, &error_str);
	if (!success) {
		statusbar_gui_warning(10, "%s", error_str);
	}
	return success;
}

static gboolean
handle_urn(const gchar *url)
{
	const gchar *error_str;
	gboolean success;

	g_return_val_if_fail(url, FALSE);

	success = search_gui_handle_urn(url, &error_str);
	if (!success) {
		statusbar_gui_warning(10, "%s", error_str);
	}
	return success;
}

/*
 * Private data
 */

static const struct {
	const char * const proto;
	gboolean (* handler)(const gchar *url);
} proto_handlers[] = {
	{ "ftp",	handle_not_implemented },
	{ "http",	handle_http },
	{ "magnet",	handle_magnet },
	{ "urn",	handle_urn },
};


/* FIXME: We shouldn't try to handle from ourselves without a confirmation
 *        because an URL might have been accidently while dragging it
 *		  around.
 */
static void
drag_data_received(GtkWidget *unused_widget, GdkDragContext *dc,
	gint x, gint y, GtkSelectionData *data, guint info, guint stamp,
	gpointer unused_udata)
{
	gboolean succ = FALSE;

	(void) unused_widget;
	(void) unused_udata;

	if (gui_debug > 0)
		g_message("drag_data_received: x=%d, y=%d, info=%u, t=%u",
			x, y, info, stamp);
	if (data->length > 0 && data->format == 8) {
		gchar *p, *url = cast_to_gchar_ptr(data->data);
		size_t len;
		guint i;

		if (gui_debug > 0)
			g_message("drag_data_received: url=\"%s\"", url);


		p = strchr(url, ':');
		len = p ? p - url : 0;
		if (!p || (ssize_t) len < 1) {
			statusbar_gui_warning(10, _("Cannot handle the dropped data"));
			goto cleanup;
		}

		for (i = 0; i < G_N_ELEMENTS(proto_handlers); i++)
			if (is_strprefix(url, proto_handlers[i].proto)) {
				succ = proto_handlers[i].handler(url);
				break;
			}

		if (i == G_N_ELEMENTS(proto_handlers))
			statusbar_gui_warning(10, _("Protocol is not supported"));
	}

cleanup:

	gtk_drag_finish(dc, succ, FALSE, stamp);
}

/*
 * Public functions
 */

void
drop_init(void)
{
	static const GtkTargetEntry targets[] = {
		{ "STRING",		0, 23 },
		{ "text/plain", 0, 23 },
	};
	GtkWidget *w = GTK_WIDGET(main_window);

	gtk_drag_dest_set(w, GTK_DEST_DEFAULT_ALL, targets,
		G_N_ELEMENTS(targets), GDK_ACTION_COPY | GDK_ACTION_MOVE);

#ifdef USE_GTK2
	{
		static GtkClipboard *clipboard;
	
		g_return_if_fail(!clipboard);
		clipboard = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
		g_return_if_fail(clipboard);
	}
	
	g_signal_connect(G_OBJECT(w), "drag-data-received",
		G_CALLBACK(drag_data_received), NULL);

	gtk_drag_dest_set_target_list(w, gtk_target_list_new(targets,
		G_N_ELEMENTS(targets)));
#endif /* USE_GTK2 */

#ifdef USE_GTK1
	gtk_signal_connect(GTK_OBJECT(w), "drag-data-received",
		drag_data_received, NULL);

	gtk_selection_add_targets(w, GDK_SELECTION_TYPE_STRING,
		targets, G_N_ELEMENTS(targets));
#endif /* USE_GTK1 */
	
}

void
drop_close(void)
{
	/* Nothing ATM */
}

/* vi: set ts=4 sw=4 cindent: */
