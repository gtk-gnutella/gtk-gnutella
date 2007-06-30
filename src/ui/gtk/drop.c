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

RCSID("$Id$")

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
handle_url(const gchar *url)
{
	const gchar *error_str;
	gboolean success;

	g_return_val_if_fail(url, FALSE);

	success = search_gui_handle_url(url, &error_str);
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
	{ "http",	handle_url },
	{ "push",	handle_url },
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
	gboolean success = FALSE;

	(void) unused_widget;
	(void) unused_udata;

	if (GUI_PROPERTY(gui_debug) > 0) {
		g_message("drag_data_received: x=%d, y=%d, info=%u, t=%u",
			x, y, info, stamp);
	}
	if (data->length > 0 && data->format == 8) {
		const gchar *text = cast_to_gchar_ptr(data->data);
		guint i;

		if (GUI_PROPERTY(gui_debug) > 0) {
			g_message("drag_data_received: text=\"%s\"", text);
		}
		for (i = 0; i < G_N_ELEMENTS(proto_handlers); i++) {
			const char *endptr;
			
			endptr = is_strcaseprefix(text, proto_handlers[i].proto);
			if (endptr && ':' == endptr[0]) {
				success = proto_handlers[i].handler(text);
				goto cleanup;
			}
		}
		success = search_gui_insert_query(text);
	}

cleanup:
	if (!success) {
		statusbar_gui_warning(10, _("Cannot handle the dropped data"));
	}
	gtk_drag_finish(dc, success, FALSE, stamp);
}

/*
 * Public functions
 */

void
drop_widget_init(GtkWidget *widget, drag_data_received_cb callback,
	void *user_data)
{
	static const GtkTargetEntry targets[] = {
		{ "STRING",						0, 1 },
		{ "text/plain", 				0, 2 },
#if GTK_CHECK_VERSION(2,0,0)
        { "UTF8_STRING",				0, 3 },
        { "text/plain;charset=utf-8",	0, 4 },
#endif	/* Gtk+ >= 2.0 */
	};

	g_return_if_fail(widget);
	g_return_if_fail(callback);

	gtk_drag_dest_set(widget, GTK_DEST_DEFAULT_ALL, targets,
		G_N_ELEMENTS(targets), GDK_ACTION_COPY | GDK_ACTION_MOVE);

#if GTK_CHECK_VERSION(2,0,0)
	{
		static GtkClipboard *clipboard;
	
		g_return_if_fail(!clipboard);
		clipboard = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
		g_return_if_fail(clipboard);
	}
	
	gtk_drag_dest_set_target_list(widget, gtk_target_list_new(targets,
		G_N_ELEMENTS(targets)));
#endif /* USE_GTK2 */

#if !GTK_CHECK_VERSION(2,0,0)

	gtk_selection_add_targets(widget, GDK_SELECTION_TYPE_STRING,
		targets, G_N_ELEMENTS(targets));
#endif /* USE_GTK1 */

	gui_signal_connect(GTK_OBJECT(widget), "drag-data-received",
		callback, user_data);
}

void
drop_init(void)
{
	drop_widget_init(gui_main_window(), drag_data_received, NULL);
}

void
drop_close(void)
{
	/* Nothing ATM */
}

/* vi: set ts=4 sw=4 cindent: */
