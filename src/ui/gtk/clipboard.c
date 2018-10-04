/*
 * Copyright (c) 2007, Christian Biere
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
 * Clipboard-related functions.
 *
 * @author Christian Biere
 * @date 2007
 */

#include "gui.h"

#include "clipboard.h"

#include "lib/override.h"		/* Must be the last header included */

#if GTK_CHECK_VERSION(2,0,0)

void
clipboard_set_text(GtkWidget *unused_owner, const char *text)
{
	(void) unused_owner;

	gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_PRIMARY));
	gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD));

	if (text) {
		size_t length;

		length = vstrlen(text);
		if (length < UNSIGNED(INT_MAX)) {
			gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY),
				text, length);
			gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD),
				text, length);
		}
	}
}

#else	/* Gtk+ 1.2 */

#define CLIPBOARD_FETCH_TEXT ((const void *) -1)
#define CLIPBOARD_CLEAR_TEXT ((const void *) 0)

static const char *
clipboard_text(const char *value)
{
	static char *text;

	if (CLIPBOARD_FETCH_TEXT != value) {
		G_FREE_NULL(text);
		text = g_strdup(value);
	}
	return text;
}

static inline void
clipboard_text_clear(void)
{
	clipboard_text(CLIPBOARD_CLEAR_TEXT);
}

static inline const char *
clipboard_text_get(void)
{
	return clipboard_text(CLIPBOARD_FETCH_TEXT);
}

static inline void
clipboard_text_set(const char *text)
{
	clipboard_text(text);
}

static void
on_clipboard_selection_get(GtkWidget *unused_widget,
	GtkSelectionData *data, guint unused_info,
	guint unused_eventtime, gpointer unused_udata)
{
	const char *text;
	size_t length;

	(void) unused_widget;
	(void) unused_info;
	(void) unused_udata;
	(void) unused_eventtime;

	text = clipboard_text_get();
	if (NULL != text) {
		length = vstrlen(text);
		if (length >= UNSIGNED(INT_MAX)) {
			text = NULL;
			length = 0;
		}
	} else {
		length = 0;
	}
    gtk_selection_data_set(data, GDK_SELECTION_TYPE_STRING,
		8 /* CHAR_BIT */, (guchar *) text, length);
}

static int
on_clipboard_selection_clear_event(GtkWidget *unused_widget,
	GdkEventSelection *unused_event)
{
	(void) unused_widget;
	(void) unused_event;
	clipboard_text_clear();
    return TRUE;
}

void
clipboard_set_text(GtkWidget *owner, const char *text)
{
	g_return_if_fail(owner);

	if (
		gtk_selection_owner_set(owner, GDK_SELECTION_PRIMARY,
			gtk_get_current_event_time())
	) {
		clipboard_text_set(text);
	}
}

void
clipboard_clear(void)
{
	clipboard_text_clear();
}

#endif	/* Gtk+ 2.x */

void
clipboard_attach(GtkWidget *widget)
{
	g_return_if_fail(widget);

#if !GTK_CHECK_VERSION(2,0,0)
	gui_signal_connect(GTK_WIDGET(widget), "selection-get",
		on_clipboard_selection_get, NULL);
  	gui_signal_connect(GTK_WIDGET(widget), "selection-clear-event",
		on_clipboard_selection_clear_event, NULL);
#endif	/* Gtk+ 1.2 */

	gtk_selection_add_target(GTK_WIDGET(widget),
		GDK_SELECTION_PRIMARY, GDK_SELECTION_TYPE_STRING, 1);
}

/* vi: set ts=4 sw=4 cindent: */
