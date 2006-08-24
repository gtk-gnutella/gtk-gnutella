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

#include "gui.h"

RCSID("$Id$")
#include "downloads_common.h"
#include "downloads.h"
#include "statusbar.h"

#ifdef USE_GTK2
#include "gtk2/downloads_cb.h"
#endif
#ifdef USE_GTK1
#include "gtk1/downloads_cb.h"
#endif

#include "if/bridge/ui2c.h"
#include "if/gui_property_priv.h"

#include "lib/glib-missing.h"
#include "lib/override.h"		/* Must be the last header included */

#define IO_STALLED		60		/**< If nothing exchanged after that many secs */
#define IO_AVG_RATE		5		/**< Compute global recv rate every 5 secs */

static gboolean update_download_clear_needed = FALSE;

/**
 * Remember that we need to check for cleared downloads at the next
 * invocation of gui_update_download_clear_now(), which happens once
 * every second only to avoid too frequent costly list traversals.
 */
void
gui_update_download_clear(void)
{
	update_download_clear_needed = TRUE;
}

/**
 *	Checks if there are any active downloads that are clearable
 *  If so, this activates the "Clear Stopped" button
 */
void
gui_update_download_clear_now(void)
{
	if (!update_download_clear_needed)
		return;

	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_downloads_clear_stopped"),
        guc_download_something_to_clear());
}

/**
 *	Checks if the download queue is frozen, if so update the freeze queue
 *  widgets and display a message on the statusbar
 */
void
gui_update_queue_frozen(void)
{
#ifdef USE_GTK1
    static gboolean msg_displayed = FALSE;
    static statusbar_msgid_t id = {0, 0};
    GtkWidget *togglebutton_queue_freeze;

    togglebutton_queue_freeze =
        lookup_widget(main_window, "togglebutton_queue_freeze");

    if (gui_debug >= 3)
		g_message("frozen %i, msg %i\n",
			(gint) guc_download_queue_is_frozen(),
	    	(gint) msg_displayed);

    if (guc_download_queue_is_frozen()) {
    	gtk_widget_hide(lookup_widget(main_window, "vbox_queue_freeze"));
    	gtk_widget_show(lookup_widget(main_window, "vbox_queue_thaw"));
    	/*
		gtk_label_set_text(
            GTK_LABEL(GTK_BIN(togglebutton_queue_freeze)->child),
			"Thaw queue");
		*/
        if (!msg_displayed) {
            msg_displayed = TRUE;
          	id = statusbar_gui_message(0, _("Queue frozen"));
        }
    } else {
    	gtk_widget_show(lookup_widget(main_window, "vbox_queue_freeze"));
    	gtk_widget_hide(lookup_widget(main_window, "vbox_queue_thaw"));
    	/*
		gtk_label_set_text(
            GTK_LABEL(GTK_BIN(togglebutton_queue_freeze)->child),
			"Freeze queue");
		*/
        if (msg_displayed) {
            msg_displayed = FALSE;
            statusbar_gui_remove(id);
        }
	}

    gtk_signal_handler_block_by_func(
        GTK_OBJECT(togglebutton_queue_freeze),
        GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled),
        NULL);

    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(togglebutton_queue_freeze),
        guc_download_queue_is_frozen());

    gtk_signal_handler_unblock_by_func(
        GTK_OBJECT(togglebutton_queue_freeze),
        GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled),
        NULL);
#endif /* USE_GTK1 */
}

/**
 * Enable the "start now" menu entry for queued items.
 */
void
gui_download_enable_start_now(guint32 running_downloads, guint32 max_downloads)
#ifdef USE_GTK1
{
	GtkWidget *w = lookup_widget(popup_queue, "popup_queue_start_now");
	gboolean selected = TRUE;

	selected = GTK_CLIST(
		lookup_widget(main_window, "ctree_downloads_queue"))->selection != NULL;
	gtk_widget_set_sensitive(w, selected && running_downloads < max_downloads);
}
#else
{
	(void) running_downloads;
	(void) max_downloads;
}
#endif


/**
 *	Clear all stopped, complete, and unavailable downloads.
 */
void
on_button_downloads_clear_stopped_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
	guc_download_clear_stopped(TRUE, TRUE, TRUE, TRUE);
}


/**
 *	Freeze the downloads queue.
 */
void
on_togglebutton_queue_freeze_toggled(GtkToggleButton *togglebutton,
	gpointer unused_udata)
{
	(void) unused_udata;

    if (gtk_toggle_button_get_active(togglebutton)) {
        guc_download_freeze_queue();
    } else {
        guc_download_thaw_queue();
    }
}

const gchar *
download_progress_to_string(const struct download *d)
{
	static gchar buf[32];

	gm_snprintf(buf, sizeof buf, "%5.2f%%",
		100.0 * guc_download_total_progress(d));
	return buf;
}

 const gchar *
source_progress_to_string(const struct download *d)
{
	static gchar buf[32];

	gm_snprintf(buf, sizeof buf, "%5.2f%%",
		100.0 * guc_download_source_progress(d));
	return buf;
}

/* vi: set ts=4 sw=4 cindent: */
