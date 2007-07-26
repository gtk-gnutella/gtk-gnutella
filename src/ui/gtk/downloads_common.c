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
#include "settings.h"
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
#include "lib/utf8.h"

#include "lib/override.h"	/* Must be the last header included */

#define IO_STALLED		60	/**< If nothing exchanged after that many secs */
#define IO_AVG_RATE		5	/**< Compute global recv rate every 5 secs */

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
        gui_main_window_lookup("button_downloads_clear_stopped"),
        guc_download_something_to_clear());
}

/**
 * Enable the "start now" menu entry for queued items.
 */
void
gui_download_enable_start_now(guint32 running_downloads, guint32 max_downloads)
#ifdef USE_GTK1
{
	GtkWidget *w = gui_popup_queue_lookup("popup_queue_start_now");
	gboolean selected = TRUE;

	selected = GTK_CLIST(
		gui_main_window_lookup("ctree_downloads_queue"))->selection != NULL;
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
	guc_download_clear_stopped(TRUE, TRUE, TRUE, TRUE, TRUE);
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

void
downloads_gui_set_details(const gchar *filename, filesize_t filesize,
	const struct sha1 *sha1, const struct tth *tth)
{
	downloads_gui_clear_details();

	downloads_gui_append_detail(_("Filename"),
		lazy_filename_to_ui_string(filename));
	downloads_gui_append_detail(_("Size"),
		nice_size(filesize, show_metric_units()));
	downloads_gui_append_detail(_("SHA-1"),
		sha1 ? sha1_to_urn_string(sha1) : NULL);
	downloads_gui_append_detail(_("Bitprint"),
		sha1 && tth ? bitprint_to_urn_string(sha1, tth) : NULL);
}

/* vi: set ts=4 sw=4 cindent: */
