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

RCSID("$Id$");

#include "downloads_gui_common.h"
#include "downloads_gui.h"

#include "downloads.h" /* FIXME: remove this dependency */
#include "dmesh.h" /* FIXME: remove this dependency */
#include "http.h" /* FIXME: remove this dependency */
#include "pproxy.h" /* FIXME: remove this dependency */
#include "statusbar_gui.h"
#include "parq.h"

#ifdef USE_GTK2
#include "downloads_cb2.h"
#else
#include "downloads_cb.h"
#endif

#include "override.h"		/* Must be the last header included */

#define IO_STALLED		60		/* If nothing exchanged after that many secs */
#define IO_AVG_RATE		5		/* Compute global recv rate every 5 secs */

gchar *selected_url = NULL;

static gboolean update_download_clear_needed = FALSE;

/*
 * gui_update_download_clear
 *
 * Remember that we need to check for cleared downloads at the next
 * invocation of gui_update_download_clear_now(), which happens once
 * every second only to avoid too frequent costly list traversals.
 */
void gui_update_download_clear(void)
{
	update_download_clear_needed = TRUE;
}

/*
 *	gui_update_download_clear_now
 *
 *	Checks if there are any active downloads that are clearable
 *  If so, this activates the "Clear Stopped" button
 *
 */
void gui_update_download_clear_now(void)
{
	GSList *l;
	gboolean clear = FALSE;

	if (!update_download_clear_needed)
		return;

	for (l = sl_unqueued; !clear && l; l = l->next) {
		switch (((struct download *) l->data)->status) {
		case GTA_DL_COMPLETED:
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
		case GTA_DL_DONE:
			clear = TRUE;
			break;
		default:
			break;
		}
	}

	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_downloads_clear_stopped"), 
        clear);
}


/*
 *	gui_update_queue_frozen
 *
 *	Checks if the download queue is frozen, if so update the freeze queue
 *  widgets and display a message on the statusbar
 *
 */
void gui_update_queue_frozen(void)
{
    static gboolean msg_displayed = FALSE;
    static statusbar_msgid_t id = {0, 0};

    GtkWidget *togglebutton_queue_freeze;

    togglebutton_queue_freeze =
        lookup_widget(main_window, "togglebutton_queue_freeze");

    if (gui_debug >= 3)
	printf("frozen %i, msg %i\n", download_queue_is_frozen(),
	    msg_displayed);

    if (download_queue_is_frozen() > 0) {
#ifdef USE_GTK1
    	gtk_widget_hide(lookup_widget(main_window, "vbox_queue_freeze"));
    	gtk_widget_show(lookup_widget(main_window, "vbox_queue_thaw"));
#endif
    	/*
		gtk_label_set_text(
            GTK_LABEL(GTK_BIN(togglebutton_queue_freeze)->child),
			"Thaw queue");
		*/
        if (!msg_displayed) {
            msg_displayed = TRUE;
          	id = statusbar_gui_message(0, "QUEUE FROZEN");
        }
    } else {
#ifdef USE_GTK1
    	gtk_widget_show(lookup_widget(main_window, "vbox_queue_freeze"));
    	gtk_widget_hide(lookup_widget(main_window, "vbox_queue_thaw"));
#endif
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
        download_queue_is_frozen() > 0);
    
    gtk_signal_handler_unblock_by_func(
        GTK_OBJECT(togglebutton_queue_freeze),
        GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled),
        NULL);
}


/*
 *	on_popup_downloads_selection_get
 *
 */
void on_popup_downloads_selection_get(GtkWidget * widget, 
	GtkSelectionData * data, guint info, guint eventtime, gpointer user_data) 
{
    g_return_if_fail(selected_url);

    gtk_selection_data_set(data, GDK_SELECTION_TYPE_STRING,
                           8, (guchar *) selected_url, strlen(selected_url));
}


/*
 *	on_popup_downloads_selection_clear_event
 *
 */
gint on_popup_downloads_selection_clear_event(GtkWidget * widget,
                                              GdkEventSelection *event)
{
    if (selected_url != NULL) {
        g_free(selected_url);
        selected_url = NULL;
    }
    return TRUE;
}


/*
 *	on_button_downloads_clear_stopped_clicked
 *
 *	clear all stopped, complete, and unavailable downloads
 *
 */
void on_button_downloads_clear_stopped_clicked(
    GtkButton *button, gpointer user_data)
{
	download_clear_stopped(TRUE, TRUE, TRUE, TRUE);
}


/*
 *	on_togglebutton_queue_freeze_toggled
 *
 *	Freeze the downloads queue
 *
 */
void on_togglebutton_queue_freeze_toggled(GtkToggleButton *togglebutton,
	gpointer user_data) 
{
    if (gtk_toggle_button_get_active(togglebutton)) {
        download_freeze_queue();
    } else {
        download_thaw_queue();
    }
}

gchar *download_gui_get_hostname(struct download *d) 
{
    return is_faked_download(d) ? "" :
		d->server->hostname == NULL ?
		ip_port_to_gchar(download_ip(d), download_port(d)) :
		hostname_port_to_gchar(d->server->hostname, download_port(d));    
}
