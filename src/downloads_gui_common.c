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
#endif

#ifdef USE_GTK1
#include "downloads_cb.h"
#endif


RCSID("$Id$");

#define IO_STALLED		60		/* If nothing exchanged after that many secs */
#define IO_AVG_RATE		5		/* Compute global recv rate every 5 secs */

static gchar tmpstr[4096];

void gui_update_download_clear(void)
{
	GSList *l;
	gboolean clear = FALSE;

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
#ifndef USE_GTK2
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
#ifndef USE_GTK2
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
