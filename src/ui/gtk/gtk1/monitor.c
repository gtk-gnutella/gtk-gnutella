/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup gtk
 * @file
 *
 * GUI stuff used by 'share.c'.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "common.h"

#include "gtk/gui.h"
#include "gtk/monitor.h"

#include "if/core/share.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/str.h"

#include "lib/override.h"		/* Must be the last header included */

/***
 *** Private variables
 ***/

static guint32 monitor_items = 0;

/***
 *** Callbacks
 ***/

static void
monitor_gui_append_to_monitor(query_type_t type, const gchar *item,
	const host_addr_t unused_addr, guint16 unused_port)
{
    static GtkWidget *clist_monitor = NULL;

	(void) unused_addr;
	(void) unused_port;

    if (clist_monitor == NULL) {
        clist_monitor = gui_main_window_lookup("clist_monitor");
        g_assert(clist_monitor != NULL);
    }

	gtk_clist_freeze(GTK_CLIST(clist_monitor));

	while (monitor_items >= GUI_PROPERTY(monitor_max_items)) {
		gint row = GTK_CLIST(clist_monitor)->rows - 1;

		if (row < 0)
			break;

       	gtk_clist_remove(GTK_CLIST(clist_monitor), row);
		monitor_items--;
	}

	if (GUI_PROPERTY(monitor_max_items) > 0) {
    	gchar *titles[1];
    	gchar tmpstr[100];

    	if (type == QUERY_SHA1) {
        	/* If the query is empty and we have a SHA1 extension,
        	 * we print a urn:sha1-query instead. */
        	str_bprintf(tmpstr, sizeof(tmpstr), "urn:sha1:%s", item);
    	} else {
        	g_strlcpy(tmpstr, item, sizeof(tmpstr));
    	}

    	titles[0] = tmpstr;
		gtk_clist_prepend(GTK_CLIST(clist_monitor), titles);
    	monitor_items++;
	}

	gtk_clist_thaw(GTK_CLIST(clist_monitor));
}




/***
 *** Public functions
 ***/

void
monitor_gui_init(void)
{
    gtk_clist_column_titles_passive
        (GTK_CLIST(gui_main_window_lookup("clist_monitor")));
}

void
monitor_gui_shutdown(void)
{
    monitor_gui_enable_monitor(FALSE);
}

/**
 * Remove all but the first n items from the monitor.
 */
void
monitor_gui_clear_monitor(void)
{
    GtkWidget *clist_monitor;

    clist_monitor = gui_main_window_lookup("clist_monitor");

    gtk_clist_clear(GTK_CLIST(clist_monitor));
	monitor_items = 0;
}

/**
 * Enable/disable monitor.
 */
void
monitor_gui_enable_monitor(const gboolean val)
{
    static gboolean registered = FALSE;

    gtk_widget_set_sensitive(gui_main_window_lookup("clist_monitor"), !val);
    if (val != registered) {
        if (val) {
            guc_search_request_listener_add(monitor_gui_append_to_monitor);
        } else {
            guc_search_request_listener_remove(monitor_gui_append_to_monitor);
        }
        registered = val;
    }
}

/* vi: set ts=4 sw=4 cindent: */
