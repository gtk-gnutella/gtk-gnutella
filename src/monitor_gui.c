/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * GUI stuff used by share.c
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

#include "monitor_gui.h"


/***
 *** Private variables
 ***/

static guint32 monitor_items = 0;



/***
 *** Callbacks
 ***/

static void monitor_gui_append_to_monitor(
    query_type_t type, const gchar *item, guint32 ip, guint16 port)
{
    char *titles[1];
    static GtkWidget *clist_monitor = NULL;
    gchar tmpstr[100];

    if (clist_monitor == NULL) {
        clist_monitor = lookup_widget(main_window, "clist_monitor");
        g_assert(clist_monitor != NULL);
    }

	gtk_clist_freeze(GTK_CLIST(clist_monitor));

	if (monitor_items < monitor_max_items)
        monitor_items++;
	else
        gtk_clist_remove(GTK_CLIST(clist_monitor),
            GTK_CLIST(clist_monitor)->rows - 1);

    if (type == QUERY_SHA1) {
        /* If the query is empty and we have a SHA1 extension,
         * we print a urn:sha1-query instead. */
        g_snprintf(tmpstr, sizeof(tmpstr), "urn:sha1:%s", item);
    } else {
        g_snprintf(tmpstr, sizeof(tmpstr), "%s", item);
    }

    titles[0] = tmpstr;

	gtk_clist_prepend(GTK_CLIST(clist_monitor), titles);

	gtk_clist_thaw(GTK_CLIST(clist_monitor));
}




/***
 *** Public functions
 ***/

void monitor_gui_init()
{
    gtk_clist_column_titles_passive
        (GTK_CLIST(lookup_widget(main_window, "clist_monitor")));  
}

void monitor_gui_shutdown()
{
    monitor_gui_enable_monitor(FALSE);
}

/*
 * monitor_gui_clear_monitor:
 *
 * Remove all but the first n items from the monitor.
 */
void monitor_gui_clear_monitor(void) 
{
    GtkWidget *clist_monitor;

    clist_monitor = lookup_widget(main_window, "clist_monitor");

    gtk_clist_clear(GTK_CLIST(clist_monitor));
	monitor_items = 0;
}

/*
 * monitor_gui_enable_monitor:
 *
 * Enable/disable monitor.
 */
void monitor_gui_enable_monitor(const gboolean val)
{
    static gboolean registered = FALSE;
    gtk_widget_set_sensitive
        (lookup_widget(main_window, "clist_monitor"), !val);

    if (val != registered) {
        if (val) {
            share_add_search_request_listener
                (monitor_gui_append_to_monitor);
        } else {
            share_remove_search_request_listener
                (monitor_gui_append_to_monitor);
        }
        registered = val;
    }
}
