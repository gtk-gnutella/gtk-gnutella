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

#include "gnutella.h"
#include "share_gui.h"
#include "misc.h"

static guint32 monitor_items = 0;

void share_gui_init()
{
    gtk_clist_column_titles_passive
        (GTK_CLIST(lookup_widget(main_window, "clist_monitor")));  
}

void share_gui_append_to_monitor(gchar * item)
{
    char *titles[1];
    static GtkWidget *clist_monitor = NULL;

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

	titles[0] = item;

	gtk_clist_prepend(GTK_CLIST(clist_monitor), titles);

	gtk_clist_thaw(GTK_CLIST(clist_monitor));
}

/*
 * share_gui_clear_monitor:
 *
 * Remove all but the first n items from the monitor.
 */
void share_gui_clear_monitor(void) 
{
    GtkWidget *clist_monitor;

    clist_monitor = lookup_widget(main_window, "clist_monitor");

    gtk_clist_clear(GTK_CLIST(clist_monitor));
	monitor_items = 0;
}

/*
 * share_gui_enable_monitor:
 *
 * Enable/disable monitor.
 */
void share_gui_enable_monitor(gboolean b)
{
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "clist_monitor"), !b);
}
