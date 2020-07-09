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

#include "common.h"

#include "gtk/gui.h"
#include "gtk/monitor_cb.h"
#include "gtk/search.h"

#include "lib/override.h"		/* Must be the last header included */

gboolean
on_clist_monitor_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata)
{
    gint row;
    gint col;
    GtkCList *clist_monitor = GTK_CLIST(widget);

	(void) unused_udata;

	if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(clist_monitor)->selection == NULL)
        return FALSE;

  	if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_monitor), event->x, event->y, &row, &col))
		return FALSE;

	gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(gui_main_window_lookup("checkbutton_monitor_enable")),
        FALSE);
	gtk_menu_popup(GTK_MENU(gui_popup_monitor()), NULL, NULL, NULL, NULL,
		event->button, event->time);

	return TRUE;
}

void
on_popup_monitor_add_search_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GList *l;
	gchar *titles[1];
	gchar *e;
    GtkCList *clist_monitor = GTK_CLIST
        (gui_main_window_lookup("clist_monitor"));

	(void) unused_menuitem;
	(void) unused_udata;

	for (
        l = GTK_CLIST(clist_monitor)->selection;
        l != NULL;
        l = GTK_CLIST(clist_monitor)->selection
    ) {
        gtk_clist_get_text(GTK_CLIST(clist_monitor), GPOINTER_TO_INT(l->data),
			0, titles);
        gtk_clist_unselect_row(GTK_CLIST(clist_monitor),
			GPOINTER_TO_INT(l->data), 0);

		e = g_strdup(titles[0]);

		g_strstrip(e);
		if (*e)
            search_gui_new_search(e, 0, NULL);

		G_FREE_NULL(e);
	}
}

/* vi: set ts=4 sw=4 cindent: */
