/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * GUI filtering functions.
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

#include <gtk/gtk.h>
#include "search_cb.h"
#include "search_gui.h"
#include "search.h" // FIXME: remove this dependency

void on_search_popdown_switch(GtkWidget * w, gpointer data)
{
	search_t *sch = search_selected;
	if (!sch)
		return;

	search_gui_view_search(sch);
}

void on_search_notebook_switch(GtkNotebook * notebook,
							   GtkNotebookPage * page, gint page_num,
							   gpointer user_data)
{
    //FIXME: find a way this works also with Gtk2
#ifndef USE_GTK2
	search_t *sch = (search_t *)
        gtk_object_get_user_data((GtkObject *) page->child);

	g_return_if_fail(sch);

    search_gui_view_search(sch);
#endif
}

void on_clist_search_select_row(GtkCList * clist, gint row,
								 gint column, GdkEvent * event,
								 gpointer user_data)
{
    gpointer sch;

    g_assert(clist != NULL);

    sch = gtk_clist_get_row_data(clist, row);

    if (sch == NULL)
        return;

    search_gui_view_search((search_t *)sch);
}
