/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
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

#ifndef __search_cb_h__
#define __search_cb_h__

#include <gtk/gtk.h>

void on_search_popdown_switch(GtkWidget * w, gpointer data);
void on_search_notebook_switch(GtkNotebook * notebook, GtkNotebookPage * page, gint page_num, gpointer user_data);
void on_clist_search_select_row(GtkCList * clist, gint row, gint column, GdkEvent * event, gpointer user_data);

#endif /* __search_cb_h__ */
