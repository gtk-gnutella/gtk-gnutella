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

#ifndef _nodes_cb2_h_
#define _nodes_cb2_h_

#include <gtk/gtk.h>

/***
 *** nodes panel
 ***/

void on_button_nodes_add_clicked (GtkButton *button, gpointer user_data); 
void on_button_nodes_remove_clicked (GtkButton *button, gpointer user_data);
void on_entry_host_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_host_changed (GtkEditable *editable, gpointer user_data);

void nodes_gui_remove_selected(void);
#endif /* _nodes_cb2_h_ */
