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

#ifndef _gtk_nodes_common_h_
#define _gtk_nodes_common_h_

#include "gui.h"
#include "if/core/nodes.h"

GtkMenu *nodes_gui_get_popup_menu(void);
const gchar *nodes_gui_common_status_str(const gnet_node_status_t *n);
void nodes_gui_common_connect_by_name(const gchar *addr);

void nodes_gui_update_display(time_t now);
void nodes_gui_timer(time_t now);

#endif /* _gtk_nodes_common_h_ */

/* vi: set ts=4 sw=4 cindent: */
