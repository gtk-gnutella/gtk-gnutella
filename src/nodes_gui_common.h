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

#ifndef _nodes_gui_common_h_
#define _nodes_gui_common_h_

#include "gui.h"

/*
 * Symbolic column index numbers
 */

#define NODE_GUI_HOST_COLUMN		0
#define NODE_GUI_FLAGS_COLUMN		1
#define NODE_GUI_USER_AGENT_COLUMN	2
#define NODE_GUI_VERSION_COLUMN		3
#define NODE_GUI_CONNECTED_COLUMN	4
#define NODE_GUI_UPTIME_COLUMN		5
#define NODE_GUI_INFO_COLUMN		6
#define NODE_GUI_COLUMN_COUNT		7

void nodes_gui_common_init(void);
void nodes_gui_common_shutdown(void);

void nodes_gui_common_node_info_changed(void);
const gchar *nodes_gui_common_status_str(
	const gnet_node_status_t *n, time_t now);
const gchar *nodes_gui_common_flags_str(const gnet_node_flags_t *flags);

#endif /* _nodes_gui_common_h_ */
