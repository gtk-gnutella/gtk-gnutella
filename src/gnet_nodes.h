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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#ifndef _gnet_nodes_h_
#define _gnet_nodes_h_

#include "common.h"
#include "ui_core_interface_gnet_nodes_defs.h"

/***
 *** Gnet nodes
 ***/


void node_add_node_added_listener(node_added_listener_t);
void node_remove_node_added_listener(node_added_listener_t);
void node_add_node_removed_listener(node_removed_listener_t);
void node_remove_node_removed_listener(node_removed_listener_t);
void node_add_node_info_changed_listener(node_info_changed_listener_t);
void node_remove_node_info_changed_listener(node_info_changed_listener_t);
void node_add_node_flags_changed_listener(node_flags_changed_listener_t);
void node_remove_node_flags_changed_listener(node_flags_changed_listener_t);

/*
 * Nodes public interface
 */
void node_add(guint32, guint16);
void node_remove_by_handle(gnet_node_t n);
void node_remove_nodes_by_handle(GSList *node_list);
void node_get_status(const gnet_node_t n, gnet_node_status_t *s);
gnet_node_info_t *node_get_info(const gnet_node_t n);
void node_clear_info(gnet_node_info_t *info);
void node_free_info(gnet_node_info_t *info);
void node_fill_flags(gnet_node_t n, gnet_node_flags_t *flags);
void node_fill_info(const gnet_node_t n, gnet_node_info_t *info);

#endif /* _gnet_nodes_h */
