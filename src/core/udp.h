/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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

/**
 * @ingroup core
 * @file
 *
 * Handling of UDP datagrams.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _core_udp_h_
#define _core_udp_h_

#include "common.h"
#include "lib/host_addr.h"

/*
 * Public interface.
 */

struct gnutella_socket;
struct gnutella_node;

void udp_received(struct gnutella_socket *s, gboolean truncated);
void udp_connect_back(const host_addr_t addr, guint16 port, const gchar *muid);
void udp_send_msg(const struct gnutella_node *n, gconstpointer buf, gint len);
void udp_send_ping(const host_addr_t addr, guint16 port, gboolean uhc_ping);

#endif /* _core_udp_h_ */

