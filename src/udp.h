/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
 *
 * Handling of UDP datagrams.
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

#ifndef _udp_h_
#define _udp_h_

#include <glib.h>

/*
 * Public interface.
 */

struct gnutella_socket;

void udp_received(struct gnutella_socket *s);
void udp_connect_back(guint32 ip, guint16 port, const gchar *muid);

#endif /* _udp_h_ */

