/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _hosts_h_
#define _hosts_h_

#include <glib.h>

struct gnutella_host {
	guint32 ip;
	guint16 port;
};

/*
 * Global Data
 */

extern GList *sl_caught_hosts;
extern guint32 hosts_in_catcher;
extern gboolean host_low_on_pongs;

/*
 * Global Functions
 */

void host_init(void);
void host_timer(void);
void host_add_ultra(guint32 ip, guint16 port);
void host_add(guint32, guint16, gboolean);
void host_add_semi_pong(guint32 ip, guint16 port);
void host_shutdown(void);
void host_close(void);

void parse_netmasks(gchar *value);
gboolean host_is_nearby(guint32 ip);

#endif /* _hosts_h_ */
