/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Banning control.
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

#ifndef __ban_h__
#define __ban_h__

#include <glib.h>

struct gnutella_socket;

void ban_init(void);
void ban_close(void);
gint ban_allow(guint32 ip);
void ban_force(struct gnutella_socket *s);
gint ban_delay(guint32 ip);

/*
 * Return codes for ban_allow().
 */

#define BAN_OK		0		/* OK, don't ban and accept the connection */
#define BAN_FIRST	1		/* Initial banning, send polite denial */
#define BAN_FORCE	2		/* Force banning, don't send back anything */

#endif	/* __ban_h__ */

/* vi: set ts=4: */

