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

#ifndef _ban_h_
#define _ban_h_

#include <glib.h>

struct gnutella_socket;

/*
 * Return codes for ban_allow().
 */

typedef enum {
	BAN_OK		= 0,		/* OK, don't ban and accept the connection */
	BAN_FIRST	= 1,		/* Initial banning, send polite denial */
	BAN_FORCE	= 2,		/* Force banning, don't send back anything */
	BAN_MSG		= 3,		/* Ban with explicit message */
} ban_type_t;

void ban_init(void);
void ban_close(void);
ban_type_t ban_allow(guint32 ip);
void ban_record(guint32 ip, const gchar *msg);
void ban_force(struct gnutella_socket *s);
gint ban_delay(guint32 ip);
gchar *ban_message(guint32 ip);
void ban_max_recompute(void);

const gchar *ban_vendor(const gchar *vendor);

#endif	/* _ban_h_ */

/* vi: set ts=4: */

