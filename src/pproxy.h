/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Push proxy HTTP management.
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

#ifndef _pproxy_h_
#define _pproxy_h_

#include <glib.h>

/***
 *** Server side
 ***/

/*
 * A push proxy request we received.
 */
struct pproxy {
	struct gnutella_socket *socket;
	gint error_sent;		/* HTTP error code sent back */
	time_t last_update;

	guint32 ip;				/* IP of the requesting servent */
	guint16 port;			/* Port where GIV should be sent back */
	gchar *user_agent;		/* User-Agent string */
	gchar *guid;			/* GUID (atom) to which push should be sent */
	gpointer io_opaque;		/* Opaque I/O callback information */
};

#define pproxy_vendor_str(pp)	((pp)->user_agent ? (pp)->user_agent : "")

void pproxy_add(struct gnutella_socket *s);
void pproxy_remove(struct pproxy *pp, const gchar *reason, ...);
void pproxy_timer(time_t now);
void pproxy_close();

/***
 *** Client side
 ***/

/*
 * A client push proxy request.
 */
struct cproxy {
	struct download *d;		/* Which download triggered us */
	struct gnutella_socket *socket;
	time_t last_update;

	guint32 ip;				/* IP of the proxy servent */
	guint16 port;			/* Port of the proxy servent */
	gchar *server;			/* Server string */
	gchar *guid;			/* GUID (atom) to which push should be sent */
	gpointer io_opaque;		/* Opaque I/O callback information */
};

#define cproxy_vendor_str(cp)	((cp)->server ? (cp)->server : "")

struct cproxy *cproxy_create(struct download *d,
	guint32 ip, guint16 port, gchar *guid);

#endif	/* _pproxy_h_ */

/* vi: set ts=4: */

