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

#include "http.h"

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

#define pproxy_vendor_str(p)	((p)->user_agent ? (p)->user_agent : "")

void pproxy_add(struct gnutella_socket *s);
void pproxy_remove(struct pproxy *pp, const gchar *reason, ...);
void pproxy_timer(time_t now);
void pproxy_close(void);

/***
 *** Client side
 ***/

/*
 * A client push proxy request.
 */
struct cproxy {
	struct download *d;		/* Which download triggered us */

	guint32 ip;				/* IP of the proxy servent */
	guint16 port;			/* Port of the proxy servent */
	gchar *server;			/* Server string */
	gchar *guid;			/* GUID (atom) to which push should be sent */
	gpointer http_handle;	/* Asynchronous HTTP request handle */

	/*
	 * For GUI.
	 */

	http_state_t state;		/* State of the HTTP request */
	gboolean done;			/* We're done with request */
	gboolean sent;			/* Whether push was sent */
	gboolean directly;		/* Whether push was sent directly or via Gnet */
};

#define cproxy_vendor_str(c)	((c)->server ? (c)->server : "")
#define cproxy_ip(c)			((c)->ip)
#define cproxy_port(c)			((c)->port)

struct cproxy *cproxy_create(struct download *d,
	guint32 ip, guint16 port, gchar *guid);
void cproxy_free(struct cproxy *cp);
void cproxy_reparent(struct download *d, struct download *cd);
	
#endif	/* _pproxy_h_ */

/* vi: set ts=4: */
