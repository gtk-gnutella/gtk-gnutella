/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Push proxy HTTP management.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_pproxy_h_
#define _core_pproxy_h_

#include "common.h"

#include "if/core/pproxy.h"
#include "lib/array.h"

struct guid;

/***
 *** Server side
 ***/

/**
 * A push proxy request we received.
 */
struct pproxy {
	struct gnutella_socket *socket;
	gint error_sent;		/**< HTTP error code sent back */
	time_t last_update;

	host_addr_t addr_v4;	/**< IPv4 of the requesting servent */
	host_addr_t addr_v6;	/**< IPv6 of the requesting servent */
	guint16 port;			/**< Port where GIV should be sent back */
	const char *user_agent;/**< User-Agent string */
	const struct guid *guid;/**< GUID (atom) to which push should be sent */
	guint32 file_idx;		/**< File index to request (0 if none supplied) */
	guint32 flags;
	gpointer io_opaque;		/**< Opaque I/O callback information */
};

#define pproxy_vendor_str(p)	((p)->user_agent ? (p)->user_agent : "")

void pproxy_add(struct gnutella_socket *s);
void pproxy_remove(struct pproxy *pp,
	const char *reason, ...) G_GNUC_PRINTF(2, 3);
void pproxy_timer(time_t now);
void pproxy_close(void);

/***
 *** Client side
 ***/

struct cproxy *cproxy_create(struct download *d,
	const host_addr_t addr, guint16 port, const struct guid *guid,
	guint32 file_idx);
void cproxy_free(struct cproxy *cp);
void cproxy_reparent(struct download *d, struct download *cd);

struct array build_push(guint8 ttl, guint8 hops,
	const struct guid *guid, host_addr_t addr_v4, host_addr_t addr_v6,
	guint16 port, guint32 file_idx, gboolean supports_tls);

#endif	/* _core_pproxy_h_ */

/* vi: set ts=4 sw=4 cindent: */
