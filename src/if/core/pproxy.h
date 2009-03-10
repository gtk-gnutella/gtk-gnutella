/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
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
 * @ingroup ui
 * @file
 *
 * Needs short description here.
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#ifndef _if_core_pproxy_h_
#define _if_core_pproxy_h_

#include "if/core/http.h"	/* For http_state_t */
#include "lib/host_addr.h"	/* For host_addr_t */

struct download;
struct guid;

/**
 * A client push proxy request.
 */
struct cproxy {
	guint32 magic;
	struct download *d;		/**< Which download triggered us */

	host_addr_t addr;		/**< IP of the proxy servent */
	guint16 port;			/**< Port of the proxy servent */
	const char *server;	/**< Server string */
	const struct guid *guid;/**< GUID (atom) to which push should be sent */
	guint32 file_idx;		/**< File index to request */
	gpointer http_handle;	/**< Asynchronous HTTP request handle */
	guint32 flags;			/**< Operating flags */

	/*
	 * For GUI.
	 */

	http_state_t state;		/**< State of the HTTP request */
	gboolean done;			/**< We're done with request */
	gboolean sent;			/**< Whether push was sent */
	gboolean directly;		/**< Whether push was sent directly or via Gnet */
};

#define cproxy_vendor_str(c)	((c)->server ? (c)->server : "")
#define cproxy_addr(c)			((c)->addr)
#define cproxy_port(c)			((c)->port)

#endif /* _if_core_pproxy_h_ */

/* vi: set ts=4 sw=4 cindent: */
