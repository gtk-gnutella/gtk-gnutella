/*
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_core_http_h_
#define _if_core_http_h_

/**
 * HTTP request states.
 */

typedef enum http_state {
	HTTP_AS_UNKNOWN = 0,		/**< No defined state */
	HTTP_AS_CONNECTING,			/**< Connecting to server */
	HTTP_AS_REQ_SENDING,		/**< Sending request to server */
	HTTP_AS_REQ_SENT,			/**< Request sent, waiting for reply */
	HTTP_AS_HEADERS,			/**< Receiving headers */
	HTTP_AS_RECEIVING,			/**< Receiving data */
	HTTP_AS_REDIRECTED,			/**< Request redirected */
	HTTP_AS_REMOVED				/**< Removed, pending free */
} http_state_t;

#endif /* _if_core_http_h_ */

/* vi: set ts=4 sw=4 cindent: */
