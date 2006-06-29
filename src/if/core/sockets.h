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

#ifndef _if_core_sockets_h_
#define _if_core_sockets_h_

#define SOCK_BUFSZ	4096

/***
 *** Proxy protocols
 ***/
enum {
    PROXY_NONE    = 0,
    PROXY_HTTP    = 1,
    PROXY_SOCKSV4 = 4,
    PROXY_SOCKSV5 = 5
};

/***
 *** Network protocols
 ***/
enum {
    NET_USE_BOTH  = 0,
    NET_USE_IPV4  = 4,
    NET_USE_IPV6  = 6,
};

enum {
	CONNECT_F_FORCE	= (1 << 0),		/* Bypass limitation checks */
	CONNECT_F_TLS	= (1 << 1),		/* Initiate a TLS connection */
	CONNECT_F_PUSH	= (1 << 2)		/* Use a Gnutella PUSH */
};

#endif /* _if_core_sockets_h_ */

/* vi: set ts=4 sw=4 cindent: */
