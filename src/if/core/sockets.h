/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_core_sockets_h_
#define _if_core_sockets_h_

#define SOCK_BUFSZ	4096		/**< Buffer size for connected sockets */
#define SOCK_LBUFSZ	32768		/**< Buffer size for datagram sockets */

/***
 *** Proxy protocols
 ***/
enum proxy_protocol {
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
    NET_USE_IPV6  = 6
};

/***
 *** Tracing options for higher-level protocols, defined here for
 *** lacking a better common place.
 ***/
enum {
	SOCK_TRACE_NONE = 0,
	SOCK_TRACE_IN	= 0x1,
	SOCK_TRACE_OUT	= 0x2,
	SOCK_TRACE_BOTH = 0x1 | 0x2
};

/**
 * Operating flags
 */
enum {
	SOCK_F_ESTABLISHED	= (1UL << 0),  /**< Connection was established */
	SOCK_F_EOF			= (1UL << 1),  /**< Got an EOF condition */
	SOCK_F_FORCE		= (1UL << 2),  /**< Bypass usual restrictions */
	SOCK_F_TLS			= (1UL << 3),  /**< Request a TLS connection */
	SOCK_F_PUSH			= (1UL << 4),  /**< Use a Gnutella PUSH */
	SOCK_F_NODELAY		= (1UL << 5),  /**< Set if TCP_NODELAY is enabled */
	SOCK_F_CORKED		= (1UL << 6),  /**< Set if TCP_CORK is enabled */
	SOCK_F_SHUTDOWN		= (1UL << 7),  /**< Set if shutdown() was called */
	SOCK_F_OMIT_TOKEN	= (1UL << 8),  /**< If set X-Token header is omitted */
	SOCK_F_PREPARED		= (1UL << 9),  /**< Prepared (known address) */
	SOCK_F_SINGLE		= (1UL << 10), /**< Read one single datagram */
	SOCK_F_CONNRESET	= (1UL << 11), /**< Got a connection reset event */
	SOCK_F_OLD			= (1UL << 12), /**< Processing an "old" UDP datagram */
	SOCK_F_G2			= (1UL << 13), /**< Targeting a G2 node */
	SOCK_F_LOCAL		= (1UL << 28), /**< Is a local socket */
	SOCK_F_UDP			= (1UL << 29), /**< Is a UDP socket */
	SOCK_F_TCP			= (1UL << 30)  /**< Is a TCP socket */
};

/**
 * Connection types.
 */
enum socket_type {
	SOCK_TYPE_UNKNOWN = 0,
	SOCK_TYPE_CONTROL,
	SOCK_TYPE_DOWNLOAD,
	SOCK_TYPE_UPLOAD,
	SOCK_TYPE_HTTP,
    SOCK_TYPE_SHELL,
    SOCK_TYPE_CONNBACK,
    SOCK_TYPE_PPROXY,
    SOCK_TYPE_DESTROYING,
	SOCK_TYPE_UDP
};

/**
 * Socket buffer type.
 */
enum socket_buftype {
	SOCK_BUF_RX,
	SOCK_BUF_TX
};

#endif /* _if_core_sockets_h_ */

/* vi: set ts=4 sw=4 cindent: */
