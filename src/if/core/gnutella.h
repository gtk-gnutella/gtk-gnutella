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

#ifndef _if_core_gnutella_h_
#define _if_core_gnutella_h_

/*
 * Constants
 */

enum gta_msg {
	GTA_MSG_INIT					= 0x00,
	GTA_MSG_INIT_RESPONSE			= 0x01,
	GTA_MSG_BYE						= 0x02,
	GTA_MSG_QRP						= 0x30,
	GTA_MSG_VENDOR					= 0x31,	/**< Vendor-specific */
	GTA_MSG_STANDARD				= 0x32,	/**< Standard vendor-specific */
	GTA_MSG_PUSH_REQUEST			= 0x40,
	GTA_MSG_RUDP					= 0x41,
	GTA_MSG_SEARCH					= 0x80,
	GTA_MSG_SEARCH_RESULTS			= 0x81,
	GTA_MSG_HSEP_DATA 				= 0xcd
};

/*
 * Structures
 */

#if !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(p)
#endif

/**
 * Header structure
 */

struct gnutella_header {
	gchar muid[16];
	guchar function;
	guchar ttl;
	guchar hops;
	guchar size[4];
} __attribute__((__packed__));

#define GTA_HEADER_SIZE		sizeof(struct gnutella_header)

/**
 * UDP traffic compression (TTL marking flags)
 */

#define GTA_UDP_CAN_INFLATE		0x08	/**< TTL marking for deflate support */
#define GTA_UDP_DEFLATED		0x80	/**< TTL marking: payload deflated */

#endif /* _if_core_gnutella_h_ */

/* vi: set ts=4 sw=4 cindent: */
