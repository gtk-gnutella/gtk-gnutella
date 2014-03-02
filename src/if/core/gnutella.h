/*
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

#include "lib/endian.h"

struct guid;

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
	GTA_MSG_DHT						= 0x44, /**< DHT message encapsulation */
	GTA_MSG_SEARCH					= 0x80,
	GTA_MSG_SEARCH_RESULTS			= 0x81,
	GTA_MSG_G2_SEARCH				= 0x82,	/**< Internal, does not exist! */
	GTA_MSG_HSEP_DATA 				= 0xcd
};

/*
 * Starting 2006-08-20, gtk-gnutella enforces a maximal payload size of 64K.
 * This frees up 16 bits in the size field for future flags, for yet
 * unforeseen extensions.
 *
 * To mark the size field as containing flags, the highest bit will have to
 * be set.
 */

#define GTA_SIZE_MASK		0xffff
#define GTA_SIZE_MARKED		0x80000000
#define GTA_SIZE_FLAG_SHIFT	16

/*
 * Gnutella header message flags viewed as a 16-bit quantity.
 */

#define GTA_FLAGS_MARK		0x8000		/**< Mark signalling flags presence */

/*
 * Structures
 */

/**
 * Header structure
 */

#define GTA_HEADER_SIZE	23

#if 0
struct gnutella_header_ {
	uint8 muid[16];
	uint8 function;
	uint8 ttl;
	uint8 hops;
	uint8 size[4];
};
#endif

typedef uint8 gnutella_header_t[GTA_HEADER_SIZE];

static inline const void *
gnutella_data(const void *header)
{
	return (char *) header + GTA_HEADER_SIZE;
}

static inline struct guid *
gnutella_header_muid(gnutella_header_t *header)
{
	return (struct guid *) header;
}

static inline const struct guid *
gnutella_header_get_muid(const void *data)
{
	return data;
}

static inline void
gnutella_header_set_muid(gnutella_header_t *header, const struct guid *muid)
{
	memcpy(header, muid, 16);
}

static inline uint8
gnutella_header_get_function(const void *data)
{
	const uint8 *u8 = data;
	return u8[16];
}

static inline void
gnutella_header_set_function(gnutella_header_t *header, uint8 function)
{
	uint8 *u8 = (void *) header;
	u8[16] = function;
}

static inline uint8
gnutella_header_get_ttl(const void *data)
{
	const uint8 *u8 = data;
	return u8[17];
}

static inline void
gnutella_header_set_ttl(gnutella_header_t *header, uint8 ttl)
{
	uint8 *u8 = (void *) header;
	u8[17] = ttl;
}

static inline uint8
gnutella_header_get_hops(const void *data)
{
	const uint8 *u8 = data;
	return u8[18];
}

static inline void
gnutella_header_set_hops(gnutella_header_t *header, uint8 hops)
{
	uint8 *u8 = (void *) header;
	u8[18] = hops;
}

static inline uint32
gnutella_header_get_size(const void *data)
{
	const uint8 *u8 = data;
	return peek_le32(&u8[19]);
}

static inline void
gnutella_header_set_size(gnutella_header_t *header, uint32 size)
{
	uint8 *u8 = (void *) header;
	g_assert(0 == (size & ~GTA_SIZE_MASK));	/* Don't set any "header flags" */
	poke_le32(&u8[19], size);
}

static inline void
gnutella_header_check(void)
{
	STATIC_ASSERT(23 == sizeof(gnutella_header_t));
	STATIC_ASSERT(23 == GTA_HEADER_SIZE);
}

/**
 * UDP traffic compression (TTL marking flags)
 */

#define GTA_UDP_CAN_INFLATE		0x08	/**< TTL marking for deflate support */
#define GTA_UDP_DEFLATED		0x80	/**< TTL marking: payload deflated */

#endif /* _if_core_gnutella_h_ */

/* vi: set ts=4 sw=4 cindent: */
