/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * Definitions for the (semi-)reliable UDP layer.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _core_udp_reliable_h_
#define _core_udp_reliable_h_

/*
 * Protocol tag.
 */

typedef struct udp_tag {
	char value[3];			/* 3-letter tag */
} udp_tag_t;

static inline const char *
udp_tag_to_string(const udp_tag_t tag)
{
	static char buf[4];

	memcpy(buf, tag.value, 3);
	buf[3] = '\0';

	return buf;
}

static inline void
udp_tag_set(udp_tag_t *tag, const char *str)
{
	g_assert(str != NULL);
	g_assert(3 == strlen(str));

	memcpy(tag->value, str, 3);
}

/*
 * Header sizes.
 */

#define UDP_RELIABLE_HEADER_SIZE		8		/* Fragments, normal ACKs */
#define UDP_RELIABLE_EXT_HEADER_SIZE	12		/* Extended ACKs */

/*
 * Critical flags.
 */

#define UDP_RF_DEFLATED			0x01	/* Payload is deflated */
#define UDP_RF_ACKME			0x02	/* Packet must be acknowledged */
#define UDP_RF_CRITICAL_MASK	0x0c	/* These are undefined as of now */

/*
 * Optional flags.
 */

#define UDP_RF_IMPROVED_ACKS	0x10	/* For G2 only (native in Gnutella) */
#define UDP_RF_CUMULATIVE_ACK	0x10	/* Cumulative acknowledgment */
#define UDP_RF_EXTENDED_ACK		0x20	/* Extended acknowledgment */

static inline udp_tag_t
udp_reliable_header_get_tag(const void *data)
{
	udp_tag_t tag;

	memcpy(tag.value, data, 3);
	return tag;
}

static inline uint8
udp_reliable_header_get_flags(const void *data)
{
	const uint8 *u8 = data;
	return u8[3];
}

static inline uint16
udp_reliable_header_get_seqno(const void *data)
{
	const uint8 *u8 = data;
	return peek_be16(&u8[4]);
}

static inline uint8
udp_reliable_header_get_part(const void *data)
{
	const uint8 *u8 = data;
	return u8[6];
}

static inline uint8
udp_reliable_header_get_count(const void *data)
{
	const uint8 *u8 = data;
	return u8[7];
}

static inline bool
udp_reliable_is_ack(const void *data)
{
	const uint8 *u8 = data;
	return 0 == u8[7];
}

static inline bool
udp_reliable_is_extended_ack(const void *data)
{
	const uint8 *u8 = data;
	return (u8[3] & UDP_RF_EXTENDED_ACK) && 0 == u8[7];
}

static inline uint8
udp_reliable_get_received(const void *data)
{
	const uint8 *u8 = data;
	g_assert(udp_reliable_is_extended_ack(data));
	return u8[8];
}

static inline uint32
udp_reliable_get_missing(const void *data)
{
	const uint8 *u8 = data;
	g_assert(udp_reliable_is_extended_ack(data));
	return peek_be32(&u8[8]) & 0x00ffffff;		/* Trailing 24 bits */
}

#endif /* _core_udp_reliable_h_ */

